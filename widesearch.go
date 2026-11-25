package main

// wide-search: keep searches inside the project instead of sweeping the whole
// disk or the home directory.
//
// A first attempt is denied with an explanation. Repeating the same search root
// escalates to "ask", so a genuinely intended global search costs one
// confirmation instead of being walled off.
//
// "Already warned" is tracked per agent, not per session: subagents share their
// parent's session id, so session-wide state made a subagent's first attempt
// look like a repeat of a warning it never saw. The discriminator has to be
// agent_id; transcript_path looks like it would work and does not, because the
// payload derives it from the session id and every subagent therefore reports
// the parent's transcript.
//
// Inside a subagent a repeat stays a "deny". Claude Code can route a
// subagent's permission prompt to the main session, but that interrupts the
// user over something the subagent can fix on its own by naming a narrower
// directory, and in a headless run nobody is there to answer at all. Deferring
// the decision to the main thread, which can ask, is the better trade.
//
// Commands are read with a real shell parser, so quoting, keywords,
// assignments, pipelines and command substitutions — even inside double
// quotes — are taken apart the way the shell would. Here-document bodies are
// data, not commands, and are not inspected. A command that does not parse is
// refused (see unparsedReason).
//
// This is a guardrail against wasted time, not a security boundary — anything
// that hides the path from a plain reading of the command (a variable, a path
// built at run time) will pass straight through.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

// denyBody explains the refusal. Naming the caches is not a detail: replaying
// 52k historical calls, essentially every wide search was a hunt for dependency
// source — jars, SwiftPM checkouts, node_modules of another project, crates.
// All of that really is outside the project, and all of it has an address
// narrower than a filesystem root. The three named here cover the ecosystems
// evenly; swap them for whatever your stack actually uses.
const denyBody = "Search scoped to %q — that is the whole disk or your home directory, not the project (%s). " +
	"You almost certainly want the project instead: use a relative path, or name the subdirectory you need. " +
	"If the target genuinely lives outside the project — dependency source, a build cache — name that " +
	"directory rather than a root: a package cache (~/.gradle, ~/.m2, ~/.cargo), a build directory " +
	"(~/Library/Developer/Xcode/DerivedData), or the dependency tree inside the project (node_modules). "

const mainTail = "If this search must be global after all, run it again and it will be put to the user for confirmation."

const subTail = "A subagent does not escalate this to the user, so a root will stay refused here: " +
	"pick a concrete directory, or report the limitation in your result and let the main thread ask the user."

const askFmt = "Global search of %q requested again after a scope warning. " +
	"Confirm with the user that searching outside the project is intended."

const subRepeatFmt = "Global search of %q was already refused in this agent. " +
	"Retrying does not escalate to the user from inside a subagent. " +
	"Name a concrete directory — a package cache, a build directory, or the project itself — " +
	"or state in your result that the answer needs a search outside the project."

// searchCmds are the commands whose arguments name a place to walk. Claude
// Code's shell runs `find` and `grep` as embedded bfs and ugrep, so those names
// can turn up too.
var searchCmds = map[string]bool{
	"find": true, "bfs": true, "grep": true, "egrep": true, "fgrep": true,
	"ugrep": true, "ug": true, "rg": true, "ag": true, "fd": true, "fdfind": true,
}

// findLike take paths and an expression rather than a pattern and paths.
var findLike = map[string]bool{"find": true, "bfs": true}

// valueFlags consume the following argument, so that argument is neither the
// search pattern nor a path. Missing an entry here is harmless: the value gets
// mistaken for the pattern, which only matters if it is literally "/" or "~".
var valueFlags = map[string]bool{
	"-e": true, "-f": true, "-m": true, "-A": true, "-B": true, "-C": true,
	"-d": true, "-g": true, "-t": true, "-T": true, "-E": true, "-x": true,
	"-X": true, "-j": true, "-M": true, "--include": true, "--exclude": true,
	"--glob": true, "--iglob": true, "--type": true, "--type-not": true,
	"--max-count": true, "--max-depth": true, "--search-path": true,
	"--threads": true, "--sort": true, "--pre": true, "--colors": true,
	"--binary-files": true, "--regexp": true, "--file": true,
}

// patternFlags supply the pattern directly, or say there is none (rg --files
// lists what it would search), so no positional pattern follows.
var patternFlags = map[string]bool{
	"-e": true, "-f": true, "--regexp": true, "--file": true, "--files": true,
}

// findValuePreds are find/bfs predicates that consume the following word. That
// word is a name, a pattern or a number, never a place to walk.
var findValuePreds = map[string]int{
	"-name": 1, "-iname": 1, "-path": 1, "-ipath": 1, "-wholename": 1, "-iwholename": 1,
	"-regex": 1, "-iregex": 1, "-lname": 1, "-ilname": 1, "-regextype": 1,
	"-newer": 1, "-anewer": 1, "-cnewer": 1, "-samefile": 1,
	"-user": 1, "-group": 1, "-uid": 1, "-gid": 1, "-perm": 1, "-type": 1, "-xtype": 1,
	"-size": 1, "-mtime": 1, "-mmin": 1, "-atime": 1, "-amin": 1, "-ctime": 1, "-cmin": 1,
	"-maxdepth": 1, "-mindepth": 1, "-depth": 0, "-fstype": 1, "-inum": 1, "-links": 1,
	"-used": 1, "-context": 1, "-printf": 1, "-fprint": 1, "-fprint0": 1, "-fls": 1,
	"-fprintf": 2, "-files0-from": 1,
}

// findPaths returns the places a find or bfs invocation walks. GNU find wants
// them before the expression, but bfs — which is what `find` is in Claude
// Code's shell — takes a path anywhere, so every word that is not an option,
// a predicate or a predicate's value counts. `-maxdepth 0` only looks at the
// paths themselves, which is not a walk.
func findPaths(args []string) []string {
	var paths []string
	i := 0
	// Leading options: symlink handling, optimisation level, debug flags.
leading:
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-H", a == "-L", a == "-P", a == "-E", a == "-X", a == "-s", a == "-x",
			strings.HasPrefix(a, "-O"):
			i++
		case a == "-D":
			i += 2
		case a == "-f" && i+1 < len(args): // BSD find: the next word is a path
			paths = append(paths, args[i+1])
			i += 2
		default:
			break leading
		}
	}
	for ; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-maxdepth" && i+1 < len(args) && args[i+1] == "0":
			return nil
		case a == "-exec", a == "-execdir", a == "-ok", a == "-okdir":
			for i+1 < len(args) && args[i+1] != ";" && args[i+1] != "+" {
				i++
			}
			i++
		case strings.HasPrefix(a, "-newer"):
			i++ // -newer and -newerXY take a reference
		case strings.HasPrefix(a, "-") && a != "-":
			i += findValuePreds[a]
		case a == "(", a == ")", a == "!", a == ",":
		default:
			paths = append(paths, a)
		}
	}
	return paths
}

// searchPaths returns the arguments of a search invocation that name a place to
// walk. The pattern-first tools (grep, rg, fd, ag) take everything after the
// pattern.
func searchPaths(name string, args []string) []string {
	if findLike[name] {
		return findPaths(args)
	}
	needPattern := true

	var paths []string
	endOfFlags := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !endOfFlags {
			if a == "--" {
				endOfFlags = true
				continue
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				base, inline := a, strings.Contains(a, "=")
				if eq := strings.Index(a, "="); eq >= 0 {
					base = a[:eq]
				}
				if patternFlags[base] {
					needPattern = false
				}
				if valueFlags[base] && !inline {
					i++ // the next argument belongs to this flag
				}
				continue
			}
		}
		if needPattern {
			needPattern = false
			continue // this positional is the search pattern, not a path
		}
		paths = append(paths, a)
	}
	return paths
}

// wideRoots is what this hook refuses to search: the filesystem root, the
// user's home, and the directory holding all homes. Anything narrower — a
// sibling repo, ~/Projects — is the user's business.
func wideRoots(home string) map[string]bool {
	set := map[string]bool{"/": true}
	if home == "" || home == "/" {
		return set
	}
	set[filepath.Clean(home)] = true
	if parent := filepath.Dir(filepath.Clean(home)); parent != "/" && parent != "." {
		set[parent] = true
	}
	return set
}

// globRoot returns the directory an absolute glob pattern starts walking from:
// the literal part before the first wildcard, cut back to a whole directory.
func globRoot(pattern string) (string, bool) {
	if !strings.HasPrefix(pattern, "/") && !strings.HasPrefix(pattern, "~") && !strings.HasPrefix(pattern, "$HOME") {
		return "", false
	}
	i := strings.IndexAny(pattern, "*?[{")
	if i < 0 {
		return "", false // a literal path is looked up, not walked
	}
	lit := pattern[:i]
	if i := strings.LastIndex(lit, "/"); i >= 0 {
		lit = lit[:i+1]
	}
	return lit, lit != ""
}

// isWide reports whether tok names one of the roots we refuse to walk.
func isWide(tok, home string, wide map[string]bool) bool {
	switch {
	case tok == "":
		return false
	case tok == "~", tok == "~/", tok == "$HOME", tok == "${HOME}":
		tok = home
	case strings.HasPrefix(tok, "~/"):
		tok = home + "/" + tok[len("~/"):]
	case strings.HasPrefix(tok, "$HOME/"):
		tok = home + "/" + tok[len("$HOME/"):]
	case strings.HasPrefix(tok, "${HOME}/"):
		tok = home + "/" + tok[len("${HOME}/"):]
	}
	if !strings.HasPrefix(tok, "/") {
		return false // relative paths stay inside the project
	}
	return wide[filepath.Clean(tok)]
}

// decideWide returns the offending search root, and true when the call must not
// proceed unchallenged.
func decideWide(in hookIn, home string) (string, bool) {
	wide := wideRoots(home)

	switch in.ToolName {
	case "Grep", "Glob":
		if isWide(in.ToolInput.Path, home, wide) {
			return in.ToolInput.Path, true
		}
		// Glob also walks from an absolute pattern: `/**/*.jar`.
		if in.ToolName == "Glob" {
			if dir, ok := globRoot(in.ToolInput.Pattern); ok && isWide(dir, home, wide) {
				return dir, true
			}
		}
	}
	cmd, ok := in.shellCommand()
	if !ok {
		return "", false
	}
	f, err := parseShell(cmd)
	if err != nil {
		return "", false
	}
	var target string
	syntax.Walk(f, func(n syntax.Node) bool {
		if target != "" {
			return false
		}
		c, ok := n.(*syntax.CallExpr)
		if !ok || len(c.Args) == 0 {
			return true
		}
		args := unwrap(callArgs(c))
		if len(args) == 0 {
			return true
		}
		name := commandName(args[0])
		if !searchCmds[name] {
			return true
		}
		for _, p := range searchPaths(name, args[1:]) {
			if isWide(p, home, wide) {
				target = p
				return false
			}
		}
		return true
	})
	if target != "" {
		return target, true
	}
	return "", false
}

// stateKey identifies the context that gets warned. Subagents inherit their
// parent's session id, so the agent id has to be part of the key: without it,
// three subagents fanned out from one session share a single ledger and two of
// them are escalated over a warning that landed in somebody else's context.
func stateKey(in hookIn) string {
	if in.SessionID == "" {
		return ""
	}
	key := sanitize(in.SessionID)
	if in.AgentID != "" {
		key += "__" + sanitize(in.AgentID)
	}
	return key
}

// warned reports whether this agent was already told about target, recording it
// when it was not. An agent that insists gets escalated rather than walled off
// behind the same message again.
func warned(key, target, home string) bool {
	if key == "" || home == "" {
		return false
	}
	dir := filepath.Join(home, ".claude", "hooks", "state", "wide-search")
	if os.MkdirAll(dir, 0o755) != nil {
		return false
	}
	prune(dir)

	f := filepath.Join(dir, key)
	if data, err := os.ReadFile(f); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if line == target {
				return true
			}
		}
	}
	fh, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	defer fh.Close()
	fmt.Fprintln(fh, target)
	return false
}

// respondWide turns a blocked search into a permission decision and the reason
// the model will read. Only the main thread escalates, so only there does a
// repeat become an "ask".
func respondWide(in hookIn, target string, repeat bool) (decision, reason string) {
	inSubagent := in.AgentID != ""
	switch {
	case repeat && !inSubagent:
		return "ask", fmt.Sprintf(askFmt, target)
	case repeat:
		return "deny", fmt.Sprintf(subRepeatFmt, target)
	case inSubagent:
		return "deny", fmt.Sprintf(denyBody+subTail, target, in.Cwd)
	default:
		return "deny", fmt.Sprintf(denyBody+mainTail, target, in.Cwd)
	}
}

// sanitize keeps an id safe to use as a filename.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '_'
	}, s)
}

// prune drops state for sessions that have been idle for a week.
func prune(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

const unparsedFmt = "This command does not parse as bash or zsh (%v), so it cannot be checked and is refused. " +
	"Fix the syntax, or rewrite it in plain bash — split it into simpler commands, or put a longer script " +
	"in a file and run that."

// unparsedReason refuses a shell command no parser can read: it cannot be
// checked, and replaying 44k real commands found only one, itself broken.
// It returns the refusal, or "" when the command parses.
func unparsedReason(in hookIn) string {
	cmd, ok := in.shellCommand()
	if !ok {
		return ""
	}
	if _, err := parseShell(cmd); err != nil {
		return fmt.Sprintf(unparsedFmt, err)
	}
	return ""
}

func runWideSearch(in hookIn) {
	home := homeDir()
	if reason := unparsedReason(in); reason != "" {
		emit(os.Stdout, "deny", reason)
		return
	}
	target, blocked := decideWide(in, home)
	if !blocked {
		return
	}
	decision, reason := respondWide(in, target, warned(stateKey(in), target, home))
	emit(os.Stdout, decision, reason)
}
