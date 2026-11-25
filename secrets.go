package main

// secrets: keep the agent out of secret files — .env files and sops-encrypted
// files — whichever tool it reaches for.
//
// A deny rule in permissions cannot do this well: Read(...) deny rules make
// Claude Code's Bash analyzer prompt on any command that touches a directory
// that "may contain" a denied file. A hook only fires on a concrete path or
// command, so it never causes those prompts.
//
// Some .env files are meant for the agent. `--allow NAME` exempts an exact file
// name — `--allow .env.development` opens .env.development and nothing else:
// not .env.development.local, not .env, not .env.local. A command passes only if
// every secret file it names is exempt, so `cp .env.development .env.local` is
// still refused.
//
// Like wide-search this is a guardrail, not a security boundary: a file read
// without being named — `grep -r TOKEN .`, a path in a variable — passes.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"mvdan.cc/sh/v3/syntax"
)

// secretBasename matches file names that are always secrets. Word characters
// are Unicode letters and digits, as they are to isWordRune.
var secretBasename = regexp.MustCompile(`^(\.env|\.env\.[\p{L}\p{N}_.-]+|[\p{L}\p{N}_.-]+\.env|[\p{L}\p{N}_.-]+\.sops\.[\p{L}\p{N}_.-]+)\n?$`)

// safeSuffix marks .env variants that hold no secrets.
var safeSuffix = regexp.MustCompile(`\.(example|sample|template|dist|schema|d\.ts)\n?$`)

// secretDir matches directories that are always secrets, whatever the allow list says.
var secretDir = regexp.MustCompile(`(^|/)\.config/sops(/|$)`)

// runtimeEnvObjects are identifiers whose `.env` is a runtime object, not a
// file: `process.env`, `os.env`, `ctx.env`.
var runtimeEnvObjects = map[string]bool{
	"process": true, "meta": true, "deno": true, "bun": true, "os": true, "env": true,
	"this": true, "self": true, "window": true, "globalthis": true, "config": true,
	"ctx": true, "context": true, "app": true, "settings": true, "req": true, "res": true,
}

// globProbes are the secret file names a shell glob is tried against. A glob
// that could expand to one of them — `.env*`, `*.env`, `.env.{local,prod}` —
// reads secrets as surely as naming the file does.
var globProbes = []string{
	".env", ".env.local", ".env.production", ".env.staging", ".env.test",
	".env.development", ".env.development.local", ".env.production.local",
	"prod.env", "secrets.sops.yaml", "secrets.sops.json",
}

type secretsConfig struct {
	allow map[string]bool
	// bad lists flags that were rejected; the hook then runs on its built-in
	// rules alone and says so in every refusal.
	bad []string
}

// parseSecretsFlags reads `--allow NAME` / `--allow=NAME`. A name must be a
// bare file name. Anything it cannot use is reported, never guessed at: a typo
// in an allow list must not open more than was meant.
func parseSecretsFlags(args []string) secretsConfig {
	cfg := secretsConfig{allow: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		var name string
		switch {
		case a == "--allow" && i+1 < len(args):
			i++
			name = args[i]
		case strings.HasPrefix(a, "--allow="):
			name = strings.TrimPrefix(a, "--allow=")
		default:
			cfg.bad = append(cfg.bad, a)
			continue
		}
		if name == "" || strings.ContainsAny(name, `/*?[{\`) {
			cfg.bad = append(cfg.bad, "--allow "+name)
			continue
		}
		cfg.allow[name] = true
	}
	if len(cfg.bad) > 0 {
		cfg.allow = map[string]bool{}
	}
	return cfg
}

// isSecretName reports whether a bare file name is a secret under cfg.
func isSecretName(base string, cfg secretsConfig) bool {
	if safeSuffix.MatchString(base) || !secretBasename.MatchString(base) {
		return false
	}
	return !cfg.allow[base]
}

func isSecretPath(path, home string, cfg secretsConfig) bool {
	if path == "" {
		return false
	}
	if path == "~" {
		path = home
	} else if strings.HasPrefix(path, "~/") {
		path = home + path[1:]
	}
	if secretDir.MatchString(path) {
		return true
	}
	return isSecretName(filepath.Base(strings.TrimRight(path, "/")), cfg)
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

func isWordOrHyphen(r rune) bool { return isWordRune(r) || r == '-' }

// tokenBoundary may precede a secret file name in a command.
func tokenBoundary(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(`'"=:/(`, r) }

// tokenEnd may follow one.
func tokenEnd(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(`'"|;&)>\`, r) }

// Each tokenAlt tries one shape of secret file name at rs[i:] and returns
// where it ends. Only the longest reading can be followed by a tokenEnd rune —
// every shorter one is followed by a word rune, a dot or a slash — so there is
// nothing to backtrack into.
type tokenAlt func(rs []rune, i int) (int, bool)

func hasPrefixAt(rs []rune, i int, p string) bool {
	pr := []rune(p)
	if i+len(pr) > len(rs) {
		return false
	}
	for k, r := range pr {
		if rs[i+k] != r {
			return false
		}
	}
	return true
}

var tokenAlts = []tokenAlt{
	// .env, .env.local, .env.development.local
	func(rs []rune, i int) (int, bool) {
		if !hasPrefixAt(rs, i, ".env") {
			return 0, false
		}
		e := i + 4
		for e+1 < len(rs) && rs[e] == '.' && isWordOrHyphen(rs[e+1]) {
			e++
			for e < len(rs) && isWordOrHyphen(rs[e]) {
				e++
			}
		}
		return e, true
	},
	// prod.env
	func(rs []rune, i int) (int, bool) {
		j := i
		for j < len(rs) && isWordOrHyphen(rs[j]) {
			j++
		}
		if j == i || !hasPrefixAt(rs, j, ".env") {
			return 0, false
		}
		return j + 4, true
	},
	// secrets.sops.yaml
	func(rs []rune, i int) (int, bool) {
		r := i
		for r < len(rs) && (isWordOrHyphen(rs[r]) || rs[r] == '.') {
			r++
		}
		run := string(rs[i:r])
		k := strings.LastIndex(run, ".sops.")
		if k < 1 {
			return 0, false
		}
		tail := []rune(run[k+len(".sops."):])
		if len(tail) == 0 {
			return 0, false
		}
		for _, c := range tail {
			if !isWordOrHyphen(c) {
				return 0, false
			}
		}
		return r, true
	},
	// .config/sops, .config/sops/age/keys.txt
	func(rs []rune, i int) (int, bool) {
		if !hasPrefixAt(rs, i, ".config/sops") {
			return 0, false
		}
		e := i + len(".config/sops")
		for e < len(rs) && rs[e] == '/' {
			e++
			for e < len(rs) && (isWordOrHyphen(rs[e]) || rs[e] == '.') {
				e++
			}
		}
		return e, true
	},
}

func tokenAt(rs []rune, i int) (int, bool) {
	for _, alt := range tokenAlts {
		if e, ok := alt(rs, i); ok && (e == len(rs) || tokenEnd(rs[e])) {
			return e, true
		}
	}
	return 0, false
}

// namedSecrets returns the secret file names a shell command spells out.
// `process.env`, `dotenv`, `.envrc` and `NODE_ENV` are not file names; the
// boundaries around a token and the runtime-object list keep them out.
func namedSecrets(cmd string, cfg secretsConfig) []string {
	rs := []rune(cmd)
	var hits []string
	add := func(start, end int) {
		tok := strings.Trim(string(rs[start:end]), " \t\n'\"=:/(")
		if safeSuffix.MatchString(tok) {
			return
		}
		if stem, ok := strings.CutSuffix(tok, ".env"); ok {
			stem = strings.ToLower(stem)
			if stem != "" && !strings.HasPrefix(stem, ".") && runtimeEnvObjects[stem] {
				return
			}
		}
		if !strings.Contains(tok, "/") && cfg.allow[tok] {
			return
		}
		hits = append(hits, tok)
	}
	for p := 0; p < len(rs); {
		if p == 0 || rs[p-1] == '\n' {
			if e, ok := tokenAt(rs, p); ok {
				add(p, e)
				p = e
				continue
			}
		}
		if tokenBoundary(rs[p]) {
			if e, ok := tokenAt(rs, p+1); ok {
				add(p, e)
				p = e
				continue
			}
		}
		p++
	}
	return hits
}

func isGlobRune(r rune) bool { return strings.ContainsRune("*?[{", r) }

func isGlobWordRune(r rune) bool {
	return isWordOrHyphen(r) || strings.ContainsRune(".*?[]{}!,", r)
}

// expandBraces turns `.env.{local,prod}` into `.env.local` and `.env.prod`.
func expandBraces(p string) []string {
	open := strings.Index(p, "{")
	if open < 0 {
		return []string{p}
	}
	end := strings.Index(p[open:], "}")
	if end < 0 {
		return []string{p}
	}
	end += open
	var out []string
	for _, alt := range strings.Split(p[open+1:end], ",") {
		out = append(out, expandBraces(p[:open]+alt+p[end+1:])...)
	}
	return out
}

// globSecret returns the first secret file name the glob could expand to, if
// any. Only the last path segment is matched: `**/.env.local` names
// .env.local. Exempt names do not count, so `.env.{development,example}` with
// .env.development allowed passes, while `.env.develop*` — which also matches
// .env.development.local — does not.
func globSecret(glob string, cfg secretsConfig) (string, bool) {
	for _, p := range expandBraces(glob) {
		if i := strings.LastIndex(p, "/"); i >= 0 {
			p = p[i+1:]
		}
		if !strings.ContainsFunc(p, isGlobRune) {
			if isSecretName(p, cfg) {
				return p, true // a literal name, probe list or not
			}
			continue
		}
		for _, probe := range globProbes {
			if ok, err := filepath.Match(p, probe); err == nil && ok && isSecretName(probe, cfg) {
				return probe, true
			}
		}
	}
	return "", false
}

// globbedSecrets returns the globs in a shell command that could expand to a
// secret file.
func globbedSecrets(cmd string, cfg secretsConfig) []string {
	rs := []rune(cmd)
	var hits []string
	for i := 0; i < len(rs); {
		if !isGlobWordRune(rs[i]) {
			i++
			continue
		}
		j := i
		for j < len(rs) && isGlobWordRune(rs[j]) {
			j++
		}
		word := string(rs[i:j])
		i = j
		if !strings.ContainsFunc(word, isGlobRune) {
			continue
		}
		if !strings.Contains(word, "env") && !strings.Contains(word, "sops") {
			continue
		}
		if _, ok := globSecret(word, cfg); ok {
			hits = append(hits, word)
		}
	}
	return hits
}

// decideSecrets returns the secret files a tool call would touch.
func decideSecrets(in hookIn, home string, cfg secretsConfig) []string {
	switch in.ToolName {
	case "Read", "Edit", "Write", "NotebookEdit":
		path := in.ToolInput.FilePath
		if path == "" {
			path = in.ToolInput.NotebookPath
		}
		if isSecretPath(path, home, cfg) {
			return []string{path}
		}
		return nil
	case "Grep", "Glob":
		if isSecretPath(in.ToolInput.Path, home, cfg) {
			return []string{in.ToolInput.Path}
		}
		if in.ToolName == "Grep" && in.ToolInput.Glob != "" {
			if _, ok := globSecret(in.ToolInput.Glob, cfg); ok {
				return []string{in.ToolInput.Glob}
			}
		}
		return nil
	}
	cmd, ok := in.shellCommand()
	if !ok {
		return nil
	}
	hits := shellSecrets(cmd, cfg)
	sort.Strings(hits)
	return dedupe(hits)
}

// shellSecrets returns the secret files a shell command names. Every word the
// parser finds is checked — arguments, assignments, redirect targets,
// here-document bodies, loop lists, words inside command substitutions — so a
// name cannot hide in a corner of the grammar. A command that does not parse
// is checked as raw text instead, which is stricter, never looser.
func shellSecrets(cmd string, cfg secretsConfig) []string {
	f, err := parseShell(cmd)
	if err != nil {
		return textSecrets(cmd, cfg)
	}
	exempt := listingWords(f)
	var hits []string
	syntax.Walk(f, func(n syntax.Node) bool {
		if w, ok := n.(*syntax.Word); ok && !exempt[w] {
			hits = append(hits, textSecrets(wordText(w), cfg)...)
		}
		return true
	})
	return hits
}

// listingCmds name a file without reading it: whether it exists, its size, its
// mode, or just the name itself. `ls -la .env*` or `[ -f .env.local ]` tells
// the agent what is there, not what is inside, and `echo '.env*' >> .gitignore`
// writes a name, not a secret.
var listingCmds = map[string]bool{
	"ls": true, "test": true, "[": true, "stat": true, "echo": true, "printf": true,
}

// pipeSafe may read a listing's output in a pipeline: they print or count
// names, they do not open them.
var pipeSafe = map[string]bool{
	"head": true, "tail": true, "grep": true, "egrep": true, "fgrep": true,
	"rg": true, "wc": true, "sort": true, "uniq": true,
}

// listingWords returns the arguments of listing commands, whose file names
// need no check. A listing loses that exemption when its output is captured —
// inside $(…), `…` or <(…) — or piped into anything but pipeSafe commands,
// because then the names it prints can be opened: `cat $(ls .env*)`,
// `ls .env* | xargs cat`. Redirect targets, assignments and substitutions
// inside the arguments are never exempt; they are separate words.
func listingWords(f *syntax.File) map[*syntax.Word]bool {
	captured := map[syntax.Node]bool{}
	markAll := func(root syntax.Node) {
		syntax.Walk(root, func(n syntax.Node) bool {
			switch n.(type) {
			case *syntax.CallExpr, *syntax.TestClause:
				captured[n] = true
			}
			return true
		})
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		switch n := n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			markAll(n)
		case *syntax.BinaryCmd:
			if n.Op != syntax.Pipe && n.Op != syntax.PipeAll {
				break
			}
			stages := pipeStages(n)
			for i := range stages {
				for _, later := range stages[i+1:] {
					if !isPipeSafe(later) {
						markAll(stages[i])
						break
					}
				}
			}
		}
		return true
	})

	exempt := map[*syntax.Word]bool{}
	syntax.Walk(f, func(n syntax.Node) bool {
		if captured[n] {
			return true
		}
		switch n := n.(type) {
		case *syntax.CallExpr:
			if len(n.Args) > 0 && listingCmds[commandName(wordText(n.Args[0]))] {
				for _, w := range n.Args[1:] {
					exempt[w] = true
				}
			}
		case *syntax.TestClause:
			// [[ -f .env.local ]]: every operand word, but not the words of a
			// command substitution inside one.
			syntax.Walk(n, func(m syntax.Node) bool {
				switch m := m.(type) {
				case *syntax.CmdSubst, *syntax.ProcSubst:
					return false
				case *syntax.Word:
					exempt[m] = true
				}
				return true
			})
		}
		return true
	})
	return exempt
}

// pipeStages flattens a pipeline into its stages, in order.
func pipeStages(b *syntax.BinaryCmd) []*syntax.Stmt {
	var stages []*syntax.Stmt
	for _, s := range []*syntax.Stmt{b.X, b.Y} {
		if inner, ok := s.Cmd.(*syntax.BinaryCmd); ok && (inner.Op == syntax.Pipe || inner.Op == syntax.PipeAll) {
			stages = append(stages, pipeStages(inner)...)
		} else {
			stages = append(stages, s)
		}
	}
	return stages
}

func isPipeSafe(s *syntax.Stmt) bool {
	c, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || len(c.Args) == 0 || len(s.Redirs) > 0 {
		return false
	}
	return pipeSafe[commandName(wordText(c.Args[0]))]
}

// textSecrets returns the secret files a piece of text names outright or
// through a glob.
func textSecrets(text string, cfg secretsConfig) []string {
	return append(namedSecrets(text, cfg), globbedSecrets(text, cfg)...)
}

func dedupe(sorted []string) []string {
	var out []string
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func secretsReason(in hookIn, hits []string, cfg secretsConfig) string {
	var b strings.Builder
	if _, ok := in.shellCommand(); ok {
		fmt.Fprintf(&b, "Command references secret file(s) and is blocked by the nkt-cc-hooks secrets hook: %s. ",
			strings.Join(hits, ", "))
	} else {
		fmt.Fprintf(&b, "%s on a secret file is blocked by the nkt-cc-hooks secrets hook: %s. ",
			in.ToolName, strings.Join(hits, ", "))
	}
	b.WriteString("Do not read or write .env or sops files; ask the user for the value you need.")
	if len(cfg.allow) > 0 {
		names := make([]string, 0, len(cfg.allow))
		for n := range cfg.allow {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Fprintf(&b, " These files are open to you: %s.", strings.Join(names, ", "))
	}
	if len(cfg.bad) > 0 {
		fmt.Fprintf(&b, " (nkt-cc-hooks secrets ignored bad flags %q and applies only its built-in rules — tell the user.)",
			cfg.bad)
	}
	return b.String()
}

func runSecrets(in hookIn, cfg secretsConfig) {
	hits := decideSecrets(in, homeDir(), cfg)
	if len(hits) == 0 {
		return
	}
	emit(os.Stdout, "deny", secretsReason(in, hits, cfg))
}
