package main

import (
	"reflect"
	"strings"
	"testing"
)

const (
	testCwd  = "/Users/dev/projects/acme/web-app"
	testHome = "/Users/dev"
)

func bash(cmd string) hookIn {
	var in hookIn
	in.ToolName = "Bash"
	in.Cwd = testCwd
	in.ToolInput.Command = cmd
	return in
}

func tool(name, path string) hookIn {
	var in hookIn
	in.ToolName = name
	in.Cwd = testCwd
	in.ToolInput.Path = path
	return in
}

func monitor(cmd string) hookIn {
	in := bash(cmd)
	in.ToolName = "Monitor"
	return in
}

func globPattern(pattern string) hookIn {
	var in hookIn
	in.ToolName = "Glob"
	in.Cwd = testCwd
	in.ToolInput.Pattern = pattern
	return in
}

func TestBlocks(t *testing.T) {
	cases := []struct {
		name string
		in   hookIn
	}{
		{"grep tool at home", tool("Grep", "/Users/dev")},
		{"grep tool at root", tool("Grep", "/")},
		{"grep tool tilde", tool("Grep", "~")},
		{"grep tool $HOME", tool("Grep", "$HOME")},
		{"grep tool trailing slash", tool("Grep", "/Users/dev/")},
		{"glob tool /Users", tool("Glob", "/Users")},
		{"find root", bash(`find / -name "*.ts"`)},
		{"find root with expression", bash(`find / -path "*Collection*" -name "*.swift"`)},
		{"find home", bash(`find ~ -maxdepth 3 -name "AuthKey_*.p8"`)},
		{"find $HOME", bash("find $HOME -type f")},
		{"grep -r into home", bash("grep -r pattern $HOME")},
		{"rg after &&", bash("echo hi && rg foo /Users/dev")},
		{"rg after pipe", bash("true | rg foo /")},
		{"sudo find root", bash("sudo find / -name x")},
		{"absolute binary path", bash("/usr/bin/find / -name x")},
		{"fd into root", bash("fd -d 3 cards-new /")},
		{"quoted root is still a path", bash(`find "/" -name x`)},
		{"command substitution is inspected", bash("echo $(find / -name x)")},
		{"rg with pattern flag then root", bash("rg -e foo /")},
		{"find /Users", bash("find /Users -name x")},
		{"monitor command", monitor("find / -name x")},

		// Gaps found by the 2026-11 audit: each is a real walk the parser missed.
		{"find -L before root", bash("find -L / -name x")},
		{"find -H before home", bash("find -H ~ -name x")},
		{"path after the expression", bash("find -name x /")},
		{"bfs by name", bash("bfs / -name x")},
		{"ugrep by name", bash("ugrep -r foo /")},
		{"ug by name", bash("ug -r foo ~")},
		{"timeout prefix", bash("timeout 30 find / -name x")},
		{"timeout with flags", bash("timeout -k 5 30 rg foo /")},
		{"env with assignment", bash("env X=1 find / -name x")},
		{"bare assignment", bash("VAR=1 rg x ~")},
		{"sudo -u", bash("sudo -u root find / -name x")},
		{"if condition", bash("if find / -name x; then echo y; fi")},
		{"loop body", bash("for d in a b; do find / -name $d; done")},
		{"brace group", bash("{ find / -name x; }")},
		{"negation", bash("! grep -r foo /")},
		{"rg --files", bash("rg --files /")},
		{"glob tool absolute pattern", globPattern("/**/*.jar")},
		{"glob tool home pattern", globPattern("/Users/dev/**/AuthKey_*.p8")},
		{"glob tool tilde pattern", globPattern("~/**/*.p8")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, blocked := decideWide(c.in, testHome); !blocked {
				t.Error("expected block, got allow")
			}
		})
	}
}

// Every case here was a real false positive found by replaying 18783 historical
// Bash calls through the previous implementation.
func TestRegressionsFromHistory(t *testing.T) {
	cases := []struct {
		name string
		in   hookIn
	}{
		{"slash inside quoted pattern", bash(`rg -c "QR / external wallet" src/i18n`)},
		{"spaced slash in pattern", bash(`grep -rn "a / b" src`)},
		{"comment marker single quoted", bash(`grep -n '//' src/foo.ts`)},
		{"comment marker double quoted", bash(`grep -vi "//" src`)},
		{"comment marker with space", bash(`grep -v '// ' src`)},
		{"pipe inside quoted regex", bash(`ps aux | rg "bfs|find /" | head -5`)},
		{"pipe inside regex with flag", bash(`rg -i "bfs|find /" file`)},
		{"slash is the pattern", bash(`brew list --formula | grep '/'`)},
		{"alternation with escaped pipes", bash(`grep -rn '<<<<<<<\|>>>>>>>' src/`)},
		{"glob flag takes a value", bash(`rg -g '*.ts' foo src`)},
		{"heredoc body is data, not commands", bash("cat > t.sh <<'EOF'\nfind / -name x\nEOF\necho done")},
		{"unquoted heredoc delimiter", bash("cat > t.sh <<EOF\nrg foo ~\nEOF")},
		{"cross project locate", bash(`find /Users/dev/projects -maxdepth 2 -iname "*web-app*" -type d`)},
		{"cross project grep", bash(`grep -ri "SECRET" ~/projects --include="*.json"`)},
		{"sibling repo by absolute path", bash(`rg -n "foo" /Users/dev/projects/acme/api/src`)},
		{"parent of project", bash(`find /Users/dev/projects/acme -maxdepth 3 -iname "*.css"`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if tok, blocked := decideWide(c.in, testHome); blocked {
				t.Errorf("expected allow, got block on %q", tok)
			}
		})
	}
}

func TestAllows(t *testing.T) {
	cases := []struct {
		name string
		in   hookIn
	}{
		{"no path", tool("Grep", "")},
		{"relative path", tool("Grep", "src")},
		{"project subdir", tool("Grep", testCwd+"/src")},
		{"project root itself", tool("Grep", testCwd)},
		{"dotfile dir in home", tool("Grep", "~/.claude/hooks")},
		{"find dot", bash(`find . -name "*.ts"`)},
		{"find subdir", bash("find src -type f")},
		{"rg relative", bash("rg foo src/")},
		{"grep in a pipe", bash("cat package.json | grep name")},
		{"git log piped to grep", bash("git log --oneline | grep fix")},
		{"ls root is not a search", bash("ls /")},
		{"cd root is not a search", bash("cd / && pwd")},
		{"url in pattern", bash(`grep -r "http://" src`)},
		{"unrelated tool", tool("Read", "/Users/dev/.zshrc")},
		{"cat outside project", bash("cat /Users/dev/.zshrc")},
		{"maxdepth 0 only looks at root", bash("find / -maxdepth 0")},
		{"command -v only looks find up", bash("command -v find")},
		{"find name value is not a path", bash(`find . -name "/"`)},
		{"exec args are not paths", bash(`find . -name x -exec echo / \;`)},
		{"timeout duration is not the command", bash("timeout 30 ls /")},
		{"assignment then non-search", bash("DEBUG=1 ls /")},
		{"glob tool relative pattern", globPattern("**/*.ts")},
		{"glob tool narrow absolute", globPattern("/Users/dev/projects/**/*.ts")},
		{"glob tool literal file in home", globPattern("/Users/dev/.zshrc")},
		{"glob tool literal root dir", globPattern("/tmp")},
		{"rg --files relative", bash("rg --files src")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if tok, blocked := decideWide(c.in, testHome); blocked {
				t.Errorf("expected allow, got block on %q", tok)
			}
		})
	}
}

// A command no parser reads cannot be checked, so it never runs — not on a
// repeat, not in a subagent.
func TestUnparsedIsRefused(t *testing.T) {
	broken := bash("echo \"`unterminated")
	for i := 0; i < 2; i++ {
		if reason := unparsedReason(broken); !strings.Contains(reason, "does not parse") {
			t.Fatalf("attempt %d: reason %q", i+1, reason)
		}
	}
	if reason := unparsedReason(monitor("echo \"`unterminated")); reason == "" {
		t.Error("Monitor commands are shell commands too")
	}
	if reason := unparsedReason(bash("find . -name x")); reason != "" {
		t.Errorf("a command that parses must not be refused: %q", reason)
	}
	if reason := unparsedReason(tool("Grep", "src")); reason != "" {
		t.Errorf("only shell commands are parsed: %q", reason)
	}
}

func TestStateKeyIsPerAgent(t *testing.T) {
	main := hookIn{SessionID: "s1"}
	subA := hookIn{SessionID: "s1", AgentID: "agent-a"}
	subB := hookIn{SessionID: "s1", AgentID: "agent-b"}

	if stateKey(main) == stateKey(subA) {
		t.Error("a subagent must not inherit the main thread's ledger")
	}
	if stateKey(subA) == stateKey(subB) {
		t.Error("two subagents of one session must not share a ledger")
	}
	if stateKey(subA) != stateKey(hookIn{SessionID: "s1", AgentID: "agent-a"}) {
		t.Error("the same agent must keep the same ledger")
	}
	if stateKey(hookIn{}) != "" {
		t.Error("a payload with no session id has nowhere to record state")
	}
	if got := stateKey(hookIn{SessionID: "a/b", AgentID: "c/d"}); strings.ContainsAny(got, "/.") {
		t.Errorf("key %q is not safe as a filename", got)
	}
}

func TestRespond(t *testing.T) {
	main := hookIn{SessionID: "s1", Cwd: testCwd}
	sub := hookIn{SessionID: "s1", AgentID: "agent-a", Cwd: testCwd}

	cases := []struct {
		name     string
		in       hookIn
		repeat   bool
		decision string
		contains string
	}{
		{"main first hit explains", main, false, "deny", "use a relative path"},
		{"main repeat escalates to the user", main, true, "ask", "Confirm with the user"},
		{"subagent first hit explains", sub, false, "deny", "use a relative path"},
		{"subagent first hit does not promise a prompt", sub, false, "deny", "does not escalate this to the user"},
		{"subagent repeat stays a deny", sub, true, "deny", "does not escalate to the user"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			decision, reason := respondWide(c.in, "/", c.repeat)
			if decision != c.decision {
				t.Errorf("got decision %q, want %q", decision, c.decision)
			}
			if !strings.Contains(reason, c.contains) {
				t.Errorf("reason %q does not mention %q", reason, c.contains)
			}
			if strings.Contains(reason, "%!") {
				t.Errorf("format verb mismatch in reason: %q", reason)
			}
		})
	}
}

// A subagent that is only ever told "permission denied" has no way to guess
// that a narrower path would work, so every refusal must name the alternative.
func TestEveryReasonNamesAWayForward(t *testing.T) {
	for _, in := range []hookIn{
		{SessionID: "s1", Cwd: testCwd},
		{SessionID: "s1", AgentID: "agent-a", Cwd: testCwd},
	} {
		for _, repeat := range []bool{false, true} {
			_, reason := respondWide(in, "/", repeat)
			if !strings.Contains(reason, "/") {
				t.Errorf("reason gives no concrete path to try instead: %q", reason)
			}
		}
	}
}

func TestSearchPaths(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		args []string
		want []string
	}{
		{"find takes leading paths", "find", []string{"/", "-name", "x"}, []string{"/"}},
		{"find two paths", "find", []string{".", "src", "-type", "f"}, []string{".", "src"}},
		{"grep skips the pattern", "grep", []string{"-r", "pat", "src"}, []string{"src"}},
		{"grep pattern only", "grep", []string{"/"}, nil},
		{"rg value flag", "rg", []string{"-g", "*.ts", "pat", "src"}, []string{"src"}},
		{"rg -e means no positional pattern", "rg", []string{"-e", "pat", "src"}, []string{"src"}},
		{"inline flag value", "rg", []string{"--glob=*.ts", "pat", "src"}, []string{"src"}},
		{"end of flags", "grep", []string{"--", "pat", "src"}, []string{"src"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := searchPaths(c.cmd, c.args); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestWideRoots(t *testing.T) {
	set := wideRoots("/Users/dev")
	for _, want := range []string{"/", "/Users", "/Users/dev"} {
		if !set[want] {
			t.Errorf("expected %q to be refused", want)
		}
	}
	// Narrowed deliberately: locating a sibling repo is legitimate work.
	for _, notWanted := range []string{"/Users/dev/projects", "/Users/dev/projects/acme"} {
		if set[notWanted] {
			t.Errorf("%q must not be refused", notWanted)
		}
	}
}
