package main

import (
	"reflect"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// calls returns every simple command in cmd as the words the shell would pass.
func calls(t *testing.T, cmd string) [][]string {
	t.Helper()
	f, err := parseShell(cmd)
	if err != nil {
		t.Fatalf("parse %q: %v", cmd, err)
	}
	var out [][]string
	syntax.Walk(f, func(n syntax.Node) bool {
		if c, ok := n.(*syntax.CallExpr); ok && len(c.Args) > 0 {
			out = append(out, callArgs(c))
		}
		return true
	})
	return out
}

func TestWordText(t *testing.T) {
	cases := []struct {
		cmd  string
		want [][]string
	}{
		// From the hand-written splitter this parser replaced.
		{`rg "a | b" src`, [][]string{{"rg", "a | b", "src"}}},
		{`echo hi | grep x`, [][]string{{"echo", "hi"}, {"grep", "x"}}},
		{`grep '//' f`, [][]string{{"grep", "//", "f"}}},
		{`find "/" -name x`, [][]string{{"find", "/", "-name", "x"}}},
		{"a\nfind / -name x", [][]string{{"a"}, {"find", "/", "-name", "x"}}},
		{`echo "a;b"`, [][]string{{"echo", "a;b"}}},
		{`grep -e "x\"y" f`, [][]string{{"grep", "-e", `x"y`, "f"}}},

		// Quoting and escapes.
		{`find . -exec echo {} \;`, [][]string{{"find", ".", "-exec", "echo", "{}", ";"}}},
		{`echo a"b"c 'd'e`, [][]string{{"echo", "abc", "de"}}},
		{`echo "a\nb" "\$x" "a\\b"`, [][]string{{"echo", `a\nb`, "$x", `a\b`}}},
		{`echo a\ b`, [][]string{{"echo", "a b"}}},
		{"echo a \\\n  b", [][]string{{"echo", "a", "b"}}},

		// Expansions.
		{`ls $HOME "${HOME}/x" ~ ~/y`, [][]string{{"ls", "$HOME", "${HOME}/x", "~", "~/y"}}},
		{`ls "$(pwd)/x" ${#a}`, [][]string{{"ls", opaque + "/x", opaque}, {"pwd"}}},
		{"echo `date`", [][]string{{"echo", opaque}, {"date"}}},

		// Structure the parser takes apart.
		{`X=1 find / -name x`, [][]string{{"find", "/", "-name", "x"}}},
		{`if find / -name x; then echo y; fi`, [][]string{{"find", "/", "-name", "x"}, {"echo", "y"}}},
		{"cat > t.sh <<'EOF'\nfind / -name x\nEOF", [][]string{{"cat"}}},
	}
	for _, c := range cases {
		t.Run(c.cmd, func(t *testing.T) {
			if got := calls(t, c.cmd); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestUnwrap(t *testing.T) {
	cases := []struct {
		args []string
		want []string
	}{
		{[]string{"sudo", "-u", "root", "find", "/"}, []string{"find", "/"}},
		{[]string{"timeout", "-k", "5", "30", "rg", "x"}, []string{"rg", "x"}},
		{[]string{"env", "-i", "A=1", "B=2", "ls"}, []string{"ls"}},
		{[]string{"xargs", "-0", "-I", "{}", "grep", "x", "{}"}, []string{"grep", "x", "{}"}},
		{[]string{"/usr/bin/sudo", "ls"}, []string{"ls"}},
		{[]string{"command", "-v", "find"}, nil},
		{[]string{"ls", "-la"}, []string{"ls", "-la"}},
	}
	for _, c := range cases {
		if got := unwrap(c.args); !reflect.DeepEqual(got, c.want) {
			t.Errorf("unwrap(%q) = %q, want %q", c.args, got, c.want)
		}
	}
}

func TestParseShellFallsBackToZsh(t *testing.T) {
	// Valid zsh, rejected by the bash grammar.
	if _, err := parseShell(`print -l ${(f)"$(ls)"}`); err != nil {
		t.Errorf("zsh fallback did not parse: %v", err)
	}
	if _, err := parseShell("echo \"`unterminated"); err == nil {
		t.Error("a broken command must report an error")
	}
}
