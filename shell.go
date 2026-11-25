package main

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// opaque stands in for anything whose value is only known at run time — a
// command substitution, an arithmetic expansion, a parameter with operators.
// It never matches a path, a root or a file name.
const opaque = "\x00"

// parseShell parses a command line the way the shell would. Claude's shell is
// often zsh, but bash is the better-supported grammar, so zsh is the fallback.
// Replaying 44k historical commands, bash rejects 12 and zsh rejects 2; only
// one — a genuinely broken command — defeats both. A parser panic is reported
// as an error: an unrecovered Go panic exits 2, which Claude Code treats as a
// blocking error.
func parseShell(cmd string) (f *syntax.File, err error) {
	defer func() {
		if r := recover(); r != nil {
			f, err = nil, fmt.Errorf("parser panic: %v", r)
		}
	}()
	f, err = syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err == nil {
		return f, nil
	}
	return syntax.NewParser(syntax.Variant(syntax.LangZsh)).Parse(strings.NewReader(cmd), "")
}

// wordText renders a word as the shell would pass it, quotes removed and
// escapes resolved. Expansions that only have a value at run time become
// opaque, except plain parameters: "$HOME" and "${HOME}" are kept as written,
// since a home directory spelled that way is still a home directory.
func wordText(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	for _, p := range w.Parts {
		writePart(&b, p, false)
	}
	return b.String()
}

func writePart(b *strings.Builder, p syntax.WordPart, quoted bool) {
	switch p := p.(type) {
	case *syntax.Lit:
		b.WriteString(unescape(p.Value, quoted))
	case *syntax.SglQuoted:
		b.WriteString(p.Value)
	case *syntax.DblQuoted:
		for _, q := range p.Parts {
			writePart(b, q, true)
		}
	case *syntax.ParamExp:
		switch {
		case p.Param == nil || p.Excl || p.Length:
			b.WriteString(opaque)
		case p.Short:
			b.WriteString("$" + p.Param.Value)
		default:
			b.WriteString("${" + p.Param.Value + "}")
		}
	default: // command and process substitution, arithmetic, extended globs
		b.WriteString(opaque)
	}
}

// unescape resolves backslash escapes in a literal. Inside double quotes a
// backslash only escapes $, `, ", \ and a newline; outside, it escapes
// anything, and an escaped newline joins two lines.
func unescape(s string, quoted bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		next := s[i+1]
		switch {
		case next == '\n':
			i++ // line continuation
		case !quoted || strings.IndexByte("$`\"\\", next) >= 0:
			b.WriteByte(next)
			i++
		default:
			b.WriteByte('\\')
		}
	}
	return b.String()
}

// callArgs returns a simple command's words as the shell would pass them.
func callArgs(c *syntax.CallExpr) []string {
	args := make([]string, len(c.Args))
	for i, w := range c.Args {
		args[i] = wordText(w)
	}
	return args
}

// commandName returns the program a command runs, without its directory.
func commandName(arg string) string {
	if i := strings.LastIndex(arg, "/"); i >= 0 {
		return arg[i+1:]
	}
	return arg
}

// prefixValueFlags lists, for each command that wraps another without changing
// which one runs, the flags that consume the following word. Flags not listed
// stand alone.
var prefixValueFlags = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-U": true, "-C": true, "-h": true, "-p": true, "-r": true, "-t": true, "-T": true, "-D": true},
	"env":     {"-u": true, "-C": true, "-S": true, "-P": true},
	"xargs":   {"-I": true, "-n": true, "-P": true, "-L": true, "-d": true, "-s": true, "-E": true, "-a": true},
	"nice":    {"-n": true},
	"timeout": {"-k": true, "-s": true},
	"stdbuf":  {"-i": true, "-o": true, "-e": true},
	"time":    {}, "nohup": {}, "command": {}, "builtin": {}, "exec": {},
}

// unwrap strips the wrappers in front of the real command — sudo, env,
// timeout and the like, with their own flags — and returns the command and its
// arguments. `command -v find` only looks find up, so it yields nothing.
// Keywords and leading assignments never get here: the parser already took
// them apart.
func unwrap(args []string) []string {
	for len(args) > 0 {
		head := commandName(args[0])
		flags, isPrefix := prefixValueFlags[head]
		if !isPrefix {
			return args
		}
		args = args[1:]
		for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
			f := args[0]
			args = args[1:]
			if f == "--" {
				break
			}
			if head == "command" && (f == "-v" || f == "-V") {
				return nil
			}
			if flags[f] && len(args) > 0 {
				args = args[1:]
			}
		}
		if head == "env" {
			for len(args) > 0 && isAssignment(args[0]) {
				args = args[1:]
			}
		}
		if head == "timeout" && len(args) > 0 {
			args = args[1:] // the duration
		}
	}
	return args
}

// isAssignment reports whether an env argument sets a variable (NAME=value).
func isAssignment(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	for i, r := range s[:eq] {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
