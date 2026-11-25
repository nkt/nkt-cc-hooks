// nkt-cc-hooks is a set of PreToolUse hooks for Claude Code, one per subcommand:
//
//	nkt-cc-hooks wide-search                 keep searches inside the project
//	nkt-cc-hooks secrets [--allow NAME]...   keep the agent out of secret files
//
// Each reads the hook payload as JSON on stdin and writes a decision as JSON on
// stdout. A malformed payload is let through silently: a crashing hook would be
// worse than a missed check. An unknown hook exits 1, which Claude Code reports
// as a non-blocking error. Bad secrets flags are the exception: that hook keeps
// its built-in rules and names the bad flags in every refusal, because a typo in
// an allow list must never switch the guard off.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const usage = `usage: nkt-cc-hooks <hook> [flags]

hooks:
  wide-search                  refuse searches of /, the home directory or /Users
  secrets [--allow NAME]...    refuse access to .env and sops files;
                               --allow exempts an exact file name, e.g. .env.development
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	var run func(hookIn)
	switch os.Args[1] {
	case "wide-search":
		if len(os.Args) > 2 {
			fail("wide-search takes no flags")
		}
		run = runWideSearch
	case "secrets":
		cfg := parseSecretsFlags(os.Args[2:])
		run = func(in hookIn) { runSecrets(in, cfg) }
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fail(fmt.Sprintf("unknown hook %q", os.Args[1]))
	}

	var in hookIn
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		return // malformed payload: fail open
	}
	if in.Cwd == "" {
		in.Cwd, _ = os.Getwd()
	}
	run(in)
}

func fail(msg string) {
	fmt.Fprintf(os.Stderr, "nkt-cc-hooks: %s\n\n%s", msg, usage)
	os.Exit(1)
}

func homeDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return os.Getenv("HOME")
}
