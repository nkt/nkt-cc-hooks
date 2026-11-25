package main

import (
	"strings"
	"testing"
)

func fileTool(name, path string) hookIn {
	var in hookIn
	in.ToolName = name
	in.Cwd = testCwd
	in.ToolInput.FilePath = path
	return in
}

func grepTool(path, glob string) hookIn {
	var in hookIn
	in.ToolName = "Grep"
	in.Cwd = testCwd
	in.ToolInput.Path = path
	in.ToolInput.Glob = glob
	return in
}

var (
	strict   = parseSecretsFlags(nil)
	devAllow = parseSecretsFlags([]string{"--allow", ".env.development"})
)

func TestSecretsBlocks(t *testing.T) {
	cases := []struct {
		name string
		in   hookIn
		cfg  secretsConfig
	}{
		{"read .env", fileTool("Read", testCwd+"/.env"), strict},
		{"read .env.local", fileTool("Read", testCwd+"/.env.local"), strict},
		{"edit prod.env", fileTool("Edit", "config/prod.env"), strict},
		{"write sops file", fileTool("Write", "deploy/secrets.sops.yaml"), strict},
		{"sops key dir", fileTool("Read", "~/.config/sops/age/keys.txt"), strict},
		{"grep tool on .env", grepTool(".env", ""), strict},
		{"cat .env", bash("cat .env"), strict},
		{"source .env.local", bash("source apps/web/.env.local && yarn dev"), strict},
		{"env-file flag", bash("node --env-file=.env.local scripts/seed.js"), strict},
		{"redirect into .env", bash("echo X=1 >> .env"), strict},
		{"sops dir in bash", bash("cat ~/.config/sops/age/keys.txt"), strict},
		{"sops file in bash", bash("cat deploy/secrets.sops.yaml"), strict},

		// --allow .env.development opens that name and nothing near it.
		{"allow does not open .env.local", fileTool("Read", ".env.local"), devAllow},
		{"allow does not open .env", fileTool("Read", ".env"), devAllow},
		{"allow does not open .env.development.local", fileTool("Read", ".env.development.local"), devAllow},
		{"allow does not open sops keys", fileTool("Read", "~/.config/sops/age/keys.txt"), devAllow},
		{"copy allowed onto secret", bash("cp .env.development .env.local"), devAllow},
		{"secret beside allowed", bash("cat .env.development .env.production"), devAllow},

		// A glob that could expand to a secret reads it as surely as its name.
		{"glob .env*", bash("cat .env*"), strict},
		{"glob .env.*", bash("cat .env.*"), devAllow},
		{"glob *.env", bash("rg -g '*.env' TOKEN"), strict},
		{"glob in path", bash("cat apps/*/.env*"), strict},
		{"brace expansion", bash("cat .env.{local,production}"), strict},
		{"glob reaching dev.local", bash("cat .env.develop*"), devAllow},
		{"grep tool glob", grepTool("", ".env*"), strict},
		{"grep tool glob in subdir", grepTool("apps", "**/.env.local"), devAllow},
		{"grep tool literal name outside probes", grepTool("", ".env.prod"), strict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if hits := decideSecrets(c.in, testHome, c.cfg); len(hits) == 0 {
				t.Error("expected block, got allow")
			}
		})
	}
}

func TestSecretsAllows(t *testing.T) {
	cases := []struct {
		name string
		in   hookIn
		cfg  secretsConfig
	}{
		{"example file", fileTool("Read", ".env.example"), strict},
		{"template file", fileTool("Read", ".env.local.template"), strict},
		{"type declarations", fileTool("Read", "src/env.d.ts"), strict},
		{"envrc", fileTool("Read", ".envrc"), strict},
		{"unrelated file", fileTool("Read", "src/env.ts"), strict},
		{"process.env", bash(`node -e "console.log(process.env.HOME)"`), strict},
		{"import.meta.env", bash(`rg "import.meta.env" src`), strict},
		{"process.env alone", bash(`rg -n "process.env" src`), strict},
		{"dotenv package", bash("yarn add dotenv"), strict},
		{"NODE_ENV", bash("NODE_ENV=production yarn build"), strict},
		{"env command", bash("env | sort"), strict},
		{"envrc in bash", bash("direnv allow .envrc"), strict},
		{"example in bash", bash("cp .env.example apps/web/.env.example"), strict},
		{"ENV glob is not a file", bash(`rg "NODE_ENV.*" src`), strict},
		{"grep tool unrelated glob", grepTool("", "*.ts"), strict},

		// The exempt name itself, through every tool.
		{"read allowed", fileTool("Read", testCwd+"/.env.development"), devAllow},
		{"edit allowed", fileTool("Edit", ".env.development"), devAllow},
		{"write allowed", fileTool("Write", "apps/web/.env.development"), devAllow},
		{"cat allowed", bash("cat .env.development"), devAllow},
		{"source allowed", bash("set -a; . apps/web/.env.development; set +a"), devAllow},
		{"env-file allowed", bash("node --env-file=.env.development x.js"), devAllow},
		{"glob only reaching allowed", bash("cat .env.{development,example}"), devAllow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if hits := decideSecrets(c.in, testHome, c.cfg); len(hits) != 0 {
				t.Errorf("expected allow, got block on %q", hits)
			}
		})
	}
}

// Listing a secret file says it exists, not what is in it.
func TestSecretsListing(t *testing.T) {
	allows := []string{
		"ls -la .env*",
		"ls apps/web/.env.local",
		"ls .env* 2>/dev/null",
		"ls -a .env* | head -5",
		"ls .env* | grep local | wc -l",
		"test -f .env.local && echo yes",
		"[ -f .env.local ] && echo yes",
		"[[ -f .env.local ]] && echo yes",
		"stat -f %z .env.local",
		"/bin/ls -la .env.local",
		"echo '.env*' >> .gitignore",
		"echo .env.local >> .gitignore",
		`printf '%s\n' .env.local .env.production >> .gitignore`,
	}
	for _, cmd := range allows {
		t.Run("allow "+cmd, func(t *testing.T) {
			if hits := decideSecrets(bash(cmd), testHome, strict); len(hits) != 0 {
				t.Errorf("expected allow, got block on %q", hits)
			}
		})
	}
	blocks := []string{
		"ls .env*; cat .env.local", // the next command reads it
		`ls "$(cat .env.local)"`,   // a substitution in a listing's argument
		"ls > .env.local",          // a redirect target is a write
		"X=.env.local ls",          // an assignment is not an argument
		"ls .env* | xargs cat",     // names piped into something that opens them
		"ls .env* | while read f; do echo $f; done",
		"f=$(ls .env*); cat $f",        // output captured
		"cat <(ls .env*)",              // process substitution
		`[[ -f "$(cat .env.local)" ]]`, // a substitution inside a test
		"sudo cat .env.local",          // only listings are exempt
		"echo X=1 > .env.local",        // writing into the file
		"echo .env.local | xargs cat",  // a printed name, then opened
		"cat $(echo .env.local)",       // the same through a substitution
	}
	for _, cmd := range blocks {
		t.Run("block "+cmd, func(t *testing.T) {
			if hits := decideSecrets(bash(cmd), testHome, strict); len(hits) == 0 {
				t.Error("expected block, got allow")
			}
		})
	}
}

func TestSecretsFlags(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		allowed []string
		bad     bool
	}{
		{"none", nil, nil, false},
		{"separate value", []string{"--allow", ".env.development"}, []string{".env.development"}, false},
		{"inline value", []string{"--allow=.env.test"}, []string{".env.test"}, false},
		{"repeated", []string{"--allow", ".env.development", "--allow=.env.test"}, []string{".env.development", ".env.test"}, false},
		{"unknown flag", []string{"--alow", ".env.development"}, nil, true},
		{"missing value", []string{"--allow"}, nil, true},
		{"path is not a name", []string{"--allow", "apps/.env.development"}, nil, true},
		{"glob is not a name", []string{"--allow", ".env.*"}, nil, true},
		{"empty name", []string{"--allow="}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := parseSecretsFlags(c.args)
			if (len(cfg.bad) > 0) != c.bad {
				t.Errorf("bad flags %q, want bad=%v", cfg.bad, c.bad)
			}
			if len(cfg.allow) != len(c.allowed) {
				t.Errorf("allow %v, want %v", cfg.allow, c.allowed)
			}
			for _, n := range c.allowed {
				if !cfg.allow[n] {
					t.Errorf("%q not allowed", n)
				}
			}
		})
	}
}

// A bad flag must leave the built-in rules in force — never open more — and
// the refusal must say so, or nobody learns the config is broken.
func TestBadFlagsFallBackToStrict(t *testing.T) {
	cfg := parseSecretsFlags([]string{"--allow", ".env.development", "--typo"})
	in := fileTool("Read", ".env.development")
	hits := decideSecrets(in, testHome, cfg)
	if len(hits) == 0 {
		t.Fatal("a broken config must not open the allowed file")
	}
	if reason := secretsReason(in, hits, cfg); !strings.Contains(reason, "--typo") {
		t.Errorf("reason does not name the bad flag: %q", reason)
	}
}

func TestSecretsReasonNamesOpenFiles(t *testing.T) {
	in := bash("cat .env.local")
	reason := secretsReason(in, decideSecrets(in, testHome, devAllow), devAllow)
	for _, want := range []string{".env.local", "open to you: .env.development"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not mention %q", reason, want)
		}
	}
}

func TestExpandBraces(t *testing.T) {
	got := strings.Join(expandBraces(".env.{a,b}.{x,y}"), " ")
	if want := ".env.a.x .env.a.y .env.b.x .env.b.y"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
