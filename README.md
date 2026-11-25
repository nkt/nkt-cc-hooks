# nkt-cc-hooks

`PreToolUse` hooks for [Claude Code](https://claude.com/claude-code), in one small Go binary. Each
hook is a subcommand:

| hook | what it stops |
|---|---|
| [`wide-search`](#wide-search) | searches that sweep the whole disk or your home directory |
| [`secrets`](#secrets) | reading or writing `.env` and sops files, whichever tool the agent uses |

Both run in a few milliseconds and read the hook payload on stdin. Shell commands are read with a
real shell parser, [mvdan.cc/sh](https://github.com/mvdan/sh) — the one behind `shfmt` — so quoting,
escapes, pipelines, keywords, assignments, redirects and command substitutions are taken apart the
way the shell would, not guessed at with regular expressions. Commands are parsed as bash, then as
zsh; replaying 44k real commands, only one (itself broken) defeated both.

## Install

Requires Go 1.26+ to build.

```sh
git clone https://github.com/nkt/nkt-cc-hooks
cd nkt-cc-hooks
go test ./...
go build -trimpath -ldflags="-s -w" -o ~/.claude/hooks/bin/nkt-cc-hooks .
```

Then register the hooks in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Grep|Glob|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/Users/you/.claude/hooks/bin/nkt-cc-hooks",
            "args": ["wide-search"],
            "statusMessage": "Checking search scope..."
          }
        ]
      },
      {
        "matcher": "Read|Edit|Write|NotebookEdit|Grep|Glob|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/Users/you/.claude/hooks/bin/nkt-cc-hooks",
            "args": ["secrets", "--allow", ".env.development"],
            "timeout": 10,
            "statusMessage": "Checking for secret files..."
          }
        ]
      }
    ]
  }
}
```

The path must be absolute — `~` is not expanded there. With `args`, Claude Code runs the binary
directly rather than through a shell. Per the Claude Code docs, a `Bash` matcher also covers the
shell commands Claude starts with the Monitor tool and the shell calls Code Mode makes from code.

## wide-search

`find / -iname "*.jar"` on a developer machine walks millions of inodes, takes tens of seconds, and
almost always answers a question that `find . -name "*.jar"` would have answered instantly. This hook
intercepts those calls before they run and tells the model what to do instead.

### What it blocks

Only three roots: `/`, your home directory, and the directory that holds all homes (`/Users`,
`/home`). Everything narrower is your business — a sibling repo, `~/projects`, `~/.gradle/caches`
and `/opt/homebrew` all pass through untouched.

It understands the tools that take a place to walk — `find`/`bfs`, `grep`/`egrep`/`fgrep`,
`ugrep`/`ug`, `rg`, `ag`, `fd`/`fdfind` — plus Claude Code's own `Grep` and `Glob` tools, including an
absolute `Glob` pattern like `/**/*.jar`. Every simple command the parser finds is checked — in a
pipeline, after `&&`, inside `if`/`for`/`{ }`, inside `$(…)` even within double quotes — and
wrappers with their own flags are unwrapped (`sudo -u root`, `timeout 30`, `env X=1`, `xargs -I{}`,
`nice -n 5`). Absolute binary paths (`/usr/bin/find`) are resolved to their name. Here-document
bodies are data, not commands, and are left alone.

Claude Code's shell runs `find` as an embedded bfs, which accepts a path anywhere on the command line,
so every word of a `find` that is not an option, a predicate or a predicate's value counts as a path.
`find / -maxdepth 0` only looks at `/` itself and passes.

```
find / -name "*.ts"                       blocked
sudo find ~ -maxdepth 3 -name "id_rsa"    blocked
echo hi && rg foo /Users/you              blocked
find -name x /                            blocked
Grep(path="$HOME")                        blocked
Glob(pattern="/**/*.jar")                 blocked

find . -name "*.ts"                       allowed
rg -n foo ~/projects/other-repo/src       allowed
find ~/.gradle/caches -iname "*.jar"      allowed
ls /                                      allowed  (not a search)
```

### Escalation

A guardrail that cannot be overridden is a guardrail you end up deleting, so a genuinely intended
global search costs one confirmation rather than being walled off:

| | first attempt | same root again |
|---|---|---|
| **main thread** | `deny` + explanation | `ask` — the user confirms |
| **subagent** | `deny` + explanation | `deny` + "the main thread can ask" |

Two details in that table were learned the hard way, by reading eight days of real transcripts:

**"Already warned" is tracked per agent, not per session.** Subagents inherit their parent's
`session_id`, so a session-wide ledger made a subagent's *first* attempt look like a repeat of a
warning that had landed in some other context — sometimes hours earlier, sometimes in a sibling
agent running in parallel. The hook keys its state on `agent_id`, which the payload sets only inside
a subagent.

**Escalation stays a `deny` inside a subagent.** Claude Code can route a subagent's permission
prompt to the main session, but that interrupts you over something the subagent can fix on its own
by naming a narrower directory — and in a headless run nobody is there to answer at all. The refusal
tells the subagent to pick a concrete directory or hand the question back to the main thread, which
can ask.

For what it's worth, the transcripts also settled the question the escalation path exists for: in
12 out of 12 cases where the explanation actually reached the model, the very next command was
correctly scoped. Models take the hint the first time. It's the plumbing around the hint that needs
the care.

### Tuning

Everything worth changing is a map or a constant near the top of `widesearch.go`:

- `searchCmds` — the commands whose arguments name a place to walk.
- `wideRoots` — what counts as too wide. Deliberately narrow; add `~/projects` here if you want
  cross-repo searches challenged too.
- `denyBody` / `subTail` / `askFmt` / `subRepeatFmt` — the text the model reads. `denyBody` names a
  package cache, a build directory and `node_modules` as legitimate out-of-project targets, because
  that is what wide searches are almost always after. Replaying 52k historical calls, the 103 the
  hook refuses split almost evenly between JVM jars, SwiftPM checkouts and another project's
  `node_modules`. Swap the examples for whatever your stack actually uses — a hint naming the wrong
  ecosystem is worse than no hint.

State lives in `~/.claude/hooks/state/wide-search/<session>__<agent>`, one line per warned root, and
is pruned after seven idle days.

### Scope

A command that parses as neither bash nor zsh cannot be checked, so it is refused, with the parser's
error and a request to fix the syntax or rewrite it in plain bash. Replaying 44k real commands found
one such command, and it was broken anyway.

This is a guardrail against wasted time, not a security boundary. Anything that hides the path from
a plain reading of the command — a variable, a path assembled at runtime, a `cd` into the root before
a relative search — passes straight through, by design.
Every case in `TestRegressionsFromHistory` is a real false positive — a slash inside a quoted
pattern, a comment marker, a pipe inside a regex — found by replaying historical `Bash` calls
through an earlier implementation.

## secrets

Keeps the agent out of secret files: `.env`, `.env.*`, `*.env`, `*.sops.*`, and everything under
`~/.config/sops`. `.env.example`, `.sample`, `.template`, `.dist`, `.schema` and `.d.ts` are not
secrets. It checks the path of `Read`, `Edit`, `Write` and `NotebookEdit`, the `path` and `glob` of
`Grep`, the `path` of `Glob`, and every file a shell command names — in any word the parser finds:
arguments, assignments, redirect targets, here-document bodies, loop lists, substitutions. A command
that does not parse is checked as raw text, which is stricter, never looser (and `wide-search`
refuses it outright).

A `permissions.deny` rule like `Read(**/.env*)` looks like the obvious tool for this and is not: it
makes Claude Code's Bash analyzer prompt on any command that touches a directory that *may contain*
a denied file. A hook fires only on a concrete path or command, so it never causes those prompts.

```
cat .env.local                            blocked
node --env-file=.env x.js                 blocked
cat .env*                                 blocked  (the glob could expand to a secret)
rg TOKEN -g '*.env'                       blocked
Read(apps/web/.env.production)            blocked

cat .env.example                          allowed
node -e "console.log(process.env.HOME)"   allowed  (process.env is not a file)
NODE_ENV=production yarn build            allowed
direnv allow .envrc                       allowed
```

### Opening some .env files to the agent

Some `.env` files are meant for the agent — committed development defaults, say, kept apart from the
`.env.local` that holds real keys. `--allow NAME` exempts an exact file name, for every tool, reading
and writing alike:

```json
"args": ["secrets", "--allow", ".env.development", "--allow", ".env.test"]
```

- **Exact names only.** `--allow .env.development` opens `.env.development` and nothing else: not
  `.env.development.local`, not `.env`, not `.env.local`. Paths and globs are rejected.
- **Every file must be open.** A command passes only if every secret file it names is exempt, so
  `cp .env.development .env.local` and `cat .env.*` are still refused.
- **A bad flag never opens anything.** If any flag is malformed, the hook ignores the whole allow
  list, applies its built-in rules, and names the bad flag in every refusal so that you find out.

The refusal tells the model which files are open to it, so it can use them instead of asking.

### Naming is not reading

`ls`, `stat`, `test`, `[ … ]` and `[[ … ]]` say whether a file exists, not what is in it, and `echo`
and `printf` only print a name, so the names they are given are not checked: `ls -la .env*`,
`[ -f .env.local ]` and `echo '.env*' >> .gitignore` pass. The exemption is narrow:

- **Only the command's own arguments.** A redirect (`echo X=1 > .env.local`), an assignment, or a
  `$(…)` inside an argument is checked as usual, and so is every other command in the line.
- **Not when the names can be opened.** Inside `$(…)`, backticks or `<(…)`, or piped into anything
  but `head`, `tail`, `grep`, `rg`, `wc`, `sort` or `uniq`, these commands are checked like any
  other: `cat $(ls .env*)` and `echo .env.local | xargs cat` are refused.

To give worktrees their `.env` files without the agent naming them, list the files in a
[`.worktreeinclude`](https://code.claude.com/docs/en/worktrees) at the repository root; Claude Code
copies them into every worktree it creates.

### Scope

Like `wide-search`, a guardrail rather than a security boundary: it catches the agent naming a secret
file, not a file read without being named — `grep -r TOKEN .`, a path in a variable, a script that
opens it.

## Checking against your own history

[`tools/replay/`](tools/replay) has the two scripts these were built with. `replay.py` runs every
`Bash` call in your transcripts through a hook and prints what it would have blocked — the way to
find false positives before they find you. `firings.py` shows where the hooks actually fired and
what the model did next. Neither needs anything but Python 3.

## License

MIT
