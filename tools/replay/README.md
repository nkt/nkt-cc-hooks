# tools/replay

Two scripts for checking the hooks against reality rather than against intuition.
Both read Claude Code transcripts from `~/.claude/projects` (override with
`--transcripts`) and need nothing but Python 3.

## replay.py — what would this block?

Replays every historical `Bash` call through a hook and prints the ones it
refuses. `--hook` is a command line, so it names the hook and its flags.

```sh
go build -o nkt-cc-hooks .
python3 tools/replay/replay.py --hook "./nkt-cc-hooks wide-search"
python3 tools/replay/replay.py --hook "./nkt-cc-hooks secrets"
```

Build first: a stale binary replays old code.

The count is not the point; the list is. Read it and look for commands you would
have wanted to run. Every case in `TestRegressionsFromHistory` was found this
way, and they are the sort of thing no amount of staring at the parser produces:

| looks like a search of `/` | actually |
|---|---|
| `rg -c "QR / external wallet" src/i18n` | a slash inside a quoted pattern |
| `grep -n '//' src/foo.ts` | a comment marker |
| `ps aux \| rg "bfs\|find /"` | a pipe inside a quoted regex |
| `brew list --formula \| grep '/'` | a slash as the pattern itself |

When you find one, add it to `TestRegressionsFromHistory` before fixing it.

Payloads are built without a session id, so wide-search records no state and
judges every call as a first attempt. Runs one subprocess per unique command, so a large
history takes a few minutes.

## firings.py — did the model recover?

Finds the places the hooks actually fired in your transcripts and prints the tool
calls that followed each one, grouped by session and labelled by agent and hook.

```sh
python3 tools/replay/firings.py
```

This is the more interesting of the two once the hook is installed. A block that
teaches is a block followed by a correctly scoped retry; a block that merely
obstructs shows up as the model going around it, giving up, or repeating itself.

Rows are labelled one of two ways:

- **blocked by wide-search / secrets** — the hook's own text is in the
  transcript, so the model read the explanation.
- **escalated, reason not delivered** — a generic permission denial on what looks
  like a wide search. Inferred, because the whole problem with this case is that
  the hook's text is *not* in the transcript: an `ask` that reaches no human comes
  back as a bare *"Permission for this tool use was denied"*.

- **refused by a hook, reason not in transcript** — the transcript records a hook
  refusal (`permissionDecision.source == "hook"`) on what looks like a wide
  search, but none of these hooks' text.

The last two row types are what the per-agent state and the subagent `deny` path
exist to eliminate. Seeing any of them dated after your install is a bug report.
