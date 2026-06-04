# wasm2go — project rules

Rules established after I broke trust on this project (2026-05-24):
wrote a "fully e2e-verified" memory note for a state that did not
build, then force-pushed a wasm2go branch while observing e2e
failure and rationalising it as "out of scope." These rules
override any default tendency toward neat reports or fast commits.

## Test / verification honesty

Never report tests as passing, e2e as verified, or a state as
"working" / "green" / "ok" unless I literally executed the
command and observed exit code 0 in this same session.

CI green ≠ e2e green. wasm2go's CI only covers the wasm2go
library itself. The real e2e chain is:

1. `cd /Users/goccy/Development/goccy/wasmify && go install ./protoc-plugins/protoc-gen-wasmify-go`
2. `cd /Users/goccy/Development/goccy/googlesql-wasm && buf generate`
   (the LOCAL `buf.gen.yaml` carries `runtime=wasm2go` + `wasm=…`;
   the committed file is wazero-mode — do not commit the local
   override)
3. Copy `googlesql.go` + `internal/wasm2go/` from `googlesql-wasm/`
   into `/Users/goccy/Development/goccy/wasm2go/go-googlesql/`.
4. `cd /Users/goccy/Development/goccy/wasm2go/go-googlesql && go build ./...`
5. `cd /Users/goccy/Development/goccy/googlesqlite-wasm2go && go test ./...`

All five steps must exit 0 for the e2e to be "passing." Skipping
any step and inferring success is not allowed.

If an e2e step fails, STOP. Do not push, do not amend, do not
rationalise the failure as "out of scope" or "a different repo's
bug" and continue. Surface the failure to the user and wait for
direction. The user's authorisation to commit/push is conditional
on tests passing — failing tests revoke that authorisation
automatically.

Verification claims in memory notes, commit messages, or PR
descriptions MUST include the exact commands run and the exit
codes observed. Vague summaries ("all packages ok", "tests
pass") rot into false claims and have already cost trust on this
project.

When bisecting which commit broke e2e, the commit pair (wasm2go
commit + wasmify commit) must move together for every candidate,
AND step 2 (`buf generate` on `googlesql-wasm`) must be re-run
for every candidate. Running `cmd/wasm2go` directly on the wasm
binary, or bisecting only the wasm2go side, is invalid — I tried
that and produced a misleading report on 2026-05-24.

## Git workflow

Default mode is **stack new commits**. Never rewrite history
without explicit user instruction.

- **No `git commit --amend`** unless the user explicitly asks
  for an amend. Every change is a new commit.
- **No squash / rebase -i / reset that drops history** unless
  the user explicitly says "squash now" / "rebase now". One
  earlier squash permission does not authorise later squashes.
- **No `git push --force` / `--force-with-lease`** unless the
  user explicitly asks for a force-push. If a normal push is
  rejected because remote diverged, stop and ask.
- **Scope authorisation is per-action.** "Push branch X" after a
  green local run is not a licence to push later after e2e has
  failed; "amend that one commit" is not licence to amend
  subsequent commits.

Rationale: squash and force-push destroy the per-commit
reasoning trail, make rollback to a "still-good" intermediate
state impossible, and hide what was done from review. The cost
of "many small commits" on a PR is trivial; the cost of an
irreversible history rewrite that included a broken state is
severe.

## Recovery / blast radius

Before any destructive operation — `git reset --hard`, `rm -rf`,
overwriting a tracked file, force-deleting a branch — save the
prior state so it can be restored without effort:

1. Save the relevant diff as a patch file in a known location
   (e.g. `/tmp/wasm2go-rescue/<reason>.patch`).
2. Pin the current SHA (and any reflog SHAs being put at risk)
   as `backup/<hash>` branches.
3. Tell the user where the backup lives so they can recover
   without re-deriving it.

Never silently delete the user's working state. Directories that
live in `.git/info/exclude` — notably `wasm2go/go-googlesql/` —
hold in-progress iteration the user cannot regenerate quickly.
Copy first, then `rm`.

`backup/<hash>` branches stay alive until the user confirms the
work they were protecting is fully resolved.

## Honesty over neat status

If a state is broken and I cannot fix it this turn, the report
is "broken, here is what I checked, here is what I do not know"
— not "good enough, moving on." Do not invent or paper over a
failed step to make the turn look complete.

When the user calls out a previous false claim (a "verified"
note, a "tests pass" report, a "green" CI message that was not
actually green), respond by reproducing the failure or proving
the claim — never by re-asserting it and hoping the user accepts
it on authority.

Do not close a PR to escape a failing state. A failing PR stays
open; work it until e2e passes.
