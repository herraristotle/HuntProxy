# HuntProxy — Agent Instructions

## Build policy (mandatory)

**Never build, check, test, or lint Rust code on this machine.**

All Rust compilation, clippy, rustfmt, and test execution happens on GitHub
Actions runners. This machine has no working Rust toolchain configured for this
repo, and local `cargo check` output has repeatedly been wrong or misleading.

- Do **not** run `cargo build`, `cargo check`, `cargo test`, `cargo clippy`,
  `cargo fmt`, or `cargo run` locally.
- Do **not** run `scripts/check.sh` locally.
- To validate a change, push it and watch CI:

  ```bash
  gh run list -L 10
  gh run watch <run-id>
  gh run view <run-id> --log-failed
  ```

- CI workflows: `.github/workflows/ci.yml` (fmt, clippy, test, build),
  `.github/workflows/candidate.yml` (release candidate), release flow.

### Why

The local working tree has diverged from upstream in ways that produce
compilation errors unrelated to whatever change is in flight. Local `cargo`
output cannot distinguish "your change broke this" from "this was already
broken," so it is not a usable signal. The CI runner checks out a clean tree at
the pushed commit, which is the only trustworthy signal.

Many source files may be syntactically incomplete locally (see
`INTEGRATION_STATUS.md`). This is a known, documented state — do not treat local
compile errors as your own regressions without first checking whether the file
is clean at the pushed commit.

## Do not stash

Never run `git stash`, `git checkout --`, `git reset --hard`, or `git clean` on
this repository. The working tree holds unreconciled work-in-progress that is
not recoverable from history. There is already a pre-existing stash
("pre-reconcile full WIP snapshot (crawler+oast) 2026-10-16") that must be left
alone.

To inspect another revision without disturbing the tree, use `git show` (see
below) rather than switching branches.

## Inspecting other revisions without touching the tree

```bash
git show upstream/master:src/history/mod.rs          # read a file at a revision
git show upstream/master:src/history/mod.rs | sed -n '328,380p'
git diff upstream/master -- src/history/mod.rs       # diff a file
```

## Repo layout notes

- `src/api/mod.rs` — versioned REST API (axum router).
- `src/mcp/mod.rs` — MCP tool surface for AI agents (JSON-RPC).
- `src/plugins/mod.rs` — JavaScript extension runtime (QuickJS via `rquickjs`).
  Extensions are JS; there is no Go plugin runtime.
- `src/history/mod.rs` — history query DSL compiler (HTTPQL-like).
- `upstream` remote = `BehiSecc/HuntProxy` (canonical). `origin` = fork.
