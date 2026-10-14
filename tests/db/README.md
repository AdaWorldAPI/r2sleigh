# Golden tests

Each file here holds tests in radare2's r2r format. `crates/r2s/tests/golden.rs`
runs them against the r2s that the build produced, one trial per test. It runs
under `cargo test` and `cargo nextest`, filtered by `file::NAME`.

```
# A comment.
NAME=x86 listing
FILE=tests/coverage/pinned/hashes_gcc_x64_O2
CMDS=<<EOF
s 0x401330
pd 24
EOF
EXPECT=<<EOF
...
EOF
RUN
```

| Key | Meaning |
|---|---|
| `NAME` | Unique within the file. The trial is `<file>::<NAME>`. |
| `FILE` | The binary, relative to the repository root, so every run reads the same bytes. |
| `ARGS` | r2s flags before the file, split at whitespace (`-e key=value`). |
| `CMDS` | The script, one command per line or `;`-separated, passed as `r2s -q -c`. |
| `EXPECT` | stdout, exactly. |
| `EXPECT_ERR` | stderr, exactly, where it is stated; otherwise stderr is not read. |
| `BROKEN=1` | A known failure: skipped by default, run with `--ignored`. |

A test fails on any difference, printing a unified diff, and on r2s dying from a
signal.

## Blessing

```bash
R2S_BLESS=1 cargo test -p r2s --features sleigh --test golden
```

This writes what ran into each `EXPECT` and `EXPECT_ERR`, or adds them before
`RUN` where they are missing. Use `cargo test`, not nextest: nextest runs each
trial in its own process, and they would race on the files.

Read every changed line before committing a bless, as a census move is read.
An expectation records today's output. It proves that output right only after
someone judges it. The C must still follow from canonical facts (AGENTS.md,
"Tests must not train the engine to look good").

## What belongs here

A command's whole output on a fixed binary: listings, renderings, tables, the
proof line. A fact that needs logic stays a Rust test in `crates/r2s/tests/`:
a property over many lines, a comparison of two commands, or an exit status.
