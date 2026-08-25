# The 6502 conformance corpus — fetched, never vendored

`fetch-6502-suite.sh` pulls Klaus Dormann's `6502_65C02_functional_tests`
prebuilt binaries into `cache/` (gitignored) and verifies them by sha256.

## Why this is fetched rather than committed

Two independent reasons, either of which alone would be sufficient.

**Licensing.** The suite is GPL-3.0 (its own `license.txt`). r2sleigh is not,
and this workspace carries a standing rule that GPL emulator and test sources
are *behavioural reference only* — never transcribed, never copied in. The
bytes stay outside the tree; the licence is copied next to them on fetch so
whoever has the corpus has its terms.

**Fixture hygiene, which would apply even under a permissive licence.** A test
fixture that lives outside the repo but is read as if it were inside is a time
bomb: it passes on the machine that has it, skips on the machine that doesn't,
and the skip hides the failure exactly where CI would have caught it. So the
rule here is strict — **nothing under `tests/` may depend on this script having
run.** The committed `arch_table_tests` in `r2sleigh-lift` read no files at
all. The corpus is a *measurement* input, never a gate.

## What it is good for

A deterministic, graphics-free 6502 program with a known entry point at
`$0400` and a self-checking pass/fail trap. That makes it the one oracle three
different consumers can share:

- **r2sleigh** — does the 6502 R2IL lift reproduce the reference semantics?
- **an emulator under test** — does it execute the suite to the success trap?
- **a cross-check between the two** — the same corpus, two independent readers.

Measured on fetch (2026-08-25): both binaries are 65,536 B; the functional
test's `$0400` reads `D8 A2 FF 9A A9 00 8D 00 02 …` — `CLD / LDX #$FF / TXS /
LDA #$00 / STA $0200 / …`, the genuine entry sequence.

## What it is NOT

It is not an Elite oracle. Elite's `4-reference-binaries` verify that an
*assembly* reproduces the original (that repo's own README says so); they are
raw, partly encrypted, multi-part fragments with no load address, and they do
not constitute a runnable program or a runtime observable. That distinction is
why this corpus exists.

## Hash mismatch is a hard failure

A conformance corpus that silently changed is worse than an absent one —
every number measured against it moves with nothing saying so. Verified
red-then-green: corrupting an expected hash makes the script report `MISMATCH`
and exit 1; restoring it exits 0.
