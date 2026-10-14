# PROBE-CALLOTHER-WIN32 — the OS-boundary census

Measures the standing objection to the "dowry" thesis: *p-code lifts the ISA,
but a Win32 binary's real behaviour partly IS the operating system.* This
counts the ratio instead of arguing about it.

## Build the fixture

Needs `gcc-mingw-w64-x86-64` (apt). The fixture is a deliberately
representative 1990s-shaped line-of-business app — business rules in pure
arithmetic, persistence via file I/O, config via registry, a dialog — written
here so the **import set is known ground truth** rather than trusted from the
lifter's own output.

```sh
x86_64-w64-mingw32-gcc -O1 -o legacy_app.exe legacy_app.c \
    -lgdi32 -luser32 -ladvapi32
```

## Run the census

```sh
cargo run -p r2sleigh-lift --features x86 --example win32_census --release \
    -- probes/win32-census/legacy_app.exe
```

`WIN32_CENSUS_DUMP=1` prints the ops of the first blocks containing an
indirect transfer. It exists because **three successive classifier versions
were wrong** and only reading the real lift settled it (see below).

## Measured, 2026-08-27

Fixture: PE32+ x86-64, 19 sections, `.text` = 7 688 bytes, 48 imports
across 4 DLLs (ADVAPI32 / KERNEL32 / USER32 / msvcrt), 52 IAT slots.

| quantity | value |
|---|---|
| instructions decoded | 2 417 |
| decode failures (linear sweep) | 14 |
| p-code ops | 12 408 |
| **CALLOTHER** | **6 (0.048 %)** |
| direct calls | 73 — all into `.text` |
| indirect calls | 39 → **25 via IAT**, 14 register-indirect |
| distinct IAT slots called | 20 |
| data/arith ops | 11 902 (95.92 %) |

**Two populations, and conflating them is the measurement error.**

1. **CALLOTHER** — instructions SLEIGH has no p-code semantics for. Measured
   at **0.048 %**: machine-level opacity is essentially nil. Remedy would be
   a p-code semantic for the instruction.
2. **Imported calls** — lifted *perfectly* as ordinary calls; what escapes is
   the callee's body, which is not in this binary. Measured at 25 of 98
   resolved call sites, so **74.5 % of resolved calls stay inside the
   binary**. Remedy is a model of the API, not of the instruction.

## What this does and does not support

**Supports:** the OS escape is *bounded and enumerable*. This binary touches
**20 distinct APIs**, not an open-ended surface. You do not need to model
Windows; you need to model the few dozen APIs a given binary actually calls.

**Does not support:** any claim about a real Delphi/VB6/COM application. This
fixture is small, C, and mingw-linked; its CRT is `msvcrt` rather than a
vendor RTL. A binary with heavy COM or an embedded runtime will shift the
ratio and must be measured separately.

## Honest limits

- **Linear sweep**, not recursive descent: x86-64 is variable-length and
  `.text` holds data and padding, so some decodes are garbage. Failures are
  reported (14) rather than hidden.
- **The CRT is included on purpose.** Lifting someone's binary does not let
  you exclude the runtime — it is part of what you bought.
- `CALLOTHER` userops print as `userop#N`; the userop-name map is not
  populated from the `.sla`. Cosmetic for a count, but it means the six are
  unidentified.

## Three wrong classifiers, and why the dump arm is committed

The first census reported `-> IAT 0` — read naively, "this binary makes no OS
calls", which is false of a program whose source I wrote to call eleven of
them. Each version failed for a different reason:

1. Only inspected **direct** `Call` targets. On x86-64 an API call is
   *indirect* through the IAT, so every one was invisible.
2. Walked back for a **`Load`** producing the call temporary. Wrong shape.
3. Reading the actual lift showed SLEIGH emits **`Copy` whose SOURCE is a
   `Ram`-space varnode** carrying the already-folded absolute address.

*A null result is a claim about the measurement apparatus until proven
otherwise* — three times in one probe. The `WIN32_CENSUS_DUMP` arm is
committed so the next person reads the lift instead of guessing a fourth time.
