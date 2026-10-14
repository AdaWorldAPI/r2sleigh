# Executing a lifted Win32 image — what is already zero-copy, and what is not

Companion to `README.md`. That file measures whether the *lift* captures the
binary. This one records what the *executor* would still need, measured
against `r2conc` as it stands, so a later session extends rather than
rediscovers.

## Already done — do not rebuild it

**`r2conc` is zero-copy today.** `SlabState<'a>` borrows `register: &'a mut
[u8]` and `ram: &'a mut [u8]`; only `unique` (SLEIGH scratch, never
persisted by its own contract) is owned. Its own test pins the property
two-sided — *"the CALLER's ram saw the store — zero-copy, not a shadow"*.
The module doc states the design intent: *the IR was born zero-copy; only
the executor materialized.*

**RAM-writable is therefore already a hard requirement, not a tweak.** The
`&mut [u8]` borrow *is* the requirement, enforced by the type system. A
read-only mapping cannot be handed to `SlabState` at all — which is the
correct failure mode (a compile error rather than a silent shadow copy).

## Blocker found by this probe — `Custom(n)` is NOT stable across processes

The 2026-08-26 correction in `r2conc`'s own docs established that 6502
memory arrives as `SpaceId::Ram`, and concluded `Custom(n)` was *"correct
machinery this architecture simply does not need."* True of 6502. **The
x86-64 lift needs it — and the ids are non-deterministic.**

Measured on the identical fixture binary, three consecutive runs:

```
Custom(1062180976)
Custom(2279590000)
Custom(1968052336)
```

The x86-64 lift emits BOTH spaces in one instruction — a stack push is
`Store { space: Custom(n), .. }` while the IAT read is `Copy { src:
Varnode { space: Ram, .. } }`. So on x86-64 the same block addresses
memory through two different space ids, one of which changes every run.

**Cause is CONJECTURE, not measured:** the value looks like a pointer (it
varies per process, in the range of a heap address), so it is most likely
derived from an `AddressSpace*` rather than from anything intrinsic to the
architecture. Confirming that means reading the id's construction in
`r2sleigh_lift::disasm::translate_space`; it has not been done.

### Why this matters more than an executor inconvenience

1. **`SlabState::register_custom` cannot be keyed on a literal.** Any
   caller that writes `Custom(1574422640)` is correct for exactly one
   process. The registration must be derived from the same lift that
   produced the ops.
2. **It poisons persisted R2IL.** The V4 idea is that lifted ops become
   addressable rows. A row whose `space` field holds a per-process pointer
   hash is not addressable — it is a run-local handle written into durable
   storage. Anything persisting `SpaceId::Custom(n)` from an x86-64 lift is
   storing garbage that will silently mismatch on read-back.
3. **It splits the address space.** `Ram` and `Custom(n)` referring to the
   same physical memory means an executor must alias the two slabs, or a
   store through one is invisible to a load through the other.

**Proposed fix, not implemented:** normalize at the lift boundary — map the
architecture's default data space to `SpaceId::Ram` in
`translate_space` regardless of how libsla names it, so `Custom(n)` is
reserved for genuinely additional spaces. That keeps the persisted row
stable and collapses the aliasing question. It needs its own falsifier
(same binary, two processes, identical `space` fields) and must not change
the 6502 result, which is already `Ram` and byte-parity green.

## Prefetch — TWO different subsystems, and the first version of this
## section only addressed one of them

**Correction (operator, 2026-08-27).** What follows below was written about
the **decode** cache — memoizing lifted `R2ILBlock`s by machine address.
That analysis stands. But it silently answered only half the question,
because *reserve-don't-claim + hydrate-on-first-access* introduces a
**second, unrelated** prefetch problem on the **data** side, and the two
share nothing but the word.

| | decode prefetch | lane hydration prefetch |
|---|---|---|
| what is cold | the lifted ops for an address | the reserved-but-unclaimed backing lane |
| cost of a miss | one libsla decode (~µs) | a page fault / allocation (~µs, but **scattered**) |
| access pattern | follows control flow | follows the data the program touches |
| already exists? | yes — `pre_lift`'s `BTreeMap` | **no** |

### The cache wall

Lazy hydration does not remove the cost of materializing a lane; it
**relocates** it, from a bulk pass at startup into a spray of faults across
the execution loop. That is the wall: the aggregate work is similar or
worse, but it now lands interleaved with execution, where each stall
drains the pipeline and evicts whatever the interpreter had warm. A design
that reserves aggressively and claims lazily has *chosen* this failure mode
unless it also prefetches.

**Why this substrate is unusually well placed to avoid it:** the access
pattern is not a guess. `pre_lift` has already decoded the instruction
stream before execution starts, so every `Load`/`Store` varnode in the
upcoming window is *statically visible* — the addresses to warm can be read
off the ops rather than predicted from history. A hardware prefetcher
guesses; this one can simply look.

Sketch, not implemented: walk the decoded blocks ahead of the execution
cursor, collect the constant-address `Ram`/`Custom(n)` varnodes, and warm
those lanes before the cursor reaches them. Indirect accesses
(register-computed addresses) are invisible to that walk and remain
demand-faulted — the census measured **48 `BranchInd` and 14
register-indirect calls**, so the unpredictable fraction is real but small
on this fixture.

### Operator ruling (2026-08-27): eager hydration is acceptable, and it
### makes the prefetch walk a SCALE concern rather than a day-one one

*"If it's a 7 MB file that runs 7× speed if hydrated, I'm fine with that."*

Taken as settled, and it changes what the open item actually is. The cache
wall above is about **scattered** faults landing inside the execution loop.
If paying the materialization cost up front is acceptable, the simplest
answer is not a prefetch walk at all — it is **eager hydration at load**:
one bulk pass, sequential, before execution starts. That is strictly
simpler than walking decoded blocks ahead of a cursor, and on a working set
that fits it produces the same end state with none of the machinery.

So the honest ordering is:

1. **Working set fits** (a 7 MB image — the overwhelmingly common case for a
   legacy line-of-business binary): hydrate eagerly. No prefetcher, no
   cursor, no ahead-of-execution walk. Done.
2. **Working set does not fit** (corpus-scale sweeps, or an image whose
   touched pages exceed what is worth resident): only then does the
   prefetch walk earn its complexity, because only then is there something
   eager hydration cannot simply do.

The prefetch walk stays recorded above because case 2 is real at dowry
scale — a customer estate, not one binary. But it is **not** a prerequisite
for the single-binary path, and building it first would be optimizing an
unmeasured case while the measured one had a one-line answer.

**The falsifier, so this cannot become folklore:** measure faults (or
first-touch count) per executed instruction with hydration lazy, then with
the prefetch walk enabled, on the same binary. If the walk does not
measurably reduce first-touch stalls it is not earning its complexity. And
it must be measured on a working set that **exceeds** the warm set —
prefetch is definitionally free of benefit on an image small enough to stay
resident, which is exactly the shape of the current fixture.

## Not yet needed — the DECODE cache specifically

**No tweak required yet, and here is why rather than an assumption.**

The block cache already exists in the shape the probes use: `pre_lift` in
the LIVE-REGFILE probe builds a `BTreeMap<u64, R2ILBlock>` keyed by machine
address, lifting every instruction once before execution. That is exactly
a tier-0 decode cache. This census lifts 2 417 instructions of `.text` in
well under a second, so for a single binary of this size there is nothing
to optimize.

Where it *would* become load-bearing, stated so the trigger is recognisable:

- **Self-modifying or packed code** — a cache keyed by address is wrong the
  moment the bytes at that address change. Legacy installers and copy
  protection do this. Needs invalidation, which the current map has no
  concept of.
- **Indirect-branch-heavy dispatch** — the census found **48 `BranchInd`**
  and **14 register-indirect calls** the classifier could not resolve
  statically. A recursive-descent lifter reaches those targets only at
  runtime, so the cache becomes a *lazily filled* structure rather than a
  pre-pass.
- **Whole-corpus lifting** — one binary is trivial; a dowry-scale sweep over
  a customer's estate is where per-block memoization and a shared codebook
  start to pay.

Until one of those is the actual workload, adding cache machinery would be
optimizing an unmeasured path — the failure mode this repo's own probes keep
catching.

## The scale boundary — and a distinction the eager ruling above hides

*"If we start to use R2IL for entire ontologies in the 300 MB–3 GB range we
need lance-graph-ontology's cache IN FRONT of R2IL lifting, as a non-eager
op too."* (operator, 2026-08-27)

Correct, and the measurements make it sharper than "large inputs need
laziness". **Two different quantities were being called "hydration", and
only one of them is 7 MB.**

| | the memory IMAGE | the lifted IR |
|---|---|---|
| what it is | the binary's own bytes: `.text`, `.data`, stack | the `Vec<R2ILOp>` those bytes lift to |
| 7 MB input | 7 MB | **~2.2 GB** |
| eager? | yes — the ruling above | **no, not even at 7 MB** |

### Measured, not estimated

- `size_of::<R2ILOp>()` = **464 bytes** (`Varnode` = 112, `R2ILBlock` = 128).
- This census: 12 408 ops from 7 688 bytes of `.text` = **1.614 ops/byte**.
- Therefore lifted IR is **≈ 749× the input size**.

| input | lifted IR |
|---|---|
| 3 MB of `.text` (a 7 MB binary) | **2.2 GB** |
| 300 MB | **225 GB** |
| 3 GB | **2.2 TB** |

So the eager-hydration ruling holds **for the image** and does not transfer
to the IR. Even the single-binary case cannot materialize its own lift
eagerly; at ontology scale it is not a tuning question but an
impossibility.

### The inversion this forces

`lance-graph-ontology` cache **in front of** R2IL lifting is not a
performance layer bolted on — it changes which operation is primary:

```
today:      lower  ->  address  ->  execute        (lift is a load-time pass)
at scale:   address -> [cache hit? serve : lower] -> execute
```

Lifting becomes a **cache-miss path**, per-region and on demand, never a
whole-image pass. That is the substrate's own doctrine rather than a new
idea — *the key prerenders nodes with zero value decode*. If a classid plus
a cascade path answers the query, the value is never decoded and the region
is never lifted. Lifting is what happens when the key **cannot** answer.

Reserve-don't-claim then applies unchanged at this scale, and is what makes
it tractable: reserving 3 GB of *address space* is nearly free because
addresses are not bytes; claiming a region is what costs, and only touched
regions are ever claimed.

### Prerequisite nobody has looked at: 464 bytes per op

Before any GB-scale lifting is contemplated, `R2ILOp`'s footprint is the
first thing to attack, and it is almost all metadata. `Varnode` is 112 bytes
carrying an inline `Option<VarnodeMetadata>` whose seven `Option` fields
dominate; the payload (`space` + `offset` + `size`) is ~24. Boxing or
interning the metadata plausibly gets an op to ~128 bytes — **3.6×** — which
moves 300 MB from 225 GB to 62 GB. Still not eager, but it changes what a
cache tier has to hold.

**Stated as CONJECTURE:** the 128-byte figure is arithmetic on the field
widths, not a measured refactor. The measurement that would settle it is a
`size_of` after boxing `VarnodeMetadata`, plus a benchmark proving the extra
indirection does not cost more in the interpreter's hot loop than it saves
in cache residency — that trade is exactly the kind that can invert.

## Summary

| concern | status |
|---|---|
| zero-copy state borrow | **done** — `SlabState` borrows, test-pinned |
| RAM writable | **done** — enforced by `&mut [u8]`, not a runtime check |
| `Custom(n)` stability | **fixed** — the fallback no longer bottles a host pointer; `Custom(u32)` is now name-derived by invariant, unresolvable handles become `SpaceId::Unresolved` |
| `Ram`/`Custom` aliasing | **expressible** — `AddressSpace::aliases` declares "same memory, second identity" without merging the ids (reserve, don't claim). No lifter populates it yet |
| persisted-row safety | **guarded** — an unresolvable space renders as the visible token `"Unresolved"` (never a plausible number) and `Varnode::is_persistable()` is the check a write path calls. Weaker than "cannot be written" — see the correction below |
| prefetch: DECODE cache | **not needed yet** — exists as `pre_lift`; triggers named above |
| prefetch: LANE hydration (IMAGE) | **ruled** — eager at load for a working set that fits; ahead-of-cursor walk is scale-out |
| eager materialization of lifted IR | **no — 749x expansion, 2.2 GB from a 7 MB binary**; lifting must be a cache-miss path |
| ontology scale (300 MB–3 GB) | **open** — needs lance-graph-ontology cache in front of lifting; inverts lower->address into address->lift-on-miss |
| `R2ILOp` = 464 bytes | **done (Move A)** — 464 -> 144 B by boxing `VarnodeMetadata`, 3.22x measured, size pinned by a `const _` assert. (This row read "open prerequisite" for three commits after it landed — a stale row is a doc that lies about its own repo.) |

### Correction — the `Custom(n)` root cause was misdiagnosed (2026-08-27)

This file previously described the defect as "`Custom(n)` is non-deterministic",
which named the symptom and left the mechanism open. Reading the lift path
settled it, and the answer changes what the fix had to be.

There are **two** producers of `SpaceId::Custom`, and only one was broken:

| producer | input | verdict |
|---|---|---|
| `Disassembler::translate_space` | the space's **name** | **fine** — a byte-sum hash, stable across processes. Never suspected correctly before; it was cleared by reading it, not by assuming. |
| `space_from_index` (3 impls) | LOAD/STORE **input-0** | **the defect** |

Ghidra p-code encodes a LOAD/STORE's target space as its input-0 constant,
and that constant holds the host **`AddrSpace*` pointer** — not a space index.
So `spaces.get(ptr as usize)` always missed, and the fallback truncated the
pointer into `Custom(ptr as u32)`. That is why the same instruction lifted to
`Custom(1062180976)`, `Custom(2279590000)` and `Custom(1968052336)` on three
runs: ASLR, bottled into a `Serialize`-derived field.

Two consequences, which is why both open rows closed together:

1. **The lift was unreproducible.** Same binary, different IR.
2. **The row was unreproducible.** A persisted row keyed on a dead process's
   pointer can never be matched again.

The fix drops the handle instead of bottling it (`SpaceId::Unresolved`), and
makes the drop loud: unresolvable spaces refuse to serialize and fail closed
in `r2conc` rather than guessing RAM.

**What is NOT fixed.** Resolving the pointer *properly* — mapping it back
through libsla to a named space — is the follow-up. Until then the lift is
honest about not knowing rather than confidently wrong, which is a strictly
better failure but is not the capability.

### The refusal was tried in `Serialize` first, and that was wrong

The first cut made `SpaceId`'s `Serialize` **fail** on `Unresolved`, on the
reasoning that a row which cannot be reproduced must not be writable at all.

It broke **24 of 124** `r2sleigh-plugin` tests, on ordinary x86 fixtures.
Baselined against a stash first, so this was measured as caused rather than
assumed pre-existing.

The cause is instructive on its own. `types.rs`'s
`function_analysis_cache_key_parts` calls `hash_json_value(&blocks)` — serde
is how an **in-process cache key** is computed, not only how a row is stored.
The same is true of the plugin's diagnostic JSON export. A veto on the type
hits every one of those.

So the guarantee moved to where persistence actually happens:

* `Unresolved` **serializes**, as the self-describing token `"Unresolved"` —
  a reader can detect it; it can never be mistaken for a space id the way a
  truncated pointer could.
* `Varnode::is_persistable()` is the guard a write path calls.
* `r2conc` still **fails closed** at execution (`ConcError::UnresolvedSpace`),
  because guessing a slab there would corrupt memory silently.

State it precisely: **"cannot be written unnoticed", not "cannot be written".**
`r2il` has no row-persist entry point yet (`serialize.rs` persists `ArchSpec`,
not lifted ops), so the guard is available for the write path when it lands
rather than wired into one today. That is the honest boundary.

**A measurement fell out of the failure.** Those 24 tests were passing before
because the pointer serialized fine — which means they had been hashing ASLR'd
pointers into cache keys all along. Harmless within one process, and proof that
the unresolved path is hit constantly on ordinary x86 code, not in some corner.
