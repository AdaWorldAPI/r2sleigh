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

## Summary

| concern | status |
|---|---|
| zero-copy state borrow | **done** — `SlabState` borrows, test-pinned |
| RAM writable | **done** — enforced by `&mut [u8]`, not a runtime check |
| `Custom(n)` stability | **BROKEN on x86-64** — non-deterministic per process |
| `Ram`/`Custom` aliasing | **open** — same memory, two space ids |
| persisted-row safety | **open** — depends on the `Custom(n)` fix |
| prefetch: DECODE cache | **not needed yet** — exists as `pre_lift`; triggers named above |
| prefetch: LANE hydration | **open** — the cache wall reserve-don't-claim creates; no mechanism exists |
