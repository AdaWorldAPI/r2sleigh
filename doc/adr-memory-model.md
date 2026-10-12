# ADR: memory is a linear budget

Status: proposed (2026-10-12). Amends PF3 (capacities in bytes) and D26 (the
allocator), and gives F2.5 and LX their per-operation target.

## Model

A request's peak resident memory is four terms:

```
M = F + R + P(f) + A
```

- `F`, fixed: the opened image, its symbol and name tables, and the Sleigh
  specifications. Paid once per process.
- `R`, retained: what the query database holds between requests (analyses,
  sealings, walks, renderings, callee reads).
- `P(f)`, the function's own peak: every representation of `f` live at the
  worst moment of its analysis and rendering.
- `A`, the allocator's retained pages: freed memory mimalloc has not returned.

Linear means `P(f) ≤ c · n(f)` with `n` the function's SSA operations and `c`
a stated constant, `R ≤` a stated byte budget, and no term that grows with a
product of two sizes. A function past the budget refuses with a typed reason
(AGENTS.md, bounded search); it never takes the machine down.

## Measured (2026-10-12, release `pdd`, macOS)

| Term | Measurement |
|---|---|
| `F` | 68 MB (0pack) to 90 MB (pumasim): a 5-byte function's whole RSS |
| `P(f)` growth | over 148 functions in six binaries (pumasim, 0pack, ts3server, vim, libstdc++, dwarf_rust_bubble), `RSS − F` grows as size^0.71 and time as size^0.67: no real function is superlinear |
| `c` | about 2.1 KB of heap per SSA operation at the top (pumasim `0x23fdf0`: 194.7 MB heap peak, 92,007 operations) |
| largest real function | ts3server `fcn.004430b0`, 107 KB of code: 598 MB, 2.3 s |
| `R`, one session | 25 to 97 medium pumasim functions plateau at 445 to 484 MB; 50 functions including the largest reach 869 MB (heap 778.5 MB: render facts 52, liveness 48, graphs 48, value tables 43, ledgers 37, obligations 46) |
| program survey | `afl` on pumasim: 1.3 s and 156 MB, once per session; a 100-byte function whose indirect call asks the call graph's returns pays all of it (`init_fpri`) |
| `A` | 56 MB on the pumasim Gui constructor at the default purge delay (contabo, 2026-10-11) |

Every function over 1 GB in the sweep was the walk decoding a debug file's
zero fill as code (libc-2.26-debug.so: `_IO_vfscanf` 1.2 GB,
`__rpc_thread_destroy` 4.7 GB); the walk now stops at the file's last byte
(`UnresolvedReason::Unbacked`).

## Where `c` goes

At the Gui constructor's peak about ten representations of one function are
live together: the lift, the function's operations and value table, the graph
(instructions, values, uses), liveness, the obligation inventory, the semantic
facts and certificates, the type facts, the render facts, the machine
projection, the term arena, codegen's tokens and the ledger. Each is linear;
together they cost about 2 KB per operation, because every phase's output
stays alive until the response is built.

## Decisions

1. **Phases consume what only they read.** A representation whose last reader
   is the next phase is moved into it and dropped there (the machine
   projection into the term import, the term arena into codegen, tokens into
   text). The peak becomes the largest phase, not the sum of all. Target
   `c ≤ 600 B` per operation, then `c ≤ 300 B` with F2's single numbering
   (one variable table, the graph indexing the function's operations).
2. **Caches are budgeted in bytes.** `Analysed` and `Sealed` share one budget
   (128 MB by default), weighted by measured bytes per operation and evicted
   by GreedyDual-Size (cost to recompute over size), so a session's `R` is
   bounded whatever its length. A walk's lift is dropped once its function is
   prepared; a rendering keeps its text and proof line, not its ledger.
3. **The allocator returns phase garbage at phase boundaries**: one forced
   collect after the analysis and after the render, measured on the four
   large functions, before any change of purge delay (D26).
4. **Superlinear shapes are replaced when a function shows one.** The audit
   (2026-10-12) found structures bounded by a product: memory SSA's per-block
   location maps `O(B·L)`, control-domain guard sets `O(B·D)`, per-call
   memory facts `O(C·F)`, per-block assumption and call-result maps cloned
   down the dominator tree, and phi placement before pruning. None dominated
   a measured peak. Each has a linear replacement: one memory chain with
   phis at the iterated frontier of all definitions and a memoised clobber
   walk (LLVM's MemorySSA); dominator pre/post intervals for guard
   membership; a scoped table with an undo log along the dominator walk;
   interned location sets for call effects; pruned SSA placed from liveness.
5. **A budget refuses.** A function whose operations exceed the budget's
   share refuses before its analysis with the count and the budget.

## Gates

- Heap bytes per SSA operation (dhat, `census.py heap`) on pumasim
  `0x23fdf0` and 0pack `0x58e3d0`: a ratchet beside PF4's time, RSS and
  allocation count.
- Session retention: RSS of a scripted 50-function `pdd` session on pumasim,
  a ratchet.
- The sweep that found the zero fill: every function over 512 MB in the
  measured binaries is named and judged.

## Cost

Each decision is linear: moving a phase's input is O(1); GreedyDual-Size is
O(log k) per access over `k` held entries; a forced collect is one walk of
the allocator's segments; the replacements in 4 are each O(n) or O(n log n).
