# ADR: aggregates a function's accesses prove

Status: proposed 2026-10-14 (ROADMAP P9's first exit, T's exit).

## Problem

A stripped function that reads a structure through a pointer parameter
renders that parameter as `void*` or `uint8_t*`. Each field read is a byte
load at a computed address. `mixed_touch(struct mixed *value)` in
`tests/corpus/shapes.c` reads a `uint8_t` at offset 0, a `uint16_t` at 2, a
`uint32_t` at 4 and a `uint64_t` at 8. It renders as `fcn_401620(void*
arg0)` with `r2sleigh_load_u16((void*)((uint64_t)arg0 + 2))`.

The engine already proves every fact a structure needs:

- r2ssa states each certified access's width and its address as
  `parameter_expression`: a parameter, index terms, a constant offset;
- r2types solves each accessed value's type;
- r2dec defines declared aggregates (`render::tags`, from the interface's
  `SourceTypeGraph`) and types a parameter as a pointer to one.

Only stripped functions miss these facts, because they have no type graph.
The confidence-scored struct paths that tried to fill the gap reached no
graded output. They are measured and deleted under ROADMAP T.

## Decision

A pointer parameter whose every access is a constant-offset field is typed as
a pointer to a structure laid out from those accesses. Any other parameter
keeps today's rendering, and the proof line states the reason.

### The invariant

The parameter's entry value P is **field-addressed** when both hold:

1. Every certified RAM access whose `parameter_expression` names P has no
   index terms. Its offset `c` and width `w` are constants.
2. Every memory operation whose address P reaches is one of those certified
   accesses. P reaches a value through def-use: any operation or merge with
   an input P reaches, and the reloads of P's certified home. A loop that
   walks `p += 8` reaches its merge, and the merge has no parameter
   expression. An access through it therefore refuses, and so does any
   access r2ssa could not certify, because the layout would miss or
   misplace a field. Reason: `access through the parameter at <inst> is not
   a constant field`.

Other uses of P do not bear on its pointee: a call argument, a comparison,
or a return. C spells each of them on a structure pointer.

The accesses give fields `(c, w)`. Two accesses at the same `(c, w)` are one
field. Two fields that overlap but differ in extent refuse. Reason:
`fields overlap at +c`. At least two distinct offsets are required. A single
field at offset 0 is a scalar pointer, and the solve already types it.

### Owners

| Fact | Owner | Contract |
|---|---|---|
| Accesses, offsets, widths | r2ssa | `certificates().memory_accesses`, `addresses().parameter_expression` (exist) |
| Every access P reaches is a certified constant-offset one | r2ssa | a per-slot fact over def-use, beside `parameter_expression` (new) |
| Layout: fields, their types, padding, the tag | r2types | `FunctionTypeFacts::inferred_aggregates`, keyed by slot, as `AggregateDefinition` (new field, existing type) |
| The parameter's type | r2types | the merged signature's `Pointer(Struct(tag))`, under the certificate source `AccessLayout` (new) |
| Definition and spelling | r2dec | `render::tags` defines a tag the type graph states or r2types infers (extended) |

A field's type is the solve's type for the accessed value
(`EvidenceTypes::value_type`). Without one, it is the integer of that width
with the solve's signedness. The tag is `fcn_<entry>_arg<slot>`, never a
hash. Field names are `f_<offset in hex>`. Padding between fields is
`uint8_t _pad_<offset>[n]`. The layout states nothing past the last field.
Accesses reach the object only through the pointer, so no `sizeof` and no
by-value copy reads its extent.

A declared type outranks an inferred one. A parameter the interface types,
including one with a `SourceTypeGraph` aggregate, is never re-laid out.

### Rendering

First exit: the parameter is spelled `struct fcn_401620_arg0* arg0`, and its
definition is emitted once before the function, as `render::tags` does for a
declared tag. Accesses keep their byte-load spelling. That spelling is what
the declared path renders today: `declarations.rs` asserts no `->`.

Second exit (P9b): an access whose certified field matches its `(c, w)`
lowers to `CExpr::PtrMember`, for declared and inferred aggregates alike. All
or nothing per parameter: one access with no matching field keeps the byte
spelling for every access through that parameter. `CExpr::PtrMember` exists
in `ast.rs` and `codegen.rs`, and nothing lowers to it since legacy r2dec
was deleted (doc/adr-access-syntax.md).

### Cost

- r2ssa's reach fact is one forward pass over P's def-use closure,
  `O(values + uses)`.
- The layout is one pass over the function's certified accesses,
  `O(A log A)`, sorted by offset.
- Neither runs a fixpoint.

## Validation

- Behavior test in `r2engine/tests/native.rs` style: a byte-literal x86-64
  function reading `+0` u8, `+2` u16, `+4` u32 and `+8` u64 through `rdi`
  renders `struct fcn_<entry>_arg0* arg0` and the definition text.
- Negative tests: an indexed access refuses; an uncertified access refuses;
  overlapping widths refuse; a single offset-0 access stays a scalar
  pointer.
- The census moves on purpose, and each moved line is read. Equivalence must
  keep every cell. `mixed_touch`, `shape_struct_pointer` and
  `shape_struct_value` are equal today, so the check is zero loss.

## Not decided here

- Recursive and polymorphic aggregates (P9 after T).
- Structures reached through a local or a global.
- Arrays of structures (`shape_struct_array`).
- Member spelling for locals.
