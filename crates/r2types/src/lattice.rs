//! Ordering and combination of types, over *regular trees*.
//!
//! A source type graph is cyclic in ordinary C: zlib declares
//! `z_stream.state : internal_state *` and `inflate_state.strm : z_streamp`, so
//! the two refer to each other. Read as finite trees those types have no finite
//! representation, and the structural recursion this file used to do had no
//! reason to stop -- `join(Ptr a, Ptr b) = Ptr(join a b)` on a cyclic pair walked
//! forever, interning one fresh node per step, and `meet` would do the same. The
//! join is gone with the solver constraints that loosened a type, but the
//! lesson stands. The ascending chain
//!
//! ```text
//! Ptr(Bottom) < Ptr(Struct{.. Ptr(Bottom) ..}) < Ptr(Struct{.. Ptr(Struct{..}) ..}) < ..
//! ```
//!
//! is strictly increasing and infinite, so the lattice does not satisfy the
//! ascending chain condition and the solver's Kleene iteration cannot converge.
//! Measured: one 126-byte, 11-block zlib function -- the one that walks
//! `strm->state->strm` -- did not finish in ten minutes, and the arena grew
//! until the kernel killed the process.
//!
//! So a type here is a regular tree: an infinite unfolding with finitely many
//! distinct subtrees, held as a finite graph that may contain back edges. Two
//! consequences, and they are what makes this terminate.
//!
//! `is_subtype` is coinductive. It carries the set of pairs it has already
//! assumed related and answers `true` on meeting one again, which is the
//! greatest-fixpoint reading of the rule rather than the least. Termination is
//! immediate: the assumption set only grows and is bounded by the square of the
//! carrier, so the recursion is O(n^2). This is the Amadio-Cardelli algorithm.
//!
//! `meet` is a product construction. A state of the result is a
//! *pair* of input states, each pair is built once and memoised, and the id is
//! reserved before its children are computed so a back edge has something to
//! point at. The result therefore has at most |A|x|B| nodes, again by
//! construction rather than by any depth parameter.
//!
//! One thing the construction cannot do is invent recursion: a cycle in a
//! product exists only where both components return to a state they have
//! already visited, so every cycle in the result is a cycle in an operand. The
//! check that says so is kept anyway, and refuses that one value rather than
//! asserting a recursive type no declaration backs.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{Signedness, StructField, StructShape, Type, TypeArena, TypeId};

#[derive(Debug, Default, Clone, Copy)]
pub struct TypeLattice;

#[cfg(test)]
thread_local! {
    /// Aggregate pairs `meet_pair` built on this thread, for the test that each is built once.
    static AGGREGATE_PAIRS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl TypeLattice {
    /// The narrower width under the signedness both admit: `Unknown` admits either sign, as
    /// `is_subtype` reads it, so only a signed against an unsigned has no common integer.
    fn meet_integer_shape(
        a_bits: u32,
        a_sign: Signedness,
        b_bits: u32,
        b_sign: Signedness,
    ) -> Option<(u32, Signedness)> {
        let signedness = match (a_sign, b_sign) {
            (a, b) if a == b => a,
            (Signedness::Unknown, known) | (known, Signedness::Unknown) => known,
            _ => return None,
        };
        Some((a_bits.min(b_bits), signedness))
    }

    pub fn is_subtype(arena: &TypeArena, sub: TypeId, sup: TypeId) -> bool {
        let mut assumed = BTreeSet::new();
        Self::is_subtype_coinductive(arena, sub, sup, &mut assumed)
    }

    /// `sub <= sup` read as a greatest fixpoint.
    ///
    /// `assumed` holds the pairs this derivation has already taken as related.
    /// Meeting one again means the obligation has come back to itself, which
    /// under the coinductive reading is discharged rather than infinite -- and
    /// it is what stops a cyclic type from being walked forever. The set only
    /// grows and is bounded by the carrier squared, so this is O(n^2).
    fn is_subtype_coinductive(
        arena: &TypeArena,
        sub: TypeId,
        sup: TypeId,
        assumed: &mut BTreeSet<(TypeId, TypeId)>,
    ) -> bool {
        if sub == sup {
            return true;
        }
        if !assumed.insert((sub, sup)) {
            return true;
        }

        match (arena.get(sub), arena.get(sup)) {
            (_, Type::Top) => true,
            (Type::Bottom, _) => true,
            // `_Bool` is an unsigned integer type (C11 6.2.5p6), so it is below no signed one.
            (Type::Bool, Type::Int { bits, signedness }) => {
                *bits >= 1 && *signedness != Signedness::Signed
            }
            (
                Type::Int {
                    bits: a_bits,
                    signedness: a_sign,
                },
                Type::Int {
                    bits: b_bits,
                    signedness: b_sign,
                },
            ) => {
                a_bits <= b_bits
                    && matches!(
                        (a_sign, b_sign),
                        (Signedness::Signed, Signedness::Signed)
                            | (Signedness::Unsigned, Signedness::Unsigned)
                            | (_, Signedness::Unknown)
                    )
            }
            (Type::Float { bits: a_bits }, Type::Float { bits: b_bits }) => a_bits <= b_bits,
            (Type::Ptr(a_inner), Type::Ptr(b_inner)) => {
                Self::is_subtype_coinductive(arena, *a_inner, *b_inner, assumed)
            }
            (
                Type::Array {
                    elem: a_elem,
                    len: a_len,
                    ..
                },
                Type::Array {
                    elem: b_elem,
                    len: b_len,
                    ..
                },
            ) => {
                let len_ok = match (a_len, b_len) {
                    (_, None) => true,
                    (Some(x), Some(y)) => x == y,
                    (None, Some(_)) => false,
                };
                len_ok && Self::is_subtype_coinductive(arena, *a_elem, *b_elem, assumed)
            }
            (Type::Struct(a), Type::Struct(b)) => b.fields.iter().all(|(off, b_field)| {
                a.fields.get(off).is_some_and(|a_field| {
                    Self::is_subtype_coinductive(arena, a_field.ty, b_field.ty, assumed)
                })
            }),
            _ => false,
        }
    }

    /// The greatest lower bound, or `Bottom` where the construction refuses.
    pub fn meet(arena: &mut TypeArena, a: TypeId, b: TypeId) -> TypeId {
        Self::try_meet(arena, a, b).unwrap_or_else(|| arena.bottom())
    }

    /// The greatest lower bound, refusing rather than inventing recursion.
    pub fn try_meet(arena: &mut TypeArena, a: TypeId, b: TypeId) -> Option<TypeId> {
        let mut state = ProductState::default();
        let id = Self::meet_pair(arena, a, b, &mut state);
        state.settle(arena).then_some(id)
    }

    /// Whether the graph rooted at `id` reaches itself.
    ///
    /// Asked only when a product actually closed a cycle, which is rare, so the
    /// walk is paid for by the case that needs it rather than by every meet.
    fn is_cyclic(arena: &TypeArena, id: TypeId) -> bool {
        fn walk(
            arena: &TypeArena,
            id: TypeId,
            path: &mut BTreeSet<TypeId>,
            done: &mut BTreeSet<TypeId>,
        ) -> bool {
            if path.contains(&id) {
                return true;
            }
            if !done.insert(id) {
                return false;
            }
            path.insert(id);
            let children: Vec<TypeId> = match arena.get(id) {
                Type::Ptr(inner) => vec![*inner],
                Type::Array { elem, .. } => vec![*elem],
                Type::Struct(shape) => shape.fields.values().map(|field| field.ty).collect(),
                Type::Function { params, ret, .. } => params
                    .iter()
                    .copied()
                    .chain(std::iter::once(*ret))
                    .collect(),
                _ => Vec::new(),
            };
            let cyclic = children
                .into_iter()
                .any(|child| walk(arena, child, path, done));
            path.remove(&id);
            cyclic
        }
        let mut path = BTreeSet::new();
        let mut done = BTreeSet::new();
        walk(arena, id, &mut path, &mut done)
    }

    fn meet_pair(arena: &mut TypeArena, a: TypeId, b: TypeId, state: &mut ProductState) -> TypeId {
        if Self::is_subtype(arena, a, b) {
            return a;
        }
        if Self::is_subtype(arena, b, a) {
            return b;
        }
        if let Some(existing) = state.pairs.get(&(a, b)).copied() {
            state.closed.insert(existing);
            return existing;
        }

        match (arena.get(a).clone(), arena.get(b).clone()) {
            (Type::Top, other) | (other, Type::Top) => arena.intern(other),
            (Type::Bottom, _) | (_, Type::Bottom) => arena.bottom(),
            (
                Type::Int {
                    bits: a_bits,
                    signedness: a_sign,
                },
                Type::Int {
                    bits: b_bits,
                    signedness: b_sign,
                },
            ) => {
                if let Some((bits, signedness)) =
                    Self::meet_integer_shape(a_bits, a_sign, b_bits, b_sign)
                {
                    arena.int(bits, signedness)
                } else {
                    arena.bottom()
                }
            }
            (Type::Ptr(a_inner), Type::Ptr(b_inner)) => {
                let slot = state.open(arena, a, b);
                let inner = Self::meet_pair(arena, a_inner, b_inner, state);
                state.close(arena, slot, Type::Ptr(inner), a, b)
            }
            (Type::Float { bits: a_bits }, Type::Float { bits: b_bits }) => {
                arena.float(a_bits.min(b_bits))
            }
            (
                Type::Array {
                    elem: a_elem,
                    len: a_len,
                    stride: a_stride,
                },
                Type::Array {
                    elem: b_elem,
                    len: b_len,
                    stride: b_stride,
                },
            ) => {
                // Two stated lengths that differ have no array below both.
                let len = match (a_len, b_len) {
                    (Some(x), Some(y)) if x != y => return arena.bottom(),
                    (Some(len), _) | (None, Some(len)) => Some(len),
                    (None, None) => None,
                };
                let slot = state.open(arena, a, b);
                #[cfg(test)]
                AGGREGATE_PAIRS.with(|built| built.set(built.get() + 1));
                let elem = Self::meet_pair(arena, a_elem, b_elem, state);
                let stride = (a_stride == b_stride).then_some(a_stride).flatten();
                state.close(arena, slot, Type::Array { elem, len, stride }, a, b)
            }
            (Type::Struct(a_shape), Type::Struct(b_shape)) => {
                // Width subtyping: below both is every field of either, a shared offset met.
                let slot = state.open(arena, a, b);
                #[cfg(test)]
                AGGREGATE_PAIRS.with(|built| built.set(built.get() + 1));
                let mut fields = a_shape.fields.clone();
                for (offset, b_field) in b_shape.fields {
                    let field = match fields.remove(&offset) {
                        Some(a_field) => StructField {
                            name: agreed(a_field.name, b_field.name),
                            ty: Self::meet_pair(arena, a_field.ty, b_field.ty, state),
                        },
                        None => b_field,
                    };
                    fields.insert(offset, field);
                }
                let name = agreed(a_shape.name, b_shape.name);
                state.close(
                    arena,
                    slot,
                    Type::Struct(StructShape { name, fields }),
                    a,
                    b,
                )
            }
            _ => arena.bottom(),
        }
    }
}

/// A name both sides give, or the one side that gives one; two names are none.
fn agreed(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => (a == b).then_some(a),
        (a, b) => a.or(b),
    }
}

/// The pair table a product construction is built from.
///
/// `pairs` maps a pair of input states to the id standing for it, so each pair
/// is built once and the whole construction is bounded by |A|x|B|. `open`
/// reserves that id before the children are known, which is what gives a back
/// edge something to point at; `closed` records the ids something actually
/// pointed back at, so the ones nothing did can be interned normally and keep
/// the id-equality that the rest of the solver relies on for acyclic types.
#[derive(Debug, Default)]
struct ProductState {
    pairs: BTreeMap<(TypeId, TypeId), TypeId>,
    slots: BTreeMap<TypeId, (TypeId, TypeId)>,
    closed: BTreeSet<TypeId>,
}

impl ProductState {
    /// Reserve the id for a pair before its children are known.
    fn open(&mut self, arena: &mut TypeArena, a: TypeId, b: TypeId) -> TypeId {
        let slot = arena.reserve();
        self.pairs.insert((a, b), slot);
        self.slots.insert(slot, (a, b));
        slot
    }

    /// Give a reserved id its shape, or intern the shape if nothing pointed back.
    ///
    /// Only a node some descendant actually closed onto has to keep its
    /// reserved identity; every other node is acyclic and is interned, so two
    /// equal acyclic types keep one id and the reserved slot is left as an
    /// unreferenced hole. Without this every meet would mint fresh ids for
    /// ordinary types and the identity the rest of the solver compares on would
    /// stop meaning anything.
    fn close(
        &mut self,
        arena: &mut TypeArena,
        slot: TypeId,
        ty: Type,
        a: TypeId,
        b: TypeId,
    ) -> TypeId {
        if self.closed.contains(&slot) {
            arena.define(slot, ty);
            return slot;
        }
        self.slots.remove(&slot);
        let id = arena.intern(ty);
        self.pairs.insert((a, b), id);
        id
    }

    /// Whether every cycle this construction created was already in an operand.
    fn settle(&self, arena: &TypeArena) -> bool {
        self.closed.iter().all(|slot| {
            self.slots.get(slot).is_none_or(|(a, b)| {
                TypeLattice::is_cyclic(arena, *a) || TypeLattice::is_cyclic(arena, *b)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meet_signed_unsigned_is_bottom() {
        let mut arena = TypeArena::default();
        let signed = arena.int(32, Signedness::Signed);
        let unsigned = arena.int(32, Signedness::Unsigned);
        let meet = TypeLattice::meet(&mut arena, signed, unsigned);
        assert_eq!(meet, arena.bottom());
    }

    #[test]
    fn meet_signed_unsigned_with_different_widths_is_bottom() {
        let mut arena = TypeArena::default();
        let a = arena.int(64, Signedness::Signed);
        let b = arena.int(32, Signedness::Unsigned);
        let met = TypeLattice::meet(&mut arena, a, b);
        assert_eq!(met, arena.bottom());
    }

    #[test]
    fn meet_pointer_meets_inner_types() {
        let mut arena = TypeArena::default();
        let i64_ty = arena.int(64, Signedness::Signed);
        let i32_ty = arena.int(32, Signedness::Signed);
        let p1 = arena.ptr(i64_ty);
        let p2 = arena.ptr(i32_ty);
        let met = TypeLattice::meet(&mut arena, p1, p2);
        let Type::Ptr(inner) = arena.get(met) else {
            panic!("meet should return pointer");
        };
        assert_eq!(
            arena.get(*inner),
            &Type::Int {
                bits: 32,
                signedness: Signedness::Signed
            }
        );
    }

    /// A small type, interned into an arena: the shapes the order relates, without recursion.
    #[derive(Debug, Clone)]
    enum Shape {
        Top,
        Bottom,
        Bool,
        Int(u32, Signedness),
        Float(u32),
        Ptr(Box<Shape>),
        Array(Box<Shape>, Option<usize>),
        Struct(BTreeMap<u64, Shape>),
    }

    fn shape() -> impl proptest::strategy::Strategy<Value = Shape> {
        use proptest::prelude::*;
        let sign = prop_oneof![
            Just(Signedness::Signed),
            Just(Signedness::Unsigned),
            Just(Signedness::Unknown)
        ];
        let leaf = prop_oneof![
            Just(Shape::Top),
            Just(Shape::Bottom),
            Just(Shape::Bool),
            (prop::sample::select(vec![8u32, 16, 32, 64]), sign)
                .prop_map(|(b, s)| Shape::Int(b, s)),
            prop::sample::select(vec![32u32, 64]).prop_map(Shape::Float),
        ];
        leaf.prop_recursive(3, 12, 3, |inner| {
            prop_oneof![
                inner.clone().prop_map(|s| Shape::Ptr(Box::new(s))),
                (inner.clone(), prop::option::of(1usize..3))
                    .prop_map(|(s, len)| Shape::Array(Box::new(s), len)),
                prop::collection::btree_map(prop::sample::select(vec![0u64, 8]), inner, 0..3)
                    .prop_map(Shape::Struct),
            ]
        })
    }

    fn intern(arena: &mut TypeArena, shape: &Shape) -> TypeId {
        match shape {
            Shape::Top => arena.top(),
            Shape::Bottom => arena.bottom(),
            Shape::Bool => arena.bool_ty(),
            Shape::Int(bits, sign) => arena.int(*bits, *sign),
            Shape::Float(bits) => arena.float(*bits),
            Shape::Ptr(inner) => {
                let inner = intern(arena, inner);
                arena.ptr(inner)
            }
            Shape::Array(elem, len) => {
                let elem = intern(arena, elem);
                arena.array(elem, *len, None)
            }
            Shape::Struct(fields) => {
                let fields = fields
                    .iter()
                    .map(|(offset, ty)| {
                        let ty = intern(arena, ty);
                        (*offset, StructField { name: None, ty })
                    })
                    .collect();
                arena.intern(Type::Struct(StructShape { name: None, fields }))
            }
        }
    }

    /// A supertype of `shape`, each choice read from `seed`: a wider integer, an unknown sign, an
    /// unstated length, fewer fields, or `Top`.
    fn widen(shape: &Shape, seed: &mut impl Iterator<Item = u8>) -> Shape {
        let pick = seed.next().unwrap_or(0);
        if pick.is_multiple_of(7) {
            return Shape::Top;
        }
        match shape {
            Shape::Int(bits, sign) => {
                let bits = if pick & 2 != 0 {
                    (bits * 2).min(64)
                } else {
                    *bits
                };
                let sign = if pick & 4 != 0 {
                    Signedness::Unknown
                } else {
                    *sign
                };
                Shape::Int(bits, sign)
            }
            Shape::Bool if pick & 2 != 0 => {
                let sign = if pick & 4 != 0 {
                    Signedness::Unsigned
                } else {
                    Signedness::Unknown
                };
                Shape::Int(if pick & 8 != 0 { 32 } else { 8 }, sign)
            }
            Shape::Float(bits) if pick & 2 != 0 => Shape::Float(64.max(*bits)),
            Shape::Ptr(inner) => Shape::Ptr(Box::new(widen(inner, seed))),
            Shape::Array(elem, len) => {
                let len = if pick & 2 != 0 { None } else { *len };
                Shape::Array(Box::new(widen(elem, seed)), len)
            }
            Shape::Struct(fields) => {
                let mut kept = BTreeMap::new();
                for (offset, ty) in fields {
                    if !seed.next().unwrap_or(0).is_multiple_of(3) {
                        kept.insert(*offset, widen(ty, seed));
                    }
                }
                Shape::Struct(kept)
            }
            Shape::Bottom => {
                let leaves = [
                    Shape::Bool,
                    Shape::Int(8, Signedness::Signed),
                    Shape::Float(32),
                ];
                leaves[usize::from(pick) % 3].clone()
            }
            other => other.clone(),
        }
    }

    /// Every scalar of the order, so a law over scalars is checked on all of them.
    fn scalars(arena: &mut TypeArena) -> Vec<TypeId> {
        let mut all = vec![arena.top(), arena.bottom(), arena.bool_ty()];
        for bits in [8, 16, 32, 64] {
            for sign in [
                Signedness::Signed,
                Signedness::Unsigned,
                Signedness::Unknown,
            ] {
                all.push(arena.int(bits, sign));
            }
        }
        all.push(arena.float(32));
        all.push(arena.float(64));
        all
    }

    #[test]
    fn every_scalar_meet_is_the_greatest_lower_bound() {
        let mut arena = TypeArena::default();
        let all = scalars(&mut arena);
        for &a in &all {
            for &b in &all {
                let m = TypeLattice::meet(&mut arena, a, b);
                assert!(TypeLattice::is_subtype(&arena, m, a));
                assert!(TypeLattice::is_subtype(&arena, m, b));
                for &c in &all {
                    if TypeLattice::is_subtype(&arena, c, a)
                        && TypeLattice::is_subtype(&arena, c, b)
                    {
                        assert!(
                            TypeLattice::is_subtype(&arena, c, m),
                            "{:?} is below {:?} and {:?} but not their meet {:?}",
                            arena.get(c),
                            arena.get(a),
                            arena.get(b),
                            arena.get(m)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_signed_and_an_unsigned_integer_have_no_common_type_bool_included() {
        let mut arena = TypeArena::default();
        let signed = arena.int(32, Signedness::Signed);
        let unsigned = arena.int(32, Signedness::Unsigned);
        let boolean = arena.bool_ty();
        let su = TypeLattice::meet(&mut arena, signed, unsigned);
        let left = TypeLattice::meet(&mut arena, su, boolean);
        let ub = TypeLattice::meet(&mut arena, unsigned, boolean);
        let right = TypeLattice::meet(&mut arena, signed, ub);
        assert_eq!(ub, boolean);
        assert_eq!(left, arena.bottom());
        assert_eq!(right, arena.bottom());
    }

    #[test]
    fn a_struct_pair_shared_by_two_fields_is_met_once() {
        let mut arena = TypeArena::default();
        let s8 = arena.int(8, Signedness::Signed);
        // A field at different offsets: neither struct is below the other, so each pair is met.
        let leaf = |arena: &mut TypeArena, offset| {
            let fields = BTreeMap::from([(offset, StructField { name: None, ty: s8 })]);
            arena.intern(Type::Struct(StructShape { name: None, fields }))
        };
        let (mut a, mut b) = (leaf(&mut arena, 0), leaf(&mut arena, 8));
        // Each level holds the level below twice, so a meet that does not memoise aggregate
        // pairs visits 2^depth of them.
        for _ in 0..24 {
            let twice = |arena: &mut TypeArena, ty| {
                let fields = BTreeMap::from([
                    (0, StructField { name: None, ty }),
                    (64, StructField { name: None, ty }),
                ]);
                arena.intern(Type::Struct(StructShape { name: None, fields }))
            };
            a = twice(&mut arena, a);
            b = twice(&mut arena, b);
        }
        AGGREGATE_PAIRS.with(|built| built.set(0));
        let met = TypeLattice::meet(&mut arena, a, b);
        assert!(TypeLattice::is_subtype(&arena, met, a));
        assert_eq!(AGGREGATE_PAIRS.with(std::cell::Cell::get), 25);
    }

    fn equivalent(arena: &TypeArena, a: TypeId, b: TypeId) -> bool {
        TypeLattice::is_subtype(arena, a, b) && TypeLattice::is_subtype(arena, b, a)
    }

    proptest::proptest! {
        /// `meet` is the greatest lower bound of the subtype order, so the solver's fold over a
        /// class's bounds is one value whatever order the bounds arrive in.
        #[test]
        fn meet_is_the_greatest_lower_bound(a in shape(), b in shape(), c in shape()) {
            let mut arena = TypeArena::default();
            let (a, b, c) = (intern(&mut arena, &a), intern(&mut arena, &b), intern(&mut arena, &c));
            let ab = TypeLattice::meet(&mut arena, a, b);
            proptest::prop_assert!(TypeLattice::is_subtype(&arena, ab, a));
            proptest::prop_assert!(TypeLattice::is_subtype(&arena, ab, b));
            let ba = TypeLattice::meet(&mut arena, b, a);
            proptest::prop_assert!(equivalent(&arena, ab, ba));
            let aa = TypeLattice::meet(&mut arena, a, a);
            proptest::prop_assert!(equivalent(&arena, aa, a));
            let left = TypeLattice::meet(&mut arena, ab, c);
            let bc = TypeLattice::meet(&mut arena, b, c);
            let right = TypeLattice::meet(&mut arena, a, bc);
            proptest::prop_assert!(equivalent(&arena, left, right));
            // Below a and b, so below their meet.
            let below = TypeLattice::meet(&mut arena, a, bc);
            proptest::prop_assert!(TypeLattice::is_subtype(&arena, below, ab));
        }

        /// Any type below two types is below their meet: the meet is the greatest such.
        #[test]
        fn a_common_lower_bound_is_below_the_meet(
            c in shape(),
            left in proptest::collection::vec(proptest::prelude::any::<u8>(), 24),
            right in proptest::collection::vec(proptest::prelude::any::<u8>(), 24),
        ) {
            let (a, b) = (widen(&c, &mut left.into_iter()), widen(&c, &mut right.into_iter()));
            let mut arena = TypeArena::default();
            let (a, b, c) = (intern(&mut arena, &a), intern(&mut arena, &b), intern(&mut arena, &c));
            proptest::prop_assert!(TypeLattice::is_subtype(&arena, c, a));
            proptest::prop_assert!(TypeLattice::is_subtype(&arena, c, b));
            let ab = TypeLattice::meet(&mut arena, a, b);
            proptest::prop_assert!(TypeLattice::is_subtype(&arena, c, ab), "{:?}", arena.get(ab));
        }
    }

    #[test]
    fn a_known_sign_meets_an_unknown_one_at_the_narrower_width() {
        let mut arena = TypeArena::default();
        let signed = arena.int(64, Signedness::Signed);
        let unknown = arena.int(32, Signedness::Unknown);
        let met = TypeLattice::meet(&mut arena, signed, unknown);
        assert_eq!(
            arena.get(met),
            &Type::Int {
                bits: 32,
                signedness: Signedness::Signed
            }
        );
    }

    #[test]
    fn meet_incompatible_types_goes_bottom() {
        let mut arena = TypeArena::default();
        let i32_ty = arena.int(32, Signedness::Signed);
        let f64_ty = arena.float(64);
        let met = TypeLattice::meet(&mut arena, i32_ty, f64_ty);
        assert_eq!(arena.get(met), &Type::Bottom);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn pick_signedness(tag: u8) -> Signedness {
        match tag % 3 {
            0 => Signedness::Signed,
            1 => Signedness::Unsigned,
            _ => Signedness::Unknown,
        }
    }

    #[kani::proof]
    fn integer_meet_shape_is_sound() {
        let a_bits: u32 = kani::any();
        let b_bits: u32 = kani::any();
        let a_sign = pick_signedness(kani::any());
        let b_sign = pick_signedness(kani::any());

        let result = TypeLattice::meet_integer_shape(a_bits, a_sign, b_bits, b_sign);

        // A common integer exists exactly when the signs agree or one is unknown, and it is the
        // narrower width under the known sign.
        let conflict =
            a_sign != b_sign && a_sign != Signedness::Unknown && b_sign != Signedness::Unknown;
        match result {
            None => assert!(conflict),
            Some((bits, signedness)) => {
                assert!(!conflict);
                assert_eq!(bits, a_bits.min(b_bits));
                let known = if a_sign == Signedness::Unknown {
                    b_sign
                } else {
                    a_sign
                };
                assert_eq!(signedness, known);
            }
        }
    }
}
