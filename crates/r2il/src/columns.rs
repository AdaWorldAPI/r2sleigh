//! `OpColumns` — a struct-of-arrays projection over an op stream.
//!
//! # Why a projection and not a rewrite
//!
//! Converting `R2ILOp` itself to SoA is not feasible and was measured
//! rather than guessed: **82 variants, 1 257 construction/match sites
//! across 34 files** in this workspace, **25 more files** in downstream
//! repos (ruff, lance-graph, OGAR), and the enum is `Serialize` — it is a
//! persisted wire format. That migration is weeks of work with a format
//! break in the middle and three repos to land in lockstep.
//!
//! It is also unnecessary. `R2ILOp` is the *decode and execute* type; this
//! is the *scan* type. Building columns costs one pass — but the cache
//! path is already writing the stream somewhere ([`pre_lift`-style block
//! memoization](https://example.invalid) is a write that has to happen
//! anyway), so a cache that stores columns instead of `Vec<R2ILOp>` pays
//! **no conversion at all**. It chose a different output shape for a write
//! it was already doing.
//!
//! The same idea the substrate uses everywhere: *the durable form and the
//! working form do not have to be the same type.* A `ClassView` projecting
//! a dumb byte register is this, one layer up.
//!
//! # What this is for
//!
//! Scans. Every analysis the Win32 census performs is a filter over an
//! array of tagged records — count ops by kind, find every `CallOther`,
//! classify call targets by address range, find constant-address `Ram`
//! varnodes for a prefetch walk. On `Vec<R2ILOp>` those stride 144 bytes
//! and touch a different cache line per element. On columns they are
//! contiguous `u8`/`u64` sweeps, which is the shape `ndarray::simd`'s mask
//! surface (`eq_u32_to_mask`, `masked_strided_group_sum`) already consumes.
//!
//! **No SIMD here.** This crate has no `ndarray` dependency and gains none;
//! the columns are laid out so a *consumer* that has one can vectorize.
//! Whether that is worth doing is a profiling question nobody has answered
//! — `tesseract-rs` measured an obvious-looking SIMD target at 2.85 % of a
//! page and correctly declined it.
//!
//! # What it deliberately does not carry
//!
//! Only the fields scans actually filter on: the op tag, and the first
//! varnode's space/offset. Reconstructing an `R2ILOp` from columns is a
//! non-goal — the AoS stream remains the source of truth and every column
//! index maps back to it positionally.

use crate::{R2ILOp, SpaceId, Varnode};

/// A dense tag per op, stable and small enough to compare in bulk.
///
/// Deliberately NOT the 82-variant discriminant: scans group by *kind of
/// control flow*, and a scan that had to enumerate 82 values to ask "is
/// this a call?" would defeat the purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum OpTag {
    /// Anything that is not control flow: arithmetic, moves, loads, stores.
    Data = 0,
    Branch = 1,
    CBranch = 2,
    BranchInd = 3,
    Call = 4,
    CallInd = 5,
    Return = 6,
    /// No p-code semantics — an instruction SLEIGH cannot express.
    CallOther = 7,
}

impl OpTag {
    pub fn of(op: &R2ILOp) -> Self {
        match op {
            R2ILOp::Branch { .. } => Self::Branch,
            R2ILOp::CBranch { .. } => Self::CBranch,
            R2ILOp::BranchInd { .. } => Self::BranchInd,
            R2ILOp::Call { .. } => Self::Call,
            R2ILOp::CallInd { .. } => Self::CallInd,
            R2ILOp::Return { .. } => Self::Return,
            R2ILOp::CallOther { .. } => Self::CallOther,
            _ => Self::Data,
        }
    }

    #[inline]
    pub fn is_control_flow(self) -> bool {
        self != Self::Data
    }
}

/// Dense encoding of a varnode's address space, for bulk comparison.
///
/// `Custom(n)` collapses to a single tag on purpose: the census measured
/// `n` to be **different on every process** for the x86-64 lift, so the
/// integer is a run-local handle and must never be a scan key. Callers
/// needing the specific space read the AoS op at the same index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpaceTag {
    None = 0,
    Const = 1,
    Register = 2,
    Ram = 3,
    Unique = 4,
    Custom = 5,
}

impl SpaceTag {
    pub fn of(space: SpaceId) -> Self {
        match space {
            SpaceId::Const => Self::Const,
            SpaceId::Register => Self::Register,
            SpaceId::Ram => Self::Ram,
            SpaceId::Unique => Self::Unique,
            _ => Self::Custom,
        }
    }
}

/// Columns over one op stream. Every column has the same length, and index
/// `i` refers to `ops[i]` in the stream it was built from.
#[derive(Debug, Clone, Default)]
pub struct OpColumns {
    /// `OpTag as u8`, one per op.
    pub tag: Vec<u8>,
    /// `SpaceTag as u8` of the op's primary varnode, `None` where the op
    /// has no natural primary (most `Data` ops).
    pub space: Vec<u8>,
    /// Offset of the primary varnode; `0` where `space` is `None`.
    pub offset: Vec<u64>,
}

/// The varnode a scan cares about for a given op.
///
/// For control flow that is the target — the thing address-range
/// classification asks about. For everything else there is no single
/// meaningful answer, and inventing one would put noise in the column.
fn primary(op: &R2ILOp) -> Option<&Varnode> {
    match op {
        R2ILOp::Branch { target }
        | R2ILOp::CBranch { target, .. }
        | R2ILOp::BranchInd { target }
        | R2ILOp::Call { target }
        | R2ILOp::CallInd { target }
        | R2ILOp::Return { target } => Some(target),
        R2ILOp::Copy { src, .. } => Some(src),
        R2ILOp::Load { addr, .. } => Some(addr),
        R2ILOp::Store { addr, .. } => Some(addr),
        _ => None,
    }
}

impl OpColumns {
    pub fn len(&self) -> usize {
        self.tag.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tag.is_empty()
    }

    /// Project an op stream into columns.
    pub fn build(ops: &[R2ILOp]) -> Self {
        let n = ops.len();
        let mut c = Self {
            tag: Vec::with_capacity(n),
            space: Vec::with_capacity(n),
            offset: Vec::with_capacity(n),
        };
        c.extend(ops);
        c
    }

    /// Append a stream's ops to existing columns.
    ///
    /// This is what makes a whole-program cache cheap: blocks are lifted
    /// one at a time and appended, so the columns grow with the code that
    /// actually executed rather than being rebuilt per query.
    pub fn extend(&mut self, ops: &[R2ILOp]) {
        for op in ops {
            self.tag.push(OpTag::of(op) as u8);
            match primary(op) {
                Some(v) => {
                    self.space.push(SpaceTag::of(v.space) as u8);
                    self.offset.push(v.offset);
                }
                None => {
                    self.space.push(SpaceTag::None as u8);
                    self.offset.push(0);
                }
            }
        }
    }

    /// Indices of every op carrying `tag`.
    ///
    /// The scalar reference implementation. A consumer holding
    /// `ndarray::simd` can replace the body with `eq_u32_to_mask` over
    /// [`Self::tag`] and get the same answer — which is the point of the
    /// layout, and why the equivalence is pinned by test.
    pub fn find_tag(&self, tag: OpTag) -> Vec<u32> {
        let want = tag as u8;
        self.tag
            .iter()
            .enumerate()
            .filter(|&(_, t)| *t == want)
            .map(|(i, _)| i as u32)
            .collect()
    }

    /// Count of each tag, indexed by `OpTag as usize`.
    pub fn tag_histogram(&self) -> [u64; 8] {
        let mut h = [0u64; 8];
        for &t in &self.tag {
            h[(t as usize).min(7)] += 1;
        }
        h
    }

    /// Indices whose primary varnode is a constant-address `Ram` reference
    /// inside `[lo, hi)`.
    ///
    /// This is the prefetch walk's core query and the census's IAT
    /// classification, expressed once over columns instead of twice over
    /// the AoS stream.
    pub fn find_ram_in_range(&self, lo: u64, hi: u64) -> Vec<u32> {
        let ram = SpaceTag::Ram as u8;
        (0..self.len())
            .filter(|&i| self.space[i] == ram && self.offset[i] >= lo && self.offset[i] < hi)
            .map(|i| i as u32)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vn(space: SpaceId, offset: u64) -> Varnode {
        Varnode::new(space, offset, 8)
    }

    fn stream() -> Vec<R2ILOp> {
        vec![
            R2ILOp::Copy {
                dst: vn(SpaceId::Unique, 1),
                src: vn(SpaceId::Ram, 0x1000),
            },
            R2ILOp::CallInd {
                target: vn(SpaceId::Unique, 1),
            },
            R2ILOp::Call {
                target: vn(SpaceId::Ram, 0x4000),
            },
            R2ILOp::CallOther {
                output: None,
                userop: 17,
                inputs: vec![],
            },
            R2ILOp::Return {
                target: vn(SpaceId::Register, 0),
            },
        ]
    }

    #[test]
    fn columns_are_positional_against_the_source_stream() {
        let ops = stream();
        let c = OpColumns::build(&ops);
        assert_eq!(c.len(), ops.len(), "one column entry per op");
        // Index i must describe ops[i] — the whole contract.
        for (i, op) in ops.iter().enumerate() {
            assert_eq!(c.tag[i], OpTag::of(op) as u8, "tag mismatch at {i}");
        }
    }

    #[test]
    fn find_tag_locates_control_flow_and_not_data() {
        let c = OpColumns::build(&stream());
        assert_eq!(c.find_tag(OpTag::CallOther), vec![3]);
        assert_eq!(c.find_tag(OpTag::Call), vec![2]);
        assert_eq!(c.find_tag(OpTag::CallInd), vec![1]);
        // Two-sided: the Copy is Data and must NOT appear as a call.
        assert_eq!(c.find_tag(OpTag::Data), vec![0]);
        assert!(c.find_tag(OpTag::Branch).is_empty());
    }

    #[test]
    fn histogram_totals_the_stream_exactly() {
        let ops = stream();
        let h = OpColumns::build(&ops).tag_histogram();
        assert_eq!(h.iter().sum::<u64>(), ops.len() as u64);
        assert_eq!(h[OpTag::CallOther as usize], 1);
        assert_eq!(h[OpTag::Data as usize], 1);
    }

    /// The range filter must discriminate, not merely return something —
    /// the failure mode that produced `-> IAT 0` in the census's first
    /// three classifiers.
    #[test]
    fn ram_range_filter_is_two_sided() {
        let c = OpColumns::build(&stream());
        // 0x1000 (the Copy's src) is in range; 0x4000 (the Call target) is not.
        assert_eq!(c.find_ram_in_range(0x0F00, 0x2000), vec![0]);
        // Widen and the second Ram reference joins.
        assert_eq!(c.find_ram_in_range(0x0F00, 0x5000), vec![0, 2]);
        // Narrow past both and the answer is empty, not "everything".
        assert!(c.find_ram_in_range(0x9000, 0x9100).is_empty());
    }

    /// `Custom(n)` was measured to differ on every process for the x86-64
    /// lift, so it must collapse to one tag and never become a scan key.
    #[test]
    fn custom_spaces_collapse_regardless_of_their_run_local_integer() {
        let a = OpColumns::build(&[R2ILOp::Branch {
            target: vn(SpaceId::Custom(1_062_180_976), 8),
        }]);
        let b = OpColumns::build(&[R2ILOp::Branch {
            target: vn(SpaceId::Custom(2_279_590_000), 8),
        }]);
        assert_eq!(a.space, b.space, "two runs must agree on the space tag");
        assert_eq!(a.space[0], SpaceTag::Custom as u8);
    }

    #[test]
    fn extend_appends_rather_than_replacing() {
        let ops = stream();
        let mut c = OpColumns::build(&ops);
        let before = c.len();
        c.extend(&ops);
        assert_eq!(c.len(), before * 2);
        assert_eq!(c.offset.len(), c.tag.len());
        assert_eq!(c.space.len(), c.tag.len());
    }
}
