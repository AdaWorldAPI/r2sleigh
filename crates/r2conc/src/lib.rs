//! `r2conc` — the **concrete slab executor** for R2IL: realtime,
//! op-at-a-time interpretation of the concrete subset over **zero-copy
//! machine state**.
//!
//! # Why this crate exists beside `r2sym`
//!
//! `r2sym` is a *symbolic* executor — string-keyed register maps, sparse
//! per-byte memory, `Clone` values carrying Z3 ASTs, whole-state forks per
//! step. All of that is correct for path exploration and exactly wrong for
//! realtime execution. The IL itself never asked for it: a
//! [`Varnode`] `{space, offset, size}` is already a slice descriptor —
//! the IR was born zero-copy; only the executor materialized.
//!
//! This crate is the executor the descriptor implies:
//!
//! - **State is slabs.** One flat byte slab per address space —
//!   [`SlabState`] *borrows* `register` and `ram` (`&mut [u8]`), so the
//!   machine state can live wherever the caller keeps it (a facet
//!   register, a lane slab, a mapped file) and is never copied in or out.
//!   `unique` is owned scratch — the one space whose contents are
//!   never persisted, so ownership there is not a copy of anything.
//! - **Values are transient.** A read is an LE load from a slab slice into
//!   a `u64`; a write is an LE store. Nothing is reified, keyed, hashed,
//!   or cloned. (Rust's `Copy` + monomorphization already provide what
//!   Valhalla's value classes promise; a slab addressed by
//!   `(offset, size)` is what Panama's `MemorySegment` promises.)
//! - **Unsupported means LOUD.** Ops outside the concrete subset (floats,
//!   atomics, `CallOther`, SSA-analysis forms) return
//!   [`ConcError::Unsupported`] — never a silent skip. A concrete
//!   executor that guesses is worse than one that stops.
//!
//! # Semantics anchor
//!
//! Where an op's edge behaviour has more than one defensible reading, this
//! crate matches `r2sym` (the fork's own executor), so the two can be run
//! differentially: `IntCarry` is the carry-out (`(a + b) mod 2^w <u a`),
//! shifts of `>= width` produce 0 (arithmetic right: sign fill),
//! `Subpiece.offset` counts **bytes**, comparisons and booleans write 0/1.
//!
//! # Control flow
//!
//! [`step`](SlabState::step) is one op; sequencing is the caller's.
//! Direct `Branch`/`CBranch`/`Call` targets follow p-code semantics — the
//! target varnode's **offset IS the address** (no load); `BranchInd` /
//! `CallInd` / `Return` read the varnode's **value**. `step` reports the
//! outcome as [`Control`]; the caller maps addresses onto its own program
//! representation.
//!
//! # Disable-run log (each verified red-then-green before commit)
//!
//! | falsifier | disable | observed red |
//! |---|---|---|
//! | carry two-sided | carry computed at u64 width, unmasked | 0xFF+1 reports no carry |
//! | ashr sign fill | arithmetic right fills zero | 0x81 >>s 9 gives 0, not 0xFF |
//! | direct-target semantics | `Branch` loads the target's value | jumps to the planted decoy |
//! | subpiece refusal | out-of-range returns 0 | the refusal test sees `Ok` |
//! | width-relative lzcount | `leading_zeros()` on the raw u64 | u8 0x01 counts 63 |
//! | LE store | write emits BE bytes | field-isolation + Piece round-trip fail |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use r2il::{R2ILOp, SpaceId, Varnode};

/// Errors a concrete step can produce. Every variant is a refusal, never a
/// guess — the caller decides whether to abort, fork to `r2sym`, or report.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConcError {
    /// A varnode reaches past its slab.
    #[error("{space:?}+{offset:#x}..+{size} out of bounds (slab len {len})")]
    OutOfBounds {
        /// The space whose slab was too small.
        space: SpaceId,
        /// Varnode offset.
        offset: u64,
        /// Varnode size in bytes.
        size: u32,
        /// The slab's actual length.
        len: usize,
    },
    /// This executor computes in `u64`; a varnode wider than 8 bytes is
    /// refused, not truncated.
    #[error("varnode width {0} > 8 bytes — not representable in the u64 core")]
    WidthTooWide(u32),
    /// Writing to the constant space is meaningless.
    #[error("write into Const space")]
    ConstWrite,
    /// A `Custom(n)` space with no slab registered.
    #[error("no slab registered for custom space {0}")]
    UnknownSpace(u32),
    /// Unsigned or signed division / remainder by zero.
    #[error("division by zero")]
    DivByZero,
    /// `Subpiece` with a byte offset at or past the source width.
    #[error("subpiece offset {offset} >= source size {size}")]
    SubpieceOutOfRange {
        /// Byte offset requested.
        offset: u32,
        /// Source varnode size in bytes.
        size: u32,
    },
    /// The op is outside the concrete subset. Loud by design.
    #[error("op outside the concrete subset: {0}")]
    Unsupported(&'static str),
}

/// What one step asks the sequencer to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Fall through to the next op.
    Next,
    /// Transfer to this address (direct or conditional branch taken).
    Jump(u64),
    /// Call this address. Stack discipline is the lifted code's own
    /// (the 6502 pushes its return address through Ram itself); this
    /// executor adds none.
    Call(u64),
    /// Return to this address.
    Return(u64),
}

/// Zero-copy concrete machine state: one flat slab per address space.
///
/// `register` and `ram` are **borrowed** — the state lives with the
/// caller. `unique` is owned scratch (never persisted, per the space's own
/// contract). `Custom(n)` slabs are registered explicitly — the 6502
/// lift mints `Custom` spaces (its `RAM` aliases case-sensitively), so a
/// caller that forgets one gets [`ConcError::UnknownSpace`], not a
/// silently conjured slab.
pub struct SlabState<'a> {
    register: &'a mut [u8],
    ram: &'a mut [u8],
    unique: Vec<u8>,
    custom: Vec<(u32, &'a mut [u8])>,
}

/// Truncate `v` to the low `size` bytes.
#[inline]
const fn mask(v: u64, size: u32) -> u64 {
    if size >= 8 {
        v
    } else {
        v & ((1u64 << (8 * size)) - 1)
    }
}

/// Sign-extend the low `size` bytes of `v` to i64.
#[inline]
const fn sext(v: u64, size: u32) -> i64 {
    let bits = 8 * size;
    if bits >= 64 {
        v as i64
    } else {
        ((v << (64 - bits)) as i64) >> (64 - bits)
    }
}

impl<'a> SlabState<'a> {
    /// Borrow the machine state. `unique_len` bounds the scratch space —
    /// a lift that overruns it gets [`ConcError::OutOfBounds`], loudly.
    pub fn new(register: &'a mut [u8], ram: &'a mut [u8], unique_len: usize) -> Self {
        SlabState {
            register,
            ram,
            unique: vec![0; unique_len],
            custom: Vec::new(),
        }
    }

    /// Register the slab for a `Custom(n)` space (e.g. the 6502's own
    /// case-sensitive `RAM` alias). Last registration for an id wins.
    pub fn with_custom(mut self, id: u32, slab: &'a mut [u8]) -> Self {
        self.custom.retain(|(i, _)| *i != id);
        self.custom.push((id, slab));
        self
    }

    fn slab(&mut self, space: SpaceId) -> Result<&mut [u8], ConcError> {
        match space {
            SpaceId::Register => Ok(self.register),
            SpaceId::Ram => Ok(self.ram),
            SpaceId::Unique => Ok(&mut self.unique),
            SpaceId::Custom(n) => self
                .custom
                .iter_mut()
                .find(|(i, _)| *i == n)
                .map(|(_, s)| &mut **s)
                .ok_or(ConcError::UnknownSpace(n)),
            SpaceId::Const => unreachable!("Const handled before slab lookup"),
        }
    }

    /// Read a varnode as an LE `u64` (in-place slab load; Const = the
    /// offset itself, truncated to the varnode's size).
    pub fn read(&mut self, vn: &Varnode) -> Result<u64, ConcError> {
        if vn.size > 8 {
            return Err(ConcError::WidthTooWide(vn.size));
        }
        if vn.space == SpaceId::Const {
            return Ok(mask(vn.offset, vn.size));
        }
        let (space, offset, size) = (vn.space, vn.offset, vn.size);
        let slab = self.slab(space)?;
        let end = offset
            .checked_add(u64::from(size))
            .filter(|e| *e <= slab.len() as u64)
            .ok_or(ConcError::OutOfBounds {
                space,
                offset,
                size,
                len: slab.len(),
            })?;
        let mut buf = [0u8; 8];
        buf[..size as usize].copy_from_slice(&slab[offset as usize..end as usize]);
        Ok(u64::from_le_bytes(buf))
    }

    /// Write the low `vn.size` bytes of `v` at the varnode (LE).
    pub fn write(&mut self, vn: &Varnode, v: u64) -> Result<(), ConcError> {
        if vn.size > 8 {
            return Err(ConcError::WidthTooWide(vn.size));
        }
        if vn.space == SpaceId::Const {
            return Err(ConcError::ConstWrite);
        }
        let (space, offset, size) = (vn.space, vn.offset, vn.size);
        let slab = self.slab(space)?;
        let end = offset
            .checked_add(u64::from(size))
            .filter(|e| *e <= slab.len() as u64)
            .ok_or(ConcError::OutOfBounds {
                space,
                offset,
                size,
                len: slab.len(),
            })?;
        slab[offset as usize..end as usize].copy_from_slice(&v.to_le_bytes()[..size as usize]);
        Ok(())
    }

    /// A load/store address: read the ADDRESS varnode's value, then access
    /// `space` at that address with `size`.
    fn deref(&mut self, space: SpaceId, addr: &Varnode, size: u32) -> Result<Varnode, ConcError> {
        let a = self.read(addr)?;
        Ok(Varnode::new(space, a, size))
    }

    /// Execute one op. Sequencing is the caller's; see [`Control`].
    #[expect(
        clippy::too_many_lines,
        reason = "one match arm per opcode is the readable shape"
    )]
    pub fn step(&mut self, op: &R2ILOp) -> Result<Control, ConcError> {
        use R2ILOp as Op;
        // Binary helper: read both, compute at the A-operand's width,
        // write masked to dst's width.
        macro_rules! bin {
            ($dst:expr, $a:expr, $b:expr, |$x:ident, $y:ident, $w:ident| $e:expr) => {{
                let $x = self.read($a)?;
                let $y = self.read($b)?;
                let $w = $a.size;
                let r: u64 = $e;
                self.write($dst, mask(r, $dst.size))?;
                Ok(Control::Next)
            }};
        }
        macro_rules! un {
            ($dst:expr, $src:expr, |$x:ident, $w:ident| $e:expr) => {{
                let $x = self.read($src)?;
                let $w = $src.size;
                let r: u64 = $e;
                self.write($dst, mask(r, $dst.size))?;
                Ok(Control::Next)
            }};
        }
        match op {
            Op::Copy { dst, src } => un!(dst, src, |x, _w| x),
            Op::Load { dst, space, addr } => {
                let at = self.deref(*space, addr, dst.size)?;
                let v = self.read(&at)?;
                self.write(dst, v)?;
                Ok(Control::Next)
            }
            Op::Store { space, addr, val } => {
                let v = self.read(val)?;
                let at = self.deref(*space, addr, val.size)?;
                self.write(&at, v)?;
                Ok(Control::Next)
            }

            Op::IntAdd { dst, a, b } => bin!(dst, a, b, |x, y, w| mask(x.wrapping_add(y), w)),
            Op::IntSub { dst, a, b } => bin!(dst, a, b, |x, y, w| mask(x.wrapping_sub(y), w)),
            Op::IntMult { dst, a, b } => bin!(dst, a, b, |x, y, w| mask(x.wrapping_mul(y), w)),
            Op::IntDiv { dst, a, b } => {
                let (x, y) = (self.read(a)?, self.read(b)?);
                if y == 0 {
                    return Err(ConcError::DivByZero);
                }
                self.write(dst, mask(x / y, dst.size))?;
                Ok(Control::Next)
            }
            Op::IntSDiv { dst, a, b } => {
                let (x, y) = (sext(self.read(a)?, a.size), sext(self.read(b)?, b.size));
                if y == 0 {
                    return Err(ConcError::DivByZero);
                }
                self.write(dst, mask(x.wrapping_div(y) as u64, dst.size))?;
                Ok(Control::Next)
            }
            Op::IntRem { dst, a, b } => {
                let (x, y) = (self.read(a)?, self.read(b)?);
                if y == 0 {
                    return Err(ConcError::DivByZero);
                }
                self.write(dst, mask(x % y, dst.size))?;
                Ok(Control::Next)
            }
            Op::IntSRem { dst, a, b } => {
                let (x, y) = (sext(self.read(a)?, a.size), sext(self.read(b)?, b.size));
                if y == 0 {
                    return Err(ConcError::DivByZero);
                }
                self.write(dst, mask(x.wrapping_rem(y) as u64, dst.size))?;
                Ok(Control::Next)
            }
            Op::IntNegate { dst, src } => un!(dst, src, |x, w| mask(x.wrapping_neg(), w)),
            // r2sym anchor: carry-out == ((a + b) mod 2^w) <u a.
            Op::IntCarry { dst, a, b } => {
                bin!(dst, a, b, |x, y, w| u64::from(
                    mask(x.wrapping_add(y), w) < x
                ))
            }
            Op::IntSCarry { dst, a, b } => bin!(dst, a, b, |x, y, w| {
                let (sx, sy) = (sext(x, w), sext(y, w));
                let sum = sext(mask(sx.wrapping_add(sy) as u64, w), w);
                u64::from((sx < 0) == (sy < 0) && (sum < 0) != (sx < 0))
            }),
            Op::IntSBorrow { dst, a, b } => bin!(dst, a, b, |x, y, w| {
                let (sx, sy) = (sext(x, w), sext(y, w));
                let diff = sext(mask(sx.wrapping_sub(sy) as u64, w), w);
                u64::from((sx < 0) != (sy < 0) && (diff < 0) != (sx < 0))
            }),

            Op::IntAnd { dst, a, b } => bin!(dst, a, b, |x, y, _w| x & y),
            Op::IntOr { dst, a, b } => bin!(dst, a, b, |x, y, _w| x | y),
            Op::IntXor { dst, a, b } => bin!(dst, a, b, |x, y, _w| x ^ y),
            Op::IntNot { dst, src } => un!(dst, src, |x, w| mask(!x, w)),

            // r2sym anchor (Z3 bvshl/bvlshr/bvashr): shift >= width gives
            // 0 for shl/lshr, sign fill for ashr.
            Op::IntLeft { dst, a, b } => bin!(dst, a, b, |x, y, w| {
                if y >= u64::from(8 * w) {
                    0
                } else {
                    mask(x << y, w)
                }
            }),
            Op::IntRight { dst, a, b } => bin!(dst, a, b, |x, y, w| {
                if y >= u64::from(8 * w) {
                    0
                } else {
                    mask(x, w) >> y
                }
            }),
            Op::IntSRight { dst, a, b } => bin!(dst, a, b, |x, y, w| {
                let sx = sext(x, w);
                let sh = y.min(u64::from(8 * w) - 1);
                mask((sx >> sh) as u64, w)
            }),

            Op::IntEqual { dst, a, b } => {
                bin!(dst, a, b, |x, y, w| u64::from(mask(x, w) == mask(y, w)))
            }
            Op::IntNotEqual { dst, a, b } => {
                bin!(dst, a, b, |x, y, w| u64::from(mask(x, w) != mask(y, w)))
            }
            Op::IntLess { dst, a, b } => {
                bin!(dst, a, b, |x, y, w| u64::from(mask(x, w) < mask(y, w)))
            }
            Op::IntSLess { dst, a, b } => {
                bin!(dst, a, b, |x, y, w| u64::from(sext(x, w) < sext(y, w)))
            }
            Op::IntLessEqual { dst, a, b } => {
                bin!(dst, a, b, |x, y, w| u64::from(mask(x, w) <= mask(y, w)))
            }
            Op::IntSLessEqual { dst, a, b } => {
                bin!(dst, a, b, |x, y, w| u64::from(sext(x, w) <= sext(y, w)))
            }

            Op::IntZExt { dst, src } => un!(dst, src, |x, _w| x),
            Op::IntSExt { dst, src } => un!(dst, src, |x, w| sext(x, w) as u64),

            Op::BoolNot { dst, src } => un!(dst, src, |x, _w| u64::from(x == 0)),
            Op::BoolAnd { dst, a, b } => bin!(dst, a, b, |x, y, _w| u64::from(x != 0 && y != 0)),
            Op::BoolOr { dst, a, b } => bin!(dst, a, b, |x, y, _w| u64::from(x != 0 || y != 0)),
            Op::BoolXor { dst, a, b } => {
                bin!(dst, a, b, |x, y, _w| u64::from((x != 0) != (y != 0)))
            }

            Op::Piece { dst, hi, lo } => {
                let (h, l) = (self.read(hi)?, self.read(lo)?);
                self.write(dst, mask((h << (8 * lo.size)) | l, dst.size))?;
                Ok(Control::Next)
            }
            // r2sym anchor: offset counts BYTES; at/past the source width
            // r2sym yields Unknown — the concrete reading of "unknown" is a
            // refusal, not a zero.
            Op::Subpiece { dst, src, offset } => {
                if *offset >= src.size {
                    return Err(ConcError::SubpieceOutOfRange {
                        offset: *offset,
                        size: src.size,
                    });
                }
                let v = self.read(src)?;
                self.write(dst, mask(v >> (8 * offset), dst.size))?;
                Ok(Control::Next)
            }
            Op::PopCount { dst, src } => un!(dst, src, |x, _w| u64::from(x.count_ones())),
            Op::Lzcount { dst, src } => {
                un!(dst, src, |x, w| u64::from(x.leading_zeros() - (64 - 8 * w)))
            }

            // Direct control transfer: the target varnode's OFFSET is the
            // address (p-code semantics — no load, no read).
            Op::Branch { target } => Ok(Control::Jump(target.offset)),
            Op::CBranch { target, cond } => {
                if self.read(cond)? != 0 {
                    Ok(Control::Jump(target.offset))
                } else {
                    Ok(Control::Next)
                }
            }
            Op::Call { target } => Ok(Control::Call(target.offset)),
            // Indirect: the target's VALUE is the address.
            Op::BranchInd { target } => Ok(Control::Jump(self.read(target)?)),
            Op::CallInd { target } => Ok(Control::Call(self.read(target)?)),
            Op::Return { target } => Ok(Control::Return(self.read(target)?)),

            Op::Nop => Ok(Control::Next),

            Op::Fence { .. } => Err(ConcError::Unsupported("Fence")),
            Op::LoadLinked { .. } => Err(ConcError::Unsupported("LoadLinked")),
            Op::StoreConditional { .. } => Err(ConcError::Unsupported("StoreConditional")),
            Op::AtomicCAS { .. } => Err(ConcError::Unsupported("AtomicCAS")),
            Op::LoadGuarded { .. } => Err(ConcError::Unsupported("LoadGuarded")),
            Op::StoreGuarded { .. } => Err(ConcError::Unsupported("StoreGuarded")),
            Op::FloatAdd { .. } => Err(ConcError::Unsupported("FloatAdd")),
            Op::FloatSub { .. } => Err(ConcError::Unsupported("FloatSub")),
            Op::FloatMult { .. } => Err(ConcError::Unsupported("FloatMult")),
            Op::FloatDiv { .. } => Err(ConcError::Unsupported("FloatDiv")),
            Op::FloatNeg { .. } => Err(ConcError::Unsupported("FloatNeg")),
            Op::FloatAbs { .. } => Err(ConcError::Unsupported("FloatAbs")),
            Op::FloatSqrt { .. } => Err(ConcError::Unsupported("FloatSqrt")),
            Op::FloatCeil { .. } => Err(ConcError::Unsupported("FloatCeil")),
            Op::FloatFloor { .. } => Err(ConcError::Unsupported("FloatFloor")),
            Op::FloatRound { .. } => Err(ConcError::Unsupported("FloatRound")),
            Op::FloatNaN { .. } => Err(ConcError::Unsupported("FloatNaN")),
            Op::FloatEqual { .. } => Err(ConcError::Unsupported("FloatEqual")),
            Op::FloatNotEqual { .. } => Err(ConcError::Unsupported("FloatNotEqual")),
            Op::FloatLess { .. } => Err(ConcError::Unsupported("FloatLess")),
            Op::FloatLessEqual { .. } => Err(ConcError::Unsupported("FloatLessEqual")),
            Op::Int2Float { .. } => Err(ConcError::Unsupported("Int2Float")),
            Op::Float2Int { .. } => Err(ConcError::Unsupported("Float2Int")),
            Op::FloatFloat { .. } => Err(ConcError::Unsupported("FloatFloat")),
            Op::Trunc { .. } => Err(ConcError::Unsupported("Trunc")),
            Op::CallOther { .. } => Err(ConcError::Unsupported("CallOther")),
            Op::Unimplemented => Err(ConcError::Unsupported("Unimplemented")),
            Op::CpuId { .. } => Err(ConcError::Unsupported("CpuId")),
            Op::Breakpoint => Err(ConcError::Unsupported("Breakpoint")),
            Op::Multiequal { .. } => Err(ConcError::Unsupported("Multiequal")),
            Op::Indirect { .. } => Err(ConcError::Unsupported("Indirect")),
            Op::PtrAdd { .. } => Err(ConcError::Unsupported("PtrAdd")),
            Op::PtrSub { .. } => Err(ConcError::Unsupported("PtrSub")),
            Op::SegmentOp { .. } => Err(ConcError::Unsupported("SegmentOp")),
            Op::New { .. } => Err(ConcError::Unsupported("New")),
            Op::Cast { .. } => Err(ConcError::Unsupported("Cast")),
            Op::Extract { .. } => Err(ConcError::Unsupported("Extract")),
            Op::Insert { .. } => Err(ConcError::Unsupported("Insert")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(off: u64, size: u32) -> Varnode {
        Varnode::register(off, size)
    }
    fn konst(v: u64, size: u32) -> Varnode {
        Varnode::constant(v, size)
    }

    /// Field isolation: a 2-byte write at offset 3 is LE and touches
    /// NOTHING else in the slab (the I-LEGACY field-isolation matrix
    /// shape, applied to the register file).
    #[test]
    fn sub_slab_writes_are_le_and_touch_nothing_else() {
        let mut r = [0xAAu8; 8];
        let mut m = [0u8; 4];
        let mut st = SlabState::new(&mut r, &mut m, 0);
        st.step(&R2ILOp::Copy {
            dst: reg(3, 2),
            src: konst(0x1234, 2),
        })
        .unwrap();
        drop(st);
        assert_eq!(r, [0xAA, 0xAA, 0xAA, 0x34, 0x12, 0xAA, 0xAA, 0xAA]);
    }

    /// Const reads truncate to the varnode's size; Const writes are refused.
    #[test]
    fn const_space_is_read_only_and_width_masked() {
        let mut r = [0u8; 8];
        let mut m = [0u8; 1];
        let mut st = SlabState::new(&mut r, &mut m, 0);
        assert_eq!(st.read(&konst(0x1_FF, 1)).unwrap(), 0xFF);
        assert_eq!(st.write(&konst(0, 1), 1), Err(ConcError::ConstWrite));
    }

    /// u8 wrap + carry-out, both halves: 0xFF+1 wraps to 0 with carry 1;
    /// 1+1 carries 0. (r2sym anchor: carry == sum <u a.)
    #[test]
    fn carry_is_two_sided_at_operand_width() {
        let mut r = [0u8; 8];
        let mut m = [0u8; 1];
        let mut st = SlabState::new(&mut r, &mut m, 0);
        let (a, b, sum, c) = (reg(0, 1), reg(1, 1), reg(2, 1), reg(3, 1));
        for (x, y, want_sum, want_c) in [(0xFFu64, 1u64, 0u64, 1u64), (1, 1, 2, 0)] {
            st.write(&a, x).unwrap();
            st.write(&b, y).unwrap();
            st.step(&R2ILOp::IntAdd {
                dst: sum.clone(),
                a: a.clone(),
                b: b.clone(),
            })
            .unwrap();
            st.step(&R2ILOp::IntCarry {
                dst: c.clone(),
                a: a.clone(),
                b: b.clone(),
            })
            .unwrap();
            assert_eq!(st.read(&sum).unwrap(), want_sum);
            assert_eq!(st.read(&c).unwrap(), want_c);
        }
    }

    /// Signed overflow / borrow at u8 width, each two-sided.
    #[test]
    fn signed_carry_and_borrow_fire_and_stay_silent() {
        let mut r = [0u8; 8];
        let mut m = [0u8; 1];
        let mut st = SlabState::new(&mut r, &mut m, 0);
        let (a, b, f) = (reg(0, 1), reg(1, 1), reg(2, 1));
        let cases = [
            (
                R2ILOp::IntSCarry {
                    dst: f.clone(),
                    a: a.clone(),
                    b: b.clone(),
                },
                0x7Fu64,
                1u64,
                1u64,
            ),
            (
                R2ILOp::IntSCarry {
                    dst: f.clone(),
                    a: a.clone(),
                    b: b.clone(),
                },
                1,
                1,
                0,
            ),
            (
                R2ILOp::IntSBorrow {
                    dst: f.clone(),
                    a: a.clone(),
                    b: b.clone(),
                },
                0x80,
                1,
                1,
            ),
            (
                R2ILOp::IntSBorrow {
                    dst: f.clone(),
                    a: a.clone(),
                    b: b.clone(),
                },
                5,
                3,
                0,
            ),
        ];
        for (op, x, y, want) in cases {
            st.write(&a, x).unwrap();
            st.write(&b, y).unwrap();
            st.step(&op).unwrap();
            assert_eq!(st.read(&f).unwrap(), want, "x={x:#x} y={y:#x}");
        }
    }

    /// Shift-past-width: shl/lshr give 0, ashr sign-fills (the Z3
    /// bvshl/bvlshr/bvashr anchor).
    #[test]
    fn shifts_past_the_operand_width_match_the_symbolic_anchor() {
        let mut r = [0u8; 8];
        let mut m = [0u8; 1];
        let mut st = SlabState::new(&mut r, &mut m, 0);
        let (a, d) = (reg(0, 1), reg(2, 1));
        st.write(&a, 0x81).unwrap(); // negative at w=1
        let sh = konst(9, 1); // >= 8
        st.step(&R2ILOp::IntLeft {
            dst: d.clone(),
            a: a.clone(),
            b: sh.clone(),
        })
        .unwrap();
        assert_eq!(st.read(&d).unwrap(), 0);
        st.step(&R2ILOp::IntRight {
            dst: d.clone(),
            a: a.clone(),
            b: sh.clone(),
        })
        .unwrap();
        assert_eq!(st.read(&d).unwrap(), 0);
        st.step(&R2ILOp::IntSRight {
            dst: d.clone(),
            a: a.clone(),
            b: sh,
        })
        .unwrap();
        assert_eq!(st.read(&d).unwrap(), 0xFF, "arithmetic right sign-fills");
    }

    /// Signed division truncates toward zero; both division families
    /// refuse a zero divisor rather than panicking.
    #[test]
    fn signed_division_truncates_and_zero_divisors_are_refused() {
        let mut r = [0u8; 8];
        let mut m = [0u8; 1];
        let mut st = SlabState::new(&mut r, &mut m, 0);
        let d = reg(0, 1);
        st.step(&R2ILOp::IntSDiv {
            dst: d.clone(),
            a: konst(0xF9, 1),
            b: konst(2, 1),
        })
        .unwrap(); // -7 / 2
        assert_eq!(
            st.read(&d).unwrap() as u8 as i8,
            -3,
            "trunc toward zero, not floor"
        );
        for op in [
            R2ILOp::IntDiv {
                dst: d.clone(),
                a: konst(1, 1),
                b: konst(0, 1),
            },
            R2ILOp::IntSDiv {
                dst: d.clone(),
                a: konst(1, 1),
                b: konst(0, 1),
            },
            R2ILOp::IntRem {
                dst: d.clone(),
                a: konst(1, 1),
                b: konst(0, 1),
            },
            R2ILOp::IntSRem {
                dst: d.clone(),
                a: konst(1, 1),
                b: konst(0, 1),
            },
        ] {
            assert_eq!(st.step(&op), Err(ConcError::DivByZero));
        }
    }

    /// Piece then Subpiece round-trips; a byte offset past the source is a
    /// refusal (the concrete reading of r2sym's Unknown), never a zero.
    #[test]
    fn piece_subpiece_round_trip_and_out_of_range_refusal() {
        let mut r = [0u8; 8];
        let mut m = [0u8; 1];
        let mut st = SlabState::new(&mut r, &mut m, 0);
        let (hi, lo, w, back) = (reg(0, 1), reg(1, 1), reg(2, 2), reg(4, 1));
        st.write(&hi, 0xAB).unwrap();
        st.write(&lo, 0xCD).unwrap();
        st.step(&R2ILOp::Piece {
            dst: w.clone(),
            hi: hi.clone(),
            lo: lo.clone(),
        })
        .unwrap();
        assert_eq!(st.read(&w).unwrap(), 0xABCD);
        st.step(&R2ILOp::Subpiece {
            dst: back.clone(),
            src: w.clone(),
            offset: 1,
        })
        .unwrap();
        assert_eq!(st.read(&back).unwrap(), 0xAB);
        assert_eq!(
            st.step(&R2ILOp::Subpiece {
                dst: back,
                src: w,
                offset: 2
            }),
            Err(ConcError::SubpieceOutOfRange { offset: 2, size: 2 })
        );
    }

    /// Lzcount counts within the OPERAND width — u8 0x01 has 7 leading
    /// zeros, not 63 (a u64-naive implementation dies here).
    #[test]
    fn lzcount_is_width_relative() {
        let mut r = [0u8; 8];
        let mut m = [0u8; 1];
        let mut st = SlabState::new(&mut r, &mut m, 0);
        let d = reg(0, 1);
        st.step(&R2ILOp::Lzcount {
            dst: d.clone(),
            src: konst(0x01, 1),
        })
        .unwrap();
        assert_eq!(st.read(&d).unwrap(), 7);
    }

    /// Load/Store dereference: the ADDRESS varnode's value selects the ram
    /// cell; a Custom space works only when its slab is registered.
    #[test]
    fn load_store_deref_and_custom_spaces() {
        let mut r = [0u8; 8];
        let mut m = [0u8; 16];
        let mut zp = [0u8; 4]; // the 6502's own case-sensitive `RAM` alias
        let mut st = SlabState::new(&mut r, &mut m, 0).with_custom(1, &mut zp);
        let addr = reg(0, 1);
        st.write(&addr, 5).unwrap();
        st.step(&R2ILOp::Store {
            space: SpaceId::Ram,
            addr: addr.clone(),
            val: konst(0x7E, 1),
        })
        .unwrap();
        let d = reg(2, 1);
        st.step(&R2ILOp::Load {
            dst: d.clone(),
            space: SpaceId::Ram,
            addr: addr.clone(),
        })
        .unwrap();
        assert_eq!(st.read(&d).unwrap(), 0x7E);
        st.step(&R2ILOp::Store {
            space: SpaceId::Custom(1),
            addr: konst(2, 1),
            val: konst(9, 1),
        })
        .unwrap();
        assert_eq!(
            st.step(&R2ILOp::Load {
                dst: d,
                space: SpaceId::Custom(7),
                addr: konst(0, 1)
            }),
            Err(ConcError::UnknownSpace(7))
        );
        drop(st);
        assert_eq!(
            m[5], 0x7E,
            "the CALLER's ram saw the store — zero-copy, not a shadow"
        );
        assert_eq!(zp[2], 9);
    }

    /// Direct branch targets are the varnode's OFFSET (p-code semantics —
    /// no load), indirect targets are its VALUE; the anti-vacuity half
    /// plants a decoy value AT the offset so a loading implementation
    /// answers differently and fails.
    #[test]
    fn direct_targets_are_offsets_indirect_targets_are_values() {
        let mut r = [0u8; 8];
        let mut m = [0u8; 64];
        m[0x20] = 0x99; // decoy: a load-based Branch would jump to 0x99
        let mut st = SlabState::new(&mut r, &mut m, 0);
        let target = Varnode::new(SpaceId::Ram, 0x20, 1);
        assert_eq!(
            st.step(&R2ILOp::Branch {
                target: target.clone()
            }),
            Ok(Control::Jump(0x20))
        );
        assert_eq!(
            st.step(&R2ILOp::Call {
                target: target.clone()
            }),
            Ok(Control::Call(0x20))
        );
        assert_eq!(
            st.step(&R2ILOp::BranchInd {
                target: target.clone()
            }),
            Ok(Control::Jump(0x99))
        );
        assert_eq!(
            st.step(&R2ILOp::Return { target }),
            Ok(Control::Return(0x99))
        );
        // CBranch: nonzero taken, zero falls through.
        let cond = reg(0, 1);
        st.write(&cond, 1).unwrap();
        let t2 = Varnode::new(SpaceId::Ram, 0x30, 1);
        assert_eq!(
            st.step(&R2ILOp::CBranch {
                target: t2.clone(),
                cond: cond.clone()
            }),
            Ok(Control::Jump(0x30))
        );
        st.write(&cond, 0).unwrap();
        assert_eq!(
            st.step(&R2ILOp::CBranch { target: t2, cond }),
            Ok(Control::Next)
        );
    }

    /// Every refusal is loud: OOB names the slab, floats and analysis ops
    /// are Unsupported — never silently skipped.
    #[test]
    fn refusals_are_loud_never_silent() {
        let mut r = [0u8; 4];
        let mut m = [0u8; 4];
        let mut st = SlabState::new(&mut r, &mut m, 2);
        assert_eq!(
            st.read(&reg(3, 2)),
            Err(ConcError::OutOfBounds {
                space: SpaceId::Register,
                offset: 3,
                size: 2,
                len: 4
            })
        );
        assert_eq!(st.read(&reg(0, 9)), Err(ConcError::WidthTooWide(9)));
        assert_eq!(
            st.step(&R2ILOp::FloatAdd {
                dst: reg(0, 4),
                a: reg(0, 4),
                b: reg(0, 4)
            }),
            Err(ConcError::Unsupported("FloatAdd"))
        );
        assert_eq!(
            st.step(&R2ILOp::Breakpoint),
            Err(ConcError::Unsupported("Breakpoint"))
        );
    }

    /// End-to-end: a real loop (sum 1..=5) sequenced by the caller — the
    /// crate's contract is step-only, so the test IS the reference
    /// sequencer shape: addresses map to op indices, `Control` drives.
    #[test]
    fn a_caller_sequenced_loop_computes_the_hand_derived_sum() {
        let mut r = [0u8; 8];
        let mut m = [0u8; 1];
        let mut st = SlabState::new(&mut r, &mut m, 4);
        let (i, sum, cond) = (reg(0, 1), reg(1, 1), Varnode::new(SpaceId::Unique, 0, 1));
        let loop_head = Varnode::new(SpaceId::Ram, 0, 1); // address 0 == op index 0
        let prog = [
            R2ILOp::IntAdd {
                dst: sum.clone(),
                a: sum.clone(),
                b: i.clone(),
            },
            R2ILOp::IntAdd {
                dst: i.clone(),
                a: i.clone(),
                b: konst(1, 1),
            },
            R2ILOp::IntLessEqual {
                dst: cond.clone(),
                a: i.clone(),
                b: konst(5, 1),
            },
            R2ILOp::CBranch {
                target: loop_head,
                cond: cond.clone(),
            },
        ];
        st.write(&i, 1).unwrap();
        let mut pc = 0usize;
        let mut steps = 0;
        while pc < prog.len() {
            steps += 1;
            assert!(steps < 100, "runaway loop — CBranch semantics broken");
            match st.step(&prog[pc]).unwrap() {
                Control::Next => pc += 1,
                Control::Jump(a) => pc = a as usize,
                other => panic!("unexpected control: {other:?}"),
            }
        }
        assert_eq!(st.read(&sum).unwrap(), 15);
        assert_eq!(st.read(&i).unwrap(), 6);
        assert!(steps > prog.len(), "the loop must actually have looped");
    }
}
