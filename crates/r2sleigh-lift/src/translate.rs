//! Shared P-code translation abstraction.
//!
//! This module provides a trait-based abstraction for translating P-code operations
//! to r2il, reducing code duplication between the `disasm` and `pcode` modules.

use r2il::{R2ILOp, SpaceId, Varnode};

/// A source of P-code operands that can be translated to r2il.
///
/// This trait abstracts over different P-code representations:
/// - `libsla::PcodeInstruction` (from runtime disassembly)
/// - `RawPcodeOp` (from raw P-code bytes)
pub trait PcodeSource {
    /// Get the output varnode, if any.
    fn output(&self) -> Option<Varnode>;

    /// Get the input varnode at the given index, if any.
    fn input(&self, idx: usize) -> Option<Varnode>;

    /// Get a raw input value (for space IDs, constants) at the given index.
    fn input_raw_offset(&self, idx: usize) -> Option<u64>;

    /// Get the number of input operands.
    fn input_count(&self) -> usize;

    /// Get the space ID from a space index (for LOAD/STORE operations).
    fn space_from_index(&self, idx: u64) -> SpaceId;

    /// Width of an address in this architecture's default code space, if known.
    ///
    /// Defaulted to `None` so a source that cannot answer keeps today's
    /// behaviour exactly; see [`cf_target`] for why anything asks.
    fn addr_size(&self) -> Option<u32> {
        None
    }
}

/// Errors that can occur during translation.
#[derive(Debug, Clone)]
pub enum TranslateError {
    MissingOutput(&'static str),
    MissingInput(&'static str, usize),
    InvalidSpace(u64),
}

impl std::fmt::Display for TranslateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TranslateError::MissingOutput(op) => write!(f, "{} requires an output", op),
            TranslateError::MissingInput(op, idx) => {
                write!(f, "{} requires input at index {}", op, idx)
            }
            TranslateError::InvalidSpace(idx) => write!(f, "Invalid space index: {}", idx),
        }
    }
}

impl std::error::Error for TranslateError {}

/// Result type for translation operations.
pub type Result<T> = std::result::Result<T, TranslateError>;

/// Helper to require an output varnode.
pub fn require_output<S: PcodeSource>(source: &S, name: &'static str) -> Result<Varnode> {
    source.output().ok_or(TranslateError::MissingOutput(name))
}

/// Helper to require an input varnode at the given index.
pub fn require_input<S: PcodeSource>(
    source: &S,
    idx: usize,
    name: &'static str,
) -> Result<Varnode> {
    source
        .input(idx)
        .ok_or(TranslateError::MissingInput(name, idx))
}

/// Helper for unary operations (one input, one output).
pub fn translate_unary<S: PcodeSource, F>(source: &S, name: &'static str, f: F) -> Result<R2ILOp>
where
    F: FnOnce(Varnode, Varnode) -> R2ILOp,
{
    let dst = require_output(source, name)?;
    let src = require_input(source, 0, name)?;
    Ok(f(dst, src))
}

/// Helper for binary operations (two inputs, one output).
pub fn translate_binary<S: PcodeSource, F>(source: &S, name: &'static str, f: F) -> Result<R2ILOp>
where
    F: FnOnce(Varnode, Varnode, Varnode) -> R2ILOp,
{
    let dst = require_output(source, name)?;
    let a = require_input(source, 0, name)?;
    let b = require_input(source, 1, name)?;
    Ok(f(dst, a, b))
}

/// Common P-code opcodes for translation.
///
/// These numeric values match Ghidra's P-code opcode definitions.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonOp {
    Copy = 1,
    Load = 2,
    Store = 3,
    Branch = 4,
    CBranch = 5,
    BranchInd = 6,
    Call = 7,
    CallInd = 8,
    CallOther = 9,
    Return = 10,

    IntEqual = 11,
    IntNotEqual = 12,
    IntSLess = 13,
    IntSLessEqual = 14,
    IntLess = 15,
    IntLessEqual = 16,
    IntZExt = 17,
    IntSExt = 18,
    IntAdd = 19,
    IntSub = 20,
    IntCarry = 21,
    IntSCarry = 22,
    IntSBorrow = 23,
    Int2Comp = 24,  // Two's complement (unary minus)
    IntNegate = 25, // Bitwise NOT (confusing Ghidra naming)
    IntXor = 26,
    IntAnd = 27,
    IntOr = 28,
    IntLeft = 29,
    IntRight = 30,
    IntSRight = 31,
    IntMult = 32,
    IntDiv = 33,
    IntSDiv = 34,
    IntRem = 35,
    IntSRem = 36,

    BoolNot = 37,
    BoolXor = 38,
    BoolAnd = 39,
    BoolOr = 40,

    FloatEqual = 41,
    FloatNotEqual = 42,
    FloatLess = 43,
    FloatLessEqual = 44,
    FloatNaN = 46,
    FloatAdd = 47,
    FloatDiv = 48,
    FloatMult = 49,
    FloatSub = 50,
    FloatNeg = 51,
    FloatAbs = 52,
    FloatSqrt = 53,
    Int2Float = 54,
    Float2Int = 55,
    FloatFloat = 56,
    Trunc = 57,
    FloatCeil = 58,
    FloatFloor = 59,
    FloatRound = 60,

    Multiequal = 61,
    Indirect = 62,
    Piece = 63,
    Subpiece = 64,

    Cast = 65,
    PtrAdd = 66,
    PtrSub = 67,
    SegmentOp = 68,
    CpuId = 69,
    New = 70,

    Insert = 71,
    Extract = 72,
    PopCount = 73,
    Lzcount = 74,
}

/// Translate a LOAD operation.
pub fn translate_load<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let dst = require_output(source, "LOAD")?;
    let space_idx = source
        .input_raw_offset(0)
        .ok_or(TranslateError::MissingInput("LOAD", 0))?;
    let addr = require_input(source, 1, "LOAD")?;
    let space = source.space_from_index(space_idx);
    Ok(R2ILOp::Load { dst, space, addr })
}

/// Translate a STORE operation.
pub fn translate_store<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let space_idx = source
        .input_raw_offset(0)
        .ok_or(TranslateError::MissingInput("STORE", 0))?;
    let addr = require_input(source, 1, "STORE")?;
    let val = require_input(source, 2, "STORE")?;
    let space = source.space_from_index(space_idx);
    Ok(R2ILOp::Store { space, addr, val })
}

/// Translate a CBRANCH operation.
///
/// P-code spec: CBRANCH(dest, cond) - destination first, condition second.
pub fn translate_cbranch<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let target = cf_target(source, 0, "CBRANCH")?;
    let cond = require_input(source, 1, "CBRANCH")?;
    Ok(R2ILOp::CBranch { target, cond })
}

/// Require a CONTROL-FLOW target operand, normalised to the address width.
///
/// # Why this exists, and why it is not `require_input`
///
/// A branch target varnode in an address space carries its destination in the
/// OFFSET. Its `size` is whatever the SLEIGH operand constructor happened to
/// export, and for a constructor that doubles as a data operand that is the
/// DATA width, not the address width.
///
/// The 6502 is the clear case (`6502.slaspec:120`):
///
/// ```text
/// ADDR16: imm16  is imm16  { export *:1 imm16; }
/// ```
///
/// `ADDR16` serves both `LDA ADDR16` — where `*:1` is right, one byte of an
/// 8-bit machine's RAM — and `goto ADDR16`, where SLEIGH branches to the
/// varnode's ADDRESS and the size is residue. So the target arrives 1 byte
/// wide in a 2-byte address space, and `r2il`'s
/// `op.controlflow.target_width_mismatch` rejects it.
///
/// **No information is discarded by normalising.** The address lives in the
/// offset, which is untouched; the size on a control-flow target was never
/// meaningful for the branch. Correcting it here lets r2il keep a genuinely
/// useful invariant — *a branch target's size IS the address width* — instead
/// of relaxing the rule and leaving every consumer to wonder.
///
/// Const-space targets are left alone: those are relative displacements, and
/// r2il's validator deliberately exempts them.
pub fn cf_target<S: PcodeSource>(source: &S, idx: usize, name: &'static str) -> Result<Varnode> {
    let target = require_input(source, idx, name)?;
    match (target.space, source.addr_size()) {
        (SpaceId::Const, _) | (_, None) => Ok(target),
        (_, Some(width)) => Ok(Varnode::new(target.space, target.offset, width)),
    }
}

/// Translate a SUBPIECE operation.
pub fn translate_subpiece<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let dst = require_output(source, "SUBPIECE")?;
    let src = require_input(source, 0, "SUBPIECE")?;
    let offset = source
        .input_raw_offset(1)
        .ok_or(TranslateError::MissingInput("SUBPIECE", 1))? as u32;
    Ok(R2ILOp::Subpiece { dst, src, offset })
}

/// Translate a PTRADD operation.
pub fn translate_ptradd<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let dst = require_output(source, "PTRADD")?;
    let base = require_input(source, 0, "PTRADD")?;
    let index = require_input(source, 1, "PTRADD")?;
    let element_size = source
        .input_raw_offset(2)
        .ok_or(TranslateError::MissingInput("PTRADD", 2))? as u32;
    Ok(R2ILOp::PtrAdd {
        dst,
        base,
        index,
        element_size,
    })
}

/// Translate a PTRSUB operation.
pub fn translate_ptrsub<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let dst = require_output(source, "PTRSUB")?;
    let base = require_input(source, 0, "PTRSUB")?;
    let index = require_input(source, 1, "PTRSUB")?;
    let element_size = source
        .input_raw_offset(2)
        .ok_or(TranslateError::MissingInput("PTRSUB", 2))? as u32;
    Ok(R2ILOp::PtrSub {
        dst,
        base,
        index,
        element_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock implementation for testing
    struct MockPcodeSource {
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
    }

    impl PcodeSource for MockPcodeSource {
        fn output(&self) -> Option<Varnode> {
            self.output.clone()
        }

        fn input(&self, idx: usize) -> Option<Varnode> {
            self.inputs.get(idx).cloned()
        }

        fn input_raw_offset(&self, idx: usize) -> Option<u64> {
            self.inputs.get(idx).map(|v| v.offset)
        }

        fn input_count(&self) -> usize {
            self.inputs.len()
        }

        fn space_from_index(&self, idx: u64) -> SpaceId {
            match idx {
                0 => SpaceId::Ram,
                1 => SpaceId::Register,
                2 => SpaceId::Unique,
                _ => SpaceId::Unresolved,
            }
        }
    }

    #[test]
    fn test_translate_unary() {
        let source = MockPcodeSource {
            output: Some(Varnode::register(0, 8)),
            inputs: vec![Varnode::constant(42, 8)],
        };

        let result = translate_unary(&source, "TEST", |dst, src| R2ILOp::Copy { dst, src });
        assert!(result.is_ok());
    }

    #[test]
    fn test_translate_binary() {
        let source = MockPcodeSource {
            output: Some(Varnode::register(0, 8)),
            inputs: vec![Varnode::register(8, 8), Varnode::constant(1, 8)],
        };

        let result = translate_binary(&source, "TEST", |dst, a, b| R2ILOp::IntAdd { dst, a, b });
        assert!(result.is_ok());
    }

    #[test]
    fn test_cbranch_order() {
        let target = Varnode::constant(0x1000, 8);
        let cond = Varnode::register(0, 1);

        let source = MockPcodeSource {
            output: None,
            inputs: vec![target.clone(), cond.clone()],
        };

        let result = translate_cbranch(&source).unwrap();
        match result {
            R2ILOp::CBranch { target: t, cond: c } => {
                assert_eq!(t.offset, 0x1000);
                assert!(c.is_register());
            }
            _ => panic!("Expected CBranch"),
        }
    }

    #[test]
    fn test_translate_ptradd() {
        // PTRADD(base, index, element_size)
        // r2il: base + (index * element_size)
        let base = Varnode::register(0, 8);
        let index = Varnode::register(8, 8);
        let element_size = Varnode::constant(4, 8); // 4-byte elements

        let source = MockPcodeSource {
            output: Some(Varnode::register(16, 8)),
            inputs: vec![base, index, element_size],
        };

        let result = translate_ptradd(&source).unwrap();
        match result {
            R2ILOp::PtrAdd {
                dst,
                base: b,
                index: i,
                element_size: sz,
            } => {
                assert_eq!(dst.offset, 16);
                assert_eq!(b.offset, 0);
                assert_eq!(i.offset, 8);
                assert_eq!(sz, 4);
            }
            _ => panic!("Expected PtrAdd"),
        }
    }
}

#[cfg(test)]
mod cf_target_tests {
    use super::*;

    /// A source that answers a fixed address width, so the rule is testable
    /// without a loaded SLEIGH spec.
    struct Src {
        target: Varnode,
        addr_size: Option<u32>,
    }

    impl PcodeSource for Src {
        fn output(&self) -> Option<Varnode> {
            None
        }
        fn input(&self, idx: usize) -> Option<Varnode> {
            (idx == 0).then(|| self.target.clone())
        }
        fn input_raw_offset(&self, _idx: usize) -> Option<u64> {
            None
        }
        fn input_count(&self) -> usize {
            1
        }
        fn space_from_index(&self, _idx: u64) -> SpaceId {
            SpaceId::Ram
        }
        fn addr_size(&self) -> Option<u32> {
            self.addr_size
        }
    }

    /// The 6502 case, exactly: `ADDR16` exports `*:1`, so a branch target
    /// arrives 1 byte wide in a 2-byte address space.
    #[test]
    fn a_ram_target_is_widened_to_the_address_size() {
        let src = Src {
            target: Varnode::new(SpaceId::Ram, 0x433, 1),
            addr_size: Some(2),
        };
        let t = cf_target(&src, 0, "BRANCH").unwrap();
        assert_eq!(t.size, 2, "the target must carry the ADDRESS width");
        assert_eq!(t.offset, 0x433, "the address itself must be untouched");
        assert_eq!(t.space, SpaceId::Ram);
    }

    /// The half that stops this from being a blunt overwrite: a const-space
    /// target is a relative displacement, not an address, and r2il's validator
    /// deliberately exempts it. Widening one would corrupt a p-code-relative
    /// branch.
    #[test]
    fn a_const_target_is_left_alone() {
        let src = Src {
            target: Varnode::new(SpaceId::Const, 3, 1),
            addr_size: Some(8),
        };
        let t = cf_target(&src, 0, "CBRANCH").unwrap();
        assert_eq!(t.size, 1, "const displacements must not be widened");
        assert_eq!(t.offset, 3);
    }

    /// A source that cannot answer keeps today's behaviour exactly — the
    /// defaulted trait method must not silently change any existing lift.
    #[test]
    fn an_unknown_address_size_changes_nothing() {
        let src = Src {
            target: Varnode::new(SpaceId::Ram, 0x1000, 1),
            addr_size: None,
        };
        let t = cf_target(&src, 0, "BRANCH").unwrap();
        assert_eq!(t.size, 1);
    }

    /// Already-correct targets pass through unchanged — the rule normalises,
    /// it does not merely "set to 8".
    #[test]
    fn a_correctly_sized_target_is_unchanged() {
        let src = Src {
            target: Varnode::new(SpaceId::Ram, 0x400000, 8),
            addr_size: Some(8),
        };
        let t = cf_target(&src, 0, "CALL").unwrap();
        assert_eq!(t.size, 8);
        assert_eq!(t.offset, 0x400000);
    }
}
