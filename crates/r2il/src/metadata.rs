//! Optional metadata hints for r2il values and operations.
//!
//! These hints are advisory and do not change core r2il semantics.

use serde::{Deserialize, Serialize};

use crate::{AtomicKind, Endianness, MemoryOrdering, MemoryPermissions, MemoryRange};

/// Storage classification hint for a varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    Stack,
    Heap,
    Global,
    ThreadLocal,
    ConstData,
    Volatile,
    Register,
    #[default]
    Unknown,
}

/// Scalar interpretation hint for a varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScalarKind {
    Bool,
    SignedInt,
    UnsignedInt,
    Float,
    Bitvector,
    #[default]
    Unknown,
}

/// Pointer interpretation hint for a varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PointerHint {
    PointerLike,
    CodePointer,
    #[default]
    Unknown,
}

/// Floating-point encoding hint for a varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FloatEncodingHint {
    Ieee754Binary16,
    Ieee754Binary32,
    Ieee754Binary64,
    Ieee754Binary80,
    Ieee754Binary128,
    #[default]
    Unknown,
}

/// Memory classification hint for operations that touch memory-like domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MemoryClass {
    Ram,
    Stack,
    Heap,
    Global,
    ThreadLocal,
    Mmio,
    IoPort,
    Code,
    #[default]
    Unknown,
}

/// Optional metadata hints attached to an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OpMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_class: Option<MemoryClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_ordering: Option<MemoryOrdering>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<MemoryPermissions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_range: Option<MemoryRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bank_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atomic_kind: Option<AtomicKind>,
}

/// The instruction each operation of a block was lifted from, one run per instruction, ascending;
/// an operation in no run was stamped by none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct InstructionRuns(Vec<InstructionRun>);

/// Operations `first .. first + len` were lifted from the instruction at `addr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionRun {
    pub first: u32,
    pub len: u32,
    pub addr: u64,
}

impl InstructionRun {
    const fn end(self) -> u32 {
        self.first + self.len
    }
}

impl InstructionRuns {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &InstructionRun> {
        self.0.iter()
    }

    /// The instruction operation `op` was lifted from.
    pub fn of(&self, op: usize) -> Option<u64> {
        let op = u32::try_from(op).ok()?;
        let after = self.0.partition_point(|run| run.first <= op);
        let run = self.0.get(after.checked_sub(1)?)?;
        (op < run.end()).then_some(run.addr)
    }

    /// `count` operations from `first` came from `addr`; appends in order, as a join lifts.
    pub fn push(&mut self, first: usize, count: usize, addr: u64) {
        for op in first..first + count {
            self.stamp(op, addr);
        }
    }

    /// Operation `op` came from `addr`: `O(1)` at or past the last run's end, `O(runs)` inside.
    pub fn stamp(&mut self, op: usize, addr: u64) {
        let op = u32::try_from(op).expect("fewer than 2^32 operations in a block");
        if let Some(last) = self.0.last_mut()
            && last.addr == addr
            && last.end() == op
        {
            last.len += 1;
            return;
        }
        if self.0.last().is_none_or(|last| op >= last.end()) {
            self.0.push(InstructionRun {
                first: op,
                len: 1,
                addr,
            });
            return;
        }
        if self.of(op as usize) == Some(addr) {
            return;
        }
        // Cut `op` out of whatever run holds it, give it a run of its own, and join neighbours.
        let mut runs = Vec::with_capacity(self.0.len() + 2);
        for run in std::mem::take(&mut self.0) {
            if op < run.first || op >= run.end() {
                runs.push(run);
                continue;
            }
            let before = op - run.first;
            if before > 0 {
                runs.push(InstructionRun { len: before, ..run });
            }
            if op + 1 < run.end() {
                runs.push(InstructionRun {
                    first: op + 1,
                    len: run.end() - op - 1,
                    addr: run.addr,
                });
            }
        }
        runs.push(InstructionRun {
            first: op,
            len: 1,
            addr,
        });
        runs.sort_by_key(|run| run.first);
        for run in runs {
            match self.0.last_mut() {
                Some(last) if last.addr == run.addr && last.end() == run.first => {
                    last.len += run.len;
                }
                _ => self.0.push(run),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InstructionRuns, OpMetadata};

    #[test]
    fn a_stamp_out_of_order_splits_and_rejoins_runs() {
        let mut runs = InstructionRuns::default();
        runs.push(0, 3, 0x10);
        runs.push(3, 2, 0x14);
        assert_eq!(
            (runs.of(2), runs.of(3), runs.of(5)),
            (Some(0x10), Some(0x14), None)
        );
        runs.stamp(1, 0x20);
        assert_eq!(
            (runs.of(0), runs.of(1), runs.of(2)),
            (Some(0x10), Some(0x20), Some(0x10))
        );
        runs.stamp(1, 0x10);
        assert_eq!(runs.iter().count(), 2);
        runs.stamp(7, 0x30);
        assert_eq!((runs.of(6), runs.of(7)), (None, Some(0x30)));
    }

    #[test]
    fn op_metadata_endianness_serde_omits_when_none() {
        let meta = OpMetadata::default();
        let json = serde_json::to_string(&meta).expect("serialize");
        assert!(!json.contains("endianness"));
    }
}
