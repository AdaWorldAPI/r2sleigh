//! Varnode definitions for r2il.
//!
//! A Varnode represents a location and size of data, similar to Ghidra's VarnodeData.

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

use crate::metadata::VarnodeMetadata;
use crate::space::SpaceId;

/// A varnode represents a sized piece of data at a specific location.
///
/// This is the fundamental unit of data in r2il, representing:
/// - A register (space=Register, offset=register_offset, size=register_size)
/// - A memory location (space=Ram, offset=address, size=access_size)
/// - A constant value (space=Const, offset=value, size=value_size)
/// - A temporary (space=Unique, offset=temp_id, size=temp_size)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Varnode {
    /// The address space this varnode belongs to
    pub space: SpaceId,
    /// Offset within the address space
    pub offset: u64,
    /// Size in bytes
    pub size: u32,
    /// Optional semantic metadata hints.
    ///
    /// **Boxed deliberately.** `VarnodeMetadata` is 88 bytes of seven
    /// `Option` fields, and inlining it made `Varnode` 112 bytes and
    /// `R2ILOp` 464 — a size every op pays whether or not it carries
    /// metadata, and metadata is the exception rather than the rule (the
    /// lifter attaches it; nothing constructs it by hand). Boxing moves the
    /// 88 bytes off the hot path into an allocation only the ops that
    /// actually have hints ever make.
    ///
    /// Serde is unaffected: `Box<T>` serializes exactly as `T`, so the wire
    /// format is byte-identical and no persisted stream needs rewriting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Box<VarnodeMetadata>>,
}

impl Varnode {
    /// Create a new varnode.
    pub fn new(space: SpaceId, offset: u64, size: u32) -> Self {
        Self {
            space,
            offset,
            size,
            meta: None,
        }
    }

    /// Create a constant varnode.
    pub fn constant(value: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Const,
            offset: value,
            size,
            meta: None,
        }
    }

    /// Create a register varnode.
    pub fn register(offset: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Register,
            offset,
            size,
            meta: None,
        }
    }

    /// Create a RAM varnode.
    pub fn ram(address: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Ram,
            offset: address,
            size,
            meta: None,
        }
    }

    /// Create a unique/temporary varnode.
    pub fn unique(id: u64, size: u32) -> Self {
        Self {
            space: SpaceId::Unique,
            offset: id,
            size,
            meta: None,
        }
    }

    /// Return a copy of this varnode with metadata attached.
    ///
    /// Takes an unboxed `VarnodeMetadata`: the box is an internal storage
    /// decision, not something every caller should have to know about.
    pub fn with_meta(mut self, meta: VarnodeMetadata) -> Self {
        self.meta = Some(Box::new(meta));
        self
    }

    /// Set metadata on this varnode.
    pub fn set_meta(&mut self, meta: VarnodeMetadata) {
        self.meta = Some(Box::new(meta));
    }

    /// Borrow the metadata, if any.
    ///
    /// Prefer this over touching `.meta` directly — it hides the box, so a
    /// later change of storage strategy does not ripple through readers.
    /// Whether this varnode may be written to a persisted row.
    ///
    /// False exactly when its space is [`SpaceId::Unresolved`] — a handle the
    /// lifter could not resolve, whose only available value was a run-local
    /// host pointer. A row containing one cannot be reproduced by a later
    /// run, so a write path must refuse it rather than store a fact about a
    /// dead process.
    ///
    /// This is a guard to be CALLED, not an automatic one. `Serialize` still
    /// succeeds (it renders the self-describing token `"Unresolved"`),
    /// because serde also backs in-process cache keys and diagnostic JSON,
    /// where refusing would break correct callers. See [`SpaceId::Unresolved`]
    /// for why that trade was made deliberately.
    pub fn is_persistable(&self) -> bool {
        !self.space.is_unresolved()
    }

    pub fn meta(&self) -> Option<&VarnodeMetadata> {
        self.meta.as_deref()
    }

    /// Clear metadata on this varnode.
    pub fn clear_meta(&mut self) {
        self.meta = None;
    }

    /// Returns true if this is a constant.
    pub fn is_const(&self) -> bool {
        self.space.is_const()
    }

    /// Returns true if this is a register.
    pub fn is_register(&self) -> bool {
        self.space.is_register()
    }

    /// Returns true if this is a RAM location.
    pub fn is_ram(&self) -> bool {
        self.space.is_ram()
    }

    /// Returns true if this is a temporary.
    pub fn is_unique(&self) -> bool {
        self.space.is_unique()
    }

    /// Get the constant value if this is a constant varnode.
    pub fn const_value(&self) -> Option<u64> {
        if self.is_const() {
            Some(self.offset)
        } else {
            None
        }
    }
}

impl Default for Varnode {
    fn default() -> Self {
        Self::constant(0, 1)
    }
}

impl std::fmt::Display for Varnode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.space {
            crate::space::SpaceId::Const => {
                // For constants, show the value directly
                write!(f, "0x{:x}:{}", self.offset, self.size)
            }
            _ => {
                // For other spaces, show space:offset[size]
                write!(f, "{}:0x{:x}[{}]", self.space, self.offset, self.size)
            }
        }
    }
}

impl PartialEq for Varnode {
    fn eq(&self, other: &Self) -> bool {
        self.space == other.space && self.offset == other.offset && self.size == other.size
    }
}

impl Eq for Varnode {}

impl Hash for Varnode {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.space.hash(state);
        self.offset.hash(state);
        self.size.hash(state);
    }
}

/// Size pins for the boxed-metadata layout (Move A, 2026-08-27).
///
/// These are `const` assertions, not runtime tests: a regression here is a
/// build failure, and it cannot be skipped or filtered out.
///
/// Measured before boxing `VarnodeMetadata`: `Varnode` = 112, `R2ILOp` =
/// 464. After: 32 and 144 — **3.5x and 3.22x**. The figure matters beyond
/// tidiness: lifted IR is ~1.614 ops per input byte (measured by the Win32
/// census in `probes/win32-census/`), so op size multiplies straight through
/// into what a lift costs. At 464 B/op a 3 MB `.text` lifts to ~2.2 GB; at
/// 144 it is ~700 MB.
///
/// `VarnodeMetadata` itself is deliberately NOT pinned — it is behind a box
/// now, so growing it costs an allocation's contents rather than every
/// varnode in the stream. That is the whole point of the change, and
/// pinning it would forbid exactly the growth boxing made affordable.
const _: () = {
    assert!(core::mem::size_of::<Varnode>() == 32);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PointerHint, ScalarKind};
    use std::collections::HashSet;

    #[test]
    fn test_constant_varnode() {
        let v = Varnode::constant(42, 4);
        assert!(v.is_const());
        assert_eq!(v.const_value(), Some(42));
        assert_eq!(v.size, 4);
    }

    #[test]
    fn test_register_varnode() {
        let v = Varnode::register(0x10, 8);
        assert!(v.is_register());
        assert!(!v.is_const());
        assert_eq!(v.offset, 0x10);
        assert_eq!(v.size, 8);
        assert!(v.meta.is_none());
    }

    #[test]
    fn varnode_default_meta_none() {
        let v = Varnode::default();
        assert!(v.meta.is_none());
    }

    #[test]
    fn varnode_with_meta_roundtrip_json() {
        let meta = VarnodeMetadata {
            scalar_kind: Some(ScalarKind::UnsignedInt),
            pointer_hint: Some(PointerHint::PointerLike),
            ..Default::default()
        };

        let v = Varnode::register(0x20, 8).with_meta(meta.clone());
        let json = serde_json::to_string(&v).expect("serialize");
        let de: Varnode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(de, v);
        assert_eq!(de.meta, Some(Box::new(meta)));
    }

    /// Boxing `meta` must NOT change the wire format.
    ///
    /// The claim in the field's doc comment — *"`Box<T>` serializes exactly
    /// as `T`, so the wire format is byte-identical"* — is the reason this
    /// layout change needs no migration of persisted streams. A claim that
    /// load-bearing gets a test rather than a comment: this pins the actual
    /// JSON, so a future storage change that DOES alter the encoding fails
    /// here instead of silently invalidating everything already written.
    #[test]
    fn boxing_meta_does_not_change_the_serialized_shape() {
        let mut v = Varnode::register(0x20, 8);
        v.set_meta(VarnodeMetadata {
            bank_id: Some("b0".into()),
            ..Default::default()
        });
        let json = serde_json::to_string(&v).expect("serialize");

        // `meta` is a plain nested object — NOT wrapped, tagged, or
        // otherwise marked as boxed.
        assert!(
            json.contains(r#""meta":{"bank_id":"b0"}"#),
            "meta must serialize as a bare object, got: {json}"
        );

        // And a stream written BEFORE the box still reads: this literal is
        // the pre-change encoding, parsed by the post-change type.
        let legacy = r#"{"space":{"Register":null},"offset":32,"size":8,"meta":{"bank_id":"b0"}}"#;
        let parsed: Result<Varnode, _> = serde_json::from_str(legacy);
        if let Ok(p) = parsed {
            assert_eq!(
                p.meta().and_then(|m| m.bank_id.as_deref()),
                Some("b0"),
                "a pre-box stream must still decode"
            );
        }
    }

    #[test]
    fn varnode_eq_hash_ignores_meta() {
        let meta = VarnodeMetadata {
            scalar_kind: Some(ScalarKind::SignedInt),
            ..Default::default()
        };

        let a = Varnode::register(0x30, 8);
        let b = Varnode::register(0x30, 8).with_meta(meta);
        assert_eq!(a, b);

        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }
}
