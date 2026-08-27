//! Address space definitions for r2il.
//!
//! Address spaces define where data lives: RAM, registers, temporaries, or constants.

use serde::{Deserialize, Serialize};

use crate::{Endianness, MemoryClass, MemoryPermissions, MemoryRange};

/// Identifier for an address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum SpaceId {
    /// Main memory (RAM)
    #[default]
    Ram,
    /// Processor registers
    Register,
    /// Temporary/unique storage for intermediate values
    Unique,
    /// Constant/immediate values
    Const,
    /// Architecture-specific custom space, identified by a **stable,
    /// name-derived** id.
    ///
    /// **Invariant (load-bearing, see [`SpaceId::Unresolved`]):** the `u32`
    /// is a pure function of the space's NAME. It is never an array index,
    /// never a host pointer, and never anything else that varies between
    /// processes. Two runs over the same binary must produce byte-identical
    /// `Custom` ids, because this value is serialized into persisted rows.
    Custom(u32),
    /// A space handle the lifter could **not** resolve to a known space.
    ///
    /// Deliberately payload-free. The situation that produces it is a
    /// LOAD/STORE whose input-0 constant is a raw host `AddrSpace*` pointer
    /// rather than a space index (Ghidra p-code encodes the space that way),
    /// so the only value available to carry here is run-local: it differs on
    /// every process and is meaningless after the process exits.
    ///
    /// Carrying that value was the defect. Three separate runs over the same
    /// x86-64 binary produced `Custom(1062180976)`, `Custom(2279590000)` and
    /// `Custom(1968052336)` for the same instruction — an unreproducible lift
    /// and, worse, an unreproducible *persisted row*.
    ///
    /// So the handle is dropped rather than bottled. Consequences, all of
    /// them intentional:
    ///
    /// * **Reproducible.** Two runs lift to the same IR, because nothing
    ///   process-specific reaches it.
    /// * **Not a scan key.** Every unresolved space compares equal. That is
    ///   an over-match, never an under-match — we genuinely do not know
    ///   whether two unresolved handles name the same space, and claiming
    ///   they differ on the strength of a pointer is the stronger lie.
    /// * **Visibly unpersistable.** It serializes as the self-describing
    ///   token `"Unresolved"` — never as a number that reads like a real
    ///   space id. Any row carrying it announces that it cannot be
    ///   reproduced, and [`Varnode::is_persistable`] is the guard a write
    ///   path calls to refuse it.
    ///
    ///   This is deliberately weaker than making `Serialize` fail. That was
    ///   tried first and was wrong: serde here also backs in-process cache
    ///   keys and the r2 plugin's diagnostic JSON, and a blanket refusal
    ///   broke 24 plugin tests on ordinary x86 input. Which incidentally
    ///   measured how common this path is — those fixtures had been hashing
    ///   ASLR'd pointers into cache keys all along. The guarantee is
    ///   therefore "cannot be written *unnoticed*", not "cannot be written";
    ///   the refusal lives at the write path, where persistence actually
    ///   happens.
    /// * **Fails closed at execution.** `r2conc` returns an error rather than
    ///   guessing a slab.
    ///
    /// Resolving these properly — mapping the pointer back through libsla to
    /// a named space — is the follow-up. Until then the lift is honest about
    /// not knowing, instead of confidently wrong.
    Unresolved,
}

impl SpaceId {
    /// Returns true if this is the constant space.
    pub fn is_const(&self) -> bool {
        matches!(self, SpaceId::Const)
    }

    /// Returns true if this is a memory space (RAM).
    pub fn is_ram(&self) -> bool {
        matches!(self, SpaceId::Ram)
    }

    /// Returns true if this is the register space.
    pub fn is_register(&self) -> bool {
        matches!(self, SpaceId::Register)
    }

    /// Returns true if this is the unique/temporary space.
    pub fn is_unique(&self) -> bool {
        matches!(self, SpaceId::Unique)
    }
}

impl SpaceId {
    /// True for a space handle the lifter could not resolve.
    ///
    /// Callers that key a scan, a cache, or a slab lookup on `SpaceId` must
    /// check this first: an unresolved handle is not a space, it is the
    /// absence of one.
    pub fn is_unresolved(&self) -> bool {
        matches!(self, SpaceId::Unresolved)
    }
}

impl std::fmt::Display for SpaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpaceId::Ram => write!(f, "ram"),
            SpaceId::Register => write!(f, "reg"),
            SpaceId::Unique => write!(f, "uniq"),
            SpaceId::Const => write!(f, "const"),
            SpaceId::Custom(id) => write!(f, "space{}", id),
            SpaceId::Unresolved => write!(f, "unresolved"),
        }
    }
}

/// Full address space definition with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSpace {
    /// Space identifier
    pub id: SpaceId,
    /// Human-readable name
    pub name: String,
    /// Size of addresses in this space (in bytes)
    pub addr_size: u32,
    /// Word size for this space (usually 1 for byte-addressable)
    pub word_size: u32,
    /// Whether this is the default code space
    pub is_default: bool,
    /// Optional endianness override for this space.
    #[serde(default)]
    pub endianness: Option<Endianness>,
    /// Optional memory classification for this space.
    #[serde(default)]
    pub memory_class: Option<MemoryClass>,
    /// Optional permissions applicable to this space.
    #[serde(default)]
    pub permissions: Option<MemoryPermissions>,
    /// Optional set of valid address ranges in this space.
    #[serde(default)]
    pub valid_ranges: Vec<MemoryRange>,
    /// Optional memory bank identifier.
    #[serde(default)]
    pub bank_id: Option<String>,
    /// Optional segment identifier.
    #[serde(default)]
    pub segment_id: Option<String>,
    /// The space this one *aliases*, if any — same underlying memory reached
    /// through a second identity.
    ///
    /// Reserve, don't claim: an architecture space that is really a window
    /// onto RAM keeps its own [`SpaceId`] (so the lift stays faithful to what
    /// the SLEIGH spec said) while declaring that reads and writes land in
    /// RAM's bytes. A consumer scanning for RAM can follow the alias; nothing
    /// merges the two ids, and no lift is rewritten.
    ///
    /// `None` means "not known to alias anything", never "known not to".
    #[serde(default)]
    pub aliases: Option<SpaceId>,
}

impl AddressSpace {
    /// Create a new address space.
    pub fn new(id: SpaceId, name: impl Into<String>, addr_size: u32) -> Self {
        Self {
            id,
            name: name.into(),
            addr_size,
            word_size: 1,
            is_default: false,
            endianness: None,
            memory_class: None,
            permissions: None,
            valid_ranges: Vec::new(),
            bank_id: None,
            segment_id: None,
            aliases: None,
        }
    }

    /// Create the standard RAM space.
    pub fn ram(addr_size: u32) -> Self {
        Self {
            id: SpaceId::Ram,
            name: "ram".into(),
            addr_size,
            word_size: 1,
            is_default: true,
            endianness: None,
            memory_class: None,
            permissions: None,
            valid_ranges: Vec::new(),
            bank_id: None,
            segment_id: None,
            aliases: None,
        }
    }

    /// Create the standard register space.
    pub fn register() -> Self {
        Self {
            id: SpaceId::Register,
            name: "register".into(),
            addr_size: 4,
            word_size: 1,
            is_default: false,
            endianness: None,
            memory_class: None,
            permissions: None,
            valid_ranges: Vec::new(),
            bank_id: None,
            segment_id: None,
            aliases: None,
        }
    }

    /// Create the standard unique/temporary space.
    pub fn unique() -> Self {
        Self {
            id: SpaceId::Unique,
            name: "unique".into(),
            addr_size: 4,
            word_size: 1,
            is_default: false,
            endianness: None,
            memory_class: None,
            permissions: None,
            valid_ranges: Vec::new(),
            bank_id: None,
            segment_id: None,
            aliases: None,
        }
    }

    /// Create the constant space.
    pub fn constant() -> Self {
        Self {
            id: SpaceId::Const,
            name: "const".into(),
            addr_size: 8,
            word_size: 1,
            is_default: false,
            endianness: None,
            memory_class: None,
            permissions: None,
            valid_ranges: Vec::new(),
            bank_id: None,
            segment_id: None,
            aliases: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressSpace, SpaceId};
    use crate::Endianness;

    // ---- Ram/Custom aliasing + persisted-row safety -------------------
    //
    // Both rows of `probes/win32-census/EXECUTION-NOTES.md`'s open table.
    // Each test below was verified to FAIL with the fix reverted; the
    // disable is named in the test's own comment.

    /// Persisted-row safety, restated for the token contract: an
    /// unresolvable space must be VISIBLE in any row it reaches, never
    /// disguised as a plausible space id.
    ///
    /// DISABLE: give `Unresolved` a `u32` payload carrying the raw pointer
    /// and the first assert fails — the row goes back to looking like a
    /// real space.
    #[test]
    fn an_unresolved_space_persists_as_a_self_describing_token() {
        // It says what it is. A reader can detect and reject it.
        assert_eq!(
            serde_json::to_string(&SpaceId::Unresolved).unwrap(),
            "\"Unresolved\""
        );

        // Anti-vacuity: it is distinguishable from every real space, and in
        // particular does not render as a number the way the old
        // `Custom(<pointer>)` did.
        let token = serde_json::to_string(&SpaceId::Unresolved).unwrap();
        assert!(!token.contains("Custom"));
        assert!(!token.chars().any(|c| c.is_ascii_digit()));

        // The other five keep their exact wire format, so existing rows
        // round-trip untouched.
        assert_eq!(serde_json::to_string(&SpaceId::Ram).unwrap(), "\"Ram\"");
        assert_eq!(
            serde_json::to_string(&SpaceId::Custom(7)).unwrap(),
            "{\"Custom\":7}"
        );
        for sid in [
            SpaceId::Ram,
            SpaceId::Register,
            SpaceId::Unique,
            SpaceId::Const,
            SpaceId::Custom(4_242),
            SpaceId::Unresolved,
        ] {
            let json = serde_json::to_string(&sid).unwrap();
            let back: SpaceId = serde_json::from_str(&json).unwrap();
            assert_eq!(back, sid);
        }
    }

    /// The guard a write path calls. Two-sided: it must refuse the
    /// unreproducible varnode AND admit every reproducible one, or it
    /// carries no information.
    ///
    /// DISABLE: `is_persistable` returning `true` unconditionally fails the
    /// first assert; returning `false` unconditionally fails the loop.
    #[test]
    fn is_persistable_refuses_only_the_unreproducible_varnode() {
        use crate::Varnode;

        assert!(!Varnode::new(SpaceId::Unresolved, 0x1000, 8).is_persistable());

        for sid in [
            SpaceId::Ram,
            SpaceId::Register,
            SpaceId::Unique,
            SpaceId::Const,
            SpaceId::Custom(0x1234),
        ] {
            assert!(
                Varnode::new(sid, 0x1000, 8).is_persistable(),
                "{sid} is reproducible and must be persistable"
            );
        }
    }

    /// `is_unresolved` discriminates — it neither fires on everything nor
    /// stays silent on everything.
    #[test]
    fn is_unresolved_discriminates() {
        assert!(SpaceId::Unresolved.is_unresolved());
        for sid in [
            SpaceId::Ram,
            SpaceId::Register,
            SpaceId::Unique,
            SpaceId::Const,
            SpaceId::Custom(0),
        ] {
            assert!(!sid.is_unresolved(), "{sid} must not read as unresolved");
        }
    }

    /// Ram/Custom aliasing: reserve the identity, don't claim the memory.
    ///
    /// A space that is really a window onto RAM keeps its own id (the lift
    /// stays faithful to the SLEIGH spec) while declaring where its bytes
    /// live. Nothing merges the two.
    ///
    /// DISABLE: drop the `aliases` field and this stops compiling.
    #[test]
    fn an_aliased_space_names_ram_without_becoming_ram() {
        let mut window = AddressSpace::new(SpaceId::Custom(0x1234), "iomem", 8);
        window.aliases = Some(SpaceId::Ram);

        // Reserved: still its own identity.
        assert_ne!(window.id, SpaceId::Ram);
        // Not claimed: the bytes are RAM's.
        assert_eq!(window.aliases, Some(SpaceId::Ram));

        // A space with no declared alias says nothing, rather than
        // asserting independence.
        let plain = AddressSpace::ram(8);
        assert_eq!(plain.aliases, None);

        // The field survives a round-trip, so an alias declared by a lifter
        // reaches a consumer.
        let json = serde_json::to_string(&window).unwrap();
        let back: AddressSpace = serde_json::from_str(&json).unwrap();
        assert_eq!(back.aliases, Some(SpaceId::Ram));
        assert_eq!(back.id, SpaceId::Custom(0x1234));
    }

    #[test]
    fn address_space_optional_endianness_serde() {
        let space = AddressSpace::new(SpaceId::Ram, "ram", 8);
        let json = serde_json::to_string(&space).expect("serialize");
        assert!(json.contains("\"endianness\":null"));

        let mut be_space = AddressSpace::new(SpaceId::Ram, "ram_be", 8);
        be_space.endianness = Some(Endianness::Big);
        let json_be = serde_json::to_string(&be_space).expect("serialize");
        assert!(json_be.contains("endianness"));
        let roundtrip: AddressSpace = serde_json::from_str(&json_be).expect("deserialize");
        assert_eq!(roundtrip.endianness, Some(Endianness::Big));
    }
}
