// SPDX-License-Identifier: Apache-2.0

//! **PROBE-R2IL-LIVE-REGFILE** — the falsifier for the executable half of
//! the V4 space binding (lance-graph
//! `r2il-machine-semantic-contract-v1.md` §7.8; plan
//! `probe-r2il-live-regfile-v1.md`).
//!
//! The claim under test, in one sentence:
//!
//! > A real 6502 routine, lifted to R2IL by **Ghidra's own SLEIGH spec**
//! > and executed through [`r2conc::SlabState`] with the machine state
//! > bound to borrowed slabs, produces byte-identical architectural state
//! > to an **independently written** reference 6502.
//!
//! Run it with:
//!
//! ```text
//! cargo test -p r2conc --features probe-6502 --test live_regfile
//! ```
//!
//! It is feature-gated because enabling it compiles Ghidra's 6502 SLEIGH
//! specification from source, which takes minutes; the default
//! `cargo test -p r2conc` has no reason to pay for that.
//!
//! # Why this is a real differential test and not an echo
//!
//! The obvious way to get a worthless green is for both sides to share one
//! author's misconception. Three independent legs prevent that:
//!
//! 1. **Side A's semantics are not this session's.** The R2IL executed
//!    here is never hand-written: it comes out of
//!    `Disassembler::from_sla(SLA_6502, PSPEC_6502, "6502")` lifting real
//!    machine-code bytes through Ghidra's compiled 6502 SLEIGH spec. Those
//!    instruction semantics were authored elsewhere, years ago, with no
//!    knowledge of this workspace. What this session contributes on side A
//!    is only the *execution* ([`r2conc`]) and the sequencing below.
//! 2. **Side B was written in enforced isolation.** The reference
//!    emulator in `mos6502_oracle.rs` was produced without reading
//!    `r2conc`, `r2il`, or anything naming R2IL/SLEIGH/p-code, and without
//!    copying an existing emulator. It was given the opcode list and the
//!    struct shape and deliberately NOT given the flag semantics, the
//!    status-bit layout, the branch offset arithmetic, or the rotate/carry
//!    behaviour — exactly the parts that must be independent.
//! 3. **Arithmetic is the third witness.** The routine is an 8x8→16
//!    unsigned multiply, so its correct answer is a fact about arithmetic
//!    rather than about any implementation:
//!    [`multiply_matches_arithmetic_truth_not_merely_the_other_side`]
//!    asserts the 16-bit result equals `(a as u16) * (b as u16)`. Operand
//!    choice is load-bearing — the pairs include products **> 255**, so an
//!    executor that silently drops the high byte passes `7 x 13` and fails
//!    `55 x 13`.
//!
//! Three sources, no shared author. Agreement across all three is
//! evidence; disagreement between any two is informative about which.
//!
//! # Zero-copy, end to end
//!
//! V3 and V4 are both zero-copy; serialization exists only in an intake
//! arm, and there is no intake arm here. The 6502's memory IS the caller's
//! `Vec<u8>` (borrowed by [`SlabState`], asserted after the executor is
//! dropped), its register file IS the caller's register slab, and
//! intermediates live in `unique` scratch. Nothing is serialized, gathered
//! or copied between the two representations at any point.
//!
//! # Two facts this probe MEASURES rather than assumes
//!
//! - **The SLEIGH register-space extent** ([`the_sleigh_register_space_is_sparse_so_the_facet_binding_is_a_projection`]).
//!   §7.8 binds `register` to a node's 12-byte V3 facet register. The
//!   6502's *semantic* register file is 7 bytes (A, X, Y, SP, P, PC:2) and
//!   fits with room to spare — but Ghidra models each status flag as its
//!   own byte register, so the *layout* is sparse and much wider. The
//!   honest consequence, pinned by that test: the facet binding is a
//!   **projection** of the register file, never a byte-identity with
//!   SLEIGH's layout.
//! - **Which `SpaceId` 6502 memory lands in**
//!   ([`sixty_five_oh_two_memory_lifts_to_ram_not_to_a_custom_space`]).
//!   This corrected a claim already committed to two repositories; see the
//!   Correction note on [`SlabState`].
//!
//! # A Ghidra 6502 spec defect, found by building this probe
//!
//! The lift of `ADC $F1` is, verbatim from the measurement:
//!
//! ```text
//! 2: IntCarry { dst: C, a: A, b: tmp }      <- carry of A+M, IGNORING carry-in
//! 3: IntAdd   { dst: tmp2, a: A, b: tmp }
//! 4: IntAdd   { dst: A, a: tmp2, b: carry_in }
//! 7: Copy     { dst: V, src: C }            <- V := C
//! ```
//!
//! Both flag computations are wrong for a real 6502: the carry-out ignores
//! the incoming carry, and the signed-overflow flag is set to the unsigned
//! carry flag (they differ — `0x50 + 0x50` gives `V=1, C=0`).
//!
//! This is **not** a defect in `r2conc`, and the probe does not paper over
//! it. Three consequences, all pinned:
//!
//! - [`the_probe_detects_the_ghidra_adc_divergence`] deliberately drives
//!   the buggy path with synthetic inputs and asserts the two sides
//!   **DISAGREE**. That is this file's can-it-fire half: without it, "the
//!   tests pass" would carry no information about whether the harness can
//!   detect a difference at all.
//! - **The first real run corrected a prediction made in this very file.**
//!   Before running, the recorded expectation was that the multiply
//!   routine could not be affected by the defect, since it `CLC`s before
//!   every `ADC` and never *reads* `V`. Both premises hold — but the
//!   conclusion did not: `ADC` still *writes* `V`, so on `255 x 255` the
//!   two sides agree on every field and the full product `0xFE01`, while
//!   Ghidra leaves `V=1` and a real 6502 leaves `V=0`. The probe found the
//!   defect in a real routine, not just in a synthetic probe of it.
//! - Consequently `V` is excluded from the headline comparison — but
//!   never silently. [`Snapshot::without_v`] states why, and
//!   [`the_ghidra_adc_defect_is_observable_in_the_routines_residual_v_flag`]
//!   asserts two-sided that `V` really does diverge on some pairs and
//!   really does agree on others, so the exclusion cannot degrade into a
//!   blanket "ignore that field". The computed product is compared in full
//!   on every pair regardless.
//!
//! # Deliberate scope limits
//!
//! Not cycle accuracy, not full instruction coverage, not a claim about
//! the SLEIGH spec's overall correctness, and nothing about the effectful
//! fragment beyond the `Store`s this routine performs. The Klaus Dormann
//! functional suite is not used (it needs the full instruction set and is
//! GPL-3.0, fetched-not-vendored on this machine); using it later is a
//! legitimate deepening, claiming it now would be false.
//!
//! # What actually gates this file (measured 2026-08-26)
//!
//! **Nothing automated.** `.github/workflows/ci.yml` declares
//! `cargo test --workspace --all-features`, which WOULD enable
//! `probe-6502` and run everything below — but the repository has **zero
//! workflow runs, ever** (`/actions/runs` → `total_count: 0`); the
//! workflow is written for a self-hosted runner that is not registered.
//! So the gate is local, and a future session should not read the CI
//! config and conclude otherwise. Run it by hand before trusting it:
//!
//! ```text
//! cargo test -p r2conc --features probe-6502
//! cargo clippy -p r2conc --features probe-6502 --all-targets -- -D warnings
//! ```
//!
//! A gate that never runs is not a gate.
//!
//! # Disable-run log (each verified red-then-green before commit)
//!
//! | # | disable | observed red |
//! |---|---|---|
//! | D1 | sequencer ignores `Control::Jump` and always falls through | 3 tests red — the loop is never taken, so A/X/zero-page all disagree |
//! | D2 | drop the high byte (report `0` for `$F2`) | 3 tests red — the `> 255` pairs fail; `7 x 13` alone would NOT have caught it |
//! | D3 | assert `Custom(1)` instead of `Ram` for zero page | 1 test red, naming the real space |
//! | D4 | resolve the register file by the wrong name (A/X swapped) | 3 tests red — proves the by-name `ArchSpec` lookup is load-bearing |
//! | D5 | oracle's `ADC` recomputed the way Ghidra does (`V := C`) | 3 tests red **including the published ADC truth table** — the oracle's independence is what makes the divergence tests mean anything |
//! | D6 | remove the `CLC` from the routine (`0x18` → `NOP`) | 4 tests red — the carry-in stops being 0 and the immunity claim correctly fails |
//! | D7 | `without_v()` stops excluding `V` | 1 test red — proves the exclusion is doing real work rather than hiding nothing |

#[path = "mos6502_oracle.rs"]
mod oracle;

use std::collections::BTreeMap;

use oracle::{Mos6502, flag};
use r2conc::{ConcError, Control, SlabState};
use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::{Disassembler, build_arch_spec};
use sleigh_config::processor_6502::{PSPEC_6502, SLA_6502};

// ── the fixture ──────────────────────────────────────────────────────────
//
// Hand-assembled by this session from the 6502 opcode table, so the bytes
// carry no third-party licence and the test is hermetic: no fetch, no
// sibling checkout, no skip-if-absent path (a fixture that may be absent
// skips-and-passes, which hides failure exactly where CI would catch it).
//
//   $C000  A9 00     LDA #$00      ; A = running high byte
//   $C002  A2 08     LDX #$08      ; 8 bits
//   $C004  46 F0     LSR $F0       ; shift multiplier, LSB -> C
//   $C006  90 03     BCC $C00B     ; loop head
//   $C008  18        CLC
//   $C009  65 F1     ADC $F1       ; add multiplicand
//   $C00B  6A        ROR A         ; rotate result right...
//   $C00C  66 F0     ROR $F0       ; ...into the low byte
//   $C00E  CA        DEX
//   $C00F  D0 F5     BNE $C006
//   $C011  85 F2     STA $F2       ; high byte out
//   $C013  EA        NOP           ; halt marker
//
// Branch offsets hand-verified: BCC at $C006 is 2 bytes, next $C008,
// target $C00B => +3. BNE at $C00F is 2 bytes, next $C011, target $C006
// => -11 = 0xF5. The routine reuses the multiplier's own zero-page cell as
// the result's low byte, which is why $F0 holds the low half at the end.
const MULTIPLY: &[u8] = &[
    0xA9, 0x00, 0xA2, 0x08, 0x46, 0xF0, 0x90, 0x03, 0x18, 0x65, 0xF1, 0x6A, 0x66, 0xF0, 0xCA, 0xD0,
    0xF5, 0x85, 0xF2, 0xEA,
];
const ORIGIN: u16 = 0xC000;
const HALT: u16 = 0xC013;
const ZP_LOW: u16 = 0xF0; // multiplier in, result low byte out
const ZP_MCAND: u16 = 0xF1; // multiplicand in
const ZP_HIGH: u16 = 0xF2; // result high byte out

/// `Disassembler::lift` requires a window of at least this many bytes and
/// hard-fails below it, so every lift is handed a padded window. The
/// padding can never change what is decoded: `lift` decodes exactly the
/// one instruction at `addr` and reports its own `size`.
const LIFT_WINDOW: usize = 16;

/// Unique-space scratch. The measured 6502 lift uses temporaries up to
/// offset `0x5580`, so this is sized well past that; an overrun would be a
/// loud `OutOfBounds`, never silent corruption.
const UNIQUE_LEN: usize = 0x1_0000;

/// Guard against a sequencer bug turning into a hang. The routine retires
/// ~50 instructions; anything near this bound is a defect, not a slow test.
const MAX_STEPS: u32 = 10_000;

// ── the architectural state both sides must agree on ─────────────────────

/// The comparison surface. Deliberately *not* a packed status byte: side B
/// keeps flags as bits in one register and side A keeps them as separate
/// SLEIGH byte-registers, so comparing booleans bridges two genuinely
/// different representations instead of assuming a shared layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Snapshot {
    a: u8,
    x: u8,
    y: u8,
    c: bool,
    z: bool,
    n: bool,
    v: bool,
    zp_low: u8,
    zp_mcand: u8,
    zp_high: u8,
}

impl Snapshot {
    /// Everything except the overflow flag.
    ///
    /// `V` is excluded from the headline comparison for one measured
    /// reason, not for convenience: Ghidra's 6502 spec ends `ADC` with
    /// `Copy { dst: V, src: C }`, so its `V` is the unsigned carry rather
    /// than signed overflow. That is a defect in the spec, and excluding
    /// the field here would be weakening the test if it were done
    /// silently — so it is not silent:
    /// [`the_ghidra_adc_defect_is_observable_in_the_routines_residual_v_flag`]
    /// asserts, two-sided, that `V` really does diverge on some operand
    /// pairs and really does agree on others. Every other field is
    /// compared in full.
    fn without_v(self) -> Snapshot {
        Snapshot { v: false, ..self }
    }
}

/// Initial machine state, applied identically to both sides.
#[derive(Clone, Default)]
struct Init {
    a: u8,
    x: u8,
    carry: bool,
    zp: Vec<(u16, u8)>,
}

// ── side A: Ghidra's lift, executed by r2conc ────────────────────────────

/// Pre-lift every instruction of `code`, keyed by machine address.
///
/// Pre-lifting (rather than lifting from the live memory image) is what
/// lets the memory slab stay exclusively borrowed by the executor for the
/// whole run — the zero-copy property this probe exists to demonstrate. It
/// is sound here because the routine is not self-modifying, which
/// [`the_routine_never_writes_into_its_own_code`] proves rather than
/// assumes.
fn pre_lift(code: &[u8], origin: u16) -> Result<BTreeMap<u64, R2ILBlock>, String> {
    let disasm = Disassembler::from_sla(SLA_6502, PSPEC_6502, "6502")
        .map_err(|e| format!("from_sla: {e}"))?;
    let mut image = code.to_vec();
    image.resize(code.len() + LIFT_WINDOW, 0xEA);
    let mut prog = BTreeMap::new();
    let mut off = 0usize;
    while off < code.len() {
        let addr = u64::from(origin) + off as u64;
        let block = disasm
            .lift(&image[off..off + LIFT_WINDOW], addr)
            .map_err(|e| format!("lift at {addr:#06x}: {e}"))?;
        assert_eq!(block.addr, addr, "lift reported a different address");
        assert!(block.size > 0, "zero-size instruction at {addr:#06x}");
        off += block.size as usize;
        prog.insert(addr, block);
    }
    Ok(prog)
}

/// Resolve a register's byte offset by NAME from the lifted `ArchSpec`.
///
/// Never a hardcoded table: the layout is data that belongs to the SLEIGH
/// spec, so reading it at runtime means the probe cannot drift from the
/// spec it is testing.
fn reg_of(spec: &r2il::ArchSpec, name: &str) -> Varnode {
    let def = spec
        .registers
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("6502 ArchSpec has no register {name}"));
    Varnode::new(SpaceId::Register, def.offset, def.size)
}

/// Execute the routine through `r2conc` and snapshot the result.
fn run_r2il(code: &[u8], origin: u16, halt: u16, init: &Init) -> Result<Snapshot, String> {
    let prog = pre_lift(code, origin)?;
    let spec = build_arch_spec(SLA_6502, PSPEC_6502, "6502").map_err(|e| format!("spec: {e}"))?;

    // The register slab is sized from the spec's own extent, not guessed.
    let extent = spec
        .registers
        .iter()
        .map(|r| r.offset as usize + r.size as usize)
        .max()
        .expect("6502 ArchSpec has registers");
    let (a_vn, x_vn, y_vn) = (reg_of(&spec, "A"), reg_of(&spec, "X"), reg_of(&spec, "Y"));
    let (c_vn, z_vn, n_vn, v_vn) = (
        reg_of(&spec, "C"),
        reg_of(&spec, "Z"),
        reg_of(&spec, "N"),
        reg_of(&spec, "V"),
    );

    let mut register = vec![0u8; extent];
    let mut ram = vec![0u8; 0x1_0000];
    ram[origin as usize..origin as usize + code.len()].copy_from_slice(code);
    for (at, val) in &init.zp {
        ram[*at as usize] = *val;
    }

    let snapshot = {
        let mut st = SlabState::new(&mut register, &mut ram, UNIQUE_LEN);
        st.write(&a_vn, u64::from(init.a)).map_err(err)?;
        st.write(&x_vn, u64::from(init.x)).map_err(err)?;
        st.write(&c_vn, u64::from(init.carry)).map_err(err)?;

        // The sequencer. `r2conc::step` is one op and says what to do next;
        // mapping that onto machine addresses is the caller's job, which is
        // exactly the division of labour the crate documents.
        let mut pc = u64::from(origin);
        let mut steps = 0u32;
        while pc != u64::from(halt) {
            let block = prog
                .get(&pc)
                .ok_or_else(|| format!("pc {pc:#06x} is not an instruction boundary"))?;
            let mut next_pc = pc + u64::from(block.size);
            let mut i = 0usize;
            while i < block.ops.len() {
                match st.step(&block.ops[i]).map_err(err)? {
                    Control::Next => i += 1,
                    // A taken branch ends the instruction: p-code has no
                    // "resume the rest of this instruction afterwards".
                    Control::Jump(target) => {
                        next_pc = target;
                        break;
                    }
                    other => return Err(format!("unexpected control at {pc:#06x}: {other:?}")),
                }
            }
            pc = next_pc;
            steps += 1;
            if steps > MAX_STEPS {
                return Err(format!(
                    "runaway: {MAX_STEPS} steps without reaching {halt:#06x}"
                ));
            }
        }
        Snapshot {
            a: st.read(&a_vn).map_err(err)? as u8,
            x: st.read(&x_vn).map_err(err)? as u8,
            y: st.read(&y_vn).map_err(err)? as u8,
            c: st.read(&c_vn).map_err(err)? != 0,
            z: st.read(&z_vn).map_err(err)? != 0,
            n: st.read(&n_vn).map_err(err)? != 0,
            v: st.read(&v_vn).map_err(err)? != 0,
            zp_low: 0,
            zp_mcand: 0,
            zp_high: 0,
        }
    };

    // The executor is dropped, so the CALLER's memory is readable again —
    // and it is the same memory the 6502 wrote through. Zero-copy is not a
    // claim here, it is the only way these reads can see the stores.
    Ok(Snapshot {
        zp_low: ram[ZP_LOW as usize],
        zp_mcand: ram[ZP_MCAND as usize],
        zp_high: ram[ZP_HIGH as usize],
        ..snapshot
    })
}

fn err(e: ConcError) -> String {
    format!("r2conc refused: {e}")
}

// ── side B: the independent oracle ───────────────────────────────────────

fn run_oracle(code: &[u8], origin: u16, halt: u16, init: &Init) -> Result<Snapshot, String> {
    let mut cpu = Mos6502::new();
    cpu.load(origin, code);
    for (at, val) in &init.zp {
        cpu.mem[*at as usize] = *val;
    }
    cpu.a = init.a;
    cpu.x = init.x;
    cpu.set_flag(flag::C, init.carry);
    cpu.pc = origin;
    cpu.run_until_pc(halt, u64::from(MAX_STEPS))?;
    Ok(Snapshot {
        a: cpu.a,
        x: cpu.x,
        y: cpu.y,
        c: cpu.get_flag(flag::C),
        z: cpu.get_flag(flag::Z),
        n: cpu.get_flag(flag::N),
        v: cpu.get_flag(flag::V),
        zp_low: cpu.mem[ZP_LOW as usize],
        zp_mcand: cpu.mem[ZP_MCAND as usize],
        zp_high: cpu.mem[ZP_HIGH as usize],
    })
}

fn multiply_init(multiplier: u8, multiplicand: u8) -> Init {
    Init {
        zp: vec![(ZP_LOW, multiplier), (ZP_MCAND, multiplicand)],
        ..Init::default()
    }
}

// ── the falsifiers ───────────────────────────────────────────────────────

/// The probe's headline: Ghidra's lift executed by `r2conc` and the
/// isolated oracle agree on the architectural state — accumulator, index
/// registers, carry/zero/negative, and all three zero-page cells — for
/// operand pairs including ones whose product exceeds 255.
///
/// `V` is excluded and separately accounted for; see [`Snapshot::without_v`].
#[test]
fn the_lifted_routine_matches_the_independent_oracle() {
    for (m, n) in PAIRS {
        let init = multiply_init(m, n);
        let a = run_r2il(MULTIPLY, ORIGIN, HALT, &init).unwrap();
        let b = run_oracle(MULTIPLY, ORIGIN, HALT, &init).unwrap();
        assert_eq!(a.without_v(), b.without_v(), "divergence on {m} x {n}");
    }
}

/// The operand pairs both parity tests sweep. `255 x 255` is the pair that
/// first exposed the residual-`V` divergence below; `(0, 200)` and
/// `(200, 0)` are the degenerate ends; the rest straddle the 255 boundary
/// so the high byte is genuinely exercised.
const PAIRS: [(u8, u8); 7] = [
    (7, 13),
    (55, 13),
    (255, 255),
    (0, 200),
    (1, 1),
    (200, 0),
    (13, 27),
];

/// **A finding this probe produced, and the reason it earns its keep.**
///
/// Before it ran, the prediction recorded in this file was that the
/// multiply routine could not be affected by Ghidra's `ADC` defect,
/// because it `CLC`s before every `ADC` (so the carry-in is always 0 and
/// the two carry-out formulas coincide) and never *reads* `V`. The first
/// two premises are true and still pinned by
/// [`the_multiply_routines_computed_result_cannot_be_affected_by_the_adc_defect`].
/// The conclusion was wrong: `ADC` still *writes* `V`, so the defect is
/// observable in the routine's residual flag state even though it cannot
/// reach the computed product.
///
/// Measured, on `255 x 255`: both sides compute `0xFE01` (= 65025) and
/// agree on every other field; Ghidra leaves `V=1`, a real 6502 leaves
/// `V=0`.
///
/// Two-sided by construction: at least one pair must diverge (or the
/// exclusion in [`Snapshot::without_v`] would be hiding nothing and should
/// be deleted) and at least one must agree (or `V` would be uniformly
/// different, which is a different claim than the one made here).
#[test]
fn the_ghidra_adc_defect_is_observable_in_the_routines_residual_v_flag() {
    let (mut diverged, mut agreed) = (Vec::new(), Vec::new());
    for (m, n) in PAIRS {
        let init = multiply_init(m, n);
        let a = run_r2il(MULTIPLY, ORIGIN, HALT, &init).unwrap();
        let b = run_oracle(MULTIPLY, ORIGIN, HALT, &init).unwrap();
        // Whatever V does, the actual product must still agree.
        assert_eq!(
            (a.zp_high, a.zp_low),
            (b.zp_high, b.zp_low),
            "the product itself must never depend on V"
        );
        if a.v == b.v {
            &mut agreed
        } else {
            &mut diverged
        }
        .push((m, n));
    }
    assert!(
        !diverged.is_empty(),
        "V never diverged — then excluding it from the headline comparison hides nothing \
         and the exclusion should be removed"
    );
    assert!(
        !agreed.is_empty(),
        "V diverged on every pair — that is a broader claim than 'Ghidra assigns V := C' \
         and needs re-measuring before it is believed"
    );
}

/// The third witness: arithmetic, which neither implementation authored.
/// The `> 255` pairs are load-bearing — an executor that drops the high
/// byte passes `7 x 13` and fails here.
#[test]
fn multiply_matches_arithmetic_truth_not_merely_the_other_side() {
    let mut saw_high_byte = false;
    for (m, n) in [(7u8, 13u8), (55, 13), (255, 255), (13, 27), (99, 3)] {
        let init = multiply_init(m, n);
        let got = run_r2il(MULTIPLY, ORIGIN, HALT, &init).unwrap();
        let product = u16::from(m) * u16::from(n);
        let assembled = (u16::from(got.zp_high) << 8) | u16::from(got.zp_low);
        assert_eq!(assembled, product, "{m} x {n} != {product}");
        assert_eq!(got.a, got.zp_high, "STA $F2 must have stored A");
        saw_high_byte |= got.zp_high != 0;
    }
    assert!(
        saw_high_byte,
        "no case produced a non-zero high byte — the operands are too small to falsify anything"
    );
}

/// **The can-it-fire half.** Ghidra's 6502 `ADC` computes its carry-out
/// ignoring the carry-in, and sets `V := C`. Both are wrong for a real
/// 6502, so on inputs that reach those paths the two sides MUST disagree —
/// and this asserts they do. Without this test, the green above would say
/// nothing about whether the harness can detect a difference at all.
#[test]
fn the_probe_detects_the_ghidra_adc_divergence() {
    // `CLC; ADC $F1; NOP` — a two-instruction body so we can drive the
    // carry-in ourselves, then halt.
    let adc_only: &[u8] = &[0x65, 0xF1, 0xEA];
    let halt = ORIGIN + 2;

    // Case 1 — carry-out. A=0xFF, M=0x00, C_in=1.
    // Real 6502: 0xFF + 0x00 + 1 = 0x100 => A=0x00, C=1.
    // Ghidra:    C := carry(0xFF, 0x00) = 0, then A = 0xFF + 1 = 0x00.
    let init = Init {
        a: 0xFF,
        carry: true,
        zp: vec![(ZP_MCAND, 0x00)],
        ..Init::default()
    };
    let ghidra = run_r2il(adc_only, ORIGIN, halt, &init).unwrap();
    let real = run_oracle(adc_only, ORIGIN, halt, &init).unwrap();
    assert_eq!(ghidra.a, real.a, "the accumulator itself still agrees");
    assert!(real.c, "a real 6502 carries out of 0xFF + 0 + 1");
    assert!(
        !ghidra.c,
        "Ghidra's spec drops the carry-in from its carry-out"
    );
    assert_ne!(ghidra, real, "the harness must SEE this divergence");

    // Case 2 — signed overflow. A=0x50, M=0x50, C_in=0.
    // Real 6502: 0x50 + 0x50 = 0xA0, V=1 (two positives, negative result).
    // Ghidra:    V := C = 0.
    let init = Init {
        a: 0x50,
        carry: false,
        zp: vec![(ZP_MCAND, 0x50)],
        ..Init::default()
    };
    let ghidra = run_r2il(adc_only, ORIGIN, halt, &init).unwrap();
    let real = run_oracle(adc_only, ORIGIN, halt, &init).unwrap();
    assert_eq!(ghidra.a, 0xA0, "the arithmetic result is not in dispute");
    assert!(real.v, "a real 6502 sets V on 0x50 + 0x50");
    assert!(!ghidra.v, "Ghidra's spec assigns V := C");
    assert_ne!(ghidra, real, "the harness must SEE this divergence too");
}

/// Why the routine's COMPUTED RESULT is immune to the `ADC` defect, even
/// though its residual `V` flag is not (see above): it `CLC`s before every
/// `ADC`, so the carry-in is always 0 and Ghidra's carry-out formula
/// coincides with the real one; and it never branches on overflow, so the
/// wrong `V` can never steer it. Proven from the bytes rather than
/// asserted in prose.
#[test]
fn the_multiply_routines_computed_result_cannot_be_affected_by_the_adc_defect() {
    let adc_at = MULTIPLY
        .windows(2)
        .position(|w| w == [0x65, 0xF1])
        .expect("the routine must contain ADC $F1");
    assert_eq!(
        MULTIPLY[adc_at - 1],
        0x18,
        "every ADC in this routine must be immediately preceded by CLC"
    );
    assert_eq!(
        MULTIPLY.iter().filter(|b| **b == 0x65).count(),
        1,
        "exactly one ADC, so the CLC check above covers all of them"
    );
    // ...and no instruction in the routine reads V (the 6502's only
    // V-reading opcodes are BVC/BVS, 0x50/0x70).
    assert!(
        !MULTIPLY.contains(&0x50) && !MULTIPLY.contains(&0x70),
        "the routine must not branch on overflow"
    );
}

/// MEASURED, not assumed: 6502 memory operands lift into `SpaceId::Ram`.
/// This is the empirical half of the Correction recorded on `SlabState` —
/// the case-sensitive alias finding is real for `ArchSpec` and false for
/// the op stream.
#[test]
fn sixty_five_oh_two_memory_lifts_to_ram_not_to_a_custom_space() {
    let prog = pre_lift(MULTIPLY, ORIGIN).unwrap();
    let lsr = &prog[&0xC004].ops; // LSR $F0
    let mem_spaces: Vec<SpaceId> = lsr
        .iter()
        .filter_map(|op| match op {
            R2ILOp::Copy { src, .. } if src.offset == 0xF0 => Some(src.space),
            R2ILOp::Copy { dst, .. } if dst.offset == 0xF0 => Some(dst.space),
            _ => None,
        })
        .collect();
    assert!(
        !mem_spaces.is_empty(),
        "LSR $F0 must touch zero-page $F0 — otherwise this test measures nothing"
    );
    for space in mem_spaces {
        assert_eq!(space, SpaceId::Ram, "6502 zero page must lift to Ram");
    }
}

/// MEASURED: the SLEIGH register-space layout is sparse, so §7.8's facet
/// binding is a PROJECTION of the register file rather than a byte-identity
/// with SLEIGH's layout. Both halves are asserted so neither can rot: the
/// semantic file fits 12 bytes, and the layout does not.
#[test]
fn the_sleigh_register_space_is_sparse_so_the_facet_binding_is_a_projection() {
    let spec = build_arch_spec(SLA_6502, PSPEC_6502, "6502").unwrap();
    let extent = spec
        .registers
        .iter()
        .map(|r| r.offset as usize + r.size as usize)
        .max()
        .unwrap();
    assert!(
        extent > 12,
        "layout extent {extent} — if SLEIGH ever packs the 6502 into 12 bytes, \
         this projection note must be re-measured, not quietly kept"
    );
    // The SEMANTIC register file, which is what a facet register carries.
    let semantic: usize = ["A", "X", "Y", "P"]
        .iter()
        .chain(["PC", "SP"].iter())
        .map(|n| {
            spec.registers
                .iter()
                .find(|r| r.name == *n)
                .unwrap_or_else(|| panic!("no register {n}"))
                .size as usize
        })
        .sum();
    assert!(
        semantic <= 12,
        "the 6502's semantic register file is {semantic} bytes and must fit a V3 facet register"
    );
}

/// The pre-lift is only sound for non-self-modifying code, so prove it:
/// no store in the routine targets the routine's own address range.
#[test]
fn the_routine_never_writes_into_its_own_code() {
    let prog = pre_lift(MULTIPLY, ORIGIN).unwrap();
    let code = u64::from(ORIGIN)..u64::from(ORIGIN) + MULTIPLY.len() as u64;
    let mut stores = 0;
    for block in prog.values() {
        for op in &block.ops {
            if let R2ILOp::Copy { dst, .. } = op
                && dst.space == SpaceId::Ram
            {
                stores += 1;
                assert!(
                    !code.contains(&dst.offset),
                    "store into own code at {:#06x}",
                    dst.offset
                );
            }
        }
    }
    assert!(stores > 0, "the routine must store SOMEWHERE, else vacuous");
}
