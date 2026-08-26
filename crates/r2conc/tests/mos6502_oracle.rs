//! # MOS 6502 reference oracle
//!
//! This file is an **independent, hand-written reference emulator** for a
//! small subset of the MOS 6502 instruction set. It exists to serve as one
//! side of a *differential test*: some other component (not read, not
//! consulted, and not named here on purpose) is expected to reproduce the
//! same architectural state transitions for the same programs. The entire
//! value of this file comes from its independence — it was written directly
//! from the author's own knowledge of publicly documented 6502 behaviour
//! (the NMOS 6502 datasheet semantics, as commonly summarized in 6502
//! reference material such as the classic "6502.org" instruction reference
//! and the well-known ADC/SBC overflow truth table), and from nothing else
//! in this repository or any other emulator implementation.
//!
//! ## Epistemic status — read this before trusting any result derived from it
//!
//! - This is **hand-written from published/remembered 6502 behaviour**. It
//!   has **not** been run against the Klaus Dormann 6502 functional test
//!   suite, has **not** been cross-checked against a real 6502 die or a
//!   widely-used cycle-accurate emulator (e.g. VICE, Mesen), and makes no
//!   claim of completeness or of matching every documented edge case of the
//!   real chip (e.g. it does not model illegal/undocumented opcodes, page
//!   boundary cycle penalties, or interrupt behaviour).
//! - It is **not cycle-accurate**: the `cycles` field on [`Mos6502`] counts
//!   *instructions retired*, not clock cycles, and no attempt is made to
//!   model per-addressing-mode cycle counts, page-crossing penalties, or
//!   bus timing of any kind.
//! - What it *is* evidence for: that a given short program, executed against
//!   the semantics described in this file's own doc comments (each
//!   instruction's implementation states the rule it applies), produces a
//!   particular final register/flag/memory state. If another independent
//!   implementation agrees with this one on such a program, that is
//!   meaningful corroborating evidence for both, precisely because the two
//!   were derived independently. If they disagree, this file's comments are
//!   the place to check first for a plain misstatement of the documented
//!   semantics — it is not "the answer" merely by virtue of being written
//!   first.
//! - Decimal (BCD) mode is **out of scope**. The `D` status flag is tracked
//!   as a bit (so status-register round-tripping is faithful) but `ADC`
//!   below explicitly ignores it and always computes in binary. This is
//!   called out again at the `ADC` implementation.
//!
//! ## Implemented opcodes
//!
//! Exactly twelve opcodes are implemented, matching the following table.
//! Any opcode byte not in this table causes [`Mos6502::step`] to return
//! `Err` describing the unimplemented opcode in hex — there is no silent
//! no-op fallback for anything not on this list (0xEA/NOP is the *only*
//! legitimate no-op, and it is a real, explicitly implemented one).
//!
//! | opcode | mnemonic | addressing  |
//! |--------|----------|-------------|
//! | 0xA9   | LDA      | immediate   |
//! | 0xA2   | LDX      | immediate   |
//! | 0x46   | LSR      | zero page   |
//! | 0x90   | BCC      | relative    |
//! | 0x18   | CLC      | implied     |
//! | 0x65   | ADC      | zero page   |
//! | 0x6A   | ROR      | accumulator |
//! | 0x66   | ROR      | zero page   |
//! | 0xCA   | DEX      | implied     |
//! | 0xD0   | BNE      | relative    |
//! | 0x85   | STA      | zero page   |
//! | 0xEA   | NOP      | implied     |
//!
//! ## Known-answer vector provenance
//!
//! The ADC overflow (V flag) known-answer table used in
//! `adc_overflow_known_answer_vectors` below is the canonical eight-case
//! signed-overflow truth table that is ubiquitous in 6502 reference
//! material (it appears, in essentially the same form, in the "SO Sets
//! Overflow" style writeups and in the classic 6502.org overflow
//! explanation): the four cases 0x50+0x10, 0x50+0x50, 0x50+0x90, 0x50+0xD0,
//! and the four cases 0xD0+0x10, 0xD0+0x50, 0xD0+0x90, 0xD0+0xD0, each
//! computed with the carry flag initially clear. These specific eight
//! operand pairs are the standard minimal set used to exercise every
//! positive/negative-operand combination that does and does not produce
//! signed overflow, and the expected accumulator/V/C results below were
//! derived independently, digit by digit, from the definition of signed
//! two's-complement overflow (V is set exactly when two operands of the
//! same sign produce a result of the opposite sign), not copied from any
//! single external source.
// `load`, `run_until_pc`, and several struct fields are public API surface
// for the *other* half of this differential test (a separate harness that
// drives this oracle against an independent implementation); they are
// intentionally unused by the tests in this file alone.
#![allow(dead_code)]

/// Bit positions of the packed 6502 processor status register `p`.
///
/// Layout, high bit to low bit: `N V 1 B D I Z C`. Bit 5 is unused on real
/// hardware and conventionally always reads as 1; this emulator does not
/// simulate the `B` flag's push-time-only semantics (no BRK/interrupt
/// handling is implemented at all), so bit 4 is simply carried as a normal
/// bit with no special behaviour attached.
mod flag {
    pub const N: u8 = 0b1000_0000;
    pub const V: u8 = 0b0100_0000;
    pub const UNUSED: u8 = 0b0010_0000;
    #[allow(dead_code)]
    pub const B: u8 = 0b0001_0000;
    #[allow(dead_code)]
    pub const D: u8 = 0b0000_1000;
    #[allow(dead_code)]
    pub const I: u8 = 0b0000_0100;
    pub const Z: u8 = 0b0000_0010;
    pub const C: u8 = 0b0000_0001;
}

/// A minimal, deliberately obvious MOS 6502 reference emulator.
///
/// See the module documentation for what this is (and is not) evidence for.
pub struct Mos6502 {
    pub a: u8,
    pub x: u8,
    pub y: u8,
    pub sp: u8,
    pub pc: u16,
    /// Packed status register; see [`flag`] for bit positions.
    pub p: u8,
    pub mem: [u8; 65536],
    /// Count of *instructions retired* by [`Mos6502::step`], not machine
    /// cycles. See the module doc's "Epistemic status" section.
    pub cycles: u64,
}

impl Mos6502 {
    /// A freshly reset-like machine: all registers zero, all memory zeroed,
    /// and the stack pointer at the conventional post-reset value of
    /// `0xFD` (the real 6502 decrements `sp` by three during its reset
    /// sequence starting from an undefined power-on value that typically
    /// settles at `0xFF`, landing on `0xFD`; this emulator does not model
    /// the reset sequence itself, it simply starts `sp` at that
    /// commonly-documented post-reset value directly).
    pub fn new() -> Self {
        Mos6502 {
            a: 0,
            x: 0,
            y: 0,
            sp: 0xFD,
            pc: 0,
            // Bit 5 is unused and conventionally always reads as 1.
            p: flag::UNUSED,
            mem: [0u8; 65536],
            cycles: 0,
        }
    }

    /// Copy `bytes` into memory starting at address `at`. Does not touch
    /// `pc` or any register — callers are expected to set `pc` themselves
    /// (typically to `at`) before calling [`Mos6502::step`] or
    /// [`Mos6502::run_until_pc`].
    pub fn load(&mut self, at: u16, bytes: &[u8]) {
        let start = at as usize;
        for (i, b) in bytes.iter().enumerate() {
            // Wrap around the 64K address space rather than panicking, to
            // mirror how a real 6502's address bus wraps.
            self.mem[(start + i) & 0xFFFF] = *b;
        }
    }

    fn get_flag(&self, mask: u8) -> bool {
        self.p & mask != 0
    }

    fn set_flag(&mut self, mask: u8, value: bool) {
        if value {
            self.p |= mask;
        } else {
            self.p &= !mask;
        }
    }

    /// Set the Z and N flags from a just-computed 8-bit result, per the
    /// documented 6502 rule that applies to essentially every
    /// load/arithmetic/shift instruction: Z is set iff the result is
    /// exactly zero, and N is set to a copy of the result's bit 7 (the
    /// 6502 treats "negative" purely as "high bit set", with no separate
    /// signed interpretation performed by the flag-setting logic itself).
    fn set_zn(&mut self, result: u8) {
        self.set_flag(flag::Z, result == 0);
        self.set_flag(flag::N, result & 0x80 != 0);
    }

    fn fetch_u8(&mut self) -> u8 {
        let b = self.mem[self.pc as usize];
        self.pc = self.pc.wrapping_add(1);
        b
    }

    /// Execute exactly one instruction at the current `pc`, advancing `pc`
    /// past it (or, for a taken branch, to the branch target). Returns
    /// `Err` naming the opcode in hex if the opcode at `pc` is not one of
    /// the twelve implemented in this file — there is no silent fallback.
    pub fn step(&mut self) -> Result<(), String> {
        let opcode = self.fetch_u8();
        match opcode {
            // --- LDA #imm (0xA9) ---
            // Rule: A is loaded directly from the byte immediately
            // following the opcode. Affects Z (set iff loaded value is
            // zero) and N (copy of bit 7 of the loaded value). Does not
            // touch C, V, or D.
            0xA9 => {
                let v = self.fetch_u8();
                self.a = v;
                self.set_zn(self.a);
            }

            // --- LDX #imm (0xA2) ---
            // Rule: identical shape to LDA, but loads X. Affects Z/N from
            // the loaded value; does not touch C, V, or D.
            0xA2 => {
                let v = self.fetch_u8();
                self.x = v;
                self.set_zn(self.x);
            }

            // --- LSR zp (0x46) ---
            // Rule (logical shift right, memory operand): the operand
            // address is the single byte following the opcode, used
            // directly as a zero-page address (0x0000..=0x00FF). The
            // value at that address is shifted right by one bit; the bit
            // shifted OUT (the original bit 0) becomes the new value of
            // the carry flag C. Bit 7 of the result is always 0 because
            // this is a *logical* (not arithmetic) shift, which as a
            // direct consequence means N is always cleared afterward (a
            // logical right shift can never produce a result with the
            // high bit set). Z is set iff the shifted result is zero. V is
            // not affected by shift instructions on the 6502.
            0x46 => {
                let addr = self.fetch_u8() as usize;
                let v = self.mem[addr];
                let carry_out = v & 0x01 != 0;
                let result = v >> 1;
                self.mem[addr] = result;
                self.set_flag(flag::C, carry_out);
                self.set_zn(result);
            }

            // --- BCC rel (0x90) ---
            // Rule: the operand is a signed 8-bit relative offset. Per the
            // documented 6502 behaviour, the offset is added to the value
            // of `pc` *after* the two-byte branch instruction has already
            // been fully fetched (i.e. relative to the address of the
            // instruction immediately following this branch), not to the
            // address of the branch opcode itself. Branch is taken iff the
            // carry flag C is clear. No flags are affected by a branch
            // instruction itself.
            0x90 => {
                let offset = self.fetch_u8() as i8;
                // self.pc already points past the two-byte instruction.
                if !self.get_flag(flag::C) {
                    self.pc = (self.pc as i32 + offset as i32) as u16;
                }
            }

            // --- CLC (0x18) ---
            // Rule: unconditionally clears the carry flag C. No other
            // flags affected.
            0x18 => {
                self.set_flag(flag::C, false);
            }

            // --- ADC zp (0x65) ---
            // Rule (binary mode only — see module docs; if D were set this
            // emulator deliberately still computes binary addition rather
            // than BCD, since decimal mode is explicitly out of scope):
            // A := A + M + C(in), all as 8-bit values, with the *incoming*
            // carry participating in the addition as a normal +0/+1 term.
            //
            // Carry-out (C): computed from the *unsigned* 9-bit sum — if
            // the true arithmetic sum of the three unsigned 8-bit-range
            // terms (A, M, incoming-carry-as-0-or-1) exceeds 255, C is set.
            //
            // Overflow (V): set exactly when the signed (two's-complement)
            // result is wrong, which for addition happens precisely when
            // the two *operands* (A and M, as they were *before* this
            // instruction — the incoming carry does not participate in
            // this sign check) share the same sign but the result has the
            // opposite sign. Concretely: V = (A_old ^ result) & (M ^
            // result) & 0x80 != 0. This is algebraically equivalent to the
            // more commonly quoted `~(A_old ^ M) & (A_old ^ result) &
            // 0x80` form; both express "operands agreed in sign, result
            // disagreed".
            //
            // Z and N are set from the final 8-bit result exactly as for
            // any other load/arithmetic instruction.
            0x65 => {
                let addr = self.fetch_u8() as usize;
                let m = self.mem[addr];
                let a_old = self.a;
                let carry_in: u16 = if self.get_flag(flag::C) { 1 } else { 0 };
                let sum: u16 = a_old as u16 + m as u16 + carry_in;
                let result = sum as u8;
                let carry_out = sum > 0xFF;
                let overflow = (a_old ^ result) & (m ^ result) & 0x80 != 0;
                self.a = result;
                self.set_flag(flag::C, carry_out);
                self.set_flag(flag::V, overflow);
                self.set_zn(self.a);
            }

            // --- ROR A (0x6A, accumulator addressing) ---
            // Rule (rotate right through carry, 9-bit rotate): the
            // accumulator is rotated right by one bit *through* the carry
            // flag, not shifted logically. The bit rotated OUT of bit 0
            // becomes the NEW carry flag. The bit rotated IN at bit 7 is
            // the OLD (pre-instruction) value of the carry flag — i.e. the
            // rotation treats {C, A} as a single 9-bit register being
            // shifted right by one position. Z/N are set from the
            // resulting 8-bit accumulator value afterward, same as always.
            0x6A => {
                let old_carry_in: u8 = if self.get_flag(flag::C) { 0x80 } else { 0 };
                let new_carry_out = self.a & 0x01 != 0;
                self.a = (self.a >> 1) | old_carry_in;
                self.set_flag(flag::C, new_carry_out);
                self.set_zn(self.a);
            }

            // --- ROR zp (0x66) ---
            // Rule: identical rotate-through-carry semantics to ROR A
            // above, applied to the byte at the given zero-page address
            // instead of to the accumulator.
            0x66 => {
                let addr = self.fetch_u8() as usize;
                let v = self.mem[addr];
                let old_carry_in: u8 = if self.get_flag(flag::C) { 0x80 } else { 0 };
                let new_carry_out = v & 0x01 != 0;
                let result = (v >> 1) | old_carry_in;
                self.mem[addr] = result;
                self.set_flag(flag::C, new_carry_out);
                self.set_zn(result);
            }

            // --- DEX (0xCA) ---
            // Rule: X := X - 1, with 8-bit wraparound (0x00 decrements to
            // 0xFF, there is no borrow/carry flag interaction for register
            // increment/decrement instructions on the 6502 — C is left
            // untouched). Z/N set from the new value of X.
            0xCA => {
                self.x = self.x.wrapping_sub(1);
                self.set_zn(self.x);
            }

            // --- BNE rel (0xD0) ---
            // Rule: same relative-addressing shape as BCC above (offset
            // relative to the address immediately following this two-byte
            // instruction). Branch is taken iff the zero flag Z is clear.
            0xD0 => {
                let offset = self.fetch_u8() as i8;
                if !self.get_flag(flag::Z) {
                    self.pc = (self.pc as i32 + offset as i32) as u16;
                }
            }

            // --- STA zp (0x85) ---
            // Rule: stores the accumulator's current value into the
            // zero-page address given by the byte following the opcode.
            // Store instructions affect no flags at all.
            0x85 => {
                let addr = self.fetch_u8() as usize;
                self.mem[addr] = self.a;
            }

            // --- NOP (0xEA) ---
            // Rule: does nothing but consume the opcode byte, which
            // fetch_u8() already did above. No operand, no flags affected.
            0xEA => {}

            other => {
                return Err(format!("unimplemented opcode: {other:#04X}"));
            }
        }

        self.cycles += 1;
        Ok(())
    }

    /// Repeatedly call [`Mos6502::step`] until `pc == stop`, or until
    /// `max_steps` instructions have been executed without reaching it (in
    /// which case this returns `Err` rather than looping forever), or until
    /// a `step` call itself errors (propagated directly). Returns the
    /// number of instructions actually executed on success.
    pub fn run_until_pc(&mut self, stop: u16, max_steps: u64) -> Result<u64, String> {
        let mut executed: u64 = 0;
        while self.pc != stop {
            if executed >= max_steps {
                return Err(format!(
                    "run_until_pc: exceeded max_steps ({max_steps}) before reaching pc={stop:#06X}; \
                     stopped at pc={:#06X}",
                    self.pc
                ));
            }
            self.step()?;
            executed += 1;
        }
        Ok(executed)
    }
}

impl Default for Mos6502 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical eight-case ADC signed-overflow known-answer table.
    /// See the module doc's "Known-answer vector provenance" section for
    /// where this table comes from and how the expected values were
    /// derived. Each case starts with carry clear and asserts the
    /// resulting accumulator value, V, and C together — not just one of
    /// the three — because a passing V flag with a wrong accumulator (or
    /// vice versa) would still indicate a real bug.
    #[test]
    fn adc_overflow_known_answer_vectors() {
        // (a, operand, expected_result, expected_v, expected_c)
        let cases: [(u8, u8, u8, bool, bool); 8] = [
            // 0x50 (+80) + 0x10 (+16) = 0x60 (+96): no overflow, in range.
            (0x50, 0x10, 0x60, false, false),
            // 0x50 (+80) + 0x50 (+80) = 0xA0 (wraps to -96 signed):
            // positive + positive producing a negative result -> overflow.
            (0x50, 0x50, 0xA0, true, false),
            // 0x50 (+80) + 0x90 (-112) = 0xE0 (-32 signed): operands
            // differ in sign, so overflow cannot occur.
            (0x50, 0x90, 0xE0, false, false),
            // 0x50 (+80) + 0xD0 (-48) = 0x120 -> 0x20 (+32), carry out.
            // Operands differ in sign, so no overflow, despite the carry.
            (0x50, 0xD0, 0x20, false, true),
            // 0xD0 (-48) + 0x10 (+16) = 0xE0 (-32): operands differ in
            // sign, no overflow.
            (0xD0, 0x10, 0xE0, false, false),
            // 0xD0 (-48) + 0x50 (+80) = 0x120 -> 0x20 (+32), carry out.
            // Operands differ in sign, no overflow.
            (0xD0, 0x50, 0x20, false, true),
            // 0xD0 (-48) + 0x90 (-112) = 0x160 -> 0x60 (+96 signed),
            // carry out. Both operands negative, result positive ->
            // overflow.
            (0xD0, 0x90, 0x60, true, true),
            // 0xD0 (-48) + 0xD0 (-48) = 0x1A0 -> 0xA0 (-96 signed), carry
            // out. Both operands negative, result still negative -> no
            // overflow.
            (0xD0, 0xD0, 0xA0, false, true),
        ];

        for (i, (a, operand, expected_result, expected_v, expected_c)) in
            cases.into_iter().enumerate()
        {
            let mut cpu = Mos6502::new();
            cpu.a = a;
            cpu.mem[0x10] = operand;
            cpu.set_flag(flag::C, false); // every case starts carry-clear
            cpu.pc = 0x0200;
            // ADC $10
            cpu.load(0x0200, &[0x65, 0x10]);
            cpu.step().unwrap();

            assert_eq!(
                cpu.a, expected_result,
                "case {i}: {a:#04X} + {operand:#04X} -> expected result {expected_result:#04X}, got {:#04X}",
                cpu.a
            );
            assert_eq!(
                cpu.get_flag(flag::V),
                expected_v,
                "case {i}: {a:#04X} + {operand:#04X} -> expected V={expected_v}, got {}",
                cpu.get_flag(flag::V)
            );
            assert_eq!(
                cpu.get_flag(flag::C),
                expected_c,
                "case {i}: {a:#04X} + {operand:#04X} -> expected C={expected_c}, got {}",
                cpu.get_flag(flag::C)
            );
        }
    }

    #[test]
    fn lsr_sets_carry_from_shifted_out_bit() {
        // 0x03 (0b0000_0011) shifted right: bit0 = 1 -> carry set,
        // result = 0b0000_0001 = 0x01.
        let mut cpu = Mos6502::new();
        cpu.mem[0x20] = 0x03;
        cpu.set_flag(flag::C, false);
        cpu.pc = 0x0200;
        cpu.load(0x0200, &[0x46, 0x20]); // LSR $20
        cpu.step().unwrap();
        assert_eq!(cpu.mem[0x20], 0x01);
        assert!(cpu.get_flag(flag::C), "bit0 was 1, carry must be set");
    }

    #[test]
    fn lsr_clears_carry_when_shifted_out_bit_is_zero() {
        // 0x02 (0b0000_0010) shifted right: bit0 = 0 -> carry cleared,
        // result = 0b0000_0001 = 0x01.
        let mut cpu = Mos6502::new();
        cpu.mem[0x20] = 0x02;
        cpu.set_flag(flag::C, true); // start set, to prove it gets cleared
        cpu.pc = 0x0200;
        cpu.load(0x0200, &[0x46, 0x20]); // LSR $20
        cpu.step().unwrap();
        assert_eq!(cpu.mem[0x20], 0x01);
        assert!(!cpu.get_flag(flag::C), "bit0 was 0, carry must be cleared");
    }

    #[test]
    fn ror_accumulator_rotates_incoming_carry_into_bit7() {
        // A = 0x00, carry in = 1 -> new bit7 = 1, so A becomes 0x80.
        // The old bit0 of A (0) becomes the new carry, so carry clears.
        let mut cpu = Mos6502::new();
        cpu.a = 0x00;
        cpu.set_flag(flag::C, true);
        cpu.pc = 0x0200;
        cpu.load(0x0200, &[0x6A]); // ROR A
        cpu.step().unwrap();
        assert_eq!(cpu.a, 0x80, "incoming carry must land in bit7");
        assert!(
            !cpu.get_flag(flag::C),
            "old bit0 of A was 0, new carry must be cleared"
        );
    }

    #[test]
    fn ror_zeropage_does_not_set_bit7_when_carry_in_is_clear() {
        // M = 0x01, carry in = 0 -> new bit7 = 0. Old bit0 of M (1)
        // becomes the new carry, so carry sets. Result = 0x00.
        let mut cpu = Mos6502::new();
        cpu.mem[0x30] = 0x01;
        cpu.set_flag(flag::C, false);
        cpu.pc = 0x0200;
        cpu.load(0x0200, &[0x66, 0x30]); // ROR $30
        cpu.step().unwrap();
        assert_eq!(
            cpu.mem[0x30], 0x00,
            "no incoming carry, bit7 of result must be 0"
        );
        assert!(
            cpu.get_flag(flag::C),
            "old bit0 of M was 1, new carry must be set"
        );
    }

    #[test]
    fn backward_branch_taken_lands_at_exact_target_pc() {
        // Program at 0x0200:
        //   0x0200: BCC -4   (0x90, 0xFC)
        // The offset byte 0xFC, interpreted as a signed i8, is -4. Per the
        // documented relative-addressing rule, the offset is added to the
        // address immediately following this two-byte instruction
        // (0x0202), giving a target of 0x0202 - 4 = 0x01FE.
        let mut cpu = Mos6502::new();
        cpu.set_flag(flag::C, false); // BCC branches when C is clear
        cpu.pc = 0x0200;
        cpu.load(0x0200, &[0x90, 0xFC]);
        cpu.step().unwrap();
        assert_eq!(
            cpu.pc, 0x01FE,
            "backward branch must land at (address-after-instruction) + offset"
        );
    }

    #[test]
    fn backward_branch_not_taken_falls_through_to_next_instruction() {
        // Same program and offset as above, but with C set so BCC's
        // condition (branch when C clear) is false: pc must simply end up
        // just past the two-byte instruction, at 0x0202, with no offset
        // applied at all.
        let mut cpu = Mos6502::new();
        cpu.set_flag(flag::C, true); // condition false: no branch
        cpu.pc = 0x0200;
        cpu.load(0x0200, &[0x90, 0xFC]);
        cpu.step().unwrap();
        assert_eq!(
            cpu.pc, 0x0202,
            "branch not taken must fall through to the very next instruction"
        );
    }

    #[test]
    fn unimplemented_opcode_refuses_loudly_and_names_itself() {
        // 0x00 (BRK) is deliberately not in the implemented set.
        let mut cpu = Mos6502::new();
        cpu.pc = 0x0200;
        cpu.load(0x0200, &[0x00]);
        let err = cpu.step().expect_err("BRK (0x00) must not be implemented");
        assert!(
            err.contains("0x00") || err.to_uppercase().contains("0X00"),
            "error must name the unimplemented opcode in hex, got: {err}"
        );
    }

    #[test]
    fn run_until_pc_reports_error_instead_of_looping_forever() {
        // An infinite loop that never reaches the stop address: JMP-like
        // behaviour is not implemented, so simulate "never arrives" with a
        // BNE that keeps branching back to itself forever (Z is never set
        // by anything in this tiny program, so the branch is always
        // taken), and ask to stop at an address this program can never
        // reach.
        let mut cpu = Mos6502::new();
        cpu.set_flag(flag::Z, false); // BNE branches while Z stays clear
        cpu.pc = 0x0200;
        // BNE -2: branches back to itself forever (0x0202 - 2 = 0x0200).
        cpu.load(0x0200, &[0xD0, 0xFE]);
        let result = cpu.run_until_pc(0x9999, 1000);
        assert!(
            result.is_err(),
            "a program that never reaches the stop pc must error, not hang"
        );
    }

    #[test]
    fn clc_and_dex_and_sta_and_nop_do_the_obvious_thing() {
        // Small sanity sweep for the remaining implied/zero-page
        // instructions that don't need their own dedicated flag test: CLC
        // clears carry, DEX decrements X and sets Z/N, STA stores A to
        // memory unconditionally, and NOP does nothing but advance pc.
        let mut cpu = Mos6502::new();
        cpu.set_flag(flag::C, true);
        cpu.x = 0x01;
        cpu.a = 0x42;
        cpu.pc = 0x0200;
        cpu.load(0x0200, &[0x18, 0xCA, 0x85, 0x40, 0xEA]);

        cpu.step().unwrap(); // CLC
        assert!(!cpu.get_flag(flag::C));

        cpu.step().unwrap(); // DEX: 0x01 -> 0x00
        assert_eq!(cpu.x, 0x00);
        assert!(cpu.get_flag(flag::Z));
        assert!(!cpu.get_flag(flag::N));

        cpu.step().unwrap(); // STA $40
        assert_eq!(cpu.mem[0x40], 0x42);

        let pc_before_nop = cpu.pc;
        cpu.step().unwrap(); // NOP
        assert_eq!(cpu.pc, pc_before_nop + 1);
    }
}
