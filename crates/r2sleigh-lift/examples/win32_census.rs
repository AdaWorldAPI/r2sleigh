//! PROBE-CALLOTHER-WIN32 — the OS-boundary census.
//!
//! # The question
//!
//! The "dowry" thesis says a 40-year-old business binary can be lowered to
//! R2IL and its logic thereby OWNED as addressable rows. The standing
//! objection is that p-code lifts the ISA but not the operating system: a
//! Win32 binary's real behaviour partly IS the OS.
//!
//! This measures the ratio instead of arguing about it.
//!
//! # The distinction this probe exists to make
//!
//! Two DIFFERENT populations are routinely conflated (I conflated them
//! myself before measuring):
//!
//! 1. **`CALLOTHER`** — an instruction SLEIGH has no p-code semantics for
//!    (`cpuid`, `rdtsc`, most SIMD, `syscall`). This is *machine* opacity:
//!    the lifter decoded the instruction but cannot say what it MEANS.
//!    Nothing downstream can execute it.
//!
//! 2. **Imported calls** — an ordinary `CALL` through the IAT to
//!    `kernel32!CreateFileA`. p-code lifts this PERFECTLY; the op is a
//!    normal `Call`. What escapes is not the semantics of the call site but
//!    the *callee's body*, which is not in this binary at all.
//!
//! Both are "logic we did not capture", but they have opposite remedies —
//! (1) needs a p-code semantic for the instruction, (2) needs a model of
//! the API. Reporting one number for both would be the measurement error.
//!
//! # Honest limits, stated up front
//!
//! - **Linear sweep.** x86-64 is variable-length and `.text` contains data,
//!   padding and jump tables, so a linear sweep decodes some garbage. The
//!   probe reports decode failures rather than hiding them; treat the op
//!   counts as an upper-bound-shaped estimate, not a recursive-descent CFG.
//! - **The CRT is included**, deliberately. When you lift someone's binary
//!   you do not get to exclude the runtime — it is part of what you bought.
//!   The probe reports the whole-`.text` figure and says so.
//!
//! Run: `cargo run -p r2sleigh-lift --features x86 --example win32_census -- <path.exe>`

use std::collections::BTreeMap;

use r2il::{OpColumns, OpTag, R2ILOp, SpaceId};
use r2sleigh_lift::Disassembler;
use sleigh_config::processor_x86::{PSPEC_X86_64, SLA_X86_64};

/// Minimum window `Disassembler::lift` requires; padded so a decode near the
/// end of `.text` cannot fail for want of bytes rather than for want of a
/// valid instruction.
const LIFT_WINDOW: usize = 16;

fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

struct Section {
    name: String,
    va: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
}

struct Pe {
    image_base: u64,
    entry_rva: u32,
    sections: Vec<Section>,
    /// Data directory 12 = Import Address Table (RVA, size).
    iat: (u32, u32),
}

/// Hand-rolled, deliberately: the census must not depend on a PE crate whose
/// own heuristics could shape the answer.
fn parse_pe(b: &[u8]) -> Result<Pe, String> {
    if b.len() < 0x40 || &b[0..2] != b"MZ" {
        return Err("not an MZ image".into());
    }
    let pe_off = rd_u32(b, 0x3c) as usize;
    if b.len() < pe_off + 24 || &b[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err("no PE signature".into());
    }
    let n_sections = rd_u16(b, pe_off + 6) as usize;
    let opt_size = rd_u16(b, pe_off + 20) as usize;
    let opt = pe_off + 24;
    let magic = rd_u16(b, opt);
    if magic != 0x20b {
        return Err(format!("expected PE32+ (0x20b), got {magic:#x}"));
    }
    let entry_rva = rd_u32(b, opt + 16);
    let image_base = rd_u64(b, opt + 24);
    // PE32+: NumberOfRvaAndSizes at optional-header offset 108; dirs follow.
    let n_dirs = rd_u32(b, opt + 108) as usize;
    let dirs = opt + 112;
    let iat = if n_dirs > 12 {
        (rd_u32(b, dirs + 12 * 8), rd_u32(b, dirs + 12 * 8 + 4))
    } else {
        (0, 0)
    };

    let sec_off = opt + opt_size;
    let mut sections = Vec::new();
    for i in 0..n_sections {
        let s = sec_off + i * 40;
        if s + 40 > b.len() {
            break;
        }
        let raw_name = &b[s..s + 8];
        let end = raw_name.iter().position(|&c| c == 0).unwrap_or(8);
        sections.push(Section {
            name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
            vsize: rd_u32(b, s + 8),
            va: rd_u32(b, s + 12),
            raw_size: rd_u32(b, s + 16),
            raw_ptr: rd_u32(b, s + 20),
        });
    }
    Ok(Pe {
        image_base,
        entry_rva,
        sections,
        iat,
    })
}

#[derive(Default)]
struct Census {
    instructions: u64,
    decode_failures: u64,
    bytes_swept: u64,
    ops_total: u64,
    ops_by_kind: BTreeMap<&'static str, u64>,
    callother_total: u64,
    callother_by_userop: BTreeMap<String, u64>,
    call_direct: u64,
    call_indirect: u64,
    call_into_text: u64,
    call_into_iat: u64,
    call_elsewhere: u64,
    /// Indirect calls whose target was loaded from an address inside the IAT
    /// — i.e. an ordinary Win32 API call. See `classify_indirect`.
    callind_via_iat: u64,
    callind_unresolved: u64,
    /// Distinct IAT slots actually called: the real imported-API surface.
    iat_slots_called: std::collections::BTreeSet<u64>,
    dumped: u32,
}

/// Resolve `call qword ptr [rip+disp]`.
///
/// On x86-64 a Win32 API call is NOT a direct `CALL` to the IAT — it is an
/// indirect call through it, which SLEIGH lifts as a `Load` from a constant
/// RAM address followed by `CallInd` on the loaded temporary. A classifier
/// that only inspects `Call` targets therefore reports ZERO imported calls on
/// a binary full of them. That false negative is why this function exists:
/// the first measurement said `-> IAT 0` and the apparatus, not the binary,
/// was the reason.
///
/// Returns the IAT address the callee was loaded from, if any.
fn indirect_target_slot(ops: &[R2ILOp], idx: usize, iat: (u64, u64)) -> Option<u64> {
    let want = match &ops[idx] {
        R2ILOp::CallInd { target } => target,
        _ => return None,
    };
    // Walk backwards for the op that produced this temporary.
    //
    // MEASURED (not assumed — see the module docs): SLEIGH lifts
    // `call qword ptr [rip+disp]` as a `Copy` whose SOURCE is a `Ram`-space
    // varnode holding the already-folded absolute address, NOT as a `Load`.
    // Both shapes are accepted: `Copy`-from-Ram is what x86-64 produces here,
    // `Load` is kept for lifts that model the fetch explicitly.
    for prev in ops[..idx].iter().rev() {
        let (dst, addr) = match prev {
            R2ILOp::Copy { dst, src } if src.space == SpaceId::Ram => (dst, src.offset),
            R2ILOp::Load { dst, addr, .. } => (dst, addr.offset),
            _ => continue,
        };
        if dst.space == want.space && dst.offset == want.offset {
            return if addr >= iat.0 && addr < iat.1 {
                Some(addr)
            } else {
                None
            };
        }
    }
    None
}

fn kind_of(op: &R2ILOp) -> &'static str {
    match op {
        R2ILOp::Branch { .. } => "Branch",
        R2ILOp::CBranch { .. } => "CBranch",
        R2ILOp::BranchInd { .. } => "BranchInd",
        R2ILOp::Call { .. } => "Call",
        R2ILOp::CallInd { .. } => "CallInd",
        R2ILOp::Return { .. } => "Return",
        R2ILOp::CallOther { .. } => "CallOther",
        _ => "data/arith",
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: win32_census <path-to-pe.exe>");
        std::process::exit(2);
    });
    let image = std::fs::read(&path).expect("read PE");
    let pe = parse_pe(&image).expect("parse PE");

    let text = pe
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .expect(".text section");

    let text_lo = pe.image_base + text.va as u64;
    let text_hi = text_lo + text.vsize as u64;
    let iat_lo = pe.image_base + pe.iat.0 as u64;
    let iat_hi = iat_lo + pe.iat.1 as u64;

    println!("== image ==");
    println!("  file            {path}");
    println!("  image_base      {:#x}", pe.image_base);
    println!(
        "  entry           {:#x}",
        pe.image_base + pe.entry_rva as u64
    );
    println!(
        "  .text           {text_lo:#x}..{text_hi:#x}  ({} bytes)",
        text.vsize
    );
    println!(
        "  IAT             {iat_lo:#x}..{iat_hi:#x}  ({} bytes)",
        pe.iat.1
    );
    println!("  sections        {}", pe.sections.len());

    let disasm = Disassembler::from_sla(SLA_X86_64, PSPEC_X86_64, "x86-64")
        .expect("load x86-64 SLEIGH spec");

    // Pad so a decode at the tail fails for want of a valid instruction, never
    // for want of bytes.
    let start = text.raw_ptr as usize;
    let len = (text.raw_size as usize).min(image.len().saturating_sub(start));
    let mut buf = image[start..start + len].to_vec();
    buf.extend(std::iter::repeat_n(0u8, LIFT_WINDOW));

    let mut c = Census::default();
    // Columnar projection built alongside the AoS scan, purely so the two
    // can be compared on REAL data. See the equivalence check after the
    // sweep — synthetic streams cannot falsify a projection the way 12 000
    // ops of actual x86-64 can.
    let mut cols = OpColumns::default();
    let mut off = 0usize;
    while off < len {
        let addr = text_lo + off as u64;
        match disasm.lift(&buf[off..off + LIFT_WINDOW], addr) {
            Ok(block) => {
                let size = block.size.max(1) as usize;
                if std::env::var("WIN32_CENSUS_DUMP").is_ok()
                    && block
                        .ops
                        .iter()
                        .any(|o| matches!(o, R2ILOp::CallInd { .. } | R2ILOp::BranchInd { .. }))
                    && c.dumped < 4
                {
                    c.dumped += 1;
                    println!("--- block @ {addr:#x} size={size}");
                    for (i, o) in block.ops.iter().enumerate() {
                        println!("    [{i}] {o:?}");
                    }
                }
                c.instructions += 1;
                c.bytes_swept += size as u64;
                cols.extend(&block.ops);
                for (op_idx, op) in block.ops.iter().enumerate() {
                    c.ops_total += 1;
                    *c.ops_by_kind.entry(kind_of(op)).or_insert(0) += 1;
                    match op {
                        R2ILOp::CallOther { userop, .. } => {
                            c.callother_total += 1;
                            let name = disasm
                                .userop_name(*userop)
                                .map(str::to_owned)
                                .unwrap_or_else(|| format!("userop#{userop}"));
                            *c.callother_by_userop.entry(name).or_insert(0) += 1;
                        }
                        R2ILOp::Call { target } => {
                            c.call_direct += 1;
                            if target.space == SpaceId::Ram || target.space == SpaceId::Const {
                                let t = target.offset;
                                if t >= text_lo && t < text_hi {
                                    c.call_into_text += 1;
                                } else if pe.iat.1 > 0 && t >= iat_lo && t < iat_hi {
                                    c.call_into_iat += 1;
                                } else {
                                    c.call_elsewhere += 1;
                                }
                            } else {
                                c.call_elsewhere += 1;
                            }
                        }
                        R2ILOp::CallInd { .. } => {
                            c.call_indirect += 1;
                            match indirect_target_slot(&block.ops, op_idx, (iat_lo, iat_hi)) {
                                Some(slot) => {
                                    c.callind_via_iat += 1;
                                    c.iat_slots_called.insert(slot);
                                }
                                None => c.callind_unresolved += 1,
                            }
                        }
                        _ => {}
                    }
                }
                off += size;
            }
            Err(_) => {
                c.decode_failures += 1;
                off += 1;
            }
        }
    }

    println!("\n== sweep (linear, whole .text incl. CRT) ==");
    println!("  instructions    {}", c.instructions);
    println!("  decode failures {}", c.decode_failures);
    println!("  bytes swept     {} / {}", c.bytes_swept, len);
    println!("  p-code ops      {}", c.ops_total);

    println!("\n== op mix ==");
    for (k, v) in &c.ops_by_kind {
        let pct = 100.0 * *v as f64 / c.ops_total.max(1) as f64;
        println!("  {k:<12} {v:>8}  {pct:>6.2}%");
    }

    println!("\n== population 1: CALLOTHER (no p-code semantics) ==");
    println!(
        "  total           {}  ({:.4}% of ops)",
        c.callother_total,
        100.0 * c.callother_total as f64 / c.ops_total.max(1) as f64
    );
    if c.callother_by_userop.is_empty() {
        println!("  (none)");
    } else {
        let mut v: Vec<_> = c.callother_by_userop.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        for (name, n) in v.iter().take(20) {
            println!("  {name:<28} {n}");
        }
    }

    println!("\n== population 2: calls, by where the CALLEE lives ==");
    println!("  direct calls    {}", c.call_direct);
    println!(
        "    -> .text      {}   (intra-binary: captured)",
        c.call_into_text
    );
    println!("    -> IAT        {}   (OS: escapes)", c.call_into_iat);
    println!("    -> elsewhere  {}", c.call_elsewhere);
    println!("  indirect calls  {}", c.call_indirect);
    println!(
        "    -> via IAT    {}   (OS: escapes — the real import surface)",
        c.callind_via_iat
    );
    println!("    -> unresolved {}", c.callind_unresolved);
    println!("  distinct IAT slots called: {}", c.iat_slots_called.len());

    let os_calls = c.call_into_iat + c.callind_via_iat;
    let own_calls = c.call_into_text;
    let denom = (os_calls + own_calls).max(1);
    println!(
        "\n  call sites: own-code {own_calls} vs OS {os_calls}  ->  {:.1}% of resolved calls stay inside the binary",
        100.0 * own_calls as f64 / denom as f64
    );

    let captured = c.ops_total - c.callother_total;
    // ── columnar equivalence, on the real stream ─────────────────────────
    //
    // The SoA projection exists so scans can be vectorized later. It is only
    // worth anything if it answers IDENTICALLY to the AoS scan — and the
    // place that gets proven is here, on a real binary, not on a five-op
    // fixture. A projection that silently disagreed would be worse than no
    // projection: every consumer would inherit the discrepancy.
    assert_eq!(
        cols.len() as u64,
        c.ops_total,
        "columns must carry exactly one entry per op"
    );
    let hist = cols.tag_histogram();
    assert_eq!(
        hist[OpTag::CallOther as usize],
        c.callother_total,
        "columnar CallOther count disagrees with the AoS scan"
    );
    assert_eq!(
        hist[OpTag::Call as usize],
        c.call_direct,
        "columnar Call count disagrees with the AoS scan"
    );
    assert_eq!(
        hist[OpTag::CallInd as usize],
        c.call_indirect,
        "columnar CallInd count disagrees with the AoS scan"
    );
    assert_eq!(
        cols.find_tag(OpTag::CallOther).len() as u64,
        c.callother_total,
        "find_tag and the histogram disagree with each other"
    );
    println!(
        "\n== columnar equivalence == OK  ({} ops projected; CallOther/Call/CallInd match)",
        cols.len()
    );

    println!("\n== headline ==");
    println!(
        "  ops with p-code semantics : {captured} / {} = {:.4}%",
        c.ops_total,
        100.0 * captured as f64 / c.ops_total.max(1) as f64
    );
    println!("  (this is MACHINE capture, NOT semantic capture — see population 2)");
}

// ── debug arm ────────────────────────────────────────────────────────────
// Set WIN32_CENSUS_DUMP=1 to print the ops of every block containing an
// indirect control transfer. Kept because the first two classifier versions
// were BOTH wrong and only reading the real lift settled it.
