use anyhow::{bail, Context, Result};
use goblin::elf::{program_header::PT_LOAD, Elf};
use std::env;
use std::fs;
use std::path::PathBuf;

const DEFAULT_BASE: u64 = 0x400000;
const R_AARCH64_RELATIVE: u32 = 1027;

fn parse_base(args: &[String]) -> u64 {
    let mut base = DEFAULT_BASE;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(v) = arg.strip_prefix("--base=") {
            if let Ok(parsed) = u64::from_str_radix(v.trim_start_matches("0x"), 16) {
                base = parsed;
            }
        } else if arg == "--base" {
            if let Some(next) = iter.peek() {
                if let Ok(parsed) = u64::from_str_radix(next.trim_start_matches("0x"), 16) {
                    base = parsed;
                }
            }
        }
    }
    base
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: memory_dump_builder <path_to_so> [output=memory_dump.bin] [--base 0x400000]");
        std::process::exit(1);
    }

    let input_path = PathBuf::from(&args[1]);
    let output_path = if args.len() >= 3 && !args[2].starts_with("--") {
        PathBuf::from(&args[2])
    } else {
        PathBuf::from("memory_dump.bin")
    };
    let base = parse_base(&args);

    let bytes = fs::read(&input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    let elf = Elf::parse(&bytes).context("Failed to parse ELF")?;
    if elf.is_64 == false {
        bail!("Unsupported ELF: expected 64-bit");
    }

    let mut max_end: u64 = 0;
    for ph in &elf.program_headers {
        if ph.p_type == PT_LOAD {
            let end = ph.p_vaddr.saturating_add(ph.p_memsz);
            if end > max_end {
                max_end = end;
            }
        }
    }

    if max_end == 0 {
        bail!("No PT_LOAD segments found");
    }
    if max_end as usize as u64 != max_end {
        bail!("Image size too large to allocate");
    }

    let mut image = vec![0u8; max_end as usize];

    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD || ph.p_filesz == 0 {
            continue;
        }
        let src_start = ph.p_offset as usize;
        let src_end = src_start + ph.p_filesz as usize;
        let dst_start = ph.p_vaddr as usize;
        let dst_end = dst_start + ph.p_filesz as usize;

        if src_end > bytes.len() || dst_end > image.len() {
            bail!("Segment out of bounds while mapping PT_LOAD");
        }
        image[dst_start..dst_end].copy_from_slice(&bytes[src_start..src_end]);
    }

    // Apply basic RELATIVE relocations
    let mut applied = 0usize;
    let mut skipped = 0usize;
    for r in elf.dynrelas.iter().chain(elf.pltrelocs.iter()) {
        if r.r_type != R_AARCH64_RELATIVE {
            skipped += 1;
            continue;
        }
        let offset = r.r_offset as usize;
        if offset + 8 > image.len() {
            skipped += 1;
            continue;
        }
        let addend = r.r_addend.unwrap_or(0) as i64;
        let value = base.wrapping_add(addend as u64).to_le_bytes();
        image[offset..offset + 8].copy_from_slice(&value);
        applied += 1;
    }

    fs::write(&output_path, &image)
        .with_context(|| format!("Failed to write {}", output_path.display()))?;

    println!("memory_dump.bin generated: {} bytes", image.len());
    println!("Base: 0x{:x} | RELATIVE relocations applied: {} | skipped: {}", base, applied, skipped);
    println!("Output: {}", output_path.display());

    Ok(())
}