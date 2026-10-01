//! PE32 and PE32+ images (EXE, DLL, SYS).

use crate::model::*;
use crate::reader::{Endian, Error, Reader, Result};

struct Sec {
    va: u64,
    vsize: u64,
    raw_ptr: u64,
    raw_size: u64,
}

fn machine_name(m: u16) -> String {
    match m {
        0x014c => "x86",
        0x0200 => "IA-64",
        0x01c0 | 0x01c4 => "ARM",
        0x8664 => "x86-64",
        0xaa64 => "AArch64",
        0x5032 => "RISC-V 32",
        0x5064 => "RISC-V 64",
        other => return format!("machine {other:#x}"),
    }
    .to_string()
}

fn subsystem(s: u16) -> &'static str {
    match s {
        1 => "native",
        2 => "Windows GUI",
        3 => "Windows console",
        5 => "OS/2 console",
        7 => "POSIX console",
        9 => "Windows CE",
        10 => "EFI application",
        11 => "EFI boot driver",
        12 => "EFI runtime driver",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => "unknown subsystem",
    }
}

fn reloc_type(t: u16) -> String {
    match t {
        1 => "HIGH".into(),
        2 => "LOW".into(),
        3 => "HIGHLOW".into(),
        4 => "HIGHADJ".into(),
        10 => "DIR64".into(),
        other => format!("type {other}"),
    }
}

/// Section permissions from IMAGE_SCN_MEM_READ, WRITE and EXECUTE.
fn perms(c: u32) -> String {
    format!(
        "{}{}{}",
        if c & 0x4000_0000 != 0 { 'r' } else { '-' },
        if c & 0x8000_0000 != 0 { 'w' } else { '-' },
        if c & 0x2000_0000 != 0 { 'x' } else { '-' }
    )
}

fn section_kind(c: u32) -> &'static str {
    if c & 0x20 != 0 {
        "code"
    } else if c & 0x40 != 0 {
        "initialized data"
    } else if c & 0x80 != 0 {
        "uninitialized data"
    } else {
        "other"
    }
}

struct Image<'a> {
    r: Reader<'a>,
    secs: Vec<Sec>,
    size_of_headers: u64,
}

impl Image<'_> {
    /// Maps an RVA to a file offset through the section table.
    fn rva(&self, rva: u64) -> Result<u64> {
        if rva < self.size_of_headers {
            return Ok(rva);
        }
        for s in &self.secs {
            let span = s.vsize.max(s.raw_size);
            if rva >= s.va && rva - s.va < span {
                let delta = rva - s.va;
                if delta >= s.raw_size {
                    return Err(Error::Malformed(format!("RVA {rva:#x} lies in uninitialized section space")));
                }
                return Ok(s.raw_ptr.saturating_add(delta));
            }
        }
        Err(Error::Malformed(format!("RVA {rva:#x} is not inside any section")))
    }

    fn cstr_at_rva(&self, rva: u64, what: &'static str) -> Result<String> {
        self.r.cstr(self.rva(rva)?, what)
    }
}

pub fn parse(data: &[u8]) -> Result<Binary> {
    let r = Reader::new(data, Endian::Little);
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return Err(Error::Malformed("missing MZ header".into()));
    }
    let lfanew = r.u32(0x3c, "DOS header")? as u64;
    if r.bytes(lfanew, 4, "PE signature")? != b"PE\0\0" {
        return Err(Error::Malformed("missing PE signature".into()));
    }
    let coff = lfanew + 4;
    let machine = r.u16(coff, "COFF header")?;
    let nsec = r.u16(coff + 2, "COFF header")? as u64;
    let opt_size = r.u16(coff + 16, "COFF header")? as u64;
    let characteristics = r.u16(coff + 18, "COFF header")?;
    let opt = coff + 20;
    let magic = r.u16(opt, "optional header")?;
    let wide = match magic {
        0x10b => false,
        0x20b => true,
        0x107 => return Err(Error::Unsupported("ROM image".into())),
        m => return Err(Error::Malformed(format!("unknown optional header magic {m:#x}"))),
    };
    let entry = r.u32(opt + 16, "optional header")? as u64;
    let image_base = if wide { r.u64(opt + 24, "optional header")? } else { r.u32(opt + 28, "optional header")? as u64 };
    let size_of_headers = r.u32(opt + 60, "optional header")? as u64;
    let sub = r.u16(opt + 68, "optional header")?;
    let dll_chars = r.u16(opt + 70, "optional header")?;
    let ndirs = r.u32(opt + if wide { 108 } else { 92 }, "optional header")? as u64;
    let dirs_off = opt + if wide { 112 } else { 96 };
    let dir = |i: u64| -> Result<(u64, u64)> {
        if i >= ndirs.min(16) {
            return Ok((0, 0));
        }
        Ok((r.u32(dirs_off + i * 8, "data directory")? as u64, r.u32(dirs_off + i * 8 + 4, "data directory")? as u64))
    };

    let mut bin = Binary::empty(Format::Pe);
    bin.bits = if wide { 64 } else { 32 };
    bin.arch = machine_name(machine);
    bin.entry = entry;
    bin.image_base = Some(image_base);

    // Section table, after the optional header.
    if nsec > 1000 {
        return Err(Error::Malformed(format!("{nsec} sections")));
    }
    let table = opt + opt_size;
    let mut secs = Vec::new();
    for i in 0..nsec {
        let b = table + i * 40;
        let raw_name = r.bytes(b, 8, "section header")?;
        let end = raw_name.iter().position(|c| *c == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
        let vsize = r.u32(b + 8, "section header")? as u64;
        let va = r.u32(b + 12, "section header")? as u64;
        let raw_size = r.u32(b + 16, "section header")? as u64;
        let raw_ptr = r.u32(b + 20, "section header")? as u64;
        let flags = r.u32(b + 36, "section header")?;
        bin.sections.push(Section {
            name,
            address: image_base.saturating_add(va),
            file_offset: raw_ptr,
            size: vsize.max(raw_size),
            permissions: perms(flags),
            kind: section_kind(flags).to_string(),
        });
        secs.push(Sec { va, vsize, raw_ptr, raw_size });
    }
    let img = Image { r, secs, size_of_headers };

    bin.kind = if characteristics & 0x2000 != 0 {
        "DLL".into()
    } else if sub == 1 {
        "driver".into()
    } else {
        format!("executable ({})", subsystem(sub))
    };
    for (bit, name) in [(0x20, "high-entropy ASLR"), (0x40, "ASLR"), (0x100, "DEP"), (0x4000, "CFG"), (0x1000, "AppContainer")] {
        if dll_chars & bit != 0 {
            bin.features.push(name.to_string());
        }
    }
    if dll_chars & 0x400 != 0 {
        bin.features.push("no SEH".into());
    }
    if !wide && characteristics & 0x20 != 0 {
        bin.features.push("large address aware".into());
    }
    if dir(4)?.1 != 0 {
        bin.features.push("signed (certificate present)".into());
    }

    // Imports.
    let (imp_rva, _) = dir(1)?;
    if imp_rva != 0 {
        if let Err(e) = read_imports(&img, imp_rva, wide, &mut bin) {
            bin.notes.push(format!("import table not fully read: {e}"));
        }
    }
    // Exports.
    let (exp_rva, exp_size) = dir(0)?;
    if exp_rva != 0 {
        if let Err(e) = read_exports(&img, exp_rva, exp_size, &mut bin) {
            bin.notes.push(format!("export table not fully read: {e}"));
        }
    }
    // Base relocations.
    let (rel_rva, rel_size) = dir(5)?;
    if rel_rva != 0 {
        if let Err(e) = read_relocs(&img, rel_rva, rel_size, &mut bin) {
            bin.notes.push(format!("relocation table not fully read: {e}"));
        }
    }
    // Delay-load imports.
    let (delay_rva, _) = dir(13)?;
    if delay_rva != 0 {
        if let Err(e) = read_delay_imports(&img, delay_rva, wide, &mut bin) {
            bin.notes.push(format!("delay-load table not fully read: {e}"));
        }
    }
    Ok(bin)
}

/// Reads one thunk list (an import lookup table) and records each entry against `dll`.
fn read_thunks(img: &Image, thunks_rva: u64, dll: &str, delay_load: bool, wide: bool, bin: &mut Binary) -> Result<()> {
    let r = &img.r;
    let (esz, ordinal_flag) = if wide { (8, 1u64 << 63) } else { (4, 1u64 << 31) };
    let thunks = img.rva(thunks_rva)?;
    for j in 0..MAX_ENTRIES {
        let t = r.word(thunks + j * esz, wide, "import thunk")?;
        if t == 0 {
            break;
        }
        // Descriptors may share one thunk list, so the cap is on the total, not per DLL.
        if bin.imports.len() as u64 >= MAX_ENTRIES {
            bin.notes.push(format!("imports capped at {MAX_ENTRIES}"));
            return Ok(());
        }
        if t & ordinal_flag != 0 {
            bin.imports.push(Import { library: Some(dll.to_string()), name: String::new(), ordinal: Some((t & 0xffff) as u32), delay_load });
        } else {
            // Skip the two byte hint.
            let name = img.cstr_at_rva((t & 0x7fff_ffff) + 2, "import name")?;
            bin.imports.push(Import { library: Some(dll.to_string()), name, ordinal: None, delay_load });
        }
    }
    Ok(())
}

fn read_imports(img: &Image, rva: u64, wide: bool, bin: &mut Binary) -> Result<()> {
    let r = &img.r;
    let base = img.rva(rva)?;
    for i in 0..4096u64 {
        let d = base + i * 20;
        let (orig_first, name_rva, first) = (r.u32(d, "import descriptor")? as u64, r.u32(d + 12, "import descriptor")? as u64, r.u32(d + 16, "import descriptor")? as u64);
        if orig_first == 0 && name_rva == 0 && first == 0 {
            break;
        }
        let dll = img.cstr_at_rva(name_rva, "import DLL name")?;
        if !bin.libraries.contains(&dll) {
            bin.libraries.push(dll.clone());
        }
        // The import lookup table is the unbound copy; fall back to the address table.
        read_thunks(img, if orig_first != 0 { orig_first } else { first }, &dll, false, wide, bin)?;
    }
    Ok(())
}

/// Delay-load descriptors (32 bytes each). Only the RVA form used by current linkers is read.
fn read_delay_imports(img: &Image, rva: u64, wide: bool, bin: &mut Binary) -> Result<()> {
    let r = &img.r;
    let base = img.rva(rva)?;
    for i in 0..4096u64 {
        let d = base + i * 32;
        let (attrs, name_rva, int_rva) = (r.u32(d, "delay descriptor")?, r.u32(d + 4, "delay descriptor")? as u64, r.u32(d + 16, "delay descriptor")? as u64);
        if attrs == 0 && name_rva == 0 && int_rva == 0 {
            break;
        }
        if attrs & 1 == 0 {
            return Err(Error::Unsupported("delay-load table uses virtual addresses (pre-VC7 linker)".into()));
        }
        let dll = img.cstr_at_rva(name_rva, "delay-load DLL name")?;
        if !bin.libraries.contains(&dll) {
            bin.libraries.push(dll.clone());
        }
        read_thunks(img, int_rva, &dll, true, wide, bin)?;
    }
    Ok(())
}

fn read_exports(img: &Image, rva: u64, size: u64, bin: &mut Binary) -> Result<()> {
    let r = &img.r;
    let d = img.rva(rva)?;
    let ordinal_base = r.u32(d + 16, "export directory")? as u64;
    let nfuncs = r.u32(d + 20, "export directory")? as u64;
    let nnames = r.u32(d + 24, "export directory")? as u64;
    if nfuncs > MAX_ENTRIES || nnames > MAX_ENTRIES {
        return Err(Error::Malformed("implausible export counts".into()));
    }
    let funcs = img.rva(r.u32(d + 28, "export directory")? as u64)?;
    let names = img.rva(r.u32(d + 32, "export directory")? as u64)?;
    let ords = img.rva(r.u32(d + 36, "export directory")? as u64)?;
    let mut name_of: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    for j in 0..nnames {
        let idx = r.u16(ords + j * 2, "export ordinal")? as u64;
        let name = img.cstr_at_rva(r.u32(names + j * 4, "export name")? as u64, "export name")?;
        name_of.insert(idx, name);
    }
    for i in 0..nfuncs {
        let f = r.u32(funcs + i * 4, "export address")? as u64;
        if f == 0 {
            continue;
        }
        // An address inside the export directory itself is a forwarder string.
        let forwarder = (f >= rva && f < rva + size).then(|| img.cstr_at_rva(f, "forwarder")).transpose()?;
        bin.exports.push(Export { name: name_of.remove(&i), ordinal: Some((ordinal_base + i) as u32), address: f, forwarder });
    }
    Ok(())
}

fn read_relocs(img: &Image, rva: u64, size: u64, bin: &mut Binary) -> Result<()> {
    let r = &img.r;
    let base = img.rva(rva)?;
    let mut pos = 0u64;
    while pos + 8 <= size {
        let page = r.u32(base + pos, "relocation block")? as u64;
        let block = r.u32(base + pos + 4, "relocation block")? as u64;
        if block < 8 {
            return Err(Error::Malformed(format!("relocation block of {block} bytes")));
        }
        for k in 0..(block - 8) / 2 {
            let e = r.u16(base + pos + 8 + k * 2, "relocation entry")?;
            if e >> 12 == 0 {
                continue; // padding
            }
            if bin.relocations.len() as u64 >= MAX_ENTRIES {
                bin.notes.push(format!("relocations capped at {MAX_ENTRIES}"));
                return Ok(());
            }
            bin.relocations.push(Reloc { offset: page + (e & 0xfff) as u64, kind: reloc_type(e >> 12), symbol: None, addend: None });
        }
        pos += block;
    }
    Ok(())
}
