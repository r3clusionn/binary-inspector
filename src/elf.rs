//! ELF32 and ELF64, little and big endian.

use crate::model::*;
use crate::reader::{Endian, Error, Reader, Result};

const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;

struct Sec {
    name: String,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

/// A section header as stored, before its name is looked up.
struct RawSec {
    name: u32,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

struct Seg {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

fn machine_name(m: u16) -> String {
    match m {
        2 => "SPARC",
        3 => "x86",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        22 => "s390",
        40 => "ARM",
        42 => "SuperH",
        43 => "SPARC V9",
        50 => "IA-64",
        62 => "x86-64",
        94 => "Xtensa",
        183 => "AArch64",
        243 => "RISC-V",
        258 => "LoongArch",
        other => return format!("machine {other}"),
    }
    .to_string()
}

fn segment_kind(k: u32) -> String {
    match k {
        0 => "NULL".into(),
        1 => "LOAD".into(),
        2 => "DYNAMIC".into(),
        3 => "INTERP".into(),
        4 => "NOTE".into(),
        5 => "SHLIB".into(),
        6 => "PHDR".into(),
        7 => "TLS".into(),
        0x6474_e550 => "GNU_EH_FRAME".into(),
        PT_GNU_STACK => "GNU_STACK".into(),
        PT_GNU_RELRO => "GNU_RELRO".into(),
        0x6474_e553 => "GNU_PROPERTY".into(),
        other => format!("{other:#x}"),
    }
}

fn section_kind(k: u32) -> String {
    match k {
        0 => "NULL".into(),
        1 => "PROGBITS".into(),
        2 => "SYMTAB".into(),
        3 => "STRTAB".into(),
        4 => "RELA".into(),
        5 => "HASH".into(),
        6 => "DYNAMIC".into(),
        7 => "NOTE".into(),
        8 => "NOBITS".into(),
        9 => "REL".into(),
        11 => "DYNSYM".into(),
        14 => "INIT_ARRAY".into(),
        15 => "FINI_ARRAY".into(),
        0x6fff_fff6 => "GNU_HASH".into(),
        0x7000_0001 => "X86_64_UNWIND".into(),
        0x6fff_fffe => "GNU_VERNEED".into(),
        0x6fff_ffff => "GNU_VERSYM".into(),
        other => format!("{other:#x}"),
    }
}

fn perms(r: bool, w: bool, x: bool) -> String {
    format!("{}{}{}", if r { 'r' } else { '-' }, if w { 'w' } else { '-' }, if x { 'x' } else { '-' })
}

fn reloc_name(machine: u16, t: u32) -> String {
    let n = match (machine, t) {
        (62, 1) => "R_X86_64_64",
        (62, 2) => "R_X86_64_PC32",
        (62, 3) => "R_X86_64_GOT32",
        (62, 4) => "R_X86_64_PLT32",
        (62, 5) => "R_X86_64_COPY",
        (62, 6) => "R_X86_64_GLOB_DAT",
        (62, 7) => "R_X86_64_JUMP_SLOT",
        (62, 8) => "R_X86_64_RELATIVE",
        (62, 9) => "R_X86_64_GOTPCREL",
        (62, 10) => "R_X86_64_32",
        (62, 11) => "R_X86_64_32S",
        (62, 16) => "R_X86_64_DTPMOD64",
        (62, 17) => "R_X86_64_DTPOFF64",
        (62, 18) => "R_X86_64_TPOFF64",
        (62, 24) => "R_X86_64_PC64",
        (62, 37) => "R_X86_64_IRELATIVE",
        (62, 41) => "R_X86_64_GOTPCRELX",
        (62, 42) => "R_X86_64_REX_GOTPCRELX",
        (3, 1) => "R_386_32",
        (3, 2) => "R_386_PC32",
        (3, 6) => "R_386_GLOB_DAT",
        (3, 7) => "R_386_JMP_SLOT",
        (3, 8) => "R_386_RELATIVE",
        (183, 257) => "R_AARCH64_ABS64",
        (183, 258) => "R_AARCH64_ABS32",
        (183, 282) => "R_AARCH64_JUMP26",
        (183, 283) => "R_AARCH64_CALL26",
        (183, 1025) => "R_AARCH64_GLOB_DAT",
        (183, 1026) => "R_AARCH64_JUMP_SLOT",
        (183, 1027) => "R_AARCH64_RELATIVE",
        (183, 1032) => "R_AARCH64_IRELATIVE",
        _ => return format!("type {t}"),
    };
    n.to_string()
}

fn sym_kind(t: u8) -> String {
    match t {
        0 => "NOTYPE".into(),
        1 => "OBJECT".into(),
        2 => "FUNC".into(),
        3 => "SECTION".into(),
        4 => "FILE".into(),
        5 => "COMMON".into(),
        6 => "TLS".into(),
        10 => "IFUNC".into(),
        other => format!("{other}"),
    }
}

fn sym_bind(b: u8) -> String {
    match b {
        0 => "LOCAL".into(),
        1 => "GLOBAL".into(),
        2 => "WEAK".into(),
        10 => "UNIQUE".into(),
        other => format!("{other}"),
    }
}

struct Ctx<'a> {
    r: Reader<'a>,
    wide: bool,
    secs: Vec<Sec>,
}

impl Ctx<'_> {
    fn sec_name(&self, idx: u16) -> String {
        match idx {
            0 => "UND".into(),
            0xfff1 => "ABS".into(),
            0xfff2 => "COMMON".into(),
            i => self.secs.get(i as usize).map_or(format!("#{i}"), |s| s.name.clone()),
        }
    }

    /// Reads symbol `idx` of table `tab`: (name, value, size, info, shndx).
    fn symbol(&self, tab: &Sec, idx: u64) -> Result<(String, u64, u64, u8, u16)> {
        let esz = if self.wide { 24 } else { 16 };
        let r = &self.r;
        // Clamp so `base + n` below cannot overflow; a clamped base fails the bounds check.
        let base = tab.offset.saturating_add(idx.saturating_mul(esz)).min(r.data.len() as u64);
        let (name_off, value, size, info, shndx) = if self.wide {
            (r.u32(base, "symbol")?, r.u64(base + 8, "symbol")?, r.u64(base + 16, "symbol")?, r.u8(base + 4, "symbol")?, r.u16(base + 6, "symbol")?)
        } else {
            (r.u32(base, "symbol")?, r.u32(base + 4, "symbol")? as u64, r.u32(base + 8, "symbol")? as u64, r.u8(base + 12, "symbol")?, r.u16(base + 14, "symbol")?)
        };
        let mut name = match self.secs.get(tab.link as usize) {
            Some(strtab) if name_off != 0 => r
                .cstr(strtab.offset.saturating_add(name_off as u64), "symbol name")
                .unwrap_or_else(|_| format!("<bad name {name_off:#x}>")),
            _ => String::new(),
        };
        // Section symbols carry no name of their own; tools show the section's name instead.
        if name.is_empty() && info & 0xf == 3 && shndx != 0 && shndx < 0xff00 {
            name = self.sec_name(shndx);
        }
        Ok((name, value, size, info, shndx))
    }
}

pub fn parse(data: &[u8]) -> Result<Binary> {
    if data.len() < 20 || &data[..4] != b"\x7fELF" {
        return Err(Error::Malformed("missing ELF magic".into()));
    }
    let wide = match data[4] {
        1 => false,
        2 => true,
        c => return Err(Error::Malformed(format!("unknown ELF class {c}"))),
    };
    let endian = match data[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        e => return Err(Error::Malformed(format!("unknown ELF data encoding {e}"))),
    };
    let r = Reader::new(data, endian);
    let e_type = r.u16(16, "ELF header")?;
    let machine = r.u16(18, "ELF header")?;
    let (entry, phoff, shoff) = if wide {
        (r.u64(24, "ELF header")?, r.u64(32, "ELF header")?, r.u64(40, "ELF header")?)
    } else {
        (r.u32(24, "ELF header")? as u64, r.u32(28, "ELF header")? as u64, r.u32(32, "ELF header")? as u64)
    };
    let (phentsize, mut phnum, shentsize, mut shnum, mut shstrndx) = if wide {
        (r.u16(54, "ELF header")?, r.u16(56, "ELF header")? as u64, r.u16(58, "ELF header")?, r.u16(60, "ELF header")? as u64, r.u16(62, "ELF header")? as u32)
    } else {
        (r.u16(42, "ELF header")?, r.u16(44, "ELF header")? as u64, r.u16(46, "ELF header")?, r.u16(48, "ELF header")? as u64, r.u16(50, "ELF header")? as u32)
    };
    let min_ph = if wide { 56 } else { 32 };
    let min_sh = if wide { 64 } else { 40 };
    let sh_field = |base: u64, off64: u64, off32: u64| r.word(base + if wide { off64 } else { off32 }, wide, "section header");

    // Offsets past the end of the file can never be read, and clamping keeps `base + n` safe.
    let (phoff, shoff) = (phoff.min(data.len() as u64), shoff.min(data.len() as u64));
    // Extended counts: section 0 carries the real values when the header fields overflow.
    if shoff != 0 && (shnum == 0 || shstrndx == 0xffff) {
        if shnum == 0 {
            shnum = sh_field(shoff, 32, 20)?;
        }
        if shstrndx == 0xffff {
            shstrndx = r.u32(shoff + if wide { 40 } else { 24 }, "section header")?;
        }
    }
    if phnum == 0xffff && shoff != 0 {
        phnum = r.u32(shoff + if wide { 44 } else { 28 }, "section header")? as u64;
    }
    if phnum > MAX_ENTRIES || shnum > MAX_ENTRIES {
        return Err(Error::Malformed("implausible header counts".into()));
    }

    let mut bin = Binary::empty(Format::Elf);
    bin.bits = if wide { 64 } else { 32 };
    bin.endian = if endian == Endian::Little { "little" } else { "big" };
    bin.arch = machine_name(machine);
    bin.entry = entry;

    // Program headers.
    let mut segs: Vec<Seg> = Vec::new();
    if phnum > 0 {
        if (phentsize as usize) < min_ph {
            return Err(Error::Malformed(format!("program header size {phentsize} is too small")));
        }
        for i in 0..phnum {
            let b = phoff.saturating_add(i * phentsize as u64).min(data.len() as u64);
            let kind = r.u32(b, "program header")?;
            let s = if wide {
                Seg { kind, flags: r.u32(b + 4, "program header")?, offset: r.u64(b + 8, "program header")?, vaddr: r.u64(b + 16, "program header")?, filesz: r.u64(b + 32, "program header")?, memsz: r.u64(b + 40, "program header")? }
            } else {
                Seg { kind, offset: r.u32(b + 4, "program header")? as u64, vaddr: r.u32(b + 8, "program header")? as u64, filesz: r.u32(b + 16, "program header")? as u64, memsz: r.u32(b + 20, "program header")? as u64, flags: r.u32(b + 24, "program header")? }
            };
            bin.segments.push(Segment {
                kind: segment_kind(s.kind),
                file_offset: s.offset,
                address: s.vaddr,
                file_size: s.filesz,
                memory_size: s.memsz,
                permissions: perms(s.flags & 4 != 0, s.flags & 2 != 0, s.flags & 1 != 0),
            });
            segs.push(s);
        }
    }

    // Section headers; names come from the section named by e_shstrndx.
    let mut raw: Vec<RawSec> = Vec::new();
    if shoff != 0 && shnum > 0 {
        if (shentsize as usize) < min_sh {
            return Err(Error::Malformed(format!("section header size {shentsize} is too small")));
        }
        for i in 0..shnum {
            let b = shoff.saturating_add(i * shentsize as u64).min(data.len() as u64);
            let name = r.u32(b, "section header")?;
            let kind = r.u32(b + 4, "section header")?;
            let flags = sh_field(b, 8, 8)?;
            let addr = sh_field(b, 16, 12)?;
            let offset = sh_field(b, 24, 16)?;
            let size = sh_field(b, 32, 20)?;
            let link = r.u32(b + if wide { 40 } else { 24 }, "section header")?;
            let entsize = sh_field(b, 56, 36)?;
            raw.push(RawSec { name, kind, flags, addr, offset, size, link, entsize });
        }
    }
    let names_off = raw.get(shstrndx as usize).map(|s| s.offset);
    let secs: Vec<Sec> = raw
        .iter()
        .map(|h| Sec {
            name: match names_off {
                Some(base) => r.cstr(base.saturating_add(h.name as u64), "section name").unwrap_or_else(|_| format!("<bad name {:#x}>", h.name)),
                None => String::new(),
            },
            kind: h.kind,
            flags: h.flags,
            addr: h.addr,
            offset: h.offset,
            size: h.size,
            link: h.link,
            entsize: h.entsize,
        })
        .collect();
    for s in &secs {
        bin.sections.push(Section {
            name: s.name.clone(),
            address: s.addr,
            file_offset: s.offset,
            size: s.size,
            permissions: perms(s.flags & 2 != 0, s.flags & 1 != 0, s.flags & 4 != 0),
            kind: section_kind(s.kind),
        });
    }
    let ctx = Ctx { r, wide, secs };

    // Symbol tables.
    for tab in ctx.secs.iter().filter(|s| s.kind == SHT_SYMTAB || s.kind == SHT_DYNSYM) {
        let esz = if tab.entsize != 0 { tab.entsize } else if wide { 24 } else { 16 };
        let count = tab.size / esz;
        let table = if tab.kind == SHT_DYNSYM { "dynsym" } else { "symtab" };
        if count > MAX_ENTRIES {
            bin.notes.push(format!("{table} has {count} entries, only the first {MAX_ENTRIES} were read"));
        }
        for i in 1..count.min(MAX_ENTRIES) {
            let (name, value, size, info, shndx) = match ctx.symbol(tab, i) {
                Ok(s) => s,
                Err(e) => {
                    bin.notes.push(format!("{table} ends early: {e}"));
                    break;
                }
            };
            let section = ctx.sec_name(shndx);
            let bind = info >> 4;
            if tab.kind == SHT_DYNSYM && !name.is_empty() {
                if shndx == 0 && bind != 0 {
                    bin.imports.push(Import { library: None, name: name.clone(), ordinal: None, delay_load: false });
                } else if shndx != 0 && matches!(bind, 1 | 2) && info & 0xf != 3 && info & 0xf != 4 {
                    bin.exports.push(Export { name: Some(name.clone()), ordinal: None, address: value, forwarder: None });
                }
            }
            bin.symbols.push(Symbol { name, address: value, size, kind: sym_kind(info & 0xf), bind: sym_bind(bind), section, table });
        }
    }

    // Object files have no dynamic table, so their linker-visible interface is the symbol table:
    // undefined globals are what they need, defined globals are what they provide.
    if e_type == 1 {
        for sym in bin.symbols.iter().filter(|s| s.table == "symtab" && !s.name.is_empty() && s.kind != "SECTION" && s.kind != "FILE") {
            if sym.section == "UND" && sym.bind != "LOCAL" {
                bin.imports.push(Import { library: None, name: sym.name.clone(), ordinal: None, delay_load: false });
            } else if sym.section != "UND" && (sym.bind == "GLOBAL" || sym.bind == "WEAK") {
                bin.exports.push(Export { name: Some(sym.name.clone()), ordinal: None, address: sym.address, forwarder: None });
            }
        }
    }

    // Relocations, with symbol names from the linked table.
    for sec in ctx.secs.iter().filter(|s| s.kind == SHT_REL || s.kind == SHT_RELA) {
        let has_addend = sec.kind == SHT_RELA;
        let esz = match (wide, has_addend) {
            (true, true) => 24,
            (true, false) => 16,
            (false, true) => 12,
            (false, false) => 8,
        };
        let count = sec.size / esz;
        let symtab = ctx.secs.get(sec.link as usize).filter(|s| s.kind == SHT_SYMTAB || s.kind == SHT_DYNSYM);
        if count > MAX_ENTRIES {
            bin.notes.push(format!("{} has {count} entries, only the first {MAX_ENTRIES} were read", sec.name));
        }
        for i in 0..count.min(MAX_ENTRIES) {
            let b = sec.offset.saturating_add(i * esz).min(data.len() as u64);
            let parsed = (|| -> Result<Reloc> {
                let (off, info) = if wide { (r.u64(b, "relocation")?, r.u64(b + 8, "relocation")?) } else { (r.u32(b, "relocation")? as u64, r.u32(b + 4, "relocation")? as u64) };
                let (sym, ty) = if wide { (info >> 32, (info & 0xffff_ffff) as u32) } else { (info >> 8, (info & 0xff) as u32) };
                let addend = if has_addend {
                    Some(if wide { r.u64(b + 16, "relocation")? as i64 } else { r.u32(b + 8, "relocation")? as i32 as i64 })
                } else {
                    None
                };
                let symbol = match (symtab, sym) {
                    (Some(t), s) if s != 0 => ctx.symbol(t, s).ok().map(|x| x.0).filter(|n| !n.is_empty()),
                    _ => None,
                };
                Ok(Reloc { offset: off, kind: reloc_name(machine, ty), symbol, addend })
            })();
            match parsed {
                Ok(x) => bin.relocations.push(x),
                Err(e) => {
                    bin.notes.push(format!("{} ends early: {e}", sec.name));
                    break;
                }
            }
        }
    }

    // Interpreter and dynamic section, through the program headers so stripped files work too.
    let vaddr_to_offset = |va: u64| {
        segs.iter()
            .find(|s| s.kind == PT_LOAD && va >= s.vaddr && va - s.vaddr < s.filesz)
            .map(|s| s.offset.saturating_add(va - s.vaddr))
    };
    if let Some(s) = segs.iter().find(|s| s.kind == PT_INTERP) {
        bin.interpreter = r.cstr(s.offset, "interpreter").ok();
    }
    let (mut bind_now, mut pie_flag) = (false, false);
    if let Some(dynseg) = segs.iter().find(|s| s.kind == PT_DYNAMIC) {
        let esz = if wide { 16 } else { 8 };
        let mut needed: Vec<u64> = Vec::new();
        let (mut strtab, mut soname) = (None, None);
        for i in 0..(dynseg.filesz / esz).min(4096) {
            let b = dynseg.offset.saturating_add(i * esz).min(data.len() as u64);
            let (tag, val) = if wide { (r.u64(b, "dynamic")? as i64, r.u64(b + 8, "dynamic")?) } else { (r.u32(b, "dynamic")? as i32 as i64, r.u32(b + 4, "dynamic")? as u64) };
            match tag {
                0 => break,
                1 => needed.push(val),
                5 => strtab = vaddr_to_offset(val),
                14 => soname = Some(val),
                24 => bind_now = true,
                30 => bind_now |= val & 8 != 0,
                0x6fff_fffb => {
                    bind_now |= val & 1 != 0;
                    pie_flag = val & 0x0800_0000 != 0;
                }
                _ => {}
            }
        }
        match strtab {
            Some(st) => {
                bin.libraries = needed.iter().filter_map(|n| r.cstr(st.saturating_add(*n), "needed library").ok()).collect();
                bin.soname = soname.and_then(|n| r.cstr(st.saturating_add(n), "soname").ok());
            }
            None if !needed.is_empty() => bin.notes.push("dynamic string table address is not inside a loadable segment".into()),
            None => {}
        }
    }

    bin.kind = match e_type {
        1 => "relocatable object".into(),
        2 => "executable".into(),
        3 if bin.interpreter.is_some() || pie_flag => "position-independent executable".into(),
        3 => "shared library".into(),
        4 => "core file".into(),
        t => format!("type {t}"),
    };

    // Hardening features.
    if bin.kind == "position-independent executable" {
        bin.features.push("PIE".into());
    }
    match segs.iter().find(|s| s.kind == PT_GNU_STACK) {
        Some(s) if s.flags & 1 == 0 => bin.features.push("NX stack".into()),
        Some(_) => bin.features.push("executable stack".into()),
        None if e_type != 1 => bin.features.push("no GNU_STACK header".into()),
        None => {}
    }
    if e_type != 1 {
        match (segs.iter().any(|s| s.kind == PT_GNU_RELRO), bind_now) {
            (true, true) => bin.features.push("full RELRO".into()),
            (true, false) => bin.features.push("partial RELRO".into()),
            (false, _) => bin.features.push("no RELRO".into()),
        }
    }
    if bin.symbols.iter().any(|s| s.name == "__stack_chk_fail" || s.name == "__stack_chk_guard") {
        bin.features.push("stack protector".into());
    }
    if e_type != 1 && !ctx.secs.iter().any(|s| s.kind == SHT_SYMTAB) {
        bin.features.push("stripped".into());
    }
    Ok(bin)
}
