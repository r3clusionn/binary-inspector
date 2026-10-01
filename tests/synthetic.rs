//! Parsers checked against files built here byte by byte, so every expected value is known.

use binspect::model::Format;
use binspect::{parse, Error};

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    fn pad_to(&mut self, len: usize) -> &mut Self {
        assert!(self.0.len() <= len, "layout overflow: {} > {len}", self.0.len());
        self.0.resize(len, 0);
        self
    }
    fn at(&self) -> usize {
        self.0.len()
    }
}

const BASE: u64 = 0x40_0000;

/// A small x86-64 PIE with an interpreter, one needed library, an undefined import (`puts`), an
/// exported function (`main`), one JUMP_SLOT relocation, NX stack, RELRO and BIND_NOW.
fn elf64() -> Vec<u8> {
    let mut w = W(Vec::new());
    // Offsets are fixed by construction; asserts in pad_to catch a layout mistake.
    let (interp_off, text_off, dynstr_off, dynsym_off, rela_off, dynamic_off, shstr_off) = (344, 376, 392, 416, 488, 512, 576);
    let shstr = b"\0.text\0.dynstr\0.dynsym\0.rela.dyn\0.dynamic\0.shstrtab\0";
    let shoff = (shstr_off + shstr.len()).next_multiple_of(8);
    // ELF header
    w.bytes(b"\x7fELF").u8(2).u8(1).u8(1).u8(0).pad_to(16);
    w.u16(3).u16(62).u32(1).u64(BASE + text_off as u64).u64(64).u64(shoff as u64).u32(0);
    w.u16(64).u16(56).u16(5).u16(64).u16(6).u16(5);
    assert_eq!(w.at(), 64);
    // Program headers: LOAD, INTERP, DYNAMIC, GNU_STACK, GNU_RELRO
    let total = shoff + 7 * 64;
    for (kind, flags, off, size) in [(1u32, 5u32, 0u64, total as u64), (3, 4, interp_off as u64, 28), (2, 6, dynamic_off as u64, 64), (0x6474_e551, 6, 0, 0), (0x6474_e552, 4, dynamic_off as u64, 64)] {
        w.u32(kind).u32(flags).u64(off).u64(BASE + off).u64(BASE + off).u64(size).u64(size).u64(8);
    }
    w.pad_to(interp_off).bytes(b"/lib64/ld-linux-x86-64.so.2\0").pad_to(text_off);
    w.bytes(&[0x90; 16]);
    w.pad_to(dynstr_off).bytes(b"\0libc.so.6\0puts\0main\0").pad_to(dynsym_off);
    // dynsym: null, puts (undefined global function), main (defined in section 1, global function)
    w.bytes(&[0; 24]);
    w.u32(11).u8(0x12).u8(0).u16(0).u64(0).u64(0);
    w.u32(16).u8(0x12).u8(0).u16(1).u64(BASE + text_off as u64).u64(16);
    w.pad_to(rela_off);
    w.u64(0x40_4018).u64((1u64 << 32) | 7).u64(0); // JUMP_SLOT against symbol 1
    w.pad_to(dynamic_off);
    w.u64(1).u64(1); // DT_NEEDED "libc.so.6"
    w.u64(5).u64(BASE + dynstr_off as u64); // DT_STRTAB
    w.u64(30).u64(8); // DT_FLAGS: BIND_NOW
    w.u64(0).u64(0);
    w.pad_to(shstr_off).bytes(shstr).pad_to(shoff);
    // Section headers: null, .text, .dynstr, .dynsym, .rela.dyn, .dynamic, .shstrtab (index 6)
    let names = [0u32, 1, 7, 15, 23, 33, 42];
    let sh = |w: &mut W, i: usize, kind: u32, flags: u64, addr: u64, off: usize, size: usize, link: u32, entsize: u64| {
        w.u32(names[i]).u32(kind).u64(flags).u64(addr).u64(off as u64).u64(size as u64).u32(link).u32(0).u64(8).u64(entsize);
    };
    w.bytes(&[0; 64]);
    sh(&mut w, 1, 1, 6, BASE + text_off as u64, text_off, 16, 0, 0);
    sh(&mut w, 2, 3, 2, BASE + dynstr_off as u64, dynstr_off, 21, 0, 0);
    sh(&mut w, 3, 11, 2, BASE + dynsym_off as u64, dynsym_off, 72, 2, 24);
    sh(&mut w, 4, 4, 2, BASE + rela_off as u64, rela_off, 24, 3, 24);
    sh(&mut w, 5, 6, 3, BASE + dynamic_off as u64, dynamic_off, 64, 2, 16);
    sh(&mut w, 6, 3, 0, 0, shstr_off, shstr.len(), 0, 0);
    // Seven headers in total (null plus six), with .shstrtab last. The header was written with
    // placeholder counts because they depend on the table built after it.
    let mut v = w.0;
    v[60..62].copy_from_slice(&7u16.to_le_bytes()); // e_shnum
    v[62..64].copy_from_slice(&6u16.to_le_bytes()); // e_shstrndx
    v
}

/// PE32+ DLL: imports `CreateFileW` and ordinal 5 from KERNEL32.dll, exports `Foo` and a forwarder,
/// two base relocations, ASLR, DEP and CFG.
fn pe64() -> Vec<u8> {
    let mut w = W(Vec::new());
    let (raw, rva0) = (0x200usize, 0x1000u32);
    let rva = |off: usize| rva0 + off as u32;
    // DOS header and stub
    w.bytes(b"MZ").pad_to(0x3c).u32(0x80).pad_to(0x80);
    // PE signature, COFF header: x86-64, 1 section, optional header 240 bytes, DLL | executable
    w.bytes(b"PE\0\0").u16(0x8664).u16(1).u32(0).u32(0).u32(0).u16(240).u16(0x2022);
    // Optional header (PE32+)
    w.u16(0x20b).u8(14).u8(0).u32(0).u32(0).u32(0).u32(rva(0x300)); // entry rva
    w.u32(0x1000).u64(0x1_8000_0000).u32(0x1000).u32(0x200); // base of code, image base, alignments
    w.u16(6).u16(0).u16(0).u16(0).u16(6).u16(0).u32(0).u32(0x2000).u32(0x200).u32(0);
    w.u16(2).u16(0x40 | 0x20 | 0x100 | 0x4000); // GUI subsystem, ASLR + HE-ASLR + DEP + CFG
    w.u64(0x100000).u64(0x1000).u64(0x100000).u64(0x1000).u32(0).u32(16);
    assert_eq!(w.at(), 0x80 + 24 + 112);
    // Data directories: export, import, ..., base relocation at index 5
    for i in 0..16 {
        match i {
            0 => w.u32(rva(0x100)).u32(0xa0),
            1 => w.u32(rva(0x0)).u32(40),
            5 => w.u32(rva(0x200)).u32(12),
            _ => w.u32(0).u32(0),
        };
    }
    // Section header: .rdata
    w.bytes(b".rdata\0\0").u32(0x400).u32(rva0).u32(0x400).u32(raw as u32).u32(0).u32(0).u16(0).u16(0).u32(0x4000_0040);
    w.pad_to(raw);
    // Section contents
    let sec = |w: &mut W, off: usize| {
        let want = raw + off;
        w.pad_to(want);
    };
    sec(&mut w, 0x00);
    w.u32(rva(0x40)).u32(0).u32(0).u32(rva(0x80)).u32(rva(0x40)); // import descriptor
    w.bytes(&[0; 20]); // terminator
    sec(&mut w, 0x40);
    w.u64(rva(0x60) as u64).u64((1u64 << 63) | 5).u64(0); // ILT: by name, by ordinal 5
    sec(&mut w, 0x60);
    w.u16(0).bytes(b"CreateFileW\0");
    sec(&mut w, 0x80);
    w.bytes(b"KERNEL32.dll\0");
    sec(&mut w, 0x100);
    // Export directory: base 1, 2 functions, 1 name
    w.u32(0).u32(0).u16(0).u16(0).u32(rva(0x180)).u32(1).u32(2).u32(1).u32(rva(0x140)).u32(rva(0x150)).u32(rva(0x160));
    sec(&mut w, 0x140);
    w.u32(rva(0x300)).u32(rva(0x190)); // function 0 is code, function 1 forwards
    sec(&mut w, 0x150);
    w.u32(rva(0x170));
    sec(&mut w, 0x160);
    w.u16(0);
    sec(&mut w, 0x170);
    w.bytes(b"Foo\0");
    sec(&mut w, 0x180);
    w.bytes(b"test.dll\0");
    sec(&mut w, 0x190);
    w.bytes(b"NTDLL.RtlFoo\0");
    sec(&mut w, 0x200);
    w.u32(0x1000).u32(12).u16((10 << 12) | 0x10).u16(0); // one DIR64 at page + 0x10, one padding
    sec(&mut w, 0x400);
    w.0
}

#[test]
fn elf64_fields() {
    let b = parse(&elf64()).unwrap();
    assert_eq!((b.format, b.bits, b.arch.as_str(), b.endian), (Format::Elf, 64, "x86-64", "little"));
    assert_eq!(b.kind, "position-independent executable");
    assert_eq!(b.entry, BASE + 376);
    assert_eq!(b.interpreter.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
    assert_eq!(b.libraries, ["libc.so.6"]);
    let names: Vec<&str> = b.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["", ".text", ".dynstr", ".dynsym", ".rela.dyn", ".dynamic", ".shstrtab"]);
    assert_eq!(b.sections[1].permissions, "r-x");
    assert_eq!(b.sections[5].permissions, "rw-");
    let kinds: Vec<&str> = b.segments.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(kinds, ["LOAD", "INTERP", "DYNAMIC", "GNU_STACK", "GNU_RELRO"]);
    assert_eq!(b.segments[0].permissions, "r-x");
    assert_eq!(b.segments[3].permissions, "rw-");
    assert_eq!(b.features, ["PIE", "NX stack", "full RELRO", "stripped"]);
}

#[test]
fn elf64_symbols_imports_exports_relocations() {
    let b = parse(&elf64()).unwrap();
    assert_eq!(b.symbols.len(), 2);
    assert_eq!((b.symbols[0].name.as_str(), b.symbols[0].section.as_str(), b.symbols[0].kind.as_str()), ("puts", "UND", "FUNC"));
    assert_eq!((b.symbols[1].name.as_str(), b.symbols[1].section.as_str(), b.symbols[1].address, b.symbols[1].size), ("main", ".text", BASE + 376, 16));
    assert_eq!(b.imports.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["puts"]);
    assert_eq!(b.exports.iter().map(|e| e.name.as_deref().unwrap()).collect::<Vec<_>>(), ["main"]);
    assert_eq!(b.relocations.len(), 1);
    let r = &b.relocations[0];
    assert_eq!((r.offset, r.kind.as_str(), r.symbol.as_deref(), r.addend), (0x40_4018, "R_X86_64_JUMP_SLOT", Some("puts"), Some(0)));
}

#[test]
fn pe64_headers_and_features() {
    let b = parse(&pe64()).unwrap();
    assert_eq!((b.format, b.bits, b.arch.as_str(), b.kind.as_str()), (Format::Pe, 64, "x86-64", "DLL"));
    assert_eq!(b.image_base, Some(0x1_8000_0000));
    assert_eq!(b.entry, 0x1300);
    assert_eq!(b.features, ["high-entropy ASLR", "ASLR", "DEP", "CFG"]);
    assert_eq!(b.sections.len(), 1);
    assert_eq!((b.sections[0].name.as_str(), b.sections[0].permissions.as_str(), b.sections[0].address), (".rdata", "r--", 0x1_8000_1000));
    assert!(b.notes.is_empty(), "{:?}", b.notes);
}

#[test]
fn pe64_imports_exports_relocations() {
    let b = parse(&pe64()).unwrap();
    assert_eq!(b.libraries, ["KERNEL32.dll"]);
    assert_eq!(b.imports.len(), 2);
    assert_eq!((b.imports[0].library.as_deref(), b.imports[0].name.as_str(), b.imports[0].ordinal), (Some("KERNEL32.dll"), "CreateFileW", None));
    assert_eq!((b.imports[1].name.as_str(), b.imports[1].ordinal), ("", Some(5)));
    assert_eq!(b.exports.len(), 2);
    assert_eq!((b.exports[0].name.as_deref(), b.exports[0].ordinal, b.exports[0].address, b.exports[0].forwarder.as_deref()), (Some("Foo"), Some(1), 0x1300, None));
    assert_eq!((b.exports[1].name.as_deref(), b.exports[1].ordinal, b.exports[1].forwarder.as_deref()), (None, Some(2), Some("NTDLL.RtlFoo")));
    assert_eq!(b.relocations.len(), 1);
    assert_eq!((b.relocations[0].offset, b.relocations[0].kind.as_str()), (0x1010, "DIR64"));
}

#[test]
fn unknown_and_tiny_inputs_are_errors() {
    assert!(matches!(parse(b"hello world"), Err(Error::Unsupported(_))));
    assert!(parse(b"").is_err());
    assert!(parse(b"\x7fELF").is_err());
    assert!(parse(b"MZ").is_err());
}

#[test]
fn every_truncation_is_an_error_or_a_result_never_a_panic() {
    for file in [elf64(), pe64()] {
        for len in 0..file.len() {
            let _ = parse(&file[..len]);
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for base in [elf64(), pe64()] {
        for _ in 0..4000 {
            let mut f = base.clone();
            for _ in 0..1 + next() % 4 {
                let i = (next() % f.len() as u64) as usize;
                f[i] = match next() % 3 {
                    0 => 0xff,
                    1 => 0,
                    _ => next() as u8,
                };
            }
            let _ = parse(&f);
        }
    }
}

#[test]
fn big_endian_32_bit_elf_header() {
    // ELF32 MSB MIPS executable with no headers: still parses to the shared model.
    let mut f = vec![0u8; 52];
    f[..4].copy_from_slice(b"\x7fELF");
    f[4] = 1;
    f[5] = 2;
    f[6] = 1;
    f[16..18].copy_from_slice(&2u16.to_be_bytes());
    f[18..20].copy_from_slice(&8u16.to_be_bytes());
    f[24..28].copy_from_slice(&0x0040_0100u32.to_be_bytes());
    let b = parse(&f).unwrap();
    assert_eq!((b.bits, b.arch.as_str(), b.endian, b.kind.as_str(), b.entry), (32, "MIPS", "big", "executable", 0x40_0100));
}
