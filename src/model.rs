//! The format-independent description of an executable. Both parsers fill this in, and the
//! renderers read only this, which is what keeps ELF and PE output consistent.

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Format {
    Elf,
    Pe,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub file_offset: u64,
    pub size: u64,
    /// `rwx` with `-` for missing permissions. ELF: alloc, write, exec. PE: read, write, execute.
    pub permissions: String,
    /// Format specific type, for example `PROGBITS` or `code`.
    pub kind: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Segment {
    pub kind: String,
    pub file_offset: u64,
    pub address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub permissions: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: String,
    pub bind: String,
    /// Section name, or `UND`, `ABS`, `COMMON`.
    pub section: String,
    /// `symtab` or `dynsym`.
    pub table: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Import {
    /// The DLL for PE imports. ELF imports are not bound to a library without symbol versioning.
    pub library: Option<String>,
    pub name: String,
    pub ordinal: Option<u32>,
    /// Loaded on first use (PE delay-load table) rather than at process start.
    pub delay_load: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Export {
    pub name: Option<String>,
    pub ordinal: Option<u32>,
    pub address: u64,
    pub forwarder: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Reloc {
    /// Address (ELF) or RVA (PE) being patched.
    pub offset: u64,
    pub kind: String,
    pub symbol: Option<String>,
    pub addend: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Binary {
    pub format: Format,
    pub bits: u8,
    pub arch: String,
    pub endian: &'static str,
    /// executable, shared library, relocatable object, driver, ...
    pub kind: String,
    pub entry: u64,
    pub image_base: Option<u64>,
    pub interpreter: Option<String>,
    pub soname: Option<String>,
    pub libraries: Vec<String>,
    pub features: Vec<String>,
    pub sections: Vec<Section>,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocations: Vec<Reloc>,
    /// Anything skipped or capped, so output is never silently incomplete.
    pub notes: Vec<String>,
}

impl Binary {
    pub fn empty(format: Format) -> Binary {
        Binary {
            format,
            bits: 0,
            arch: String::new(),
            endian: "little",
            kind: String::new(),
            entry: 0,
            image_base: None,
            interpreter: None,
            soname: None,
            libraries: Vec::new(),
            features: Vec::new(),
            sections: Vec::new(),
            segments: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            relocations: Vec::new(),
            notes: Vec::new(),
        }
    }
}

/// Upper bound on entries read from any one table, so a corrupt count cannot exhaust memory.
pub const MAX_ENTRIES: u64 = 2_000_000;
