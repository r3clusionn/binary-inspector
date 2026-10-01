//! Parse ELF and PE executables into one shared model.
//!
//! ```no_run
//! let bytes = std::fs::read("a.out").unwrap();
//! let bin = binspect::parse(&bytes).unwrap();
//! println!("{} {} with {} sections", bin.arch, bin.kind, bin.sections.len());
//! ```

pub mod elf;
pub mod model;
pub mod pe;
pub mod reader;
pub mod render;

pub use model::Binary;
pub use reader::{Error, Result};

/// Detects the format from the magic bytes and parses.
pub fn parse(data: &[u8]) -> Result<Binary> {
    if data.starts_with(b"\x7fELF") {
        elf::parse(data)
    } else if data.starts_with(b"MZ") {
        pe::parse(data)
    } else {
        Err(Error::Unsupported("not an ELF or PE file (unknown magic bytes)".into()))
    }
}
