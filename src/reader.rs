//! Bounds-checked access to a byte slice. Every parser reads through this type, so a truncated or
//! hostile file produces an [`Error`], never a panic or an out-of-range read.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// A read ran past the end of the file.
    Truncated { what: &'static str, offset: u64 },
    /// A field holds a value that cannot be valid.
    Malformed(String),
    /// A valid file of a kind this tool does not handle.
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { what, offset } => write!(f, "file ends inside {what} at offset {offset:#x}"),
            Error::Malformed(m) => write!(f, "malformed file: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Clone, Copy)]
pub struct Reader<'a> {
    pub data: &'a [u8],
    pub endian: Endian,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], endian: Endian) -> Self {
        Reader { data, endian }
    }

    pub fn with_endian(self, endian: Endian) -> Self {
        Reader { endian, ..self }
    }

    pub fn bytes(&self, offset: u64, len: u64, what: &'static str) -> Result<&'a [u8]> {
        let end = offset.checked_add(len).ok_or(Error::Truncated { what, offset })?;
        if end > self.data.len() as u64 {
            return Err(Error::Truncated { what, offset });
        }
        Ok(&self.data[offset as usize..end as usize])
    }

    pub fn u8(&self, offset: u64, what: &'static str) -> Result<u8> {
        Ok(self.bytes(offset, 1, what)?[0])
    }

    pub fn u16(&self, offset: u64, what: &'static str) -> Result<u16> {
        let b: [u8; 2] = self.bytes(offset, 2, what)?.try_into().unwrap();
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        })
    }

    pub fn u32(&self, offset: u64, what: &'static str) -> Result<u32> {
        let b: [u8; 4] = self.bytes(offset, 4, what)?.try_into().unwrap();
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        })
    }

    pub fn u64(&self, offset: u64, what: &'static str) -> Result<u64> {
        let b: [u8; 8] = self.bytes(offset, 8, what)?.try_into().unwrap();
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        })
    }

    /// A 4 or 8 byte unsigned integer depending on `wide`.
    pub fn word(&self, offset: u64, wide: bool, what: &'static str) -> Result<u64> {
        if wide { self.u64(offset, what) } else { self.u32(offset, what).map(u64::from) }
    }

    /// A NUL-terminated string. Invalid UTF-8 is replaced; a missing terminator is an error.
    pub fn cstr(&self, offset: u64, what: &'static str) -> Result<String> {
        let start = offset as usize;
        if offset > self.data.len() as u64 {
            return Err(Error::Truncated { what, offset });
        }
        let tail = &self.data[start..];
        // Names longer than this are corruption, not symbols.
        let limit = tail.len().min(4096);
        match tail[..limit].iter().position(|b| *b == 0) {
            Some(n) => Ok(String::from_utf8_lossy(&tail[..n]).into_owned()),
            None => Err(Error::Truncated { what, offset }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_endians() {
        let d = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let le = Reader::new(&d, Endian::Little);
        let be = le.with_endian(Endian::Big);
        assert_eq!(le.u16(0, "t"), Ok(0x0201));
        assert_eq!(be.u16(0, "t"), Ok(0x0102));
        assert_eq!(le.u32(0, "t"), Ok(0x0403_0201));
        assert_eq!(be.u64(0, "t"), Ok(0x0102_0304_0506_0708));
        assert_eq!(le.word(0, false, "t"), Ok(0x0403_0201));
    }

    #[test]
    fn out_of_range_reads_are_errors() {
        let r = Reader::new(&[1, 2, 3], Endian::Little);
        assert!(matches!(r.u32(0, "x"), Err(Error::Truncated { .. })));
        assert!(matches!(r.u8(3, "x"), Err(Error::Truncated { .. })));
        assert!(matches!(r.bytes(u64::MAX, 2, "x"), Err(Error::Truncated { .. })));
        assert!(matches!(r.bytes(1, u64::MAX, "x"), Err(Error::Truncated { .. })));
        assert!(r.u8(2, "x").is_ok());
    }

    #[test]
    fn cstr_needs_a_terminator() {
        let r = Reader::new(b"abc\0def", Endian::Little);
        assert_eq!(r.cstr(0, "s").unwrap(), "abc");
        assert_eq!(r.cstr(1, "s").unwrap(), "bc");
        assert!(r.cstr(4, "s").is_err(), "no NUL after def");
        assert!(r.cstr(99, "s").is_err());
    }
}
