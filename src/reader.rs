//! A module to read pickle events

use std::{io::Read, str::from_utf8};

use crate::errors::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V4,
}

pub enum Event<'a> {
    Frame(usize),
    Str(&'a str),
    Bool(bool),
    Stop,
    Memoize,
    EmptyList,
    Mark,
    BinInt1(u8),
    BinInt(i32),
    Appends,
}

pub struct Reader<R> {
    reader: R,
    #[allow(dead_code)]
    version: Version,
}

impl<R: Read> Reader<R> {
    pub fn new(mut reader: R) -> Result<Self, Error> {
        let mut header = [0u8; 2];
        reader.read_exact(&mut header)?;
        if header == [0x80, 0x04] {
            Ok(Reader {
                reader,
                version: Version::V4,
            })
        } else {
            Err(Error::Protocol(header))
        }
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut byte = [0];
        self.reader.read(&mut byte)?;
        Ok(byte[0])
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        let mut bytes = [0; 8];
        self.reader.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_i32(&mut self) -> Result<i32, Error> {
        let mut bytes = [0; 4];
        self.reader.read_exact(&mut bytes)?;
        Ok(i32::from_le_bytes(bytes))
    }

    fn fill_buf(&mut self, len: usize, buf: &mut Vec<u8>) -> Result<(), Error> {
        let buf_len = buf.len();
        buf.resize(buf_len + len, 0);
        self.reader.read_exact(&mut buf[buf_len..])?;
        Ok(())
    }

    fn read_str<'a>(&mut self, len: usize, buf: &'a mut Vec<u8>) -> Result<&'a str, Error> {
        self.fill_buf(len, buf)?;
        from_utf8(&buf[buf.len() - len..]).map_err(Error::Str)
    }

    pub fn read_event<'a>(&mut self, buf: &'a mut Vec<u8>) -> Result<Event<'a>, Error> {
        let opcode = self.read_u8()?;

        // see https://github.com/Legoclones/pickledoc/blob/main/Opcodes.md
        match opcode {
            0x95 => Ok(Event::Frame(self.read_u64()? as usize)),
            0x8c => {
                // short binunicode
                let len = self.read_u8()?;
                let s = self.read_str(len as usize, buf)?;
                Ok(Event::Str(s))
            }
            0x94 => Ok(Event::Memoize),
            0x65 => Ok(Event::Appends),
            0x2e => Ok(Event::Stop),      // .
            0x5d => Ok(Event::EmptyList), // ]
            0x28 => Ok(Event::Mark),      // (
            0x4a => Ok(Event::BinInt(self.read_i32()?)),
            0x4b => Ok(Event::BinInt1(self.read_u8()?)), // K
            0x88 => Ok(Event::Bool(true)),
            _ => Err(Error::OpCode(opcode)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_true() -> Result<(), Error> {
        let data: &[u8] = b"\x80\x04\x88.";
        let mut reader = Reader::new(data)?;
        let mut buf = Vec::new();
        loop {
            match reader.read_event(&mut buf)? {
                Event::Bool(b) => assert!(b),
                Event::Stop => break,
                _ => (),
            }
            buf.clear();
        }
        Ok(())
    }

    #[test]
    fn test_read_int() -> Result<(), Error> {
        let data: &[u8] = b"\x80\x04\x95\x06\x00\x00\x00\x00\x00\x00\x00J\x00\x00\x10\x00.";
        let mut reader = Reader::new(data)?;
        let mut buf = Vec::new();
        loop {
            match reader.read_event(&mut buf)? {
                Event::BinInt(v) => assert_eq!(v, 1 << 20),
                Event::Stop => break,
                _ => (),
            }
            buf.clear();
        }

        Ok(())
    }

    #[test]
    fn test_read_str() -> Result<(), Error> {
        // "/"
        let data: &[u8] = &[
            0x80, 0x04, 0x95, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x01, b'/',
            0x94, b'.',
        ];
        let mut reader = Reader::new(data)?;
        let mut buf = Vec::new();
        loop {
            match reader.read_event(&mut buf)? {
                Event::Str(s) => assert_eq!(s, "/"),
                Event::Stop => break,
                _ => (),
            }
            buf.clear();
        }

        Ok(())
    }

    #[test]
    fn test_read_list_ints() -> Result<(), Error> {
        let data: &[u8] = b"\x80\x04\x95\x19\x00\x00\x00\x00\x00\x00\x00]\x94(K\x00K\x01K\x02K\x03K\x04K\x05K\x06K\x07K\x08K\te.";
        let mut reader = Reader::new(data)?;
        let mut buf = Vec::new();
        let mut list = Vec::new();
        loop {
            match reader.read_event(&mut buf)? {
                Event::BinInt1(v) => list.push(v),
                Event::Stop => break,
                _ => (),
            }
            buf.clear();
        }
        assert_eq!(list, (0..10).collect::<Vec<_>>());

        Ok(())
    }
}
