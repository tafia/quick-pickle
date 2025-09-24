//! A module to read pickle events

use std::{io::Read, str::from_utf8};

use crate::errors::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V4,
}

#[derive(Debug)]
pub enum Event {
    // Protocol identification
    Proto(u8),
    Frame(usize),

    // Stack manipulation
    Mark,
    Stop,
    Pop,
    PopMark,
    Dup,

    // Basic types
    None,
    Bool(bool),
    Int(i32),
    BinInt(i32),
    BinInt1(u8),
    BinInt2(u16),
    Long1(Vec<u8>),
    Long4(Vec<u8>),
    Float(f64),
    BinFloat(f64),

    // Strings and bytes
    String(String),
    BinString(Vec<u8>),
    ShortBinString(u8),
    Unicode(String),
    BinUnicode(Vec<u8>),
    ShortBinUnicode(u8),
    BinUnicode8(Vec<u8>),
    BinBytes(Vec<u8>),
    ShortBinBytes(u8),
    BinBytes8(Vec<u8>),
    ByteArray8(Vec<u8>),

    // Collections
    EmptyTuple,
    Tuple,
    Tuple1,
    Tuple2,
    Tuple3,
    EmptyList,
    List,
    Append,
    Appends,
    EmptyDict,
    Dict,
    SetItem,
    SetItems,
    EmptySet,
    AdditItems,
    FrozenSet,

    // Memo operations
    Get(i32),
    BinGet(u8),
    LongBinGet(u32),
    Put(i32),
    BinPut(u8),
    LongBinPut(u32),
    Memoize,

    // Object construction
    Global(String, String),
    StackGlobal,
    Reduce,
    Build,
    Inst(String, String),
    Obj,
    NewObj,
    NewObjEx,

    // Persistent objects
    PersId(String),
    BinPersId,

    // Extensions
    Ext1(u8),
    Ext2(u16),
    Ext4(u32),

    // Protocol 5
    NextBuffer,
    ReadonlyBuffer,
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

    fn read_u16(&mut self) -> Result<u16, Error> {
        let mut bytes = [0; 2];
        self.reader.read(&mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        let mut bytes = [0; 8];
        self.reader.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_f64(&mut self) -> Result<f64, Error> {
        let mut bytes = [0; 8];
        self.reader.read_exact(&mut bytes)?;
        Ok(f64::from_be_bytes(bytes))
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



    fn read_line_string(&mut self, _buf: &mut Vec<u8>) -> Result<String, Error> {
        let mut line = Vec::new();
        loop {
            let byte = self.read_u8()?;
            if byte == b'\n' {
                break;
            }
            line.push(byte);
        }
        from_utf8(&line).map(|s| s.to_string()).map_err(Error::Str)
    }

    pub fn read_event<'a>(&mut self, buf: &mut Vec<u8>) -> Result<Event, Error> {
        let opcode = self.read_u8()?;

        match opcode {
            // Protocol identification
            0x80 => Ok(Event::Proto(self.read_u8()?)),

            // Stack manipulation
            0x28 => Ok(Event::Mark),       // (
            0x2e => Ok(Event::Stop),       // .
            0x30 => Ok(Event::Pop),        // 0
            0x31 => Ok(Event::PopMark),    // 1
            0x32 => Ok(Event::Dup),        // 2

            // Basic types
            0x4e => Ok(Event::None),       // N
            0x88 => Ok(Event::Bool(true)), // NEWTRUE
            0x89 => Ok(Event::Bool(false)), // NEWFALSE
            0x49 => {
                // INT - decimal string
                let s = self.read_line_string(buf)?;
                if s == "01" {
                    Ok(Event::Bool(true))
                } else if s == "00" {
                    Ok(Event::Bool(false))
                } else {
                    Ok(Event::Int(s.parse().map_err(|_| Error::Protocol([0x49, 0]))?))
                }
            }
            0x4a => Ok(Event::BinInt(self.read_i32()?)),     // J
            0x4b => Ok(Event::BinInt1(self.read_u8()?)),     // K
            0x4d => Ok(Event::BinInt2(self.read_u16()?)),    // M
            0x4c => {
                // LONG - decimal string
                let s = self.read_line_string(buf)?;
                let s = if s.ends_with('L') { &s[..s.len()-1] } else { &s };
                // For simplicity, store as string bytes
                Ok(Event::Long1(s.bytes().collect()))
            }
            0x8a => {
                // LONG1
                let len = self.read_u8()? as usize;
                self.fill_buf(len, buf)?;
                let start = buf.len() - len;
                Ok(Event::Long1(buf[start..].to_vec()))
            }
            0x8b => {
                // LONG4
                let len = self.read_i32()? as usize;
                self.fill_buf(len, buf)?;
                let start = buf.len() - len;
                Ok(Event::Long4(buf[start..].to_vec()))
            }
            0x46 => {
                // FLOAT - decimal string
                let s = self.read_line_string(buf)?;
                Ok(Event::Float(s.parse().map_err(|_| Error::Protocol([0x46, 0]))?))
            }
            0x47 => Ok(Event::BinFloat(self.read_f64()?)),   // G

            // Strings and bytes
            0x53 => {
                // STRING
                let s = self.read_line_string(buf)?;
                Ok(Event::String(s))
            }
            0x54 => {
                // BINSTRING
                let len = self.read_i32()? as usize;
                self.fill_buf(len, buf)?;
                let start = buf.len() - len;
                Ok(Event::BinString(buf[start..].to_vec()))
            }
            0x55 => {
                // SHORT_BINSTRING
                let len = self.read_u8()? as usize;
                self.fill_buf(len, buf)?;
                Ok(Event::ShortBinString(len as u8))
            }
            0x56 => {
                // UNICODE
                let s = self.read_line_string(buf)?;
                Ok(Event::Unicode(s))
            }
            0x58 => {
                // BINUNICODE
                let len = self.read_i32()? as usize;
                self.fill_buf(len, buf)?;
                let start = buf.len() - len;
                Ok(Event::BinUnicode(buf[start..].to_vec()))
            }
            0x8c => {
                // SHORT_BINUNICODE
                let len = self.read_u8()? as usize;
                self.fill_buf(len, buf)?;
                Ok(Event::ShortBinUnicode(len as u8))
            }
            0x8d => {
                // BINUNICODE8
                let len = self.read_u64()? as usize;
                self.fill_buf(len, buf)?;
                let start = buf.len() - len;
                Ok(Event::BinUnicode8(buf[start..].to_vec()))
            }
            0x42 => {
                // BINBYTES
                let len = self.read_i32()? as usize;
                self.fill_buf(len, buf)?;
                let start = buf.len() - len;
                Ok(Event::BinBytes(buf[start..].to_vec()))
            }
            0x43 => {
                // SHORT_BINBYTES
                let len = self.read_u8()? as usize;
                self.fill_buf(len, buf)?;
                Ok(Event::ShortBinBytes(len as u8))
            }
            0x8e => {
                // BINBYTES8
                let len = self.read_u64()? as usize;
                self.fill_buf(len, buf)?;
                let start = buf.len() - len;
                Ok(Event::BinBytes8(buf[start..].to_vec()))
            }
            0x96 => {
                // BYTEARRAY8
                let len = self.read_u64()? as usize;
                self.fill_buf(len, buf)?;
                let start = buf.len() - len;
                Ok(Event::ByteArray8(buf[start..].to_vec()))
            }

            // Collections
            0x29 => Ok(Event::EmptyTuple),  // )
            0x74 => Ok(Event::Tuple),       // t
            0x85 => Ok(Event::Tuple1),      // TUPLE1
            0x86 => Ok(Event::Tuple2),      // TUPLE2
            0x87 => Ok(Event::Tuple3),      // TUPLE3
            0x5d => Ok(Event::EmptyList),   // ]
            0x6c => Ok(Event::List),        // l
            0x61 => Ok(Event::Append),      // a
            0x65 => Ok(Event::Appends),     // e
            0x7d => Ok(Event::EmptyDict),   // }
            0x64 => Ok(Event::Dict),        // d
            0x73 => Ok(Event::SetItem),     // s
            0x75 => Ok(Event::SetItems),    // u
            0x8f => Ok(Event::EmptySet),    // EMPTY_SET
            0x90 => Ok(Event::AdditItems),  // ADDITEMS
            0x91 => Ok(Event::FrozenSet),   // FROZENSET

            // Memo operations
            0x67 => {
                // GET
                let s = self.read_line_string(buf)?;
                Ok(Event::Get(s.parse().map_err(|_| Error::Protocol([0x67, 0]))?))
            }
            0x68 => Ok(Event::BinGet(self.read_u8()?)),       // h
            0x6a => Ok(Event::LongBinGet(self.read_i32()? as u32)), // j
            0x70 => {
                // PUT
                let s = self.read_line_string(buf)?;
                Ok(Event::Put(s.parse().map_err(|_| Error::Protocol([0x70, 0]))?))
            }
            0x71 => Ok(Event::BinPut(self.read_u8()?)),       // q
            0x72 => Ok(Event::LongBinPut(self.read_i32()? as u32)), // r
            0x94 => Ok(Event::Memoize),                       // MEMOIZE

            // Object construction
            0x63 => {
                // GLOBAL
                let module = self.read_line_string(buf)?;
                let name = self.read_line_string(buf)?;
                Ok(Event::Global(module, name))
            }
            0x93 => Ok(Event::StackGlobal), // STACK_GLOBAL
            0x52 => Ok(Event::Reduce),      // R
            0x62 => Ok(Event::Build),       // b
            0x69 => {
                // INST
                let module = self.read_line_string(buf)?;
                let name = self.read_line_string(buf)?;
                Ok(Event::Inst(module, name))
            }
            0x6f => Ok(Event::Obj),         // o
            0x81 => Ok(Event::NewObj),      // NEWOBJ
            0x92 => Ok(Event::NewObjEx),    // NEWOBJ_EX

            // Persistent objects
            0x50 => {
                // PERSID
                let s = self.read_line_string(buf)?;
                Ok(Event::PersId(s))
            }
            0x51 => Ok(Event::BinPersId),   // Q

            // Extensions
            0x82 => Ok(Event::Ext1(self.read_u8()?)),         // EXT1
            0x83 => Ok(Event::Ext2(self.read_u16()?)),        // EXT2
            0x84 => Ok(Event::Ext4(self.read_i32()? as u32)), // EXT4

            // Protocol 4
            0x95 => Ok(Event::Frame(self.read_u64()? as usize)), // FRAME

            // Protocol 5
            0x97 => Ok(Event::NextBuffer),     // NEXT_BUFFER
            0x98 => Ok(Event::ReadonlyBuffer), // READONLY_BUFFER

            _ => Err(Error::OpCode(opcode)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_event() {
        assert_eq!(std::mem::size_of::<Event>(), 56);
    }

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
    fn test_read_float() -> Result<(), Error> {
        let data: &[u8] = b"\x80\x04\x95\n\x00\x00\x00\x00\x00\x00\x00G?\xe1G\xae\x14z\xe1H.";
        let mut reader = Reader::new(data)?;
        let mut buf = Vec::new();
        loop {
            match reader.read_event(&mut buf)? {
                Event::BinFloat(v) => assert_eq!(v, 0.54),
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
        let mut s = Vec::new();
        loop {
            match reader.read_event(&mut buf)? {
                Event::ShortBinUnicode(len) => {
                    s = buf[buf.len() - len as usize..].to_vec();
                }
                Event::Stop => break,
                _ => (),
            }
            buf.clear();
        }

        assert_eq!(s, b"/");
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
