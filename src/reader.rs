//! A module to read pickle events

use std::{
    fs::File,
    io::{BufRead, BufReader, Cursor},
    path::Path,
    str::from_utf8,
    sync::mpsc::channel,
    thread::{self},
};

use crate::errors::Error;

const FRAME_SPAWN_SIZE: u64 = 1024 * 128;
// const FRAME_SPAWN_SIZE: u64 = 1 << 32;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Event {
    // Protocol identification
    Proto(u8),
    Frame(u64),

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
    Long(i64),
    Float(f64),

    // Strings and bytes
    String { len: usize },
    BinString { len: i32 },
    ShortBinString { len: u8 },
    Unicode { len: usize },
    BinUnicode { len: i32 },
    ShortBinUnicode { len: u8 },
    BinUnicode8 { len: i64 },
    BinBytes { len: i32 },
    ShortBinBytes { len: u8 },
    BinBytes8 { len: u64 },  // immutable
    ByteArray8 { len: u64 }, // mutable

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
    Global { module_len: u32, name_len: u32 },
    StackGlobal,
    Reduce,
    Build,
    Inst { module_len: u32, name_len: u32 },
    Obj,
    NewObj,
    NewObjEx,

    // Persistent objects
    PersId { id_len: usize },
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
    pos: usize,
}

impl Reader<BufReader<File>> {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        Ok(Reader::new(BufReader::new(file)))
    }
}

impl<R: BufRead> Reader<R> {
    pub fn new(reader: R) -> Self {
        Reader { reader, pos: 0 }
    }

    /// Load len bytes and create a new frame reader
    fn frame_reader(&mut self, len: u64) -> Result<Reader<Cursor<Vec<u8>>>, Error> {
        let start = self.pos;
        let mut frame_buf = Vec::new();
        self.fill_buf(len as usize, &mut frame_buf)?;
        Ok(Reader::new_at(Cursor::new(frame_buf), start))
    }

    fn new_at(reader: R, start: usize) -> Reader<R> {
        Reader { reader, pos: start }
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut byte = [0];
        self.reader.read_exact(&mut byte)?;
        self.pos += 1;
        Ok(byte[0])
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        let mut bytes = [0; 2];
        self.reader.read_exact(&mut bytes)?;
        self.pos += 2;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        let mut bytes = [0; 4];
        self.reader.read_exact(&mut bytes)?;
        self.pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_i64(&mut self) -> Result<i64, Error> {
        let mut bytes = [0; 8];
        self.reader.read_exact(&mut bytes)?;
        self.pos += 8;
        Ok(i64::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        let mut bytes = [0; 8];
        self.reader.read_exact(&mut bytes)?;
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_f64(&mut self) -> Result<f64, Error> {
        let mut bytes = [0; 8];
        self.reader.read_exact(&mut bytes)?;
        self.pos += 8;
        Ok(f64::from_be_bytes(bytes))
    }

    fn read_i32(&mut self) -> Result<i32, Error> {
        let mut bytes = [0; 4];
        self.reader.read_exact(&mut bytes)?;
        self.pos += 4;
        Ok(i32::from_le_bytes(bytes))
    }

    fn fill_buf(&mut self, len: usize, buf: &mut Vec<u8>) -> Result<(), Error> {
        let buf_len = buf.len();
        buf.resize(buf_len + len, 0);
        self.reader.read_exact(&mut buf[buf_len..])?;
        self.pos += len;
        Ok(())
    }

    fn fill_line(&mut self, buf: &mut Vec<u8>) -> Result<usize, Error> {
        let len = self.reader.read_until(b'\n', buf)?;
        self.pos += len;
        Ok(len)
    }

    pub fn read_event<'a>(&mut self, buf: &mut Vec<u8>) -> Result<Event, Error> {
        let opcode = match self.read_u8() {
            Ok(opcode) => opcode,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // fake a stop event
                return Ok(Event::Stop);
            }
            Err(e) => return Err(e),
        };

        match opcode {
            // Protocol identification
            0x80 => Ok(Event::Proto(self.read_u8()?)),

            // Stack manipulation
            0x28 => Ok(Event::Mark),    // (
            0x2e => Ok(Event::Stop),    // .
            0x30 => Ok(Event::Pop),     // 0
            0x31 => Ok(Event::PopMark), // 1
            0x32 => Ok(Event::Dup),     // 2

            // Basic types
            0x4e => Ok(Event::None),        // N
            0x88 => Ok(Event::Bool(true)),  // NEWTRUE
            0x89 => Ok(Event::Bool(false)), // NEWFALSE
            0x49 => {
                // INT - decimal string
                let start = buf.len();
                let _ = self.fill_line(buf)?;
                let s = &buf[start..];
                let event = if s == b"01" {
                    Event::Bool(true)
                } else if s == b"00" {
                    Event::Bool(false)
                } else {
                    Event::Int(atoi::atoi::<i32>(s).ok_or(Error::Protocol(0x49))?)
                };
                buf.truncate(start);
                Ok(event)
            }
            0x4a => Ok(Event::BinInt(self.read_i32()?)), // J
            0x4b => Ok(Event::BinInt1(self.read_u8()?)), // K
            0x4d => Ok(Event::BinInt2(self.read_u16()?)), // M
            0x4c => {
                // LONG - decimal string
                let start = buf.len();
                let _ = self.fill_line(buf)?;
                if buf.last() == Some(&b'L') {
                    buf.pop();
                }
                let long = atoi::atoi(&buf[start..]).ok_or(Error::Protocol(0x4c))?;
                buf.truncate(start);
                Ok(Event::Long(long))
            }
            0x8a => {
                // LONG1
                let start = buf.len();
                let len = self.read_u8()? as usize;
                let _ = self.fill_buf(len, buf)?;
                let long = atoi::atoi(&buf[start..]).ok_or(Error::Protocol(0x8a))?;
                buf.truncate(start);
                Ok(Event::Long(long))
            }
            0x8b => {
                // LONG4
                let start = buf.len();
                let len = self.read_i32()? as usize;
                let _ = self.fill_buf(len, buf)?;
                let long = atoi::atoi(&buf[start..]).ok_or(Error::Protocol(0x8a))?;
                buf.truncate(start);
                Ok(Event::Long(long))
            }
            0x46 => {
                // FLOAT - decimal string
                let start = buf.len();
                let _ = self.fill_line(buf)?;
                let s = from_utf8(&buf[start..]).map_err(Error::Str)?;
                let v = s.parse().map_err(|_| Error::Protocol(0x46))?;
                buf.truncate(start);
                Ok(Event::Float(v))
            }
            0x47 => Ok(Event::Float(self.read_f64()?)), // G

            // Strings and bytes
            0x53 => {
                // STRING
                let len = self.fill_line(buf)?;
                Ok(Event::String { len })
            }
            0x54 => {
                // BINSTRING
                let len = self.read_i32()?;
                self.fill_buf(len as usize, buf)?;
                Ok(Event::BinString { len })
            }
            0x55 => {
                // SHORT_BINSTRING
                let len = self.read_u8()?;
                self.fill_buf(len as usize, buf)?;
                Ok(Event::ShortBinString { len })
            }
            0x56 => {
                // UNICODE
                let len = self.fill_line(buf)?;
                Ok(Event::Unicode { len })
            }
            0x58 => {
                // BINUNICODE
                let len = self.read_i32()?;
                self.fill_buf(len as usize, buf)?;
                Ok(Event::BinUnicode { len })
            }
            0x8c => {
                // SHORT_BINUNICODE
                let len = self.read_u8()?;
                self.fill_buf(len as usize, buf)?;
                Ok(Event::ShortBinUnicode { len })
            }
            0x8d => {
                // BINUNICODE8
                let len = self.read_i64()?;
                self.fill_buf(len as usize, buf)?;
                Ok(Event::BinUnicode8 { len })
            }
            0x42 => {
                // BINBYTES
                let len = self.read_i32()?;
                self.fill_buf(len as usize, buf)?;
                Ok(Event::BinBytes { len })
            }
            0x43 => {
                // SHORT_BINBYTES
                let len = self.read_u8()?;
                self.fill_buf(len as usize, buf)?;
                Ok(Event::ShortBinBytes { len })
            }
            0x8e => {
                // BINBYTES8
                let len = self.read_u64()?;
                self.fill_buf(len as usize, buf)?;
                Ok(Event::BinBytes8 { len })
            }
            0x96 => {
                // BYTEARRAY8
                let len = self.read_u64()?;
                self.fill_buf(len as usize, buf)?;
                Ok(Event::ByteArray8 { len })
            }

            // Collections
            0x29 => Ok(Event::EmptyTuple), // )
            0x74 => Ok(Event::Tuple),      // t
            0x85 => Ok(Event::Tuple1),     // TUPLE1
            0x86 => Ok(Event::Tuple2),     // TUPLE2
            0x87 => Ok(Event::Tuple3),     // TUPLE3
            0x5d => Ok(Event::EmptyList),  // ]
            0x6c => Ok(Event::List),       // l
            0x61 => Ok(Event::Append),     // a
            0x65 => Ok(Event::Appends),    // e
            0x7d => Ok(Event::EmptyDict),  // }
            0x64 => Ok(Event::Dict),       // d
            0x73 => Ok(Event::SetItem),    // s
            0x75 => Ok(Event::SetItems),   // u
            0x8f => Ok(Event::EmptySet),   // EMPTY_SET
            0x90 => Ok(Event::AdditItems), // ADDITEMS
            0x91 => Ok(Event::FrozenSet),  // FROZENSET

            // Memo operations
            0x67 => {
                // GET
                let start = buf.len();
                let _ = self.fill_line(buf)?;
                let id = atoi::atoi::<i32>(&buf[start..]).ok_or(Error::Protocol(0x67))?;
                buf.truncate(start);
                Ok(Event::Get(id))
            }
            0x68 => Ok(Event::BinGet(self.read_u8()?)), // h
            0x6a => Ok(Event::LongBinGet(self.read_i32()? as u32)), // j
            0x70 => {
                // PUT
                let start = buf.len();
                let _ = self.fill_line(buf)?;
                let id = atoi::atoi::<i32>(&buf[start..]).ok_or(Error::Protocol(0x70))?;
                buf.truncate(start);
                Ok(Event::Put(id))
            }
            0x71 => Ok(Event::BinPut(self.read_u8()?)), // q
            0x72 => Ok(Event::LongBinPut(self.read_i32()? as u32)), // r
            0x94 => Ok(Event::Memoize),                 // MEMOIZE

            // Object construction
            0x63 => {
                // GLOBAL
                Ok(Event::Global {
                    module_len: self.fill_line(buf)? as u32,
                    name_len: self.fill_line(buf)? as u32,
                })
            }
            0x93 => Ok(Event::StackGlobal), // STACK_GLOBAL
            0x52 => Ok(Event::Reduce),      // R
            0x62 => Ok(Event::Build),       // b
            0x69 => {
                // INST
                Ok(Event::Inst {
                    module_len: self.fill_line(buf)? as u32,
                    name_len: self.fill_line(buf)? as u32,
                })
            }
            0x6f => Ok(Event::Obj),      // o
            0x81 => Ok(Event::NewObj),   // NEWOBJ
            0x92 => Ok(Event::NewObjEx), // NEWOBJ_EX

            // Persistent objects
            0x50 => {
                // PERSID
                let id_len = self.fill_line(buf)?;
                Ok(Event::PersId { id_len })
            }
            0x51 => Ok(Event::BinPersId), // Q

            // Extensions
            0x82 => Ok(Event::Ext1(self.read_u8()?)), // EXT1
            0x83 => Ok(Event::Ext2(self.read_u16()?)), // EXT2
            0x84 => Ok(Event::Ext4(self.read_u32()?)), // EXT4

            // Protocol 4
            0x95 => Ok(Event::Frame(self.read_u64()?)), // FRAME

            // Protocol 5
            0x97 => Ok(Event::NextBuffer),     // NEXT_BUFFER
            0x98 => Ok(Event::ReadonlyBuffer), // READONLY_BUFFER

            _ => Err(Error::OpCode(opcode)),
        }
    }

    /// Collect all events in parallel
    pub fn par_collect_events(&mut self) -> Result<Vec<Event>, Error> {
        let (tx, rx) = channel();
        let mut events = Vec::new();
        let mut buf = Vec::new();
        let mut threads = Vec::new();
        loop {
            match self.read_event(&mut buf)? {
                Event::Frame(len) => {
                    // if the frame is big enough, spawn a new reader to send in parallel
                    if len >= FRAME_SPAWN_SIZE {
                        // load the frame and spawn a new reader
                        // dbg!(len);
                        let mut frame_reader = self.frame_reader(len)?;
                        let tx = tx.clone();
                        threads.push(thread::spawn::<_, Result<(), Error>>(move || {
                            let mut frame_buf = Vec::new();
                            loop {
                                let event = frame_reader.read_event(&mut frame_buf)?;
                                if let Event::Stop = event {
                                    break;
                                }
                                frame_buf.clear();
                                tx.send((frame_reader.pos, event)).unwrap();
                            }
                            Ok(())
                        }));
                    }
                }
                Event::Stop => break,
                event => events.push((self.pos, event)),
            }
            buf.clear();
        }

        if !threads.is_empty() {
            // assert_eq!(threads.len(), 4);
            drop(tx); // drop orphaned tx

            // wait for the threads to end
            for th in threads {
                th.join().unwrap()?;
            }

            // collect all events
            while let Ok((id, event)) = rx.recv() {
                events.push((id, event));
            }
            events.sort_by_key(|(id, _)| *id); // stable sort by frame
        }

        Ok(events.into_iter().map(|(_, event)| event).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_event() {
        assert_eq!(std::mem::size_of::<Event>(), 16);
    }

    #[test]
    fn test_read_true() -> Result<(), Error> {
        let data: &[u8] = b"\x80\x04\x88.";
        let mut reader = Reader::new(data);
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
        let mut reader = Reader::new(data);
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
        let mut reader = Reader::new(data);
        let mut buf = Vec::new();
        let mut value = 0.0;
        loop {
            match reader.read_event(&mut buf)? {
                Event::Float(v) => value = v,
                Event::Stop => break,
                _ => (),
            }
            buf.clear();
        }

        assert_eq!(value, 0.54);
        Ok(())
    }

    #[test]
    fn test_read_str() -> Result<(), Error> {
        // "/"
        let data: &[u8] = &[
            0x80, 0x04, 0x95, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x01, b'/',
            0x94, b'.',
        ];
        let mut reader = Reader::new(data);
        let mut buf = Vec::new();
        let mut s = Vec::new();
        loop {
            match reader.read_event(&mut buf)? {
                Event::ShortBinUnicode { len } => {
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
        let mut reader = Reader::new(data);
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

    #[test]
    fn test_read_collect_str() -> Result<(), Error> {
        // "/"
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x80, 0x04, // proto
            0x95, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // frame
            0x8c, 0x01, b'/', // str
            0x94, // memo
            b'.', // stop
        ];
        let mut reader = Reader::new(data);
        let events = reader.par_collect_events()?;
        assert_eq!(
            &events,
            &[
                Event::Proto(4),
                Event::ShortBinUnicode { len: 1 },
                Event::Memoize
            ],
            "{events:?}"
        );
        Ok(())
    }

    #[test]
    fn test_read_ints_from_file() -> Result<(), Error> {
        let mut reader = Reader::open(concat!(env!("CARGO_MANIFEST_DIR"), "/ints.pickle"))?;
        let events = reader.par_collect_events()?;
        assert_eq!(events.len(), 10023);
        Ok(())
    }

    #[test]
    fn test_read_dict_from_file() -> Result<(), Error> {
        let mut reader = Reader::open(concat!(env!("CARGO_MANIFEST_DIR"), "/dict.pickle"))?;
        let events = reader.par_collect_events()?;
        assert_eq!(events.len(), 20057);
        Ok(())
    }
}
