// #[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Protocol([u8; 2]),
    /// Unsupported opcode
    OpCode(u8),
    Str(std::str::Utf8Error),
}

impl From<std::io::Error> for Error {
    fn from(v: std::io::Error) -> Self {
        Self::Io(v)
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(error) => error.fmt(f),
            Error::Protocol(p) => write!(f, "Unsupported protocol: 0x{p:x?}"),
            Error::OpCode(op) => write!(f, "Unsupported opcode: 0x{op:x}"),
            Error::Str(error) => error.fmt(f),
        }
    }
}
