use std::{io::{self, Write, Read}, fmt};

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    Io(io::ErrorKind),
    ShortRead,
    InvalidData,
    UnknownRequiredFeature,
}

impl std::error::Error for DecodeError {}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DecodeError::Io(e) => write!(f, "{:?}", e),
            DecodeError::ShortRead => write!(f, "short read"),
            DecodeError::InvalidData => write!(f, "invalid data"),
            DecodeError::UnknownRequiredFeature => write!(f, "unknown required feature"),
        }
    }
}

/// Objects that can be encoded into a BOLT specific format
pub trait Writeable {
    fn write<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error>;
    fn write_fmt<W: fmt::Write>(&self, writer: &mut W) -> Result<(), fmt::Error>;

    fn encode(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        self.write(&mut msg).unwrap();
        msg
    }
}

macro_rules! impl_writeable_int_be {
	($ty: ty) => {
        impl Writeable for $ty {
            fn write<W: Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
                let bytes = self.to_be_bytes();
                match writer.write(&bytes) {
                    Ok(n) => Ok(n),
                    Err(e) => panic!("{}", e)
                }
            }

            fn write_fmt<W: fmt::Write>(&self, _writer: &mut W) -> Result<(), fmt::Error> {
                todo!()
            }
        }
	};
}

impl_writeable_int_be!(u8);
impl_writeable_int_be!(u16);
impl_writeable_int_be!(u32);
impl_writeable_int_be!(u64);

/// Objects that can be decoded from a BOLT specific format
pub trait Readable where Self: Sized {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError>;
}

macro_rules! impl_readable_int_be {
	($ty: ty, $len: expr) => {
        impl Readable for $ty {
            fn read<R: Read>(reader: &mut R) -> Result<$ty, DecodeError> {
                let mut bytes = [0; $len];
                reader.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
                Ok(<$ty>::from_be_bytes(bytes))
            }
        }
	};
}

impl_readable_int_be!(u8, 1);
impl_readable_int_be!(u16, 2);
impl_readable_int_be!(u32, 4);
impl_readable_int_be!(u64, 8);

/// Read a fixed length of bytes
pub trait FixedLengthReadable where Self: Sized {
	fn read<R: Read>(reader: &mut R, length: usize) -> Result<Self, DecodeError>;
}

impl FixedLengthReadable for Vec<u8> {
	fn read<R: Read>(reader: &mut R, length: usize) -> Result<Self, DecodeError> {
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
        Ok(bytes)
    }
}

/// Picked up from rust-lightning
/// A Read which tracks whether any bytes have been read at all. This allows us to distinguish
/// between "EOF reached before we started" and "EOF reached mid-read".
pub(crate) struct ReadTrackingReader<R: Read> {
	read: R,
	pub have_read: bool,
}
impl<R: Read> ReadTrackingReader<R> {
	pub fn new(read: R) -> Self {
		Self { read, have_read: false }
	}
}
impl<R: Read> Read for ReadTrackingReader<R> {
	#[inline]
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		match self.read.read(dest) {
			Ok(0) => Ok(0),
			Ok(len) => {
				self.have_read = true;
				Ok(len)
			},
			Err(e) => Err(e),
		}
	}
}
