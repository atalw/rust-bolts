use core::fmt;
use std::io::{self, Write, Read, ErrorKind};
use crate::ser::{Writeable, Readable, DecodeError};

/// BigSize is identical to the CompactSize encoding used in bitcoin, but replaces the 
/// little-endian encoding of multi-byte values with big-endian.
#[derive(Debug)]
pub struct BigSize(pub u64);

impl Writeable for BigSize {
    fn write<W: Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let x = self.0;

        if x < 0xfd {
            (x as u8).write(writer)
        } else if x < 0x10000 {
            0xfdu8.write(writer)?;
            (x as u16).write(writer)
        } else if x < 0x100000000 {
            0xfeu8.write(writer)?;
            (x as u32).write(writer)
        } else {
            0xffu8.write(writer)?;
            (x as u64).write(writer)
        }
    }
}

impl Readable for BigSize {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let size: u8 = Readable::read(reader)?;

        if size == 0xfd {
            let x: u16 = Readable::read(reader)?;
            if x < 0xfd {
                return Err(DecodeError::Io(ErrorKind::InvalidData))
            }
            Ok(BigSize(x as u64))
        } else if size == 0xfe {
            let x: u32 = Readable::read(reader)?;
            if x < 0x10000 {
                return Err(DecodeError::Io(ErrorKind::InvalidData))
            }
            Ok(BigSize(x as u64))
        } else if size == 0xff {
            let x: u64 = Readable::read(reader)?;
            if x < 0x100000000 {
                return Err(DecodeError::Io(ErrorKind::InvalidData))
            }
            Ok(BigSize(x as u64))
        } else {
            Ok(BigSize(size as u64))
        }
    }
}

impl fmt::LowerHex for BigSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::io::Cursor;

    #[derive(Clone, Debug)]
    enum Value {
        Title(String),
        Number(u64),
        Hex(String),
        Error(Option<String>)
    }

    #[test]
    fn encode_bigsize() {
        let test_vectors = [
            [
                Value::Title("zero".into()),
                Value::Number(0),
                Value::Hex("00".into())
            ],
            [
                Value::Title("one byte high".into()),
                Value::Number(252),
                Value::Hex("fc".into())
            ],
            [
                Value::Title("two byte low".into()),
                Value::Number(253),
                Value::Hex("fd00fd".into())
            ],
            [
                Value::Title("two byte high".into()),
                Value::Number(65535),
                Value::Hex("fdffff".into())
            ],
            [
                Value::Title("four byte low".into()),
                Value::Number(65536),
                Value::Hex("fe00010000".into())
            ],
            [
                Value::Title("four byte high".into()),
                Value::Number(4294967295),
                Value::Hex("feffffffff".into())
            ],
            [
                Value::Title("eight byte low".into()),
                Value::Number(4294967296),
                Value::Hex("ff0000000100000000".into())
            ],
            [
                Value::Title("eight byte high".into()),
                Value::Number(18446744073709551615),
                Value::Hex("ffffffffffffffffff".into())
            ]
        ];

        for vector in test_vectors {
            if let (Value::Number(val), Value::Hex(res)) = (vector[1].clone(), vector[2].clone()) {
                let bytes = BigSize(val).encode();
                assert_eq!(hex::encode(bytes), res);
            }
        }
    }

    #[test]
    fn decode_bigsize() {
        // Structure: [name, value, bytes, exp_error?]
        let test_vectors: Vec<[Value; 4]> = vec![
            [
                Value::Title("zero".into()),
                Value::Number(0),
                Value::Hex("00".into()),
                Value::Error(None),
            ],
            [
                Value::Title("one byte high".into()),
                Value::Number(252),
                Value::Hex("fc".into()),
                Value::Error(None),
            ],
            [
                Value::Title("two byte low".into()),
                Value::Number(253),
                Value::Hex("fd00fd".into()),
                Value::Error(None),
            ],
            [
                Value::Title("two byte high".into()),
                Value::Number(65535),
                Value::Hex("fdffff".into()),
                Value::Error(None),
            ],
            [
                Value::Title("four byte low".into()),
                Value::Number(65536),
                Value::Hex("fe00010000".into()),
                Value::Error(None),
            ],
            [
                Value::Title("four byte high".into()),
                Value::Number(4294967295),
                Value::Hex("feffffffff".into()),
                Value::Error(None),
            ],
            [
                Value::Title("eight byte low".into()),
                Value::Number(4294967296),
                Value::Hex("ff0000000100000000".into()),
                Value::Error(None),
            ],
            [
                Value::Title("eight byte high".into()),
                Value::Number(18446744073709551615),
                Value::Hex("ffffffffffffffffff".into()),
                Value::Error(None),
            ],
            [
                Value::Title("two byte not canonical".into()),
                Value::Number(0),
                Value::Hex("fd00fc".into()),
                Value::Error(Some("decoded bigsize is not canonical".into()))
            ],
            [
                Value::Title("four byte not canonical".into()),
                Value::Number(0),
                Value::Hex("fe0000ffff".into()),
                Value::Error(Some("decoded bigsize is not canonical".into()))
            ],
            [
                Value::Title("eight byte not canonical".into()),
                Value::Number(0),
                Value::Hex("ff00000000ffffffff".into()),
                Value::Error(Some("decoded bigsize is not canonical".into()))
            ],
            [
                Value::Title("two byte short read".into()),
                Value::Number(0),
                Value::Hex("fd00".into()),
                Value::Error(Some("unexpected EOF".into()))
            ],
            [
                Value::Title("four byte short read".into()),
                Value::Number(0),
                Value::Hex("feffff".into()),
                Value::Error(Some("unexpected EOF".into()))
            ],
            [
                Value::Title("eight byte short read".into()),
                Value::Number(0),
                Value::Hex("ffffffffff".into()),
                Value::Error(Some("unexpected EOF".into()))
            ],
            [
                Value::Title("one byte no read".into()),
                Value::Number(0),
                Value::Hex("".into()),
                Value::Error(Some("EOF".into()))
            ],
            [
                Value::Title("two byte no read".into()),
                Value::Number(0),
                Value::Hex("fd".into()),
                Value::Error(Some("unexpected EOF".into()))
            ],
            [
                Value::Title("four byte no read".into()),
                Value::Number(0),
                Value::Hex("fe".into()),
                Value::Error(Some("unexpected EOF".into()))
            ],
            [
                Value::Title("eight byte no read".into()),
                Value::Number(0),
                Value::Hex("ff".into()),
                Value::Error(Some("unexpected EOF".into()))
            ]
        ];

        for vector in test_vectors {
            if let (Value::Number(val), Value::Hex(input), Value::Error(err)) = 
                (vector[1].clone(), vector[2].clone(), vector[3].clone()) {

                let bytes = hex::decode(input.clone()).expect("parse test input");
                let mut buff = Cursor::new(bytes);
                let bigsize = match BigSize::read(&mut buff) {
                    Ok(bs) => bs,
                    Err(e) => continue
                };

                assert_eq!(bigsize.0, val);
            }

        }
    }
}
