use std::fmt;
use std::io::{self, Read};
use crate::bigsize::BigSize;
use crate::ser::{Readable, FixedLengthReadable, DecodeError, Writeable};

/// A tlv_stream is a series of (possibly zero) tlv_records, represented as the concatenation of
/// the encoded tlv_records.
#[derive(Debug)]
struct TLVStream(Vec<TLVRecord>);

#[derive(Debug)]
struct TLVRecord {
    /// It functions as a message-specific, 64-bit identifier for the tlv_record determining how
    /// the contents of value should be decoded. type identifiers below 2^16 are reserved for use
    /// in this specification. type identifiers greater than or equal to 2^16 are available for
    /// custom records. Any record not defined in this specification is considered a custom record.
    record_type: BigSize,
    /// The size of value in bytes.
    length: BigSize,
    /// Depends on `type`, and should be encoded or decoded according to the message-specific 
    /// format determined by `type`.
    value: Option<Value>
}

#[derive(Debug)]
enum Value {
    Amount(u64),
    ShortChannelId([u8; 8]),
    Value3(Value3),
    CLTVExpiry(u16),
    Unknown(Vec<u8>),
}

#[derive(Debug)]
struct Value3 {
    point: Point,
    amount_msat_1: u64,
    amount_msat_2: u64,
}

#[derive(Debug)]
struct Point([u8; 33]);

impl Value3 {
    fn new(stream: Vec<u8>) -> Result<Self, DecodeError> {
        let point: Point = Point(stream[..33].try_into().map_err(|_| DecodeError::ShortRead)?);
        let amount_msat_1: u64 = u64::from_be_bytes(stream[33..41].try_into().map_err(|_| DecodeError::ShortRead)?);
        let amount_msat_2: u64 = u64::from_be_bytes(stream[41..49].try_into().map_err(|_| DecodeError::ShortRead)?);

        Ok(Value3 {
            point,
            amount_msat_1,
            amount_msat_2,
        })
    }
}

impl Readable for TLVStream {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let mut tlv_stream: Vec<TLVRecord> = Vec::new();
        loop {
            let record: TLVRecord = match Readable::read(reader) {
                Ok(r) => r,
                Err(DecodeError::ShortRead) => {
                    if !tlv_stream.is_empty() { break }
                    else { return Err(DecodeError::ShortRead) }
                }
                Err(e) => return Err(e)
            };
            match record.value {
                Some(Value::Unknown(_)) => continue,
                _ => tlv_stream.push(record)
            }
        }

        Ok(TLVStream(tlv_stream))
    }
}

impl fmt::Display for TLVStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for record in &self.0 {
            write!(f, "{}", record)?;
        }
        Ok(())
    }
}

macro_rules! decode_tlv1 {
    ($stream: expr) => {{
        match $stream.len() {
            0 => { Err(DecodeError::ShortRead) },
            n if n <= 8 => {
                let mut res = [0; 8];
                for (i, el) in $stream.iter().enumerate() {
                    res[8 - n + i] = *el;
                }
                Ok(Some(Value::Amount(u64::from_be_bytes(res))))
            },
            _ => { Err(DecodeError::ShortRead) },
        }
    }}
}

macro_rules! decode_tlv2 {
    ($stream: expr) => {{
        match $stream.try_into().map_err(|_| DecodeError::ShortRead) {
            Ok(b) => Ok(Some(Value::ShortChannelId(b))),
            Err(e) => Err(e)
        }
    }}
}

macro_rules! decode_tlv3 {
    ($stream: expr) => {{
        Ok(Some(Value::Value3(Value3::new($stream)?)))
    }}
}

macro_rules! decode_tlv4 {
    ($stream: expr) => {{
        match $stream.try_into().map_err(|_| DecodeError::ShortRead) {
            Ok(b) => Ok(Some(Value::CLTVExpiry(u16::from_be_bytes(b)))),
            Err(e) => Err(e)
        }
    }}
}

impl Readable for TLVRecord {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let record_type: BigSize = Readable::read(reader)?;
        let length: BigSize = Readable::read(reader)?;
        let v: Vec<u8> = FixedLengthReadable::read(reader, length.0 as usize)?;


        let value = match record_type.0 {
            1 => decode_tlv1!(v),
            2 => decode_tlv2!(v),
            3 => decode_tlv3!(v),
            254 => decode_tlv4!(v),
            x if x % 2 == 0 => Err(DecodeError::Io(io::ErrorKind::Unsupported)),
            _ => Ok(Some(Value::Unknown(v))),
        };

        match value {
            Err(DecodeError::ShortRead) => {
                if length.0 == 0 {
                    Ok(TLVRecord {
                        record_type,
                        length,
                        value: None
                    })
                } else {
                    Err(DecodeError::ShortRead)
                }
            },
            Err(e) => Err(e),
            Ok(value) => {
                Ok(TLVRecord {
                    record_type,
                    length,
                    value
                })
            }
        }
    }
}


impl fmt::Display for TLVRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.record_type.write_fmt(f)?;
        self.length.write_fmt(f)?;
        if let Some(v) = &self.value {
            let n: usize = (self.length.0 * 2) as usize;
            write!(f, "{:01$x}", v, n)?;
        }
        Ok(())
    }
}

impl fmt::LowerHex for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Amount(v) => Ok(v.fmt(f)?),
            Value::ShortChannelId(scid) => {
                for byte in scid {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
            Value::Value3(v) => {
                for byte in v.point.0 {
                    write!(f, "{:02x}", byte)?;
                }

                write!(f, "{:016x}", v.amount_msat_1)?;
                write!(f, "{:016x}", v.amount_msat_2)?;
                Ok(())
            }
            Value::CLTVExpiry(v) => Ok(v.fmt(f)?),
            Value::Unknown(b) => todo!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, self};

    use crate::ser::{Readable, DecodeError};

    use super::TLVStream;


    /// The following TLV streams in either namespace should correctly decode, and be ignored
    #[test]
    fn tlv_stream_decode_success_ignored() {
        let test_vectors = [
            "", // TODO: handle tlv_stream read break case
            concat!("21", "00"),
            concat!("fd0201", "00"),
            concat!("fd00fd", "00"),
            concat!("fd00ff", "00"),
            concat!("fe02000001", "00"),
            concat!("ff0200000000000001", "00"),
        ];

        for vector in test_vectors {
            println!("{}", vector);
            let mut buff = Cursor::new(hex::decode(vector).expect("input"));
            let stream: TLVStream = Readable::read(&mut buff).expect("no failure");
            assert_eq!(stream.to_string(), "");
        }
    }

    /// The following TLV streams in `n1` namespace should correctly decode, with the values given
    #[test]
    fn tlv_stream_decode_success_values() {
        let test_vectors = [
            (concat!("01", "00"), "tlv1 amount_msat=0"),
            (concat!("01", "01", "01"), "tlv1 amount_msat=1"),
            (concat!("01", "02", "0100"), "tlv1 amount_msat=256"),
            (concat!("01", "03", "010000"), "tlv1 amount_msat=65536"),
            (concat!("01", "04", "01000000"), "tlv1 amount_msat=16777216"),
            (concat!("01", "05", "0100000000"), "tlv1 amount_msat=4294967296"),
            (concat!("01", "06", "010000000000"), "tlv1 amount_msat=1099511627776"),
            (concat!("01", "07", "01000000000000"), "tlv1 amount_msat=281474976710656"),
            (concat!("01", "08", "0100000000000000"), "tlv1 amount_msat=72057594037927936"),
            (concat!("02", "08", "0000000000000226"), "tlv2 scid=0x0x550"),
            (concat!("03", "31", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002"),
            "tlv3 node_id=023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb amount_msat_1=1 amount_msat_2=2"),
            (concat!("fd00fe", "02", "0226"), "tlv4 cltv_delta=550"),
        ];

        for vector in test_vectors {
            let mut buff = Cursor::new(hex::decode(vector.0).expect("input"));
            let stream: TLVStream = Readable::read(&mut buff).expect("no failure");
            assert_eq!(stream.to_string(), vector.0);
        }
    }

    #[test]
    fn tlv_stream_decode_failure_any_namespace() {
        macro_rules! do_test {
            ($stream: expr, $err: expr) => {
                let mut buff = Cursor::new(hex::decode($stream).expect("input"));
                let expected: Result<TLVStream, DecodeError> = Readable::read(&mut buff);
                assert_eq!(expected.unwrap_err(), $err);
            };
        }
        do_test!("fd", DecodeError::ShortRead);
        do_test!("fd01", DecodeError::ShortRead);
        do_test!(concat!("fd0001", "00"), DecodeError::InvalidData);
        do_test!("fd0101", DecodeError::ShortRead);
        do_test!(concat!("0f", "fd"), DecodeError::ShortRead);
        do_test!(concat!("0f", "fd26"), DecodeError::ShortRead);
        do_test!(concat!("0f", "fd2602"), DecodeError::ShortRead);
        do_test!(concat!("0f", "fd0001", "00"), DecodeError::InvalidData);
        do_test!(concat!("0f", "fd0201", "000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
        0000"), DecodeError::ShortRead);

    }

    #[test]
    fn tlv_stream_decode_failure_either_namespace() {
        let test_vectors = [
            (concat!("12", "00"), "unknown even type."),
            (concat!("fd0102", "00"), "unknown even type."),
            (concat!("fe01000002", "00"), "unknown even type."),
            (concat!("ff0100000000000002", "00"), "unknown even type."),
        ];

        for vector in test_vectors {
            let mut buff = Cursor::new(hex::decode(vector.0).expect("input"));
            let stream: TLVStream = Readable::read(&mut buff).expect("no failure");
            assert_eq!(stream.to_string(), vector.0);
        }
    }

    #[test]
    fn tlv_stream_decode_failure_n1_namespace() {
        let test_vectors = [
            (concat!("01", "09", "ffffffffffffffffff"), "greater than encoding length for n1s tlv1."),
            (concat!("01", "01", "00"), "encoding for n1s tlv1s amount_msat is not minimal"),
            (concat!("01", "02", "0001"), "encoding for n1s tlv1s amount_msat is not minimal"),
            (concat!("01", "03", "000100"), "encoding for n1s tlv1s amount_msat is not minimal"),
            (concat!("01", "04", "00010000"), "encoding for n1s tlv1s amount_msat is not minimal"),
            (concat!("01", "05", "0001000000"), "encoding for n1s tlv1s amount_msat is not minimal"),
            (concat!("01", "06", "000100000000"), "encoding for n1s tlv1s amount_msat is not minimal"),
            (concat!("01", "07", "00010000000000"), "encoding for n1s tlv1s amount_msat is not minimal"),
            (concat!("01", "08", "0001000000000000"), "encoding for n1s tlv1s amount_msat is not minimal"),
            (concat!("02", "07", "01010101010101"), "less than encoding length for n1s tlv2."),
            (concat!("02", "09", "010101010101010101"), "greater than encoding length for n1s tlv2."),
            (concat!("03", "21", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            "less than encoding length for n1s tlv3."),
            (concat!("03", "29", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001"),
            "less than encoding length for n1s tlv3."),
            (concat!("03", "30", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb000000000000000100000000000001"),
            "less than encoding length for n1s tlv3."),
            (concat!("03", "31", "043da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002"),
            "n1s node_id is not a valid point."),
            (concat!("03", "32", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001000000000000000001"),
            "greater than encoding length for n1s tlv3."),
            (concat!("fd00fe", "00"), "less than encoding length for n1s tlv4."),
            (concat!("fd00fe", "01", "01"), "less than encoding length for n1s tlv4."),
            (concat!("fd00fe", "03", "010101"), "greater than encoding length for n1s tlv4."),
            (concat!("00", "00"), "unknown even field for n1s namespace."),
            ];
    }

    /// Any appending of an invalid stream to a valid stream should trigger a decoding failure.
    /// Any appending of a higher-numbered valid stream to a lower-numbered valid stream should not
    /// trigger a decoding failure.
    #[test]
    fn tlv_stream_decode_failure_appending_n1() {
        let test_vectors = [
            (concat!("02", "08", "0000000000000226", "01", "01", "2a"), "valid TLV records but invalid ordering"),
            (concat!("02", "08", "0000000000000231", "02", "08", "0000000000000451"), "duplicate TLV type"),
            (concat!("1f", "00", "0f", "01", "2a"), "valid (ignored) TLV records but invalid ordering"),
            (concat!("1f", "00", "1f", "01", "2a"), "duplicate TLV type (ignored)"),
        ];
    }

    /// Any appending of an invalid stream to a valid stream should trigger a decoding failure.
    /// Any appending of a higher-numbered valid stream to a lower-numbered valid stream should not
    /// trigger a decoding failure.
    #[test]
    fn tlv_stream_decode_failure_appending_n2() {
        let test_vectors = [
            (concat!("ffffffffffffffffff", "00", "00", "00"), "valid TLV records but invalid ordering"),
        ];
    }
}
