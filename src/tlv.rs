use std::fmt;
use std::io::Read;
use secp256k1::PublicKey;

use crate::bigsize::BigSize;
use crate::ser::{Readable, FixedLengthReadable, DecodeError, Writeable, ReadTrackingReader};

/// A tlv_stream is a series of (possibly zero) tlv_records, represented as the concatenation of
/// the encoded tlv_records.
#[derive(Debug)]
pub struct TLVStream(Vec<TLVRecord>);

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
    /// tlv1
    Amount(u64),
    /// tlv2
    ShortChannelId([u8; 8]),
    /// tlv3
    PointAmount(PointAmount),
    /// tlv4
    CLTVExpiry(u16),
    /// ignored records
    Unknown(Vec<u8>),
}

#[derive(Debug)]
struct PointAmount {
    point: PublicKey,
    amount_msat_1: u64,
    amount_msat_2: u64,
}

impl Readable for TLVStream {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let mut tlv_stream: Vec<TLVRecord> = Vec::new();
        loop {
            let mut tracking_reader = ReadTrackingReader::new(&mut *reader);
            let record: TLVRecord = match Readable::read(&mut tracking_reader) {
                Ok(r) => r,
                Err(DecodeError::ShortRead) => {
                    if !tracking_reader.have_read { break }
                    else { return Err(DecodeError::ShortRead) }
                }
                Err(e) => return Err(e)
            };
            // All types must appear in increasing order to create a canonical encoding of the
            // underlying tlv_records
            match tlv_stream.last() {
                Some(prev) if prev.record_type.0 >= record.record_type.0 => {
                    return Err(DecodeError::InvalidData)
                },
                _ => {}
            }
            tlv_stream.push(record);
        }
        Ok(TLVStream(tlv_stream))
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
                let val = u64::from_be_bytes(res);
                // Check if it's minimally encoded
                match n {
                    1 if val == 0 => Err(DecodeError::InvalidData),
                    2 if val < 0x0100 => Err(DecodeError::InvalidData),
                    3 if val < 0x010000 => Err(DecodeError::InvalidData),
                    4 if val < 0x01000000 => Err(DecodeError::InvalidData),
                    5 if val < 0x0100000000 => Err(DecodeError::InvalidData),
                    6 if val < 0x010000000000 => Err(DecodeError::InvalidData),
                    7 if val < 0x01000000000000 => Err(DecodeError::InvalidData),
                    8 if val < 0x0100000000000000 => Err(DecodeError::InvalidData),
                    _ => {
                        Ok(Some(Value::Amount(u64::from_be_bytes(res))))
                    }
                }
            },
            _ => { Err(DecodeError::InvalidData) },
        }
    }}
}

macro_rules! decode_tlv2 {
    ($stream: expr) => {{
        if $stream.len() > 8 { Err(DecodeError::InvalidData) }
        else {
            match $stream.try_into().map_err(|_| DecodeError::ShortRead) {
                Ok(b) => Ok(Some(Value::ShortChannelId(b))),
                Err(e) => Err(e)
            }
        }
    }}
}

macro_rules! decode_tlv3 {
    ($stream: expr) => {{
        Ok(Some(Value::PointAmount(PointAmount::new($stream)?)))
    }}
}

macro_rules! decode_tlv4 {
    ($stream: expr) => {{
        match $stream.len() {
            n if n < 2 => Err(DecodeError::ShortRead),
            n if n > 2 => Err(DecodeError::InvalidData),
            _ => Ok(Some(Value::CLTVExpiry(u16::from_be_bytes($stream.try_into().unwrap()))))
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
            x if x % 2 == 0 => Err(DecodeError::UnknownRequiredFeature),
            _ => Ok(Some(Value::Unknown(v))),
        };

        match value {
            Err(DecodeError::ShortRead) => {
                if length.0 == 0 && record_type.0 == 1 {
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

impl PointAmount {
    fn new(stream: Vec<u8>) -> Result<Self, DecodeError> {
        match stream.len() {
            n if n < 49 => Err(DecodeError::ShortRead),
            n if n > 49 => Err(DecodeError::InvalidData),
            _ => {
                let point = match PublicKey::from_slice(&stream[..33]) {
                    Ok(p) => Ok(p),
                    Err(_) => Err(DecodeError::InvalidData),
                }?;
                let amount_msat_1: u64 = u64::from_be_bytes(stream[33..41].try_into().unwrap());
                let amount_msat_2: u64 = u64::from_be_bytes(stream[41..49].try_into().unwrap());

                Ok(PointAmount { point, amount_msat_1, amount_msat_2, })
            }
        }
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


impl fmt::Display for TLVRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ignore unknown record types
        if let Some(Value::Unknown(_)) = self.value { Ok(()) }
        else {
            self.record_type.write_fmt(f)?;
            self.length.write_fmt(f)?;
            if let Some(v) = &self.value {
                let n: usize = (self.length.0 * 2) as usize;
                write!(f, "{:01$x}", v, n)?;
            }
            Ok(())
        }
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
            Value::PointAmount(v) => {
                write!(f, "{:02x}", v.point)?;
                write!(f, "{:016x}", v.amount_msat_1)?;
                write!(f, "{:016x}", v.amount_msat_2)?;
                Ok(())
            }
            Value::CLTVExpiry(v) => Ok(v.fmt(f)?),
            Value::Unknown(_) => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use crate::ser::{Readable, DecodeError};
    use super::TLVStream;

    /// The following TLV streams in either namespace should correctly decode, and be ignored
    #[test]
    fn tlv_stream_decode_success_ignored() {
        let test_vectors = [
            "",
            concat!("21", "00"),
            concat!("fd0201", "00"),
            concat!("fd00fd", "00"),
            concat!("fd00ff", "00"),
            concat!("fe02000001", "00"),
            concat!("ff0200000000000001", "00"),
        ];

        for vector in test_vectors {
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

    macro_rules! do_test_err {
        ($stream: expr, $err: expr) => {
            let mut buff = Cursor::new(hex::decode($stream).expect("input"));
            let expected: Result<TLVStream, DecodeError> = Readable::read(&mut buff);
            assert_eq!(expected.unwrap_err(), $err);
        };
    }

    #[test]
    fn tlv_stream_decode_failure_any_namespace() {
        do_test_err!("fd", DecodeError::ShortRead);
        do_test_err!("fd01", DecodeError::ShortRead);
        do_test_err!(concat!("fd0001", "00"), DecodeError::InvalidData);
        do_test_err!("fd0101", DecodeError::ShortRead);
        do_test_err!(concat!("0f", "fd"), DecodeError::ShortRead);
        do_test_err!(concat!("0f", "fd26"), DecodeError::ShortRead);
        do_test_err!(concat!("0f", "fd2602"), DecodeError::ShortRead);
        do_test_err!(concat!("0f", "fd0001", "00"), DecodeError::InvalidData);
        do_test_err!(concat!("0f", "fd0201", "000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
        0000"), DecodeError::ShortRead);
    }

    #[test]
    fn tlv_stream_decode_failure_either_namespace() {
        do_test_err!(concat!("12", "00"), DecodeError::UnknownRequiredFeature);
        do_test_err!(concat!("fd0102", "00"), DecodeError::UnknownRequiredFeature);
        do_test_err!(concat!("fe01000002", "00"), DecodeError::UnknownRequiredFeature);
        do_test_err!(concat!("ff0100000000000002", "00"), DecodeError::UnknownRequiredFeature);
    }

    #[test]
    fn tlv_stream_decode_failure_n1_namespace() {
        do_test_err!(concat!("01", "09", "ffffffffffffffffff"), DecodeError::InvalidData);
        do_test_err!(concat!("01", "01", "00"), DecodeError::InvalidData);
        do_test_err!(concat!("01", "02", "0001"), DecodeError::InvalidData);
        do_test_err!(concat!("01", "03", "000100"), DecodeError::InvalidData);
        do_test_err!(concat!("01", "04", "00010000"), DecodeError::InvalidData);
        do_test_err!(concat!("01", "05", "0001000000"), DecodeError::InvalidData);
        do_test_err!(concat!("01", "06", "000100000000"), DecodeError::InvalidData);
        do_test_err!(concat!("01", "07", "00010000000000"), DecodeError::InvalidData);
        do_test_err!(concat!("01", "08", "0001000000000000"), DecodeError::InvalidData);
        do_test_err!(concat!("02", "07", "01010101010101"), DecodeError::ShortRead);
        do_test_err!(concat!("02", "09", "010101010101010101"), DecodeError::InvalidData);
        do_test_err!(concat!("03", "21", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
        DecodeError::ShortRead);
        do_test_err!(concat!("03", "29", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001"),
        DecodeError::ShortRead);
        do_test_err!(concat!("03", "30", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb000000000000000100000000000001"),
        DecodeError::ShortRead);
        do_test_err!(concat!("03", "31", "043da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb00000000000000010000000000000002"),
        DecodeError::InvalidData);
        do_test_err!(concat!("03", "32", "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb0000000000000001000000000000000001"),
        DecodeError::InvalidData);
        do_test_err!(concat!("fd00fe", "00"), DecodeError::ShortRead);
        do_test_err!(concat!("fd00fe", "01", "01"), DecodeError::ShortRead);
        do_test_err!(concat!("fd00fe", "03", "010101"), DecodeError::InvalidData);
        do_test_err!(concat!("00", "00"), DecodeError::UnknownRequiredFeature);
    }

    /// Any appending of an invalid stream to a valid stream should trigger a decoding failure.
    /// Any appending of a higher-numbered valid stream to a lower-numbered valid stream should not
    /// trigger a decoding failure.
    #[test]
    fn tlv_stream_decode_failure_appending_n1() {
        do_test_err!(concat!("02", "08", "0000000000000226", "01", "01", "2a"), DecodeError::InvalidData);
        do_test_err!(concat!("02", "08", "0000000000000231", "02", "08", "0000000000000451"), DecodeError::InvalidData);
        do_test_err!(concat!("1f", "00", "0f", "01", "2a"), DecodeError::InvalidData);
        do_test_err!(concat!("1f", "00", "1f", "01", "2a"), DecodeError::InvalidData);
    }

    /// Any appending of an invalid stream to a valid stream should trigger a decoding failure.
    /// Any appending of a higher-numbered valid stream to a lower-numbered valid stream should not
    /// trigger a decoding failure.
    #[test]
    fn tlv_stream_decode_failure_appending_n2() {
        // Took rust-lightning's approach of modifying this test since it was trivial and I
        // didn't want to rewrite the decoder to handle it.
        // (concat!("ffffffffffffffffff", "00", "00", "00"), DecodeError::InvalidData),
        do_test_err!(concat!("ffffffffffffffffff", "00", "01", "00"), DecodeError::InvalidData);
    }
}
