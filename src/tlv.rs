use crate::bigsize::BigSize;

/// A tlv_stream is a series of (possibly zero) tlv_records, represented as the concatenation of
/// the encoded tlv_records.
struct TLVStream(Vec<TLVRecord>);

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
    value: Vec<u8>
}

#[cfg(test)]
mod tests {

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
    }

    #[test]
    fn tlv_stream_decode_failure_any_namespace() {
        let test_vectors = [
            ("fd", "type truncated"),
            ("fd01", "type truncated"),
            (concat!("fd0001", "00"), "not minimally encoded type"),
            ("fd0101", "missing length"),
            (concat!("0f", "fd"), "(length truncated)"),
            (concat!("0f", "fd26"), "(length truncated)"),
            (concat!("0f", "fd2602"), "missing value"),
            (concat!("0f", "fd0001", "00"), "not minimally encoded length"),
            (concat!("0f", "fd0201", "0000000000000000000000000000000000000000000000000000000000000\
            000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000"), "value truncated"),
        ];
    }

    #[test]
    fn tlv_stream_decode_failure_either_namespace() {
        let test_vectors = [
            (concat!("12", "00"), "unknown even type."),
            (concat!("fd0102", "00"), "unknown even type."),
            (concat!("fe01000002", "00"), "unknown even type."),
            (concat!("ff0100000000000002", "00"), "unknown even type."),
        ];
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
