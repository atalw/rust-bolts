use std::io::Read;

use crate::{tlv::TLVStream, ser::{Readable, DecodeError}};


/// Once authentication is complete, the first message reveals the features supported or required
/// by this node, even if this is a reconnection.
pub struct Init {
    typ: u16,
    /// Global features length
    gflen: u16,
    global_features: Vec<u8>,
    /// Features length
    flen: u16,
    features: Vec<u8>,
    init_tlvs: TLVStream,
}

/// For simplicity of diagnosis, it's often useful to tell a peer that something is incorrect.
pub struct ErrorMessage {
    typ: u16,
    /// The channel is referred to by channel_id, unless channel_id is 0 (i.e. all bytes are 0),
    /// in which case it refers to all channels.
    channel_id: [u8; 32],
    len: u16,
    data: Vec<u8>,
}

/// For simplicity of diagnosis, it's often useful to tell a peer that something is incorrect.
pub struct WarningMessage {
    typ: u16,
    /// The channel is referred to by channel_id, unless channel_id is 0 (i.e. all bytes are 0),
    /// in which case it refers to all channels.
    channel_id: [u8; 8],
    len: u16,
    data: Vec<u8>,
}

/// In order to allow for the existence of long-lived TCP connections, at times it may be required
/// that both ends keep alive the TCP connection at the application level. Such messages also allow
/// obfuscation of traffic patterns.
pub struct Ping {
    typ: u16,
    num_pong_bytes: u16,
    bytes_len: u16,
    ignored: Vec<u8>,
}

/// The pong message is to be sent whenever a ping message is received. It serves as a reply and
/// also serves to keep the connection alive, while explicitly notifying the other end that the
/// receiver is still active. Within the received ping message, the sender will specify the number
/// of bytes to be included within the data payload of the pong message.
pub struct Pong {
    typ: u16,
    num_pong_bytes: u16,
    bytes_len: u16,
    ignored: Vec<u8>,
}

impl Readable for Init {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::{ser::{Readable, DecodeError}, msgs::Init};

    #[test]
    fn valid_init_msgs() {
        let test_vectors = [
            "001000000000",
            "001000000000c9012acb0104"
        ];

        for vector in test_vectors {
            let mut buff = Cursor::new(hex::decode(vector).expect("input"));
            let msg: Init = Readable::read(&mut buff).expect("no failure");
            assert_eq!(msg.to_string(), "");
        }
    }

    #[test]
    fn invalid_init_msgs() {
        let test_vectors = [
            ("00100000000001", DecodeError::ShortRead),
            ("001000000000ca012a", DecodeError::UnknownRequiredFeature),
            ("001000000000c90101c90102", DecodeError::InvalidData),
        ];

        for vector in test_vectors {
            let mut buff = Cursor::new(hex::decode(vector.0).expect("input"));
            let msg: Result<Init, DecodeError> = Readable::read(&mut buff);
            assert_eq!(msg.unwrap_err(), vector.1);
        }
    }
}
