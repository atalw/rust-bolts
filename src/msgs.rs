use std::{io::Read, fmt};

use bitcoin::{Txid, Script};
use secp256k1::{PublicKey, ecdsa::Signature};

use crate::{tlv::TLVStream, ser::{Readable, DecodeError, FixedLengthReadable}};


/// Once authentication is complete, the first message reveals the features supported or required
/// by this node, even if this is a reconnection.
#[derive(Debug)]
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

pub struct OpenChannel {
    /// The chain_hash value denotes the exact blockchain that the opened channel will reside within.
    /// This is usually the genesis hash of the respective blockchain. The existence of the
    /// chain_hash allows nodes to open channels across many distinct blockchains as well as have
    /// channels within multiple blockchains opened to the same peer (if it supports the target chains).
    chain_hash: ChainHash,
    /// The temporary_channel_id is used to identify this channel on a per-peer basis until the
    /// funding transaction is established, at which point it is replaced by the channel_id, which
    /// is derived from the funding transaction.
    temp_channel_id: [u8; 32],
    /// The amount the sender is putting into the channel.
    funding_sats: u64,
    /// An amount of initial funds that the sender is unconditionally giving to the receiver.
    push_msat: u64,
    /// Threshold below which outputs should not be generated for this node's commitment or HTLC
    /// transactions (i.e. HTLCs below this amount plus HTLC transaction fees are not enforceable on-chain).
    dust_limit_sats: u64,
    /// Is a cap on total value of outstanding HTLCs, which allows a node to limit its exposure to HTLCs
    max_htlc_value_in_flight_msat: u64,
    /// The minimum amount that the other node is to keep as a direct payment.
    channel_reserve_sats: u64,
    /// Indicates the smallest value HTLC this node will accept.
    htlc_min_msat: u64,
    /// Indicates the initial fee rate in satoshi per 1000-weight (i.e. 1/4 the more normally-used
    /// 'satoshi per 1000 vbytes') that this side will pay for commitment and HTLC transactions
    feerate_per_kw: u32,
    /// Is the number of blocks that the other node's to-self outputs must be delayed, using
    /// OP_CHECKSEQUENCEVERIFY delays; this is how long it will have to wait in case of breakdown
    /// before redeeming its own funds.
    to_self_delay: u16,
    /// Limits the number of outstanding HTLCs the other node can offer.
    max_accepted_htlcs: u16,
    /// The public key in the 2-of-2 multisig script of the funding transaction output.
    funding_pubkey: PublicKey,
    revocation_basepoint: PublicKey,
    payment_basepoint: PublicKey,
    delayed_payment_basepoint: PublicKey,
    htlc_basepoint: PublicKey,
    /// The per-commitment point to be used for the first commitment transaction,
    first_per_commitment_point: PublicKey,
    /// Only the least-significant bit of channel_flags is currently defined: announce_channel.
    /// This indicates whether the initiator of the funding flow wishes to advertise this channel
    /// publicly to the network
    channel_flags: u8,
    tlv_stream: TLVStream,
    /// Allows the sending node to commit to where funds will go on mutual close, which the remote
    /// node should enforce even if a node is compromised later.
    shutdown_scriptpubkey: PublicKey,
}

/// This message contains information about a node and indicates its acceptance of the new channel.
/// This is the second step toward creating the funding transaction and both versions of the commitment transaction.
pub struct AcceptChannel {
    temp_channel_id: [u8; 32],
    dust_limit_sats: u64,
    max_htlc_value_in_flight_msat: u64,
    channel_reserve_sats: u64,
    htlc_min_msat: u64,
    min_depth: u32,
    to_self_delay: u16,
    max_accepted_htlcs: u16,
    funding_pubkey: PublicKey,
    revocation_basepoint: PublicKey,
    payment_basepoint: PublicKey,
    delayed_payment_basepoint: PublicKey,
    htlc_basepoint: PublicKey,
    first_per_commitment_point: PublicKey,
    accept_channel_tlvs: TLVStream,
    shutdown_scriptpubkey: PublicKey,
}

/// This message describes the outpoint which the funder has created for the initial commitment
/// transactions. After receiving the peer's signature, via funding_signed, it will broadcast the
/// funding transaction.
pub struct FundingCreated {
    temp_channel_id: [u8; 32],
    funding_txid: Txid,
    funding_output_index: u16,
    signature: Signature,
}

/// This message gives the funder the signature it needs for the first commitment transaction, so
/// it can broadcast the transaction knowing that funds can be redeemed, if need be.
pub struct FundingSigned {
    channel_id: [u8; 32],
    signature: Signature,
}

/// This message indicates that the funding transaction has reached the minimum_depth asked for in
/// accept_channel. Once both nodes have sent this, the channel enters normal operating mode.
pub struct FundingLocked {
    channel_id: [u8; 32],
    next_per_commitment_point: PublicKey,
}

/// Either node (or both) can send a shutdown message to initiate closing, along with the
/// scriptpubkey it wants to be paid to.
pub struct Shutdown {
    channel_id: [u8; 32],
    len: u16,
    scriptpubkey: Script,
}

/// Once shutdown is complete and the channel is empty of HTLCs, the final current commitment
/// transactions will have no HTLCs, and closing fee negotiation begins. The funder chooses a fee
/// it thinks is fair, and signs the closing transaction with the scriptpubkey fields from the
/// shutdown messages (along with its chosen fee) and sends the signature; the other node then
/// replies similarly, using a fee it thinks is fair. This exchange continues until both agree on
/// the same fee or when one side fails the channel.
///
/// In the modern method, the funder sends its permissible fee range, and the non-funder has to
/// pick a fee in this range. If the non-funder chooses the same value, negotiation is complete
/// after two messages, otherwise the funder will reply with the same value (completing after three messages).
pub struct ClosingSigned {
    channel_id: [u8; 32],
    fee_sats: u64,
    signature: Signature,
    tlv_stream: TLVStream,
}

/// Either node can send update_add_htlc to offer an HTLC to the other, which is redeemable in
/// return for a payment preimage.
pub struct UpdateAddHTLC {
    channel_id: [u8; 32],
    id: u64,
    amount_msat: u64,
    payment_hash: [u8; 32], // TODO: Create PaymentHash type if needed
    cltv_expiry: u32,
    /// Contains an obfuscated list of hops and instructions for each hop along the path. It
    /// commits to the HTLC by setting the payment_hash as associated data, i.e. includes the
    /// payment_hash in the computation of HMACs. This prevents replay attacks that would reuse a
    /// previous onion_routing_packet with a different payment_hash.
    onion_routing_packet: [u8; 1366],
}

pub struct UpdateFulfillHTLC {
    channel_id: [u8; 32],
    id: u64,
    payment_preimage: [u8; 32],
}

pub struct UpdateFailHTLC {
    channel_id: [u8; 32],
    id: u64,
    len: u16,
    reason: Vec<u8> // TODO: Error type
}

pub struct UpdateFailMalformedHTLC {
    channel_id: [u8; 32],
    id: u64,
    sha256_of_onion: [u8; 32],
    failure_code: u16,
}

/// When a node has changes for the remote commitment, it can apply them, sign the resulting
/// transaction (as defined in BOLT #3), and send a commitment_signed message.
pub struct CommitmentSigned {
    channel_id: [u8; 32],
    signature: Signature,
    num_htlc: u16,
    htlc_signature: Vec<Signature>,
}

/// Once the recipient of commitment_signed checks the signature and knows it has a valid new
/// commitment transaction, it replies with the commitment preimage for the previous commitment
/// transaction in a revoke_and_ack message.
pub struct RevokeAndACK {
    channel_id: [u8; 32],
    per_commitment_secret: [u8; 32],
    next_per_commitment_point: PublicKey,
}

/// An update_fee message is sent by the node which is paying the Bitcoin fee. Like any update,
/// it's first committed to the receiver's commitment transaction and then (once acknowledged)
/// committed to the sender's. Unlike an HTLC, update_fee is never closed but simply replaced.
pub struct UpdateFee {
    channel_id: [u8; 32],
    feerate_per_kw: u32,
}

/// Because communication transports are unreliable, and may need to be re-established from time to
/// time, the design of the transport has been explicitly separated from the protocol.
pub struct ChannelReestablish {
    channel_id: [u8; 32],
    /// A commitment number is a 48-bit incrementing counter for each commitment transaction;
    /// counters are independent for each peer in the channel and start at 0. They're only explicitly
    /// relayed to the other node in the case of re-establishment, otherwise they are implicit.
    next_commitment_number: u64,
    next_revocation_number: u64,
    your_last_per_commitment_secret: [u8; 32],
    my_current_per_commitment_point: PublicKey,
}



/// The chain_hash value denotes the exact blockchain that the opened channel will reside within.
/// This is usually the genesis hash of the respective blockchain. The existence of the
/// chain_hash allows nodes to open channels across many distinct blockchains as well as have
/// channels within multiple blockchains opened to the same peer (if it supports the target chains).
struct ChainHash {}

impl Readable for Init {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let typ: u16 = Readable::read(reader)?;
        let gflen: u16 = Readable::read(reader)?;
        let global_features: Vec<u8> = FixedLengthReadable::read(reader, gflen as usize)?;
        let flen: u16 = Readable::read(reader)?;
        let features: Vec<u8> = FixedLengthReadable::read(reader, flen as usize)?;
        let init_tlvs: TLVStream = Readable::read(reader)?;

        Ok(Init {
            typ,
            gflen,
            global_features,
            flen,
            features,
            init_tlvs
        })
    }
}

impl fmt::Display for Init {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}", self)
    }
}

impl fmt::LowerHex for Init {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}", self.typ)?;
        write!(f, "{:04x}", self.gflen)?;
        for byte in &self.global_features {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "{:04x}", self.flen)?;
        for byte in &self.features {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "{}", self.init_tlvs)
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
            assert_eq!(msg.to_string(), vector);
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
