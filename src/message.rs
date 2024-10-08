use crate::Counter;
use crate::Decode;
use crate::DecodeWithContext;
use crate::Encode;
use crate::EncodeWithContext;
use crate::EncryptedBytes;
use crate::Error;
use crate::InputBuffer;
use crate::PublicKey;
use crate::SessionIndex;
use crate::Timestamp;
use crate::HANDSHAKE_INITIATION_LEN;
use crate::HANDSHAKE_RESPONSE_LEN;
use crate::PUBLIC_KEY_LEN;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum MessageKind {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    PacketData = 4,
}

impl Decode for MessageKind {
    fn decode(buffer: &mut InputBuffer) -> Result<Self, Error> {
        buffer.get_next(MESSAGE_TYPE_LEN).ok_or(Error)?[0].try_into()
    }
}

impl Encode for MessageKind {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&[*self as u8, 0, 0, 0]);
    }
}

impl TryFrom<u8> for MessageKind {
    type Error = Error;
    fn try_from(other: u8) -> Result<Self, Self::Error> {
        match other {
            1 => Ok(Self::HandshakeInitiation),
            2 => Ok(Self::HandshakeResponse),
            4 => Ok(Self::PacketData),
            _ => Err(Error),
        }
    }
}

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub enum Message {
    HandshakeInitiation(EncryptedHandshakeInitiation),
    HandshakeResponse(EncryptedHandshakeResponse),
    PacketData(EncryptedPacketData),
}

impl Message {
    pub fn kind(&self) -> MessageKind {
        match self {
            Message::HandshakeInitiation(..) => MessageKind::HandshakeInitiation,
            Message::HandshakeResponse(..) => MessageKind::HandshakeResponse,
            Message::PacketData(..) => MessageKind::PacketData,
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Message::HandshakeInitiation(..) => EncryptedHandshakeInitiation::LEN,
            Message::HandshakeResponse(..) => EncryptedHandshakeResponse::LEN,
            Message::PacketData(message) => message.len(),
        }
    }
}

impl<V: MessageVerifier> DecodeWithContext<&mut V> for Message {
    fn decode_with_context(buffer: &mut InputBuffer, verifier: &mut V) -> Result<Self, Error> {
        let message = match MessageKind::decode(buffer)? {
            MessageKind::HandshakeInitiation => {
                let message = EncryptedHandshakeInitiation::decode_with_context(buffer, verifier)?;
                Message::HandshakeInitiation(message)
            }
            MessageKind::HandshakeResponse => {
                let message = EncryptedHandshakeResponse::decode_with_context(buffer, verifier)?;
                Message::HandshakeResponse(message)
            }
            MessageKind::PacketData => {
                let message = EncryptedPacketData::decode(buffer)?;
                Message::PacketData(message)
            }
        };
        Ok(message)
    }
}

impl<S: MessageSigner> EncodeWithContext<&mut S> for Message {
    fn encode_with_context(&self, buffer: &mut Vec<u8>, signer: &mut S) {
        match self {
            Message::HandshakeInitiation(message) => {
                MessageKind::HandshakeInitiation.encode(buffer);
                message.encode_with_context(buffer, signer);
            }
            Message::HandshakeResponse(message) => {
                MessageKind::HandshakeResponse.encode(buffer);
                message.encode_with_context(buffer, signer);
            }
            Message::PacketData(message) => {
                MessageKind::PacketData.encode(buffer);
                message.encode(buffer);
            }
        }
    }
}

pub struct HandshakeInitiation {
    pub sender_index: SessionIndex,
    pub unencrypted_ephemeral: PublicKey,
    pub static_public: PublicKey,
    pub timestamp: Timestamp,
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct EncryptedHandshakeInitiation {
    pub sender_index: SessionIndex,
    pub unencrypted_ephemeral: PublicKey,
    pub encrypted_static: EncryptedStatic,
    pub encrypted_timestamp: EncryptedTimestamp,
}

impl EncryptedHandshakeInitiation {
    const LEN: usize = HANDSHAKE_INITIATION_LEN;
}

impl<V: MessageVerifier> DecodeWithContext<&mut V> for EncryptedHandshakeInitiation {
    fn decode_with_context(buffer: &mut InputBuffer, verifier: &mut V) -> Result<Self, Error> {
        let sender_index = SessionIndex::decode(buffer)?;
        let unencrypted_ephemeral = PublicKey::decode(buffer)?;
        let encrypted_static = EncryptedStatic::decode(buffer)?;
        let encrypted_timestamp = EncryptedTimestamp::decode(buffer)?;
        verifier.verify(buffer)?;
        Ok(Self {
            sender_index,
            unencrypted_ephemeral,
            encrypted_static,
            encrypted_timestamp,
        })
    }
}

impl<S: MessageSigner> EncodeWithContext<&mut S> for EncryptedHandshakeInitiation {
    fn encode_with_context(&self, buffer: &mut Vec<u8>, signer: &mut S) {
        self.sender_index.encode(buffer);
        self.unencrypted_ephemeral.encode(buffer);
        self.encrypted_static.encode(buffer);
        self.encrypted_timestamp.encode(buffer);
        signer.sign(buffer);
    }
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct EncryptedHandshakeResponse {
    pub sender_index: SessionIndex,
    pub receiver_index: SessionIndex,
    pub unencrypted_ephemeral: PublicKey,
    pub encrypted_nothing: EncryptedNothing,
}

impl EncryptedHandshakeResponse {
    const LEN: usize = HANDSHAKE_RESPONSE_LEN;
}

impl<V: MessageVerifier> DecodeWithContext<&mut V> for EncryptedHandshakeResponse {
    fn decode_with_context(buffer: &mut InputBuffer, verifier: &mut V) -> Result<Self, Error> {
        let sender_index = SessionIndex::decode(buffer)?;
        let receiver_index = SessionIndex::decode(buffer)?;
        let unencrypted_ephemeral = PublicKey::decode(buffer)?;
        let encrypted_nothing = EncryptedNothing::decode(buffer)?;
        verifier.verify(buffer)?;
        Ok(Self {
            sender_index,
            receiver_index,
            unencrypted_ephemeral,
            encrypted_nothing,
        })
    }
}

impl<S: MessageSigner> EncodeWithContext<&mut S> for EncryptedHandshakeResponse {
    fn encode_with_context(&self, buffer: &mut Vec<u8>, signer: &mut S) {
        self.sender_index.encode(buffer);
        self.receiver_index.encode(buffer);
        self.unencrypted_ephemeral.encode(buffer);
        self.encrypted_nothing.encode(buffer);
        signer.sign(buffer);
    }
}

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub struct EncryptedPacketData {
    pub receiver_index: SessionIndex,
    pub counter: Counter,
    pub encrypted_encapsulated_packet: Vec<u8>,
}

impl EncryptedPacketData {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        PACKET_DATA_HEADER_LEN + self.encrypted_encapsulated_packet.len()
    }
}

impl Decode for EncryptedPacketData {
    fn decode(buffer: &mut InputBuffer) -> Result<Self, Error> {
        let receiver_index = SessionIndex::decode(buffer)?;
        let counter = Counter::decode(buffer)?;
        let encrypted_encapsulated_packet: Vec<u8> = Decode::decode(buffer)?;
        Ok(Self {
            receiver_index,
            counter,
            encrypted_encapsulated_packet,
        })
    }
}

impl Encode for EncryptedPacketData {
    fn encode(&self, buffer: &mut Vec<u8>) {
        self.receiver_index.encode(buffer);
        self.counter.encode(buffer);
        self.encrypted_encapsulated_packet.as_slice().encode(buffer);
    }
}

pub type EncryptedStatic = EncryptedBytes<ENCRYPTED_STATIC_LEN>;
pub type EncryptedTimestamp = EncryptedBytes<ENCRYPTED_TAI_LEN>;
pub type EncryptedNothing = EncryptedBytes<ENCRYPTED_NOTHING_LEN>;

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub struct Cookie {
    data: [u8; COOKIE_LEN],
}

impl AsRef<[u8]> for Cookie {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl AsRef<[u8; COOKIE_LEN]> for Cookie {
    fn as_ref(&self) -> &[u8; COOKIE_LEN] {
        &self.data
    }
}

pub trait MessageSigner {
    fn sign(&mut self, buffer: &mut Vec<u8>);
}

pub trait MessageVerifier {
    fn verify(&mut self, buffer: &mut InputBuffer) -> Result<(), Error>;
}

const TAI64N_LEN: usize = 12;
const ENCRYPTED_STATIC_LEN: usize = aead_len(PUBLIC_KEY_LEN);
const ENCRYPTED_TAI_LEN: usize = aead_len(TAI64N_LEN);
const ENCRYPTED_NOTHING_LEN: usize = aead_len(0);
const COOKIE_LEN: usize = aead_len(16);
const PACKET_DATA_HEADER_LEN: usize = 4 + 4 + 8;
const MESSAGE_TYPE_LEN: usize = 4;

const fn aead_len(n: usize) -> usize {
    n + 16
}

#[cfg(test)]
mod tests {

    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use arbtest::arbtest;

    use super::*;
    use crate::tests::encode_decode_symmetry;
    use crate::tests::encode_decode_symmetry_with_context;

    impl<'a> Arbitrary<'a> for EncryptedHandshakeInitiation {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self {
                sender_index: u.arbitrary()?,
                unencrypted_ephemeral: u.arbitrary::<[u8; PUBLIC_KEY_LEN]>()?.into(),
                encrypted_static: u.arbitrary()?,
                encrypted_timestamp: u.arbitrary()?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for EncryptedHandshakeResponse {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self {
                sender_index: u.arbitrary()?,
                receiver_index: u.arbitrary()?,
                unencrypted_ephemeral: u.arbitrary::<[u8; PUBLIC_KEY_LEN]>()?.into(),
                encrypted_nothing: u.arbitrary()?,
            })
        }
    }

    #[test]
    fn encode_decode() {
        arbtest(encode_decode_symmetry::<MessageKind>);
        arbtest(encode_decode_symmetry::<EncryptedStatic>);
        arbtest(encode_decode_symmetry::<EncryptedTimestamp>);
        arbtest(encode_decode_symmetry::<EncryptedNothing>);
        arbtest(encode_decode_symmetry::<EncryptedPacketData>);
        encode_decode_symmetry_with_context::<EncryptedHandshakeInitiation>();
        encode_decode_symmetry_with_context::<EncryptedHandshakeResponse>();
        encode_decode_symmetry_with_context::<Message>();
    }
}
