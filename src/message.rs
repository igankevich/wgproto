use crate::Context;
use crate::Counter;
use crate::Decode;
use crate::DecodeWithContext;
use crate::Encode;
use crate::EncodeWithContext;
use crate::EncryptedBytes;
use crate::Error;
use crate::MessageType;
use crate::PublicKey;
use crate::SessionIndex;
use crate::Timestamp;
use crate::HANDSHAKE_INITIATION_LEN;
use crate::HANDSHAKE_RESPONSE_LEN;
use crate::MAC_LEN;
use crate::PUBLIC_KEY_LEN;

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub enum Message {
    HandshakeInitiation(EncryptedHandshakeInitiation),
    HandshakeResponse(EncryptedHandshakeResponse),
    PacketData(EncryptedPacketData),
}

impl Message {
    pub fn get_type(&self) -> MessageType {
        match self {
            Message::HandshakeInitiation(..) => MessageType::HandshakeInitiation,
            Message::HandshakeResponse(..) => MessageType::HandshakeResponse,
            Message::PacketData(..) => MessageType::PacketData,
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

impl DecodeWithContext<&mut Context<'_>> for Message {
    fn decode_with_context<'a>(
        slice: &'a [u8],
        context: &mut Context,
    ) -> Result<(Self, &'a [u8]), Error> {
        let (message_type, slice) = MessageType::decode(slice)?;
        let (message, slice) = match message_type {
            MessageType::HandshakeInitiation => {
                let (message, slice) =
                    EncryptedHandshakeInitiation::decode_with_context(slice, context)?;
                (Message::HandshakeInitiation(message), slice)
            }
            MessageType::HandshakeResponse => {
                let (message, slice) =
                    EncryptedHandshakeResponse::decode_with_context(slice, context)?;
                (Message::HandshakeResponse(message), slice)
            }
            MessageType::PacketData => {
                let (message, slice) = EncryptedPacketData::decode(slice)?;
                (Message::PacketData(message), slice)
            }
        };
        Ok((message, slice))
    }
}

impl EncodeWithContext<Context<'_>> for Message {
    fn encode_with_context(&self, buffer: &mut Vec<u8>, context: Context) {
        match self {
            Message::HandshakeInitiation(message) => {
                MessageType::HandshakeInitiation.encode(buffer);
                message.encode_with_context(buffer, context);
            }
            Message::HandshakeResponse(message) => {
                MessageType::HandshakeResponse.encode(buffer);
                message.encode_with_context(buffer, context);
            }
            Message::PacketData(message) => {
                MessageType::PacketData.encode(buffer);
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

impl DecodeWithContext<&mut Context<'_>> for EncryptedHandshakeInitiation {
    fn decode_with_context<'a>(
        slice: &'a [u8],
        context: &mut Context,
    ) -> Result<(Self, &'a [u8]), Error> {
        let (sender_index, slice) = SessionIndex::decode(slice)?;
        let (unencrypted_ephemeral, slice) = PublicKey::decode(slice)?;
        let (encrypted_static, slice) = EncryptedStatic::decode(slice)?;
        let (encrypted_timestamp, slice) = EncryptedTimestamp::decode(slice)?;
        // skip macs
        let slice = slice.get((MAC_LEN + MAC_LEN)..).ok_or(Error)?;
        context.verify()?;
        Ok((
            Self {
                sender_index,
                unencrypted_ephemeral,
                encrypted_static,
                encrypted_timestamp,
            },
            slice,
        ))
    }
}

impl EncodeWithContext<Context<'_>> for EncryptedHandshakeInitiation {
    fn encode_with_context(&self, buffer: &mut Vec<u8>, context: Context<'_>) {
        self.sender_index.encode(buffer);
        self.unencrypted_ephemeral.encode(buffer);
        self.encrypted_static.encode(buffer);
        self.encrypted_timestamp.encode(buffer);
        context.sign(buffer);
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

impl DecodeWithContext<&mut Context<'_>> for EncryptedHandshakeResponse {
    fn decode_with_context<'a>(
        slice: &'a [u8],
        context: &mut Context,
    ) -> Result<(Self, &'a [u8]), Error> {
        let (sender_index, slice) = SessionIndex::decode(slice)?;
        let (receiver_index, slice) = SessionIndex::decode(slice)?;
        let (unencrypted_ephemeral, slice) = PublicKey::decode(slice)?;
        let (encrypted_nothing, slice) = EncryptedNothing::decode(slice)?;
        // skip macs
        let slice = slice.get((MAC_LEN + MAC_LEN)..).ok_or(Error)?;
        context.verify()?;
        Ok((
            Self {
                sender_index,
                receiver_index,
                unencrypted_ephemeral,
                encrypted_nothing,
            },
            slice,
        ))
    }
}

impl EncodeWithContext<Context<'_>> for EncryptedHandshakeResponse {
    fn encode_with_context(&self, buffer: &mut Vec<u8>, context: Context) {
        self.sender_index.encode(buffer);
        self.receiver_index.encode(buffer);
        self.unencrypted_ephemeral.encode(buffer);
        self.encrypted_nothing.encode(buffer);
        context.sign(buffer);
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
    fn decode(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (receiver_index, slice) = SessionIndex::decode(slice)?;
        let (counter, slice) = Counter::decode(slice)?;
        let (encrypted_encapsulated_packet, slice) = <Vec<u8>>::decode(slice)?;
        Ok((
            Self {
                receiver_index,
                counter,
                encrypted_encapsulated_packet,
            },
            slice,
        ))
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

const TAI64N_LEN: usize = 12;
const ENCRYPTED_STATIC_LEN: usize = aead_len(PUBLIC_KEY_LEN);
const ENCRYPTED_TAI_LEN: usize = aead_len(TAI64N_LEN);
const ENCRYPTED_NOTHING_LEN: usize = aead_len(0);
const COOKIE_LEN: usize = aead_len(16);
const PACKET_DATA_HEADER_LEN: usize = 4 + 4 + 8;

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
        arbtest(encode_decode_symmetry::<EncryptedStatic>);
        arbtest(encode_decode_symmetry::<EncryptedTimestamp>);
        arbtest(encode_decode_symmetry::<EncryptedNothing>);
        arbtest(encode_decode_symmetry::<EncryptedPacketData>);
        encode_decode_symmetry_with_context::<EncryptedHandshakeInitiation>();
        encode_decode_symmetry_with_context::<EncryptedHandshakeResponse>();
        encode_decode_symmetry_with_context::<Message>();
    }
}
