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
}

impl DecodeWithContext<Context<'_>> for Message {
    fn decode_with_context<'a>(
        slice: &'a [u8],
        context: Context,
    ) -> Result<(Self, &'a [u8]), Error> {
        let (message_type, slice) = MessageType::decode_from_slice(slice)?;
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
                let (message, slice) = EncryptedPacketData::decode_from_slice(slice)?;
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
                MessageType::HandshakeInitiation.encode_to_vec(buffer);
                message.encode_with_context(buffer, context);
            }
            Message::HandshakeResponse(message) => {
                MessageType::HandshakeResponse.encode_to_vec(buffer);
                message.encode_with_context(buffer, context);
            }
            Message::PacketData(message) => {
                MessageType::PacketData.encode_to_vec(buffer);
                message.encode_to_vec(buffer);
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

impl DecodeWithContext<Context<'_>> for EncryptedHandshakeInitiation {
    fn decode_with_context<'a>(
        slice: &'a [u8],
        context: Context,
    ) -> Result<(Self, &'a [u8]), Error> {
        let (sender_index, slice) = SessionIndex::decode_from_slice(slice)?;
        let (unencrypted_ephemeral, slice) = PublicKey::decode_from_slice(slice)?;
        let (encrypted_static, slice) = EncryptedStatic::decode_from_slice(slice)?;
        let (encrypted_timestamp, slice) = EncryptedTimestamp::decode_from_slice(slice)?;
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
        self.sender_index.encode_to_vec(buffer);
        self.unencrypted_ephemeral.encode_to_vec(buffer);
        self.encrypted_static.encode_to_vec(buffer);
        self.encrypted_timestamp.encode_to_vec(buffer);
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

impl DecodeWithContext<Context<'_>> for EncryptedHandshakeResponse {
    fn decode_with_context<'a>(
        slice: &'a [u8],
        context: Context,
    ) -> Result<(Self, &'a [u8]), Error> {
        let (sender_index, slice) = SessionIndex::decode_from_slice(slice)?;
        let (receiver_index, slice) = SessionIndex::decode_from_slice(slice)?;
        let (unencrypted_ephemeral, slice) = PublicKey::decode_from_slice(slice)?;
        let (encrypted_nothing, slice) = EncryptedNothing::decode_from_slice(slice)?;
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
        self.sender_index.encode_to_vec(buffer);
        self.receiver_index.encode_to_vec(buffer);
        self.unencrypted_ephemeral.encode_to_vec(buffer);
        self.encrypted_nothing.encode_to_vec(buffer);
        context.sign(buffer);
    }
}

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
pub struct EncryptedPacketData {
    pub receiver_index: SessionIndex,
    pub counter: Counter,
    pub encrypted_encapsulated_packet: Vec<u8>,
}

impl Decode for EncryptedPacketData {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (receiver_index, slice) = SessionIndex::decode_from_slice(slice)?;
        let (counter, slice) = Counter::decode_from_slice(slice)?;
        let (encrypted_encapsulated_packet, slice) = <Vec<u8>>::decode_from_slice(slice)?;
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
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        self.receiver_index.encode_to_vec(buffer);
        self.counter.encode_to_vec(buffer);
        self.encrypted_encapsulated_packet
            .as_slice()
            .encode_to_vec(buffer);
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

const fn aead_len(n: usize) -> usize {
    n + 16
}

#[cfg(test)]
mod tests {

    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use arbtest::arbtest;

    use super::*;
    use crate::tests::test_encode_decode;
    use crate::tests::test_encode_decode_with_context;

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
        arbtest(test_encode_decode::<EncryptedStatic>);
        arbtest(test_encode_decode::<EncryptedTimestamp>);
        arbtest(test_encode_decode::<EncryptedNothing>);
        arbtest(test_encode_decode::<EncryptedPacketData>);
        test_encode_decode_with_context::<EncryptedHandshakeInitiation>();
        test_encode_decode_with_context::<EncryptedHandshakeResponse>();
        test_encode_decode_with_context::<Message>();
    }
}
