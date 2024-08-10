use tai64::Tai64N;
use x25519_dalek::PublicKey;

use crate::Decode;
use crate::Encode;
use crate::EncryptedBytes;
use crate::Error;
use crate::MessageType;
use crate::SessionIndex;
use crate::MAC_LEN;
use crate::PUBLIC_KEY_LEN;

pub enum Message {
    HandshakeInitiation(EncryptedHandshakeInitiation),
    HandshakeResponse(EncryptedHandshakeResponse),
}

impl Message {
    pub fn get_type(&self) -> MessageType {
        match self {
            Message::HandshakeInitiation(..) => MessageType::HandshakeInitiation,
            Message::HandshakeResponse(..) => MessageType::HandshakeResponse,
        }
    }
}

impl Decode for Message {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (message_type, slice) = MessageType::decode_from_slice(slice)?;
        let (message, slice) = match message_type {
            MessageType::HandshakeInitiation => {
                let (message, slice) = EncryptedHandshakeInitiation::decode_from_slice(slice)?;
                // skip macs
                let slice = slice.get((MAC_LEN + MAC_LEN)..).ok_or(Error)?;
                (Message::HandshakeInitiation(message), slice)
            }
            MessageType::HandshakeResponse => {
                let (message, slice) = EncryptedHandshakeResponse::decode_from_slice(slice)?;
                // skip macs
                let slice = slice.get((MAC_LEN + MAC_LEN)..).ok_or(Error)?;
                (Message::HandshakeResponse(message), slice)
            }
        };
        Ok((message, slice))
    }
}

impl Encode for Message {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        match self {
            Message::HandshakeInitiation(message) => {
                MessageType::HandshakeInitiation.encode_to_vec(buffer);
                message.encode_to_vec(buffer);
            }
            Message::HandshakeResponse(message) => {
                MessageType::HandshakeResponse.encode_to_vec(buffer);
                message.encode_to_vec(buffer);
            }
        }
    }
}

pub struct HandshakeInitiation {
    pub sender_index: SessionIndex,
    pub unencrypted_ephemeral: PublicKey,
    pub static_public: PublicKey,
    pub timestamp: Tai64N,
}

pub struct EncryptedHandshakeInitiation {
    pub sender_index: SessionIndex,
    pub unencrypted_ephemeral: PublicKey,
    pub encrypted_static: EncryptedStatic,
    pub encrypted_timestamp: EncryptedTimestamp,
}

impl Decode for EncryptedHandshakeInitiation {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (sender_index, slice) = SessionIndex::decode_from_slice(slice)?;
        let (unencrypted_ephemeral, slice) = PublicKey::decode_from_slice(slice)?;
        let (encrypted_static, slice) = EncryptedStatic::decode_from_slice(slice)?;
        let (encrypted_timestamp, slice) = EncryptedTimestamp::decode_from_slice(slice)?;
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

impl Encode for EncryptedHandshakeInitiation {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        self.sender_index.encode_to_vec(buffer);
        self.unencrypted_ephemeral.encode_to_vec(buffer);
        self.encrypted_static.encode_to_vec(buffer);
        self.encrypted_timestamp.encode_to_vec(buffer);
    }
}

pub struct EncryptedHandshakeResponse {
    pub sender_index: SessionIndex,
    pub receiver_index: SessionIndex,
    pub unencrypted_ephemeral: PublicKey,
    pub encrypted_nothing: EncryptedNothing,
}

impl Decode for EncryptedHandshakeResponse {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (sender_index, slice) = SessionIndex::decode_from_slice(slice)?;
        let (receiver_index, slice) = SessionIndex::decode_from_slice(slice)?;
        let (unencrypted_ephemeral, slice) = PublicKey::decode_from_slice(slice)?;
        let (encrypted_nothing, slice) = EncryptedNothing::decode_from_slice(slice)?;
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

impl Encode for EncryptedHandshakeResponse {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        self.sender_index.encode_to_vec(buffer);
        self.receiver_index.encode_to_vec(buffer);
        self.unencrypted_ephemeral.encode_to_vec(buffer);
        self.encrypted_nothing.encode_to_vec(buffer);
    }
}

pub type EncryptedStatic = EncryptedBytes<ENCRYPTED_STATIC_LEN>;
pub type EncryptedTimestamp = EncryptedBytes<ENCRYPTED_TAI_LEN>;
pub type EncryptedNothing = EncryptedBytes<ENCRYPTED_NOTHING_LEN>;

const TAI64N_LEN: usize = 12;
const ENCRYPTED_STATIC_LEN: usize = aead_len(PUBLIC_KEY_LEN);
const ENCRYPTED_TAI_LEN: usize = aead_len(TAI64N_LEN);
const ENCRYPTED_NOTHING_LEN: usize = aead_len(0);

const fn aead_len(n: usize) -> usize {
    n + 16
}
