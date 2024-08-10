use blake2::digest::FixedOutput;
use blake2::Blake2s256;
use blake2::Blake2sMac;
use blake2::Blake2sMac256;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::ChaCha20Poly1305;
use constant_time_eq::constant_time_eq;
use rand_core::OsRng;
use rand_core::RngCore;
use tai64::Tai64N;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use crate::Error;

//https://www.wireguard.com/protocol/

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[repr(u8)]
pub enum MessageType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
}

impl Decode for MessageType {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        if slice.len() < 4 {
            return Err(Error::Proto);
        }
        Ok((slice[0].try_into()?, &slice[4..]))
    }
}

impl Encode for MessageType {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self as u8);
        buffer.push(0);
        buffer.push(0);
        buffer.push(0);
    }
}

impl TryFrom<u8> for MessageType {
    type Error = Error;
    fn try_from(other: u8) -> Result<Self, Self::Error> {
        match other {
            1 => Ok(Self::HandshakeInitiation),
            2 => Ok(Self::HandshakeResponse),
            _ => Err(Error::Proto),
        }
    }
}

pub enum Message {
    HandshakeInitiation(EncryptedHandshakeInitiation, Macs),
    HandshakeResponse(EncryptedHandshakeResponse, Macs),
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
                let (macs, slice) = Macs::decode_from_slice(slice)?;
                (Message::HandshakeInitiation(message, macs), slice)
            }
            MessageType::HandshakeResponse => {
                let (message, slice) = EncryptedHandshakeResponse::decode_from_slice(slice)?;
                let (macs, slice) = Macs::decode_from_slice(slice)?;
                (Message::HandshakeResponse(message, macs), slice)
            }
        };
        Ok((message, slice))
    }
}

impl Encode for Message {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        match self {
            Message::HandshakeInitiation(message, macs) => {
                MessageType::HandshakeInitiation.encode_to_vec(buffer);
                message.encode_to_vec(buffer);
                macs.encode_to_vec(buffer);
            }
            Message::HandshakeResponse(message, macs) => {
                MessageType::HandshakeResponse.encode_to_vec(buffer);
                message.encode_to_vec(buffer);
                macs.encode_to_vec(buffer);
            }
        }
    }
}

pub struct Macs {
    pub mac1: Mac,
    pub mac2: Mac,
}

impl Decode for Macs {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (mac1, slice) = Mac::decode_from_slice(slice)?;
        let (mac2, slice) = Mac::decode_from_slice(slice)?;
        Ok((Self { mac1, mac2 }, slice))
    }
}

impl Encode for Macs {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        self.mac1.encode_to_vec(buffer);
        self.mac2.encode_to_vec(buffer);
    }
}

pub struct HandshakeInitiation {
    pub sender_index: u32,
    pub unencrypted_ephemeral: PublicKey,
    pub static_public: PublicKey,
    pub timestamp: Tai64N,
}

pub struct EncryptedHandshakeInitiation {
    pub sender_index: u32,
    pub unencrypted_ephemeral: PublicKey,
    pub encrypted_static: EncryptedStatic,
    pub encrypted_timestamp: EncryptedTimestamp,
}

impl Decode for EncryptedHandshakeInitiation {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (sender_index, slice) = u32::decode_from_slice(slice)?;
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

pub struct HandshakeResponse {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub unencrypted_ephemeral: PublicKey,
}

pub struct EncryptedHandshakeResponse {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub unencrypted_ephemeral: PublicKey,
    pub encrypted_nothing: EncryptedNothing,
}

impl Decode for EncryptedHandshakeResponse {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (sender_index, slice) = u32::decode_from_slice(slice)?;
        let (receiver_index, slice) = u32::decode_from_slice(slice)?;
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

pub struct EncryptedStatic {
    data: [u8; ENCRYPTED_STATIC_LEN],
}

impl Decode for EncryptedStatic {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let data: [u8; ENCRYPTED_STATIC_LEN] = slice
            .get(..ENCRYPTED_STATIC_LEN)
            .ok_or(Error::Proto)?
            .try_into()
            .map_err(Error::map)?;
        let encrypted_static = EncryptedStatic { data };
        Ok((encrypted_static, &slice[ENCRYPTED_STATIC_LEN..]))
    }
}

impl Encode for EncryptedStatic {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.data.as_slice());
    }
}

impl AsRef<[u8]> for EncryptedStatic {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl TryFrom<Vec<u8>> for EncryptedStatic {
    type Error = Error;
    fn try_from(other: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self {
            data: other.try_into().map_err(Error::map)?,
        })
    }
}

pub struct EncryptedTimestamp {
    data: [u8; ENCRYPTED_TAI_LEN],
}

impl Decode for EncryptedTimestamp {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let data: [u8; ENCRYPTED_TAI_LEN] = slice
            .get(..ENCRYPTED_TAI_LEN)
            .ok_or(Error::Proto)?
            .try_into()
            .map_err(Error::map)?;
        let encrypted_timestamp = EncryptedTimestamp { data };
        Ok((encrypted_timestamp, &slice[ENCRYPTED_TAI_LEN..]))
    }
}

impl Encode for EncryptedTimestamp {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.data.as_slice());
    }
}

impl AsRef<[u8]> for EncryptedTimestamp {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl TryFrom<Vec<u8>> for EncryptedTimestamp {
    type Error = Error;
    fn try_from(other: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self {
            data: other.try_into().map_err(Error::map)?,
        })
    }
}

pub struct EncryptedNothing {
    data: [u8; ENCRYPTED_NOTHING_LEN],
}

impl Decode for EncryptedNothing {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let data: [u8; ENCRYPTED_NOTHING_LEN] = slice
            .get(..ENCRYPTED_NOTHING_LEN)
            .ok_or(Error::Proto)?
            .try_into()
            .map_err(Error::map)?;
        let encrypted_timestamp = EncryptedNothing { data };
        Ok((encrypted_timestamp, &slice[ENCRYPTED_NOTHING_LEN..]))
    }
}

impl Encode for EncryptedNothing {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.data.as_slice());
    }
}

impl AsRef<[u8]> for EncryptedNothing {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

pub struct Mac {
    data: [u8; MAC_LEN],
}

impl Mac {
    pub fn zero() -> Self {
        Self {
            data: Default::default(),
        }
    }
}

impl PartialEq for Mac {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.data.as_slice(), other.data.as_slice())
    }
}

impl Eq for Mac {}

impl From<[u8; 16]> for Mac {
    fn from(data: [u8; 16]) -> Self {
        Self { data }
    }
}

impl Decode for Mac {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let data: [u8; MAC_LEN] = slice
            .get(..MAC_LEN)
            .ok_or(Error::Proto)?
            .try_into()
            .map_err(Error::map)?;
        Ok((Mac { data }, &slice[MAC_LEN..]))
    }
}

impl Encode for Mac {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.data.as_slice());
    }
}

pub struct Cookie {
    data: [u8; COOKIE_LEN],
}

impl AsRef<[u8]> for Cookie {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

pub struct Initiator {
    sender_index: u32,
    chaining_key: [u8; CHAINING_KEY_LEN],
    hash: [u8; HASH_LEN],
    ephemeral_private: StaticSecret,
    ephemeral_public: PublicKey,
    static_private: StaticSecret,
    static_public: PublicKey,
    static_preshared: StaticSecret,
    responder_static_public: PublicKey,
    last_received_cookie: Option<Cookie>,
}

impl Initiator {
    pub fn new(
        static_public: PublicKey,
        static_private: StaticSecret,
        static_preshared: StaticSecret,
        responder_static_public: PublicKey,
    ) -> Self {
        let ephemeral_private = StaticSecret::random();
        let ephemeral_public: PublicKey = (&ephemeral_private).into();
        Self {
            sender_index: OsRng.next_u32(),
            chaining_key: Default::default(),
            hash: Default::default(),
            ephemeral_private,
            ephemeral_public,
            static_private,
            static_public,
            static_preshared,
            responder_static_public,
            last_received_cookie: Default::default(),
        }
    }

    pub fn handshake_initiation(&mut self) -> Result<Vec<u8>, Error> {
        self.chaining_key = blake2s(CONSTRUCTION.as_bytes());
        self.hash = blake2s_add(
            blake2s_add(self.chaining_key, IDENTIFIER),
            self.responder_static_public,
        );
        self.hash = blake2s_add(self.hash, self.ephemeral_public);
        let mut temp = hmac_blake2s(self.chaining_key, self.ephemeral_public)?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        temp = hmac_blake2s(
            self.chaining_key,
            self.ephemeral_private.diffie_hellman(&self.responder_static_public),
        )?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        let mut key = hmac_blake2s_add(temp, self.chaining_key, &[0x2])?;
        let encrypted_static: EncryptedStatic =
            aead(&key, 0, self.static_public, self.hash)?.try_into()?;
        self.hash = blake2s_add(self.hash, &encrypted_static);
        temp = hmac_blake2s(
            self.chaining_key,
            self.static_private
                .diffie_hellman(&self.responder_static_public),
        )?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        key = hmac_blake2s_add(temp, self.chaining_key, &[0x2])?;
        let timestamp = Tai64N::now();
        let encrypted_timestamp: EncryptedTimestamp =
            aead(&key, 0, timestamp.to_bytes(), self.hash)?.try_into()?;
        self.hash = blake2s_add(self.hash, &encrypted_timestamp);
        let handshake = EncryptedHandshakeInitiation {
            sender_index: self.sender_index,
            unencrypted_ephemeral: self.ephemeral_public,
            encrypted_static,
            encrypted_timestamp,
        };
        let mut buffer = Vec::with_capacity(HANDSHAKE_INITIATION_LEN);
        MessageType::HandshakeInitiation.encode_to_vec(&mut buffer);
        handshake.encode_to_vec(&mut buffer);
        let mac1: Mac = keyed_blake2s(
            blake2s_add(LABEL_MAC1, &self.responder_static_public),
            buffer.as_slice(),
        )?
        .into();
        mac1.encode_to_vec(&mut buffer);
        let mac2: Mac = match self.last_received_cookie.as_ref() {
            Some(cookie) => keyed_blake2s(cookie, buffer.as_slice())?.into(),
            None => Mac::zero(),
        };
        mac2.encode_to_vec(&mut buffer);
        Ok(buffer)
    }

    pub fn on_handshake_response(
        &mut self,
        data: &[u8],
        response: EncryptedHandshakeResponse,
        macs: Macs,
    ) -> Result<HandshakeResponse, Error> {
        self.hash = blake2s_add(self.hash, &response.unencrypted_ephemeral);
        let mut temp = hmac_blake2s(self.chaining_key, response.unencrypted_ephemeral)?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        temp = hmac_blake2s(
            &self.chaining_key,
            self.ephemeral_private.diffie_hellman(&response.unencrypted_ephemeral),
        )?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        temp = hmac_blake2s(
            &self.chaining_key,
            self.static_private.diffie_hellman(&response.unencrypted_ephemeral),
        )?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        temp = hmac_blake2s(&self.chaining_key, &self.static_preshared)?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        let temp2 = hmac_blake2s_add(temp, &self.chaining_key, &[0x2])?;
        let key = hmac_blake2s_add(temp, &temp2, &[0x3])?;
        self.hash = blake2s_add(self.hash, &temp2);
        let decrypted_nothing = aead_decrypt(&key, 0, &response.encrypted_nothing, &self.hash)?;
        if !decrypted_nothing.is_empty() {
            return Err(Error::Proto);
        }
        self.hash = blake2s_add(self.hash, decrypted_nothing.as_slice());
        let mac1: Mac = keyed_blake2s(
            blake2s_add(LABEL_MAC1, &self.static_public),
            &data[..(HANDSHAKE_RESPONSE_LEN - MAC_LEN - MAC_LEN)],
        )?
        .into();
        if mac1 != macs.mac1 {
            return Err(Error::Proto);
        }
        let mac2: Mac = match self.last_received_cookie.as_ref() {
            Some(cookie) => keyed_blake2s(
                cookie,
                &data[..(HANDSHAKE_RESPONSE_LEN - MAC_LEN)],
            )?.into(),
            None => Mac::zero(),
        };
        if mac2 != macs.mac2 {
            return Err(Error::Proto);
        }
        Ok(HandshakeResponse{
            sender_index: response.sender_index,
            receiver_index: response.receiver_index,
            unencrypted_ephemeral: response.unencrypted_ephemeral,
        })
    }
}

pub struct Responder {
    sender_index: u32,
    receiver_index: u32,
    hash: [u8; HASH_LEN],
    chaining_key: [u8; CHAINING_KEY_LEN],
    ephemeral_private: StaticSecret,
    ephemeral_public: PublicKey,
    static_public: PublicKey,
    static_private: StaticSecret,
    static_preshared: StaticSecret,
    last_sent_cookie: Option<Cookie>,
    last_received_cookie: Option<Cookie>,
}

impl Responder {
    pub fn new(
        static_public: PublicKey,
        static_private: StaticSecret,
        static_preshared: StaticSecret,
    ) -> Self {
        let ephemeral_private = StaticSecret::random();
        let ephemeral_public: PublicKey = (&ephemeral_private).into();
        Self {
            sender_index: OsRng.next_u32(),
            receiver_index: Default::default(),
            hash: Default::default(),
            chaining_key: Default::default(),
            ephemeral_private,
            ephemeral_public,
            static_private,
            static_public,
            static_preshared,
            last_sent_cookie: Default::default(),
            last_received_cookie: Default::default(),
        }
    }

    /// `data` the whole message
    pub fn on_handshake_initiation(
        &mut self,
        data: &[u8],
        initiation: EncryptedHandshakeInitiation,
        macs: Macs,
    ) -> Result<HandshakeInitiation, Error> {
        self.chaining_key = blake2s(CONSTRUCTION.as_bytes());
        self.hash = blake2s_add(blake2s_add(self.chaining_key, IDENTIFIER), self.static_public);
        self.hash = blake2s_add(self.hash, &initiation.unencrypted_ephemeral);
        let mut temp = hmac_blake2s(self.chaining_key, initiation.unencrypted_ephemeral)?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        temp = hmac_blake2s(
            self.chaining_key,
            self.static_private
                .diffie_hellman(&initiation.unencrypted_ephemeral),
        )?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        let mut key = hmac_blake2s_add(temp, self.chaining_key, &[0x2])?;
        let decrypted_static = aead_decrypt(&key, 0, &initiation.encrypted_static, self.hash)?;
        let decrypted_static: [u8; PUBLIC_KEY_LEN] =
            decrypted_static.try_into().map_err(Error::map)?;
        let decrypted_static: PublicKey = decrypted_static.into();
        self.hash = blake2s_add(self.hash, &initiation.encrypted_static);
        temp = hmac_blake2s(
            self.chaining_key,
            self.static_private.diffie_hellman(&decrypted_static),
        )?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        key = hmac_blake2s_add(temp, self.chaining_key, &[0x2])?;
        let decrypted_timestamp = aead_decrypt(&key, 0, &initiation.encrypted_timestamp, self.hash)?;
        self.hash = blake2s_add(self.hash, &initiation.encrypted_timestamp);
        let mac1: Mac = keyed_blake2s(
            blake2s_add(LABEL_MAC1, &self.static_public),
            &data[..(HANDSHAKE_INITIATION_LEN - MAC_LEN - MAC_LEN)],
        )?
        .into();
        if mac1 != macs.mac1 {
            return Err(Error::Proto);
        }
        let mac2: Mac = match self.last_sent_cookie.as_ref() {
            Some(cookie) => keyed_blake2s(
                cookie,
                &data[..(HANDSHAKE_INITIATION_LEN - MAC_LEN - MAC_LEN)],
            )?
            .into(),
            None => Mac::zero(),
        };
        if mac2 != macs.mac2 {
            return Err(Error::Proto);
        }
        Ok(HandshakeInitiation {
            sender_index: initiation.sender_index,
            unencrypted_ephemeral: initiation.unencrypted_ephemeral,
            static_public: decrypted_static,
            timestamp: decrypted_timestamp
                .as_slice()
                .try_into()
                .map_err(Error::map)?,
        })
    }

    pub fn handshake_response(
        &mut self,
        initiation: &HandshakeInitiation,
    ) -> Result<Vec<u8>, Error> {
        self.receiver_index = initiation.sender_index;
        self.hash = blake2s_add(self.hash, &self.ephemeral_public);
        let mut temp = hmac_blake2s(self.chaining_key, self.ephemeral_public)?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        temp = hmac_blake2s(
            &self.chaining_key,
            self.ephemeral_private.diffie_hellman(&initiation.unencrypted_ephemeral),
        )?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        temp = hmac_blake2s(
            &self.chaining_key,
            self.ephemeral_private.diffie_hellman(&initiation.static_public),
        )?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        temp = hmac_blake2s(&self.chaining_key, &self.static_preshared)?;
        self.chaining_key = hmac_blake2s(temp, &[0x1])?;
        let temp2 = hmac_blake2s_add(temp, &self.chaining_key, &[0x2])?;
        let key = hmac_blake2s_add(temp, &temp2, &[0x3])?;
        self.hash = blake2s_add(self.hash, &temp2);
        let encrypted_nothing = aead(&key, 0, &[], &self.hash)?;
        let encrypted_nothing: [u8; ENCRYPTED_NOTHING_LEN] =
            encrypted_nothing.try_into().map_err(Error::map)?;
        let encrypted_nothing = EncryptedNothing {
            data: encrypted_nothing,
        };
        self.hash = blake2s_add(self.hash, &encrypted_nothing);
        let response = EncryptedHandshakeResponse {
            sender_index: self.sender_index,
            receiver_index: self.receiver_index,
            unencrypted_ephemeral: self.ephemeral_public,
            encrypted_nothing,
        };
        let mut buffer = Vec::with_capacity(HANDSHAKE_RESPONSE_LEN);
        MessageType::HandshakeResponse.encode_to_vec(&mut buffer);
        response.encode_to_vec(&mut buffer);
        let mac1: Mac = keyed_blake2s(
            blake2s_add(LABEL_MAC1, &initiation.static_public),
            buffer.as_slice(),
        )?
        .into();
        mac1.encode_to_vec(&mut buffer);
        let mac2: Mac = match self.last_received_cookie.as_ref() {
            Some(cookie) => keyed_blake2s(cookie, buffer.as_slice())?.into(),
            None => Mac::zero(),
        };
        mac2.encode_to_vec(&mut buffer);
        Ok(buffer)
    }
}

pub trait Decode {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized;
}

pub trait Encode {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>);
}

impl Decode for u32 {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let n = u32::from_le_bytes(
            slice
                .get(..4)
                .ok_or(Error::Proto)?
                .try_into()
                .map_err(Error::map)?,
        );
        Ok((n, &slice[4..]))
    }
}

impl Encode for u32 {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.to_le_bytes().as_slice());
    }
}

impl Decode for PublicKey {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let bytes: [u8; PUBLIC_KEY_LEN] = slice
            .get(..PUBLIC_KEY_LEN)
            .ok_or(Error::Proto)?
            .try_into()
            .map_err(Error::map)?;
        Ok((bytes.into(), &slice[PUBLIC_KEY_LEN..]))
    }
}

impl Encode for PublicKey {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.as_bytes().as_slice());
    }
}

const CONSTRUCTION: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &str = "WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &str = "mac1----";
const _LABEL_COOKIE: &str = "cookie--";
const CHAINING_KEY_LEN: usize = 32;
const HASH_LEN: usize = 32;
const TAI64N_LEN: usize = 12;
const ENCRYPTED_TAI_LEN: usize = aead_len(TAI64N_LEN);
const PUBLIC_KEY_LEN: usize = 32;
const ENCRYPTED_STATIC_LEN: usize = aead_len(PUBLIC_KEY_LEN);
const MAC_LEN: usize = 16;
const HANDSHAKE_INITIATION_LEN: usize = 148;
const HANDSHAKE_RESPONSE_LEN: usize = 92;
const COOKIE_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const ENCRYPTED_NOTHING_LEN: usize = aead_len(0);

const fn aead_len(n: usize) -> usize {
    n + 16
}

fn blake2s(slice: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    let mut hasher = Blake2s256::new();
    hasher.update(slice);
    hasher.finalize().into()
}

fn blake2s_add(slice1: impl AsRef<[u8]>, slice2: impl AsRef<[u8]>) -> [u8; 32] {
    use blake2::Digest;
    let mut hasher = Blake2s256::new();
    hasher.update(slice1.as_ref());
    hasher.update(slice2.as_ref());
    hasher.finalize().into()
}

fn hmac_blake2s(key: impl AsRef<[u8]>, input: impl AsRef<[u8]>) -> Result<[u8; 32], Error> {
    use blake2::digest::Mac;
    let mut hasher = Blake2sMac256::new_from_slice(key.as_ref()).map_err(Error::map)?;
    hasher.update(input.as_ref());
    Ok(hasher.finalize_fixed().into())
}

fn hmac_blake2s_add(
    key: impl AsRef<[u8]>,
    input1: impl AsRef<[u8]>,
    input2: impl AsRef<[u8]>,
) -> Result<[u8; 32], Error> {
    use blake2::digest::Mac;
    let mut hasher = Blake2sMac256::new_from_slice(key.as_ref()).map_err(Error::map)?;
    hasher.update(input1.as_ref());
    hasher.update(input2.as_ref());
    Ok(hasher.finalize_fixed().into())
}

fn keyed_blake2s(key: impl AsRef<[u8]>, input: impl AsRef<[u8]>) -> Result<[u8; 16], Error> {
    use blake2::digest::Mac;
    let mut hasher = Blake2sMac::new_from_slice(key.as_ref()).map_err(Error::map)?;
    hasher.update(input.as_ref());
    Ok(hasher.finalize_fixed().into())
}

fn aead(
    key: &[u8; 32],
    counter: u64,
    plain_text: impl AsRef<[u8]>,
    auth_text: impl AsRef<[u8]>,
) -> Result<Vec<u8>, Error> {
    use chacha20poly1305::KeyInit;
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[4..].copy_from_slice(counter.to_le_bytes().as_slice());
    let payload = chacha20poly1305::aead::Payload {
        msg: plain_text.as_ref(),
        aad: auth_text.as_ref(),
    };
    cipher
        .encrypt((&nonce).into(), payload)
        .map_err(Error::map)
}

fn aead_decrypt(
    key: &[u8; 32],
    counter: u64,
    cipher_text: impl AsRef<[u8]>,
    auth_text: impl AsRef<[u8]>,
) -> Result<Vec<u8>, Error> {
    use chacha20poly1305::KeyInit;
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[4..].copy_from_slice(counter.to_le_bytes().as_slice());
    let payload = chacha20poly1305::aead::Payload {
        msg: cipher_text.as_ref(),
        aad: auth_text.as_ref(),
    };
    cipher
        .decrypt((&nonce).into(), payload)
        .map_err(Error::map)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn encode_decode_handshake_initiation_wg() {
        let bytes = VALID_HANDSHAKE_INITIATION;
        for n in 0..(bytes.len() - 1) {
            assert!(Message::decode_from_slice(&bytes[..n]).is_err());
        }
        let (message, slice) = Message::decode_from_slice(bytes.as_slice()).unwrap();
        assert_eq!(MessageType::HandshakeInitiation, message.get_type());
        assert!(slice.is_empty());
        let mut buffer = Vec::new();
        message.encode_to_vec(&mut buffer);
        assert_eq!(bytes.as_slice(), buffer.as_slice());
    }

    #[test]
    fn encode_decode_handshake_response_wg() {
        let bytes = VALID_HANDSHAKE_RESPONSE;
        for n in 0..(bytes.len() - 1) {
            assert!(Message::decode_from_slice(&bytes[..n]).is_err());
        }
        let (message, slice) = Message::decode_from_slice(bytes.as_slice()).unwrap();
        assert_eq!(MessageType::HandshakeResponse, message.get_type());
        assert!(slice.is_empty());
        let mut buffer = Vec::new();
        message.encode_to_vec(&mut buffer);
        assert_eq!(bytes.as_slice(), buffer.as_slice());
    }

    #[test]
    fn handshake() {
        let initiator_static_secret = StaticSecret::random();
        let initiator_static_public: PublicKey = (&initiator_static_secret).into();
        let responder_static_secret = StaticSecret::random();
        let responder_static_public: PublicKey = (&responder_static_secret).into();
        let static_preshared = StaticSecret::random();
        let mut initiator = Initiator::new(
            initiator_static_public,
            initiator_static_secret,
            static_preshared.clone(),
            responder_static_public,
        );
        let mut responder = Responder::new(
            responder_static_public,
            responder_static_secret,
            static_preshared,
        );
        let initiation_bytes = initiator.handshake_initiation().unwrap();
        let (message, slice) = Message::decode_from_slice(initiation_bytes.as_slice()).unwrap();
        assert_eq!(MessageType::HandshakeInitiation, message.get_type());
        assert!(slice.is_empty());
        let initiation = match message {
            Message::HandshakeInitiation(message, macs) => {
                responder
                    .on_handshake_initiation(initiation_bytes.as_slice(), message, macs)
                    .unwrap()
            }
            _ => return assert!(false, "invalid message type"),
        };
        let response_bytes = responder.handshake_response(&initiation).unwrap();
        let (message, slice) = Message::decode_from_slice(response_bytes.as_slice()).unwrap();
        assert_eq!(MessageType::HandshakeResponse, message.get_type());
        assert!(slice.is_empty());
        let _response = match message {
            Message::HandshakeResponse(message, macs) => {
                initiator
                    .on_handshake_response(response_bytes.as_slice(), message, macs)
                    .unwrap()
            }
            _ => return assert!(false, "invalid message type"),
        };
    }

    // a real packet from wg in-kernel implementation
    const VALID_HANDSHAKE_INITIATION: [u8; HANDSHAKE_INITIATION_LEN] = [
        0x01, 0x00, 0x00, 0x00, 0x8b, 0xc4, 0x5f, 0xd9, 0xe8, 0x1a, 0x5b, 0x2f, 0x47, 0x5f, 0x74,
        0xf7, 0xa0, 0xc2, 0xe6, 0x80, 0x53, 0x3d, 0xc6, 0x95, 0xa2, 0x45, 0xfb, 0xc8, 0xf0, 0xcf,
        0x1b, 0x4a, 0x99, 0x42, 0xe4, 0x4a, 0x37, 0x61, 0x46, 0x0f, 0xc8, 0xae, 0xbf, 0xae, 0xcb,
        0xb8, 0xa5, 0x13, 0x3a, 0x6b, 0x48, 0x89, 0x6e, 0x03, 0xc4, 0x87, 0x75, 0xf5, 0xce, 0x0d,
        0xcf, 0xf5, 0x5c, 0x65, 0xca, 0x1d, 0x84, 0x52, 0x85, 0xe2, 0xd3, 0x4f, 0x7f, 0x8b, 0xf4,
        0x4b, 0x36, 0x7e, 0x8e, 0xa1, 0x07, 0x1a, 0xb8, 0x61, 0x4b, 0xef, 0xf5, 0xc0, 0x84, 0x1e,
        0x60, 0x40, 0x97, 0x8c, 0x4d, 0x60, 0x8a, 0xc0, 0x01, 0xb8, 0x8e, 0xa2, 0xa7, 0x1d, 0x19,
        0x5a, 0xb5, 0x5a, 0xc4, 0x8a, 0xd7, 0x93, 0x6f, 0xb4, 0xd4, 0x78, 0xd0, 0xa1, 0x57, 0x67,
        0xa3, 0xc8, 0x9d, 0xc7, 0x6d, 0xe2, 0xb5, 0xe2, 0x55, 0x99, 0x1b, 0x92, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const VALID_HANDSHAKE_RESPONSE: [u8; HANDSHAKE_RESPONSE_LEN] = [
        0x02, 0x00, 0x00, 0x00, 0x45, 0xe4, 0xbb, 0xb9, 0x8b, 0xc4, 0x5f, 0xd9, 0xdb, 0xf5, 0xc1,
        0xaf, 0xf1, 0x3c, 0xff, 0x4f, 0x92, 0x07, 0xdc, 0xb3, 0x7c, 0x3a, 0xaa, 0xb6, 0xe4, 0x90,
        0x48, 0x3a, 0x6a, 0x4b, 0xb7, 0xe0, 0x04, 0x94, 0x43, 0xc1, 0x22, 0x83, 0xb9, 0x7d, 0x32,
        0x74, 0x5a, 0x71, 0x40, 0x08, 0x4b, 0x5c, 0xaa, 0x6a, 0x82, 0xfe, 0x52, 0xc0, 0x47, 0x04,
        0x66, 0x63, 0x2a, 0xda, 0x57, 0x98, 0x58, 0x72, 0x7b, 0x79, 0xbf, 0x38, 0x57, 0x3f, 0x63,
        0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
}
