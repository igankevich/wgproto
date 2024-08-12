use blake2::digest::FixedOutput;
use blake2::Blake2s256;
use blake2::Blake2sMac;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::SimpleHmac;
use zeroize::Zeroize;

use crate::Counter;
use crate::Encode;
use crate::EncryptedHandshakeInitiation;
use crate::EncryptedHandshakeResponse;
use crate::EncryptedNothing;
use crate::EncryptedPacketData;
use crate::EncryptedStatic;
use crate::EncryptedTimestamp;
use crate::Error;
use crate::HandshakeInitiation;
use crate::Message;
use crate::PresharedKey;
use crate::PrivateKey;
use crate::PublicKey;
use crate::SecretData;
use crate::SessionIndex;
use crate::Timestamp;
use crate::U8_32;

//https://www.wireguard.com/protocol/

pub struct Cookie {
    data: [u8; COOKIE_LEN],
}

impl AsRef<[u8]> for Cookie {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

pub struct Session {
    sender_index: SessionIndex,
    receiver_index: Option<SessionIndex>,
    chaining_key: ChainingKey,
    hash: SessionHash,
    ephemeral_private: PrivateKey,
    ephemeral_public: PublicKey,
    static_private: PrivateKey,
    static_public: PublicKey,
    static_preshared: PresharedKey,
    other_static_public: Option<PublicKey>,
    last_sent_cookie: Option<Cookie>,
    last_received_cookie: Option<Cookie>,
    sending_key: Key,
    receiving_key: Key,
    sending_key_counter: Counter,
    receiving_key_counter: Counter,
}

impl Session {
    pub fn sender_index(&self) -> SessionIndex {
        self.sender_index
    }

    pub fn initiate(
        static_public: PublicKey,
        static_private: PrivateKey,
        static_preshared: PresharedKey,
        responder_static_public: PublicKey,
    ) -> Result<(Self, Vec<u8>), Error> {
        let ephemeral_private = PrivateKey::random();
        let ephemeral_public: PublicKey = (&ephemeral_private).into();
        let mut session = Self {
            sender_index: Default::default(),
            receiver_index: Default::default(),
            chaining_key: Default::default(),
            hash: Default::default(),
            ephemeral_private,
            ephemeral_public,
            static_private,
            static_public,
            static_preshared,
            other_static_public: Some(responder_static_public),
            last_sent_cookie: Default::default(),
            last_received_cookie: Default::default(),
            sending_key: Default::default(),
            receiving_key: Default::default(),
            sending_key_counter: Default::default(),
            receiving_key_counter: Default::default(),
        };
        let handshake = session.handshake_initiation()?;
        Ok((session, handshake))
    }

    fn handshake_initiation(&mut self) -> Result<Vec<u8>, Error> {
        let responder_static_public = match self.other_static_public {
            Some(x) => x,
            None => return Err(Error),
        };
        self.chaining_key = blake2s(CONSTRUCTION.as_bytes());
        self.hash = blake2s_add(
            blake2s_add(&self.chaining_key, IDENTIFIER),
            responder_static_public,
        );
        self.hash = blake2s_add(self.hash, self.ephemeral_public);
        let mut temp = hmac_blake2s(&self.chaining_key, self.ephemeral_public)?;
        self.chaining_key = hmac_blake2s(temp, [0x1])?;
        temp = hmac_blake2s(
            &self.chaining_key,
            self.ephemeral_private
                .diffie_hellman(&responder_static_public),
        )?;
        self.chaining_key = hmac_blake2s(&temp, [0x1])?;
        let mut key = hmac_blake2s_add(&temp, &self.chaining_key, [0x2])?;
        let encrypted_static: EncryptedStatic =
            aead_encrypt(&key, 0, self.static_public, self.hash)?
                .as_slice()
                .try_into()?;
        self.hash = blake2s_add(self.hash, &encrypted_static);
        temp = hmac_blake2s(
            &self.chaining_key,
            self.static_private.diffie_hellman(&responder_static_public),
        )?;
        self.chaining_key = hmac_blake2s(&temp, [0x1])?;
        key = hmac_blake2s_add(&temp, &self.chaining_key, [0x2])?;
        let timestamp = Timestamp::now();
        let encrypted_timestamp: EncryptedTimestamp =
            aead_encrypt(&key, 0, timestamp.to_bytes(), self.hash)?
                .as_slice()
                .try_into()?;
        self.hash = blake2s_add(self.hash, &encrypted_timestamp);
        let message = Message::HandshakeInitiation(EncryptedHandshakeInitiation {
            sender_index: self.sender_index,
            unencrypted_ephemeral: self.ephemeral_public,
            encrypted_static,
            encrypted_timestamp,
        });
        let mut buffer = Vec::with_capacity(HANDSHAKE_INITIATION_LEN);
        message.encode_to_vec(&mut buffer);
        encode_macs(
            &responder_static_public,
            self.last_received_cookie.as_ref(),
            &mut buffer,
        )?;
        Ok(buffer)
    }

    pub fn on_handshake_response(
        &mut self,
        data: &[u8],
        response: EncryptedHandshakeResponse,
    ) -> Result<(), Error> {
        self.hash = blake2s_add(self.hash, response.unencrypted_ephemeral);
        let mut temp = hmac_blake2s(&self.chaining_key, response.unencrypted_ephemeral)?;
        self.chaining_key = hmac_blake2s(temp, [0x1])?;
        temp = hmac_blake2s(
            &self.chaining_key,
            self.ephemeral_private
                .diffie_hellman(&response.unencrypted_ephemeral),
        )?;
        self.chaining_key = hmac_blake2s(temp, [0x1])?;
        temp = hmac_blake2s(
            &self.chaining_key,
            self.static_private
                .diffie_hellman(&response.unencrypted_ephemeral),
        )?;
        self.chaining_key = hmac_blake2s(&temp, [0x1])?;
        temp = hmac_blake2s(&self.chaining_key, &self.static_preshared)?;
        self.chaining_key = hmac_blake2s(&temp, [0x1])?;
        let temp2 = hmac_blake2s_add(&temp, &self.chaining_key, [0x2])?;
        let key = hmac_blake2s_add(temp, &temp2, [0x3])?;
        self.hash = blake2s_add(self.hash, &temp2);
        let decrypted_nothing = aead_decrypt(&key, 0, &response.encrypted_nothing, self.hash)?;
        if !decrypted_nothing.is_empty() {
            return Err(Error);
        }
        self.hash = blake2s_add(self.hash, decrypted_nothing.as_slice());
        verify_message(
            &data[..HANDSHAKE_RESPONSE_LEN],
            &self.static_public,
            self.last_received_cookie.as_ref(),
        )?;
        self.receiver_index = Some(response.receiver_index);
        let (temp2, temp3) = self.derive_keys()?;
        self.sending_key = temp2;
        self.receiving_key = temp3;
        Ok(())
    }

    pub fn respond(
        static_public: PublicKey,
        static_private: PrivateKey,
        static_preshared: PresharedKey,
        data: &[u8],
        initiation: EncryptedHandshakeInitiation,
    ) -> Result<(Self, HandshakeInitiation, Vec<u8>), Error> {
        let ephemeral_private = PrivateKey::random();
        let ephemeral_public: PublicKey = (&ephemeral_private).into();
        let mut session = Self {
            sender_index: Default::default(),
            receiver_index: Default::default(),
            hash: Default::default(),
            chaining_key: Default::default(),
            ephemeral_private,
            ephemeral_public,
            static_private,
            static_public,
            static_preshared,
            other_static_public: None,
            last_sent_cookie: Default::default(),
            last_received_cookie: Default::default(),
            sending_key: Default::default(),
            receiving_key: Default::default(),
            sending_key_counter: Default::default(),
            receiving_key_counter: Default::default(),
        };
        let initiation = session.on_handshake_initiation(data, initiation)?;
        let response = session.handshake_response(&initiation)?;
        let (temp2, temp3) = session.derive_keys()?;
        session.receiving_key = temp2;
        session.sending_key = temp3;
        Ok((session, initiation, response))
    }

    fn derive_keys(&mut self) -> Result<(Key, Key), Error> {
        let temp1 = hmac_blake2s(&self.chaining_key, [])?;
        let temp2 = hmac_blake2s(&temp1, [0x1])?;
        let temp3 = hmac_blake2s_add(&temp1, &temp2, [0x1])?;
        self.chaining_key.zeroize();
        self.hash.zeroize();
        self.ephemeral_public.zeroize();
        self.ephemeral_private.zeroize();
        self.sending_key_counter = Default::default();
        self.receiving_key_counter = Default::default();
        Ok((temp2, temp3))
    }

    pub fn send(&mut self, data: &[u8]) -> Result<Message, Error> {
        let receiver_index = match self.receiver_index {
            Some(x) => x,
            None => return Err(Error),
        };
        // We do not need padding here as chacha20poly1305 crate handles it itself.
        let encrypted_encapsulated_packet = aead_encrypt(
            &self.sending_key,
            self.sending_key_counter.as_u64(),
            data,
            [],
        )?;
        let message = Message::PacketData(EncryptedPacketData {
            receiver_index,
            counter: self.sending_key_counter,
            encrypted_encapsulated_packet,
        });
        self.sending_key_counter.increment();
        Ok(message)
    }

    pub fn receive(&mut self, message: &EncryptedPacketData) -> Result<Vec<u8>, Error> {
        if message.counter < self.receiving_key_counter {
            return Err(Error); // TODO
        }
        let data = message.encrypted_encapsulated_packet.as_slice();
        let unencrypted_packet = aead_decrypt(
            &self.receiving_key,
            self.receiving_key_counter.as_u64(),
            data,
            [],
        )?;
        self.receiving_key_counter.increment();
        Ok(unencrypted_packet)
    }

    /// `data` the whole message
    fn on_handshake_initiation(
        &mut self,
        data: &[u8],
        initiation: EncryptedHandshakeInitiation,
    ) -> Result<HandshakeInitiation, Error> {
        self.chaining_key = blake2s(CONSTRUCTION.as_bytes());
        self.hash = blake2s_add(
            blake2s_add(&self.chaining_key, IDENTIFIER),
            self.static_public,
        );
        self.hash = blake2s_add(self.hash, initiation.unencrypted_ephemeral);
        let mut temp = hmac_blake2s(&self.chaining_key, initiation.unencrypted_ephemeral)?;
        self.chaining_key = hmac_blake2s(temp, [0x1])?;
        temp = hmac_blake2s(
            &self.chaining_key,
            self.static_private
                .diffie_hellman(&initiation.unencrypted_ephemeral),
        )?;
        self.chaining_key = hmac_blake2s(&temp, [0x1])?;
        let mut key = hmac_blake2s_add(&temp, &self.chaining_key, [0x2])?;
        let decrypted_static = aead_decrypt(&key, 0, &initiation.encrypted_static, self.hash)?;
        let decrypted_static: [u8; PUBLIC_KEY_LEN] =
            decrypted_static.try_into().map_err(Error::map)?;
        let decrypted_static: PublicKey = decrypted_static.into();
        self.hash = blake2s_add(self.hash, &initiation.encrypted_static);
        temp = hmac_blake2s(
            &self.chaining_key,
            self.static_private.diffie_hellman(&decrypted_static),
        )?;
        self.chaining_key = hmac_blake2s(&temp, [0x1])?;
        key = hmac_blake2s_add(&temp, &self.chaining_key, [0x2])?;
        let decrypted_timestamp =
            aead_decrypt(&key, 0, &initiation.encrypted_timestamp, self.hash)?;
        self.hash = blake2s_add(self.hash, &initiation.encrypted_timestamp);
        verify_message(
            &data[..HANDSHAKE_INITIATION_LEN],
            &self.static_public,
            self.last_sent_cookie.as_ref(),
        )?;
        self.other_static_public = Some(decrypted_static);
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

    fn handshake_response(&mut self, initiation: &HandshakeInitiation) -> Result<Vec<u8>, Error> {
        self.receiver_index = Some(initiation.sender_index);
        self.hash = blake2s_add(self.hash, self.ephemeral_public);
        let mut temp = hmac_blake2s(&self.chaining_key, self.ephemeral_public)?;
        self.chaining_key = hmac_blake2s(temp, [0x1])?;
        temp = hmac_blake2s(
            &self.chaining_key,
            self.ephemeral_private
                .diffie_hellman(&initiation.unencrypted_ephemeral),
        )?;
        self.chaining_key = hmac_blake2s(temp, [0x1])?;
        temp = hmac_blake2s(
            &self.chaining_key,
            self.ephemeral_private
                .diffie_hellman(&initiation.static_public),
        )?;
        self.chaining_key = hmac_blake2s(temp, [0x1])?;
        temp = hmac_blake2s(&self.chaining_key, &self.static_preshared)?;
        self.chaining_key = hmac_blake2s(&temp, [0x1])?;
        let temp2 = hmac_blake2s_add(&temp, &self.chaining_key, [0x2])?;
        let key = hmac_blake2s_add(&temp, &temp2, [0x3])?;
        self.hash = blake2s_add(self.hash, temp2);
        let encrypted_nothing = aead_encrypt(&key, 0, [], self.hash)?;
        let encrypted_nothing: EncryptedNothing = encrypted_nothing.as_slice().try_into()?;
        self.hash = blake2s_add(self.hash, &encrypted_nothing);
        let message = Message::HandshakeResponse(EncryptedHandshakeResponse {
            sender_index: self.sender_index,
            receiver_index: initiation.sender_index,
            unencrypted_ephemeral: self.ephemeral_public,
            encrypted_nothing,
        });
        let mut buffer = Vec::with_capacity(HANDSHAKE_RESPONSE_LEN);
        message.encode_to_vec(&mut buffer);
        encode_macs(
            &initiation.static_public,
            self.last_received_cookie.as_ref(),
            &mut buffer,
        )?;
        Ok(buffer)
    }
}

fn encode_macs(
    static_public: &PublicKey,
    cookie: Option<&Cookie>,
    buffer: &mut Vec<u8>,
) -> Result<(), Error> {
    let mac1 = keyed_blake2s(blake2s_add(LABEL_MAC1, static_public), buffer.as_slice())?;
    mac1.encode_to_vec(buffer);
    let mac2 = match cookie {
        Some(cookie) => keyed_blake2s(cookie, buffer.as_slice())?,
        None => Default::default(),
    };
    mac2.encode_to_vec(buffer);
    Ok(())
}

fn verify_message(
    data: &[u8],
    static_public: &PublicKey,
    cookie: Option<&Cookie>,
) -> Result<(), Error> {
    let mac2_offset = data.len() - MAC_LEN;
    let mac1_offset = mac2_offset - MAC_LEN;
    let other_mac1 = &data[mac1_offset..(mac1_offset + MAC_LEN)];
    let other_mac2 = &data[mac2_offset..(mac2_offset + MAC_LEN)];
    let mac1 = keyed_blake2s(blake2s_add(LABEL_MAC1, static_public), &data[..mac1_offset])?;
    if mac1 != other_mac1 {
        return Err(Error);
    }
    let mac2 = match cookie {
        Some(cookie) => keyed_blake2s(cookie, &data[..mac2_offset])?,
        None => Default::default(),
    };
    if mac2 != other_mac2 {
        return Err(Error);
    }
    Ok(())
}

fn blake2s(slice: &[u8]) -> SecretData {
    use blake2::Digest;
    let mut hasher = Blake2s256::new();
    hasher.update(slice);
    let digest: U8_32 = hasher.finalize().into();
    digest.into()
}

fn blake2s_add(slice1: impl AsRef<[u8]>, slice2: impl AsRef<[u8]>) -> [u8; 32] {
    use blake2::Digest;
    let mut hasher = Blake2s256::new();
    hasher.update(slice1.as_ref());
    hasher.update(slice2.as_ref());
    hasher.finalize().into()
}

fn hmac_blake2s(key: impl AsRef<[u8]>, input: impl AsRef<[u8]>) -> Result<SecretData, Error> {
    use hmac::Mac;
    let mut hasher = HmacBlake2s::new_from_slice(key.as_ref()).map_err(Error::map)?;
    hasher.update(input.as_ref());
    let digest: U8_32 = hasher.finalize_fixed().into();
    Ok(digest.into())
}

fn hmac_blake2s_add(
    key: impl AsRef<[u8]>,
    input1: impl AsRef<[u8]>,
    input2: impl AsRef<[u8]>,
) -> Result<SecretData, Error> {
    use hmac::Mac;
    let mut hasher = HmacBlake2s::new_from_slice(key.as_ref()).map_err(Error::map)?;
    hasher.update(input1.as_ref());
    hasher.update(input2.as_ref());
    let digest: U8_32 = hasher.finalize_fixed().into();
    Ok(digest.into())
}

fn keyed_blake2s(key: impl AsRef<[u8]>, input: impl AsRef<[u8]>) -> Result<[u8; 16], Error> {
    use blake2::digest::Mac;
    let mut hasher = Blake2sMac::new_from_slice(key.as_ref()).map_err(Error::map)?;
    hasher.update(input.as_ref());
    Ok(hasher.finalize_fixed().into())
}

fn aead_encrypt(
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
    cipher.encrypt((&nonce).into(), payload).map_err(Error::map)
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
    cipher.decrypt((&nonce).into(), payload).map_err(Error::map)
}

type ChainingKey = SecretData;
type SessionHash = [u8; HASH_LEN];
type Key = SecretData;
type HmacBlake2s = SimpleHmac<Blake2s256>;

const HASH_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HANDSHAKE_INITIATION_LEN: usize = 148;
const HANDSHAKE_RESPONSE_LEN: usize = 92;
const COOKIE_LEN: usize = 16;
const CONSTRUCTION: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &str = "WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &str = "mac1----";
const _LABEL_COOKIE: &str = "cookie--";
pub(crate) const PUBLIC_KEY_LEN: usize = 32;
pub(crate) const MAC_LEN: usize = 16;

#[cfg(test)]
mod tests {

    use super::*;
    use crate::Decode;
    use crate::Message;
    use crate::MessageType;

    #[test]
    fn encode_decode_handshake_initiation_wg() {
        let bytes = VALID_HANDSHAKE_INITIATION;
        let responder_static_public: PublicKey = RESPONDER_STATIC_PUBLIC.into();
        for n in 0..(bytes.len() - 1) {
            assert!(Message::decode_from_slice(&bytes[..n]).is_err());
        }
        let (message, slice) = Message::decode_from_slice(bytes.as_slice()).unwrap();
        assert_eq!(MessageType::HandshakeInitiation, message.get_type());
        assert!(slice.is_empty());
        let mut buffer = Vec::new();
        message.encode_to_vec(&mut buffer);
        encode_macs(&responder_static_public, None, &mut buffer).unwrap();
        assert_eq!(bytes.as_slice(), buffer.as_slice());
    }

    #[test]
    fn encode_decode_handshake_response_wg() {
        let bytes = VALID_HANDSHAKE_RESPONSE;
        let initiator_static_public: PublicKey = INITIATOR_STATIC_PUBLIC.into();
        for n in 0..(bytes.len() - 1) {
            assert!(Message::decode_from_slice(&bytes[..n]).is_err());
        }
        let (message, slice) = Message::decode_from_slice(bytes.as_slice()).unwrap();
        assert_eq!(MessageType::HandshakeResponse, message.get_type());
        assert!(slice.is_empty());
        let mut buffer = Vec::new();
        message.encode_to_vec(&mut buffer);
        encode_macs(&initiator_static_public, None, &mut buffer).unwrap();
        assert_eq!(bytes.as_slice(), buffer.as_slice());
    }

    #[test]
    fn respond_wg() -> Result<(), Error> {
        let initiator_static_public: PublicKey = INITIATOR_STATIC_PUBLIC.into();
        let responder_static_public: PublicKey = RESPONDER_STATIC_PUBLIC.into();
        let responder_static_secret: PrivateKey = RESPONDER_STATIC_SECRET.into();
        let static_preshared: PresharedKey = [0_u8; PUBLIC_KEY_LEN].into();
        let bytes = VALID_HANDSHAKE_INITIATION;
        let (message, _slice) = Message::decode_from_slice(bytes.as_slice())?;
        let (_responder, initiation, _) = match message {
            Message::HandshakeInitiation(message) => Session::respond(
                responder_static_public,
                responder_static_secret,
                static_preshared,
                bytes.as_slice(),
                message,
            )?,
            _ => return Err(Error),
        };
        assert_eq!(initiator_static_public, initiation.static_public);
        Ok(())
    }

    #[test]
    fn handshake() -> Result<(), Error> {
        let initiator_static_secret = PrivateKey::random();
        let initiator_static_public: PublicKey = (&initiator_static_secret).into();
        let responder_static_secret = PrivateKey::random();
        let responder_static_public: PublicKey = (&responder_static_secret).into();
        let static_preshared = PresharedKey::random();
        let (mut initiator, initiation_bytes) = Session::initiate(
            initiator_static_public,
            initiator_static_secret,
            static_preshared.clone(),
            responder_static_public,
        )?;
        let (message, slice) = Message::decode_from_slice(initiation_bytes.as_slice())?;
        assert_eq!(MessageType::HandshakeInitiation, message.get_type());
        assert!(slice.is_empty());
        let (mut responder, initiation, response_bytes) = match message {
            Message::HandshakeInitiation(message) => Session::respond(
                responder_static_public,
                responder_static_secret,
                static_preshared,
                initiation_bytes.as_slice(),
                message,
            )?,
            _ => return Err(Error),
        };
        assert_eq!(initiator_static_public, initiation.static_public);
        let (message, slice) = Message::decode_from_slice(response_bytes.as_slice())?;
        assert_eq!(MessageType::HandshakeResponse, message.get_type());
        assert!(slice.is_empty());
        match message {
            Message::HandshakeResponse(message) => {
                initiator.on_handshake_response(response_bytes.as_slice(), message)?
            }
            _ => return Err(Error),
        };
        // keep alive
        let message = initiator.send(&[])?;
        let mut buffer = Vec::new();
        message.encode_to_vec(&mut buffer);
        let (message, slice) = Message::decode_from_slice(buffer.as_slice())?;
        assert_eq!(MessageType::PacketData, message.get_type());
        assert!(slice.is_empty());
        let packet_data = match message {
            Message::PacketData(message) => responder.receive(&message)?,
            _ => return Err(Error),
        };
        assert!(packet_data.is_empty());
        Ok(())
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

    const RESPONDER_STATIC_PUBLIC: [u8; PUBLIC_KEY_LEN] = [
        0x4d, 0xd3, 0xe9, 0x23, 0x1c, 0x4d, 0xe3, 0x84, 0x0b, 0x5c, 0x80, 0x4f, 0x3c, 0x6a, 0xe8,
        0xf5, 0xfe, 0xd5, 0x6a, 0x47, 0x8f, 0xd8, 0x1f, 0xd8, 0xf1, 0xd9, 0x1b, 0x25, 0x41, 0x44,
        0xdd, 0x4f,
    ];

    const RESPONDER_STATIC_SECRET: [u8; PUBLIC_KEY_LEN] = [
        0x20, 0xa4, 0x00, 0xa6, 0x17, 0x65, 0x1a, 0x1e, 0x89, 0x22, 0x32, 0x7d, 0xc3, 0x38, 0x37,
        0x70, 0xcc, 0xa6, 0xd1, 0x88, 0xdf, 0x62, 0x88, 0x36, 0xf3, 0x58, 0x15, 0x01, 0x1b, 0xcd,
        0x26, 0x6b,
    ];

    const INITIATOR_STATIC_PUBLIC: [u8; PUBLIC_KEY_LEN] = [
        0x53, 0xa4, 0xb8, 0x5a, 0xca, 0x6c, 0x15, 0xa6, 0xfa, 0x76, 0x3a, 0x5b, 0x30, 0xc7, 0xad,
        0xb8, 0x20, 0x2a, 0xf9, 0x50, 0x0e, 0xc0, 0x95, 0x19, 0x46, 0xb5, 0xa4, 0xf6, 0x45, 0x54,
        0x4c, 0x1f,
    ];

    const _INITIATOR_STATIC_SECRET: [u8; PUBLIC_KEY_LEN] = [
        0x68, 0x00, 0x0e, 0xeb, 0x5a, 0x05, 0x6e, 0x71, 0xfc, 0x85, 0xe5, 0x30, 0x3a, 0xf7, 0x8c,
        0xee, 0x4b, 0x69, 0xf4, 0x0d, 0x7a, 0xe7, 0x0b, 0x9b, 0xab, 0x12, 0xf9, 0x07, 0x2e, 0x4a,
        0x66, 0x5a,
    ];
}
