use x25519_dalek::PublicKey;

use crate::Error;
use crate::PUBLIC_KEY_LEN;

pub trait Decode {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized;
}

pub trait Encode {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>);
}

impl<const N: usize> Decode for [u8; N] {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let array = slice
            .get(..N)
            .ok_or(Error)?
            .try_into()
            .map_err(Error::map)?;
        Ok((array, &slice[N..]))
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.as_slice())
    }
}

impl Decode for PublicKey {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (bytes, slice): ([u8; PUBLIC_KEY_LEN], _) = Decode::decode_from_slice(slice)?;
        Ok((bytes.into(), slice))
    }
}

impl Encode for PublicKey {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.as_bytes().as_slice());
    }
}

impl Decode for Vec<u8> {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        Ok((slice.to_vec(), &[]))
    }
}

impl Encode for &[u8] {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self);
    }
}
