use crate::Error;
use crate::PublicKey;
use crate::PUBLIC_KEY_LEN;

pub trait Decode<C = ()> {
    fn decode(slice: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized;
}

pub trait Encode {
    fn encode(&self, buffer: &mut Vec<u8>);
}

pub trait DecodeWithContext<C> {
    fn decode_with_context(slice: &[u8], context: C) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized;
}

pub trait EncodeWithContext<C> {
    fn encode_with_context(&self, buffer: &mut Vec<u8>, context: C);
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let array = slice
            .get(..N)
            .ok_or(Error)?
            .try_into()
            .map_err(Error::map)?;
        Ok((array, &slice[N..]))
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.as_slice())
    }
}

impl Decode for PublicKey {
    fn decode(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (bytes, slice): ([u8; PUBLIC_KEY_LEN], _) = Decode::decode(slice)?;
        Ok((bytes.into(), slice))
    }
}

impl Encode for PublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.as_bytes().as_slice());
    }
}

impl Decode for Vec<u8> {
    fn decode(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        Ok((slice.to_vec(), &[]))
    }
}

impl Encode for &[u8] {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self);
    }
}

#[cfg(test)]
mod tests {

    use arbtest::arbtest;

    use super::*;
    use crate::tests::encode_decode_symmetry_with_proxy;
    use crate::tests::PublicKeyProxy;

    #[test]
    fn encode_decode() {
        arbtest(encode_decode_symmetry_with_proxy::<PublicKeyProxy, PublicKey>);
    }
}
