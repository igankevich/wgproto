use crate::Error;
use crate::InputBuffer;
use crate::PublicKey;
use crate::PUBLIC_KEY_LEN;

pub trait Decode<C = ()> {
    fn decode(buffer: &mut InputBuffer) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait Encode {
    fn encode(&self, buffer: &mut Vec<u8>);
}

pub trait DecodeWithContext<C> {
    fn decode_with_context(buffer: &mut InputBuffer, context: C) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait EncodeWithContext<C> {
    fn encode_with_context(&self, buffer: &mut Vec<u8>, context: C);
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(buffer: &mut InputBuffer) -> Result<Self, Error> {
        buffer
            .get_next(N)
            .ok_or(Error)?
            .try_into()
            .map_err(Error::map)
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.as_slice())
    }
}

impl Decode for PublicKey {
    fn decode(buffer: &mut InputBuffer) -> Result<Self, Error> {
        let bytes: [u8; PUBLIC_KEY_LEN] = Decode::decode(buffer)?;
        Ok(bytes.into())
    }
}

impl Encode for PublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.as_bytes().as_slice());
    }
}

impl Decode for Vec<u8> {
    fn decode(buffer: &mut InputBuffer) -> Result<Self, Error> {
        Ok(buffer.get_remaining().to_vec())
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
