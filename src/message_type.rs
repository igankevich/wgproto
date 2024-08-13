use crate::Decode;
use crate::Encode;
use crate::Error;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum MessageType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    PacketData = 4,
}

impl Decode for MessageType {
    fn decode(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        if slice.len() < MESSAGE_TYPE_LEN {
            return Err(Error);
        }
        Ok((slice[0].try_into()?, &slice[MESSAGE_TYPE_LEN..]))
    }
}

impl Encode for MessageType {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&[*self as u8, 0, 0, 0]);
    }
}

impl TryFrom<u8> for MessageType {
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

const MESSAGE_TYPE_LEN: usize = 4;

#[cfg(test)]
mod tests {

    use arbtest::arbtest;

    use super::*;
    use crate::tests::encode_decode_symmetry;

    #[test]
    fn encode_decode() {
        arbtest(encode_decode_symmetry::<MessageType>);
    }
}
