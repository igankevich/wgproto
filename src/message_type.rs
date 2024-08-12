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
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        if slice.len() < 4 {
            return Err(Error);
        }
        Ok((slice[0].try_into()?, &slice[4..]))
    }
}

impl Encode for MessageType {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
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

#[cfg(test)]
mod tests {

    use arbtest::arbtest;

    use super::*;
    use crate::tests::test_encode_decode;

    #[test]
    fn encode_decode() {
        arbtest(test_encode_decode::<MessageType>);
    }
}
