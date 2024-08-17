use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use rand_core::OsRng;
use rand_core::RngCore;

use crate::Decode;
use crate::Encode;
use crate::Error;
use crate::InputBuffer;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[repr(transparent)]
pub struct SessionIndex {
    number: u32,
}

impl SessionIndex {
    pub fn new() -> Self {
        Self {
            number: OsRng.next_u32(),
        }
    }

    pub fn as_u32(&self) -> u32 {
        self.number
    }
}

impl Default for SessionIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for SessionIndex {
    fn decode(buffer: &mut InputBuffer) -> Result<Self, Error> {
        let bytes: [u8; SESSION_INDEX_LEN] = Decode::decode(buffer)?;
        let number = u32::from_le_bytes(bytes);
        Ok(SessionIndex { number })
    }
}

impl Encode for SessionIndex {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.number.to_le_bytes().as_slice());
    }
}

impl Display for SessionIndex {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(&self.number, f)
    }
}

impl Debug for SessionIndex {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Debug::fmt(&self.number, f)
    }
}

impl From<SessionIndex> for u32 {
    fn from(other: SessionIndex) -> u32 {
        other.number
    }
}

impl From<u32> for SessionIndex {
    fn from(number: u32) -> Self {
        Self { number }
    }
}

const SESSION_INDEX_LEN: usize = 4;

#[cfg(test)]
mod tests {

    use arbtest::arbtest;

    use super::*;
    use crate::tests::encode_decode_symmetry;

    #[test]
    fn encode_decode() {
        arbtest(encode_decode_symmetry::<SessionIndex>);
    }
}
