use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use rand_core::OsRng;
use rand_core::RngCore;

use crate::Decode;
use crate::Encode;
use crate::Error;

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
}

impl Default for SessionIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for SessionIndex {
    fn decode(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (bytes, slice): ([u8; 4], _) = Decode::decode(slice)?;
        let number = u32::from_le_bytes(bytes);
        Ok((SessionIndex { number }, slice))
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
