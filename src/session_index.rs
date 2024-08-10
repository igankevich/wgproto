use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use rand_core::OsRng;
use rand_core::RngCore;

use crate::Decode;
use crate::Encode;
use crate::Error;

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
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
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (bytes, slice): ([u8; 4], _) = Decode::decode_from_slice(slice)?;
        let number = u32::from_le_bytes(bytes);
        Ok((SessionIndex { number }, slice))
    }
}

impl Encode for SessionIndex {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
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
