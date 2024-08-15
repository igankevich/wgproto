use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use crate::Decode;
use crate::Encode;
use crate::Error;
use crate::InputBuffer;

#[derive(PartialEq, Eq, PartialOrd, Hash, Clone, Copy)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[repr(transparent)]
pub struct Counter {
    number: u64,
}

impl Counter {
    pub fn new() -> Self {
        Self { number: 0 }
    }

    pub fn increment(&mut self) {
        self.number = self.number.saturating_add(1); // TODO re-key on overflow
    }

    pub fn as_u64(&self) -> u64 {
        self.number
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Counter {
    fn decode(buffer: &mut InputBuffer) -> Result<Self, Error> {
        let bytes: [u8; COUNTER_LEN] = Decode::decode(buffer)?;
        let number = u64::from_le_bytes(bytes);
        Ok(Counter { number })
    }
}

impl Encode for Counter {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.number.to_le_bytes().as_slice());
    }
}

impl Display for Counter {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(&self.number, f)
    }
}

impl Debug for Counter {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Debug::fmt(&self.number, f)
    }
}

const COUNTER_LEN: usize = 8;

#[cfg(test)]
mod tests {

    use arbtest::arbtest;

    use super::*;
    use crate::tests::encode_decode_symmetry;

    #[test]
    fn encode_decode() {
        arbtest(encode_decode_symmetry::<Counter>);
    }
}
