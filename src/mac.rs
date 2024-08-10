use constant_time_eq::constant_time_eq;

use crate::Decode;
use crate::Encode;
use crate::Error;
use crate::MAC_LEN;

pub struct Mac {
    data: [u8; MAC_LEN],
}

impl Mac {
    pub fn zero() -> Self {
        Self {
            data: Default::default(),
        }
    }
}

impl PartialEq for Mac {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.data.as_slice(), other.data.as_slice())
    }
}

impl Eq for Mac {}

impl From<[u8; MAC_LEN]> for Mac {
    fn from(data: [u8; MAC_LEN]) -> Self {
        Self { data }
    }
}

impl Decode for Mac {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (bytes, slice): ([u8; MAC_LEN], _) = Decode::decode_from_slice(slice)?;
        Ok((bytes.into(), slice))
    }
}

impl Encode for Mac {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.data.as_slice());
    }
}
