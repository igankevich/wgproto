use crate::Decode;
use crate::Encode;
use crate::Error;
use crate::Mac;

pub struct Macs {
    pub mac1: Mac,
    pub mac2: Mac,
}

impl Decode for Macs {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (mac1, slice) = Mac::decode_from_slice(slice)?;
        let (mac2, slice) = Mac::decode_from_slice(slice)?;
        Ok((Self { mac1, mac2 }, slice))
    }
}

impl Encode for Macs {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>) {
        self.mac1.encode_to_vec(buffer);
        self.mac2.encode_to_vec(buffer);
    }
}
