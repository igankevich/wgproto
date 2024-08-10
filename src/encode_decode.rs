use crate::Error;

pub trait Decode {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized;
}

pub trait Encode {
    fn encode_to_vec(&self, buffer: &mut Vec<u8>);
}

impl<const N: usize> Decode for [u8; N] {
    fn decode_from_slice(slice: &[u8]) -> Result<(Self, &[u8]), Error> {
        let array = slice
            .get(..N)
            .ok_or(Error)?
            .try_into()
            .map_err(Error::map)?;
        Ok((array, &slice[N..]))
    }
}
