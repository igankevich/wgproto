use crate::Decode;
use crate::Encode;
use crate::Error;
use crate::InputBuffer;

#[cfg_attr(test, derive(arbitrary::Arbitrary, PartialEq, Eq, Debug))]
#[repr(transparent)]
pub struct EncryptedBytes<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Decode for EncryptedBytes<N> {
    fn decode(buffer: &mut InputBuffer) -> Result<Self, Error> {
        let data: [u8; N] = Decode::decode(buffer)?;
        Ok(data.into())
    }
}

impl<const N: usize> Encode for EncryptedBytes<N> {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.data.as_slice());
    }
}

impl<const N: usize> AsRef<[u8]> for EncryptedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl<const N: usize> TryFrom<&[u8]> for EncryptedBytes<N> {
    type Error = Error;
    fn try_from(other: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            data: other.try_into().map_err(Error::map)?,
        })
    }
}

impl<const N: usize> From<[u8; N]> for EncryptedBytes<N> {
    fn from(data: [u8; N]) -> Self {
        Self { data }
    }
}
