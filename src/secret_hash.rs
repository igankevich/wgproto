use std::ops::Deref;

use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) type U8_32 = [u8; SECRET_DATA_LEN];

#[derive(Default, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
pub(crate) struct SecretData {
    data: U8_32,
}

impl Deref for SecretData {
    type Target = U8_32;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl AsRef<[u8]> for SecretData {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl AsRef<U8_32> for SecretData {
    fn as_ref(&self) -> &U8_32 {
        &self.data
    }
}

impl From<U8_32> for SecretData {
    fn from(data: U8_32) -> Self {
        Self { data }
    }
}

const SECRET_DATA_LEN: usize = 32;
