use std::fmt::Debug;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;

use crate::Decode;
use crate::Encode;

pub(crate) fn test_encode_decode<T: Encode + Decode + Debug + PartialEq + for<'a> Arbitrary<'a>>(
    u: &mut Unstructured<'_>,
) -> Result<(), arbitrary::Error> {
    let expected: T = u.arbitrary()?;
    let mut buffer: Vec<u8> = Vec::new();
    expected.encode_to_vec(&mut buffer);
    let (actual, slice) = T::decode_from_slice(buffer.as_slice()).unwrap();
    assert!(slice.is_empty());
    assert_eq!(expected, actual);
    Ok(())
}

pub(crate) fn test_encode_decode_proxy<
    P: for<'a> Arbitrary<'a>,
    T: Encode + Decode + Debug + PartialEq + From<P>,
>(
    u: &mut Unstructured<'_>,
) -> Result<(), arbitrary::Error> {
    let proxy: P = u.arbitrary()?;
    let expected: T = proxy.into();
    let mut buffer: Vec<u8> = Vec::new();
    expected.encode_to_vec(&mut buffer);
    let (actual, slice) = T::decode_from_slice(buffer.as_slice()).unwrap();
    assert!(slice.is_empty());
    assert_eq!(expected, actual);
    Ok(())
}
