use std::fmt::Debug;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use arbtest::arbtest;

use crate::Context;
use crate::Cookie;
use crate::Decode;
use crate::DecodeWithContext;
use crate::Encode;
use crate::EncodeWithContext;
use crate::InputBuffer;
use crate::PublicKey;
use crate::PUBLIC_KEY_LEN;

pub(crate) fn encode_decode_symmetry<
    T: Encode + Decode + Debug + PartialEq + for<'a> Arbitrary<'a>,
>(
    u: &mut Unstructured<'_>,
) -> Result<(), arbitrary::Error> {
    let expected: T = u.arbitrary()?;
    let mut buffer: Vec<u8> = Vec::new();
    expected.encode(&mut buffer);
    let mut buffer = InputBuffer::new(buffer.as_slice());
    let actual = T::decode(&mut buffer).unwrap();
    assert!(buffer.is_empty());
    assert_eq!(expected, actual);
    Ok(())
}

pub(crate) fn encode_decode_symmetry_with_proxy<
    P: for<'a> Arbitrary<'a>,
    T: Encode + Decode + Debug + PartialEq + From<P>,
>(
    u: &mut Unstructured<'_>,
) -> Result<(), arbitrary::Error> {
    let proxy: P = u.arbitrary()?;
    let expected: T = proxy.into();
    let mut buffer: Vec<u8> = Vec::new();
    expected.encode(&mut buffer);
    let mut buffer = InputBuffer::new(buffer.as_slice());
    let actual = T::decode(&mut buffer).unwrap();
    assert!(buffer.is_empty());
    assert_eq!(expected, actual);
    Ok(())
}

#[derive(arbitrary::Arbitrary)]
pub(crate) struct PublicKeyProxy(pub(crate) [u8; PUBLIC_KEY_LEN]);

impl From<PublicKeyProxy> for PublicKey {
    fn from(other: PublicKeyProxy) -> Self {
        other.0.into()
    }
}

pub(crate) fn encode_decode_symmetry_with_context<T>()
where
    T: for<'b> EncodeWithContext<Context<'b>>
        + for<'c, 'c2> DecodeWithContext<&'c2 mut Context<'c>>
        + Debug
        + PartialEq
        + for<'a> Arbitrary<'a>,
{
    arbtest(|u| {
        let expected: T = u.arbitrary()?;
        let mut buffer: Vec<u8> = Vec::new();
        let static_public: PublicKeyProxy = u.arbitrary()?;
        let static_public: PublicKey = static_public.into();
        let cookie: Option<Cookie> = u.arbitrary()?;
        let context = Context {
            static_public: &static_public,
            cookie: cookie.as_ref(),
            under_load: false,
            mac2_is_valid: None,
        };
        expected.encode_with_context(&mut buffer, context);
        let mut context = Context {
            static_public: &static_public,
            cookie: cookie.as_ref(),
            under_load: false,
            mac2_is_valid: None,
        };
        let mut buffer = InputBuffer::new(buffer.as_slice());
        let actual = T::decode_with_context(&mut buffer, &mut context).unwrap();
        assert!(buffer.is_empty());
        assert_eq!(expected, actual);
        Ok(())
    });
}
