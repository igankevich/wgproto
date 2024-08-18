use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

pub struct Error;

impl Error {
    pub(crate) fn map<T>(_: T) -> Error {
        Error
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "wgproto error")
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(_other: Error) -> Self {
        Self::new(std::io::ErrorKind::Other, "wgproto error")
    }
}

impl From<std::io::Error> for Error {
    fn from(_other: std::io::Error) -> Self {
        Self
    }
}
