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
