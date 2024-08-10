use std::fmt::Debug;
use std::fmt::Display;

pub enum Error {
    Proto,
    Other(String),
}

impl Error {
    pub(crate) fn map<T>(_: T) -> Error {
        Error::Proto
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Proto => write!(f, "protocol error"),
            Self::Other(x) => write!(f, "{}", x),
        }
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl std::error::Error for Error {}
