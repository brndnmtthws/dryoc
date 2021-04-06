use std::convert::From;

#[derive(Debug)]
pub enum Error {
    Message(String),
    Io(std::io::Error),
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Error::Message(message)
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Error::Message(message.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

macro_rules! dryoc_error {
    ($msg:expr) => {{ crate::error::Error::from(format!("{}, from {}:{}", $msg, file!(), line!())) }};
}
