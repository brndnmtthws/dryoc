use std::convert::From;

#[derive(Debug)]
pub struct Error {
    pub message: String,
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Error { message }
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Error {
            message: message.into(),
        }
    }
}

macro_rules! dryoc_error {
    ($msg:expr) => {{
        Error::from(format!("{}, from {}:{}", $msg, file!(), line!()))
    }};
}
