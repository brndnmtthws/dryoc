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

macro_rules! validate {
    ($min:expr, $max:expr, $value:expr, $name:literal) => {
        if $value < $min {
            return Err(dryoc_error!(format!(
                "{} value of {} less than minimum {}",
                $name, $value, $min
            )));
        } else if $value > $max {
            return Err(dryoc_error!(format!(
                "{} value of {} greater than minimum {}",
                $name, $value, $max
            )));
        }
    };
}
