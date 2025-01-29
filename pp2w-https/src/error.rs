//! crate-wide error type implementing [`Format`].

use defmt::{Debug2Format, Format, Formatter, write};
use embassy_executor::SpawnError;
use embassy_time::TimeoutError;

/// crate-wide error type implementing [`Format`].
pub enum Error {
    Spawn(SpawnError),
    Cyw43(cyw43::ControlError),
    Timeout(TimeoutError),
    Http(reqwless::Error),
    AdHoc(defmt::Str),
}

impl Format for Error {
    fn format(&self, fmt: Formatter) {
        match self {
            Self::Spawn(err) => write!(fmt, "failed to spawn task: {}", err),
            Self::Cyw43(err) => {
                write!(fmt, "cyw43 error: {}", Debug2Format(&err))
            }
            Self::Timeout(_) => write!(fmt, "operation timed out!"),
            Self::Http(err) => write!(fmt, "HTTP error: {}", err),
            Self::AdHoc(err) => write!(fmt, "ad-hoc error: {=istr}", err),
        }
    }
}

impl From<SpawnError> for Error {
    fn from(err: SpawnError) -> Self {
        Self::Spawn(err)
    }
}

impl From<cyw43::ControlError> for Error {
    fn from(err: cyw43::ControlError) -> Self {
        Self::Cyw43(err)
    }
}

impl From<TimeoutError> for Error {
    fn from(err: TimeoutError) -> Self {
        Self::Timeout(err)
    }
}

impl From<reqwless::Error> for Error {
    fn from(err: reqwless::Error) -> Self {
        Self::Http(err)
    }
}

impl From<defmt::Str> for Error {
    fn from(err: defmt::Str) -> Self {
        Self::AdHoc(err)
    }
}
