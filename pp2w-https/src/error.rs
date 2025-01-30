//! error types.

use defmt::{Format, Formatter, expect, write};
use embassy_executor::SpawnError;
use embassy_rp::adc;
use embassy_time::TimeoutError;
use heapless::Vec;

/// [`Error`], but with a stacktrace.
pub struct Report {
    pub error: Error,
    pub trace: Vec<Location, 32>,
    pub more: bool,
}

/// crate-wide error type implementing [`Format`].
pub enum Error {
    Spawn(SpawnError),
    Cyw43(cyw43::ControlError),
    Timeout(TimeoutError),
    Adc(adc::Error),
    Http(reqwless::Error),
    AdHoc(defmt::Str),
}

/// a location in code.
pub struct Location {
    pub file: &'static str,
    pub line: u32,
    pub col: u32,
}

/// convenient macro to construct a [`Location`].
#[macro_export]
macro_rules! loc {
    () => {
        $crate::error::Location {
            file: ::core::file!(),
            line: ::core::line!(),
            col: ::core::column!(),
        }
    };
}

/// [`ResultExt::report`], but you don't have to call [`loc!`].
#[macro_export]
macro_rules! report {
    ($res:expr) => {
        $crate::error::ResultExt::report($res, $crate::loc!())
    };
}

/// trait for converting into [`Result<T, Report>`]
pub trait ResultExt {
    type Into;

    fn report(self, loc: Location) -> Self::Into;
}

impl Format for Error {
    fn format(&self, fmt: Formatter) {
        match self {
            Self::Spawn(err) => write!(fmt, "failed to spawn task: {}", err),
            Self::Cyw43(err) => write!(fmt, "cyw43 error: code {}", err.status),
            Self::Timeout(_) => write!(fmt, "operation timed out!"),
            Self::Adc(err) => write!(fmt, "ADC error: {}", err),
            Self::Http(err) => write!(fmt, "HTTP error: {}", err),
            Self::AdHoc(err) => write!(fmt, "ad-hoc error: {=istr}", err),
        }
    }
}

impl<T, E> ResultExt for Result<T, E>
where
    E: Into<Error>,
{
    type Into = Result<T, Report>;

    fn report(self, loc: Location) -> Self::Into {
        match self {
            Ok(val) => Ok(val),
            Err(err) => {
                let mut trace = Vec::new();
                expect!(
                    trace.push(loc),
                    "Result<T, Error> -> Result<T, Report> should never fail"
                );
                Err(Report {
                    error: err.into(),
                    trace,
                    more: false,
                })
            }
        }
    }
}

impl<T> ResultExt for Result<T, Report> {
    type Into = Self;

    fn report(self, loc: Location) -> Self::Into {
        match self {
            Ok(val) => Ok(val),
            Err(mut rep) => {
                if rep.trace.push(loc).is_err() {
                    rep.more = true;
                }

                Err(rep)
            }
        }
    }
}

impl Format for Location {
    fn format(&self, fmt: Formatter) {
        write!(fmt, "{=str}:{=u32}:{=u32}", self.file, self.line, self.col);
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

impl From<adc::Error> for Error {
    fn from(err: adc::Error) -> Self {
        Self::Adc(err)
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
