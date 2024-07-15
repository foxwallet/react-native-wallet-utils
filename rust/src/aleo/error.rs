use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum AleoError {
    InvalidData,
}

impl fmt::Display for AleoError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      write!(f, "{:?}", self)
  }
}

impl Error for AleoError {}




