#![warn(missing_docs)]
//! This module contains all things `SourceName`

use core::{
    fmt::{self, Display},
    str::FromStr,
};

use heapless::{String, Vec};

/// The name of a source
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceName {
    inner: String<{ Self::CAPACITY }>,
}

impl Display for SourceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl core::ops::Deref for SourceName {
    type Target = String<{ Self::CAPACITY }>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl SourceName {
    /// The length of the Source Name field in bytes in an ANSI E1.31-2018 packet as per ANSI E1.31-2018 Section 4, Table 4-1, 4-2, 4-3.
    pub const CAPACITY: usize = 64;

    /// Creates a new [SourceName]
    pub fn new<S: AsRef<str>>(s: S) -> Result<Self, SourceNameError> {
        let value = s.as_ref();

        let inner = String::from_str(value).map_err(|_| SourceNameError::SourceNameTooLong(value.len()))?;
        Ok(Self { inner })
    }

    /// Returns the wrapped heapless [String] as a reference
    pub const fn inner(&self) -> &String<{ Self::CAPACITY }> {
        &self.inner
    }

    /// Returns the wrapped heapless [String] as a mutable reference
    pub fn inner_mut(&mut self) -> &mut String<{ Self::CAPACITY }> {
        &mut self.inner
    }

    /// Returns a [str] reference
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Returns the length of the source name
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns the bytes this source name is made out of
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl FromStr for SourceName {
    type Err = SourceNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&[u8]> for SourceName {
    type Error = SourceNameError;

    /// Takes the given byte buffer (e.g. a c char array) and parses it into a rust &str.
    ///
    /// # Arguments
    /// buf: The byte buffer to parse into a str.
    ///
    /// # Errors
    /// MissingNullTermination: Returned if the source name is not null terminated as required by ANSI E1.31-2018 Section 6.2.2
    /// SourceNameTooLong: Returned if the source name is too long
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let first_null_pos = value.iter().position(|&b| b == 0).ok_or(SourceNameError::MissingNullTermination)?;

        let as_vec = Vec::from_slice(&value[..first_null_pos]).map_err(|_| SourceNameError::SourceNameTooLong(value.len()))?;
        let inner = String::from_utf8(as_vec)?;

        Ok(Self { inner })
    }
}

impl TryFrom<&str> for SourceName {
    type Error = SourceNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

/// For any source specific errors
#[derive(Debug, thiserror::Error)]
pub enum SourceNameError {
    /// A source name that's too long was encountered.
    /// Maximum length should be [`SourceName::CAPACITY`]
    ///
    /// # Arguments
    /// Length of too long source name
    #[error("Given source name is too long. Maximum is {} but current name is: {}", SourceName::CAPACITY, .0)]
    SourceNameTooLong(usize),

    /// A source name is invalid utf8
    #[error("Given source name is invalid utf-8 error: {0:?}")]
    Utf8(#[from] core::str::Utf8Error),

    /// Given source name is not not null terminated
    #[error("Given source name is not not null terminated")]
    MissingNullTermination,
}
