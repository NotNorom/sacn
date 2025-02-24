use core::str::FromStr;

use heapless::{String, Vec};

use crate::e131_definitions::E131_SOURCE_NAME_FIELD_LENGTH;

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceName {
    inner: String<E131_SOURCE_NAME_FIELD_LENGTH>,
}

impl core::ops::Deref for SourceName {
    type Target = String<E131_SOURCE_NAME_FIELD_LENGTH>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl SourceName {
    pub fn new<S: AsRef<str>>(s: S) -> Result<Self, SourceNameError> {
        let value = s.as_ref();

        let inner = String::from_str(value).map_err(|_| SourceNameError::SourceNameTooLong(value.len()))?;
        Ok(Self { inner })
    }

    pub const fn inner(&self) -> &String<E131_SOURCE_NAME_FIELD_LENGTH> {
        &self.inner
    }

    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    pub fn inner_mut(&mut self) -> &mut String<E131_SOURCE_NAME_FIELD_LENGTH> {
        &mut self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

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
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut source_name_length = value.len();

        for (i, b) in value.iter().enumerate() {
            if *b == 0 {
                source_name_length = i;
                break;
            }
        }

        if source_name_length == value.len() && value[value.len() - 1] != 0 {
            Err(SourceNameError::MissingNullTermination)?;
        }

        let as_vec = Vec::from_slice(value).map_err(|_| SourceNameError::SourceNameTooLong(value.len()))?;
        let inner = String::from_utf8(as_vec)?;

        Ok(Self { inner })
    }
}

/// For any source specific errors
#[derive(Debug, thiserror::Error)]
pub enum SourceNameError {
    /// A source name that's too long was encountered.
    /// Maximum length should be [`E131_SOURCE_NAME_FIELD_LENGTH`]
    ///
    /// # Arguments
    /// Length of too long source name
    #[error("Given source name is too long. Maximum is {} but current name is: {}", E131_SOURCE_NAME_FIELD_LENGTH, .0)]
    SourceNameTooLong(usize),

    /// A source name is invalid utf8
    #[error("Given source name is invalid utf-8 error: {0:?}")]
    Utf8(#[from] core::str::Utf8Error),

    ///
    #[error("Given source name is not not null terminated")]
    MissingNullTermination,
}
