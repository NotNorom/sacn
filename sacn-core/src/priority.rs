//! This module contains all things `Priority` according to ANSI E1.31-2018, Section 6.2.3.

use core::fmt::Display;

/// Priority value
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Priority(u8);

impl Display for Priority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<u8> for Priority {
    type Error = PriorityError;

    fn try_from(raw_priority: u8) -> Result<Self, Self::Error> {
        Self::in_range(raw_priority).map(|()| Self(raw_priority))
    }
}

impl From<Priority> for u8 {
    fn from(priority: Priority) -> Self {
        priority.0
    }
}

impl Default for Priority {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Priority {
    /// Minimum priority
    pub const MIN_RAW: u8 = 0;
    /// See [Self::MIN_RAW]
    pub const MIN: Self = Self(Self::MIN_RAW);

    /// The default priority used for the E1.31 packet priority field, as per ANSI E1.31-2018 Section 4.1 Table 4-1
    pub const DEFAULT_RAW: u8 = 100;
    /// See [Self::DEFAULT_RAW]
    pub const DEFAULT: Self = Self(Self::DEFAULT_RAW);

    /// The maximum allowed priority for a E1.31 packet, as per ANSI E1.31-2018 Section 6.2.3
    pub const MAX_RAW: u8 = 200;
    /// See [Self::MAX_RAW]
    pub const MAX: Self = Self(Self::MAX_RAW);

    /// Checks if the given priority is in a valid range
    ///
    /// # Errors
    /// InvalidValue: Returned if the priority is outside the allowed range.
    pub const fn in_range(raw_priority: u8) -> Result<(), PriorityError> {
        if raw_priority <= Self::MAX_RAW {
            return Ok(());
        }

        Err(PriorityError::InvalidValue(raw_priority))
    }

    /// Creates a new `Priority`
    pub const fn new(raw_priority: u8) -> Result<Self, PriorityError> {
        match Self::in_range(raw_priority) {
            Ok(()) => Ok(Self(raw_priority)),
            Err(_) => Err(PriorityError::InvalidValue(raw_priority)),
        }
    }

    /// Creates a new `Priority`
    ///
    /// # Safety
    /// Only safe, if the provided value is in the range according to [`Self::in_range`]
    pub const unsafe fn unchecked_new(raw_priority: u8) -> Self {
        Self(raw_priority)
    }

    /// Get the underlying value
    pub const fn get(&self) -> u8 {
        self.0
    }
}

/// Error for creation of [Priority]
#[derive(Debug, thiserror::Error)]
pub enum PriorityError {
    /// Attempted to use invalid value for Priority. Allowed values are:
    /// - Range from 0 to [`Priority::MAX`] inclusive
    ///
    /// # Arguments
    /// 0: Value of invalid Priority
    #[error("Invalid priority used. Must be in the range [0 - {}], Priority: {}", Priority::MAX_RAW, .0)]
    InvalidValue(u8),
}
