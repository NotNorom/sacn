//! This module contains all things `Universe` according to ANSI E1.31-2018, Section 3.3.
//!
//! A more accurate name would be `Universe Name`, but I decided against it because of brevity.

use core::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    ptr::slice_from_raw_parts,
    write,
};

use socket2::SockAddr;

use crate::e131_definitions::ACN_SDT_MULTICAST_PORT;

/// Universe identifier
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UniverseId(NonZeroU16);

impl Display for UniverseId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<u16> for UniverseId {
    type Error = UniverseError;

    fn try_from(raw_universe: u16) -> Result<Self, Self::Error> {
        Self::in_range(raw_universe).map(|()| Self(unsafe { NonZeroU16::new_unchecked(raw_universe) }))
    }
}

impl From<UniverseId> for u16 {
    fn from(universe: UniverseId) -> Self {
        universe.0.get()
    }
}

impl Default for UniverseId {
    fn default() -> Self {
        Self(NonZeroU16::MIN)
    }
}

impl PartialEq<u16> for UniverseId {
    fn eq(&self, other: &u16) -> bool {
        self.0.get().eq(other)
    }
}

impl PartialEq<Option<u16>> for UniverseId {
    fn eq(&self, other: &Option<u16>) -> bool {
        self.0.get().eq(&other.unwrap_or_default())
    }
}

impl UniverseId {
    /// Special case value used for universe discovery as defined in ANSI E1.31-2018 Appendix A: Defined Parameters (Normative)
    pub const DISCOVERY_RAW: u16 = 64214;
    /// See [Self::DISCOVERY_RAW]
    ///
    /// # Safety:
    /// Value is non-zero
    pub const DISCOVERY: Self = Self(unsafe { NonZeroU16::new_unchecked(Self::DISCOVERY_RAW) });

    /// The lowest / minimum universe number that can be used with the E1.31 protocol as specified in section 9.1.1 of ANSI E1.31-2018.
    pub const MIN_RAW: u16 = 1;
    /// See [Self::MIN_RAW]
    ///
    /// # Safety:
    /// Value is non-zero
    pub const MIN: Self = Self(unsafe { NonZeroU16::new_unchecked(Self::MIN_RAW) });

    /// The maximum universe number that can be used with the E1.31 protocol as specified in section 9.1.1 of ANSI E1.31-2018.
    pub const MAX_RAW: u16 = 63999;
    /// See [Self::MAX_RAW]
    ///
    /// # Safety:
    /// Value is non-zero
    pub const MAX: Self = Self(unsafe { NonZeroU16::new_unchecked(Self::MAX_RAW) });

    /// Special case for a sync address of 0
    pub const E131_NO_SYNC_ADDR: Option<Self> = None;

    /// Checks if the given universe is a valid universe to send on (within allowed range).
    ///
    /// # Errors
    /// InvalidValue: Returned if the universe is outside the allowed range of universes.
    pub const fn in_range(raw_universe: u16) -> Result<(), UniverseError> {
        if Self::MIN_RAW <= raw_universe && raw_universe <= Self::MAX_RAW {
            return Ok(());
        }

        if raw_universe == Self::DISCOVERY_RAW {
            return Ok(());
        }

        Err(UniverseError::InvalidValue(raw_universe))
    }

    /// Converts the given ANSI E1.31-2018 universe into an Ipv4 multicast address with the port set to the acn multicast port as defined
    /// in packet::ACN_SDT_MULTICAST_PORT.
    ///
    /// Conversion done as specified in section 9.3.1 of ANSI E1.31-2018
    ///
    /// Returns the multicast address.
    pub fn to_ipv4_multicast_addr(&self) -> SockAddr {
        let high_byte: u8 = ((self.0.get() >> 8) & 0xff) as u8;
        let low_byte: u8 = (self.0.get() & 0xff) as u8;

        // As per ANSI E1.31-2018 Section 9.3.1 Table 9-10.
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, high_byte, low_byte)), ACN_SDT_MULTICAST_PORT).into()
    }

    /// Converts the given ANSI E1.31-2018 universe into an Ipv6 multicast address with the port set to the acn multicast port as defined
    /// in packet::ACN_SDT_MULTICAST_PORT.
    ///
    /// Conversion done as specified in section 9.3.2 of ANSI E1.31-2018
    ///
    /// Returns the multicast address.
    pub fn to_ipv6_multicast_addr(&self) -> SockAddr {
        // As per ANSI E1.31-2018 Section 9.3.2 Table 9-12.
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xFF18, 0, 0, 0, 0, 0, 0x8300, self.0.get())),
            ACN_SDT_MULTICAST_PORT,
        )
        .into()
    }

    /// Create a new universe
    pub const fn new(raw_universe: u16) -> Result<Self, UniverseError> {
        // safety: Self::in_range already checks if value is non-zero
        match Self::in_range(raw_universe) {
            Ok(()) => Ok(Self(unsafe { NonZeroU16::new_unchecked(raw_universe) })),
            Err(_) => Err(UniverseError::InvalidValue(raw_universe)),
        }
    }

    /// Create a new universe from bytes in big endian order
    pub const fn from_be_bytes(bytes: [u8; 2]) -> Result<Self, UniverseError> {
        Self::new(u16::from_be_bytes(bytes))
    }

    /// Create a new universe from bytes in little endian order
    pub const fn from_le_bytes(bytes: [u8; 2]) -> Result<Self, UniverseError> {
        Self::new(u16::from_le_bytes(bytes))
    }

    /// Creates a new Universe
    ///
    /// # Safety
    /// Only safe, if the provided value is in the range according to [`Self::in_range`]
    pub const unsafe fn unchecked_new(raw_universe: u16) -> Self {
        Self(unsafe { NonZeroU16::new_unchecked(raw_universe) })
    }

    /// Get the inner value
    pub const fn get(&self) -> u16 {
        self.0.get()
    }
}

/// Represents a slice of Universes
///
/// This type is an attempt at making it easier to convert between `&[u16]` and `&[Universe]`.
#[derive(Debug)]
#[repr(transparent)]
struct UniverseSlice<'a>(&'a [UniverseId]);

impl<'a> core::ops::Deref for UniverseSlice<'a> {
    type Target = &'a [UniverseId];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> From<UniverseSlice<'a>> for &'a [u16] {
    fn from(value: UniverseSlice) -> Self {
        unsafe { &*slice_from_raw_parts(value.0.as_ptr().cast::<u16>(), value.0.len()) }
    }
}

impl<'a> TryFrom<&'a [u16]> for UniverseSlice<'a> {
    type Error = UniverseError;
    fn try_from(value: &'a [u16]) -> Result<Self, Self::Error> {
        for uni in value {
            UniverseId::in_range(*uni)?;
        }

        let result = unsafe { slice_to_universes_unchecked(value) };
        Ok(UniverseSlice(result))
    }
}

/// Converts a slice of u16 to a slice of Universe
///
/// Returns an error if at least one of the values is invalid.
pub const fn slice_to_universes(raw: &[u16]) -> Result<&[UniverseId], UniverseError> {
    // using an ugly while- instead of for loop because we're in a const function
    let mut idx = 0;
    while idx < raw.len() {
        if let Err(e) = UniverseId::in_range(raw[idx]) {
            return Err(e);
        }
        idx += 1;
    }

    let result = unsafe { slice_to_universes_unchecked(raw) };
    Ok(result)
}

/// Converts a slice of u16 to a slice of Universe without checking for correctness
///
/// # Safety
/// All values must be in the valid range of a universe. See [Universe::in_range]
pub const unsafe fn slice_to_universes_unchecked(raw: &[u16]) -> &[UniverseId] {
    unsafe { &*slice_from_raw_parts(raw.as_ptr().cast::<UniverseId>(), raw.len()) }
}

/// Error for creation of [Universe]
#[derive(Debug, thiserror::Error)]
pub enum UniverseError {
    /// Attempted to use invalid value for universe. Allowed values are:
    /// - Range from [`Universe::MIN`] to [`Universe::MAX`] inclusive
    /// - [`Universe::DISCOVERY``]
    ///
    /// # Arguments
    /// 0: Value of invalid universe
    #[error("Invalid universe used. Must be in the range [{} - {}], universe: {}", UniverseId::MIN_RAW, UniverseId::MAX_RAW, .0)]
    InvalidValue(u16),
}
