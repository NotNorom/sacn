use core::{fmt::Display, num::NonZeroU16, ptr::slice_from_raw_parts, write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::SockAddr;

use crate::e131_definitions::ACN_SDT_MULTICAST_PORT;

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Universe(NonZeroU16);

impl Display for Universe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<u16> for Universe {
    type Error = UniverseError;

    fn try_from(raw_universe: u16) -> Result<Self, Self::Error> {
        Self::in_range(raw_universe).map(|_| Self(unsafe { NonZeroU16::new_unchecked(raw_universe) }))
    }
}

impl From<Universe> for u16 {
    fn from(universe: Universe) -> Self {
        universe.0.get()
    }
}

impl Default for Universe {
    fn default() -> Self {
        Self(NonZeroU16::MIN)
    }
}

impl PartialEq<u16> for Universe {
    fn eq(&self, other: &u16) -> bool {
        self.0.get().eq(other)
    }
}

impl PartialEq<Option<u16>> for Universe {
    fn eq(&self, other: &Option<u16>) -> bool {
        self.0.get().eq(&other.unwrap_or_default())
    }
}

impl Universe {
    /// The universe used for universe discovery as defined in ANSI E1.31-2018 Appendix A: Defined Parameters (Normative)
    pub const E131_DISCOVERY_UNIVERSE_RAW: u16 = 64214;
    // safety: value is non-zero
    pub const E131_DISCOVERY_UNIVERSE: Self = Self(unsafe { NonZeroU16::new_unchecked(Self::E131_DISCOVERY_UNIVERSE_RAW) });

    /// The lowest / minimum universe number that can be used with the E1.31 protocol as specified in section 9.1.1 of ANSI E1.31-2018.
    pub const E131_MIN_MULTICAST_UNIVERSE_RAW: u16 = 1;
    // safety: value is non-zero
    pub const E131_MIN_MULTICAST_UNIVERSE: Self = Self(unsafe { NonZeroU16::new_unchecked(Self::E131_MIN_MULTICAST_UNIVERSE_RAW) });
    pub const MIN: Self = Self::E131_MIN_MULTICAST_UNIVERSE;
    pub const ONE: Self = Self::E131_MIN_MULTICAST_UNIVERSE;

    /// The maximum universe number that can be used with the E1.31 protocol as specified in section 9.1.1 of ANSI E1.31-2018.
    pub const E131_MAX_MULTICAST_UNIVERSE_RAW: u16 = 63999;
    // safety: value is non-zero
    pub const E131_MAX_MULTICAST_UNIVERSE: Self = Self(unsafe { NonZeroU16::new_unchecked(Self::E131_MAX_MULTICAST_UNIVERSE_RAW) });
    pub const MAX: Self = Self::E131_MAX_MULTICAST_UNIVERSE;

    /// Special case for a sync address of 0
    pub const E131_NO_SYNC_ADDR: Option<Self> = None;

    /// Checks if the given universe is a valid universe to send on (within allowed range).
    ///
    /// # Errors
    /// InvalidValue: Returned if the universe is outside the allowed range of universes.
    pub const fn in_range(raw_universe: u16) -> Result<(), UniverseError> {
        if Self::E131_MIN_MULTICAST_UNIVERSE_RAW <= raw_universe && raw_universe <= Self::E131_MAX_MULTICAST_UNIVERSE_RAW {
            return Ok(());
        }

        if raw_universe == Self::E131_DISCOVERY_UNIVERSE_RAW {
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
            Ok(_) => Ok(Self(unsafe { NonZeroU16::new_unchecked(raw_universe) })),
            Err(_) => Err(UniverseError::InvalidValue(raw_universe)),
        }
    }

    pub const fn from_be_bytes(bytes: [u8; 2]) -> Result<Self, UniverseError> {
        Self::new(u16::from_be_bytes(bytes))
    }

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

#[derive(Debug)]
#[repr(transparent)]
pub struct UniverseSlice<'a>(&'a [Universe]);

impl<'a> std::ops::Deref for UniverseSlice<'a> {
    type Target = &'a [Universe];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<'a> From<UniverseSlice<'a>> for &'a [u16] {
    fn from(value: UniverseSlice) -> Self {
        unsafe { &*slice_from_raw_parts(value.0.as_ptr() as *const u16, value.0.len()) }
    }
}

impl<'a> TryFrom<&'a [u16]> for UniverseSlice<'a> {
    type Error = UniverseError;
    fn try_from(value: &'a [u16]) -> Result<Self, Self::Error> {
        for uni in value {
            Universe::in_range(*uni)?;
        }

        let result = unsafe { slice_to_universes_unchecked(value) };
        Ok(UniverseSlice(result))
    }
}

pub const fn slice_to_universes(raw: &[u16]) -> Result<&[Universe], UniverseError> {
    // using an ugly while- instead of for loop because we're in a const function
    let mut idx = 0;
    while idx < raw.len() {
        if let Err(e) = Universe::in_range(raw[idx]) {
            return Err(e);
        }
        idx += 1;
    }

    let result = unsafe { slice_to_universes_unchecked(raw) };
    Ok(result)
}

pub const unsafe fn slice_to_universes_unchecked(raw: &[u16]) -> &[Universe] {
    unsafe { &*slice_from_raw_parts(raw.as_ptr() as *const Universe, raw.len()) }
}

#[derive(Debug, thiserror::Error)]
pub enum UniverseError {
    /// Attempted to use invalid value for universe. Allowed values are:
    /// - Range from [`Universe::E131_MIN_MULTICAST_UNIVERSE`] to [`Universe::E131_MAX_MULTICAST_UNIVERSE`] inclusive
    /// - [`Universe::E131_DISCOVERY_UNIVERSE`]
    ///
    /// # Arguments
    /// 0: Value of invalid universe
    #[error("Invalid universe used. Must be in the range [{} - {}], universe: {}", Universe::E131_MIN_MULTICAST_UNIVERSE_RAW, Universe::E131_MAX_MULTICAST_UNIVERSE_RAW, .0)]
    InvalidValue(u16),
}
