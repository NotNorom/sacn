//! This module contains all things `Universe` according to ANSI E1.31-2018, Section 3.3.
//!
//! A more accurate name would be `Universe Name`, but I decided against it because of brevity.

use core::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    ops::{Div, Rem},
    ptr::slice_from_raw_parts,
    write,
};

use socket2::SockAddr;

use crate::e131_definitions::ACN_SDT_MULTICAST_PORT;

/// Universe value
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
        Self::in_range(raw_universe).map(|_| Self(unsafe { NonZeroU16::new_unchecked(raw_universe) }))
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
            Ok(_) => Ok(Self(unsafe { NonZeroU16::new_unchecked(raw_universe) })),
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
        unsafe { &*slice_from_raw_parts(value.0.as_ptr() as *const u16, value.0.len()) }
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
    unsafe { &*slice_from_raw_parts(raw.as_ptr() as *const UniverseId, raw.len()) }
}

/// Container for keeping track of universes in a compact way
///
/// This should be used instead of a vec/slice of u16/Universe as it saves on memory.
/// There are 64_000 possible universes (if we count the discovery universe), summing up to
/// 64_000 * 16bit = 64_000 * 2Byte = 128_000 Byte if they were stored as u16.
///
/// Instead this container uses bitflags. So we no have 64_000 bits = 1_000 byte.
/// Each bit represents a universe being marked for something.
///
/// The discovery universe is mapped to bit 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactUniverseList {
    inner: [u64; Self::CAPACITY as usize],
}

impl CompactUniverseList {
    /// Capacity of universes.
    /// 63999 possible universes + the discovery universe are 64_000 bits.
    /// So 64_000 / 64bit = 1_000
    pub const CAPACITY: u16 = 1_000;

    /// Creates a new list with no marked universes
    pub fn new() -> Self {
        Self {
            inner: [0; Self::CAPACITY as usize],
        }
    }

    /// Unmarks all universes
    pub fn clear(&mut self) {
        self.unmark_all();
    }

    /// Mark a single universe
    pub fn mark(&mut self, universe: UniverseId) {
        let (idx, mask) = Self::universe_to_idx_and_mask(universe);
        self.inner[idx as usize] |= mask;
    }

    /// Mark all universes in slice
    pub fn mark_slice(&mut self, universes: &[UniverseId]) {
        for u in universes {
            self.mark(*u);
        }
    }

    /// Marks all universe
    pub fn mark_all(&mut self) {
        self.inner.fill(u64::MAX);
    }

    /// Mark single universe
    pub fn unmark(&mut self, universe: UniverseId) {
        let (idx, mask) = Self::universe_to_idx_and_mask(universe);
        self.inner[idx as usize] &= !mask;
    }

    /// Unmark all universes in slice
    pub fn unmark_slice(&mut self, universes: &[UniverseId]) {
        for u in universes {
            self.unmark(*u);
        }
    }

    /// Unmarks all universe
    pub fn unmark_all(&mut self) {
        self.inner.fill(0);
    }

    /// Check if a universe is marked. Return true if it is
    pub fn is_marked(&self, universe: UniverseId) -> bool {
        let (idx, mask) = Self::universe_to_idx_and_mask(universe);
        self.inner[idx as usize] & mask != 0
    }

    /// Number of marked universes
    pub fn marked_count(&self) -> usize {
        let mut result = 0;
        for entry in self.inner {
            result += entry.count_ones() as usize
        }
        result
    }

    /// Number of unmarked universes
    pub fn unmarked_count(&self) -> usize {
        let mut result = 0;
        for entry in self.inner {
            result += entry.count_zeros() as usize
        }
        result
    }

    /// Calculates the bit position of a given universe
    /// Returns:
    /// (byte index, mask)
    fn universe_to_idx_and_mask(universe: UniverseId) -> (u16, u64) {
        let universe = match universe.get() {
            UniverseId::DISCOVERY_RAW => 0,
            u => u,
        };

        let byte_idx = universe.div(64);
        let bit_idx = universe.rem(64) as u8;
        let mask = 0b_1 << bit_idx;

        (byte_idx, mask)
    }

    /// Creates an iterator over marked universes
    pub fn iter(&self) -> CompactUniverseListIter<'_> {
        self.into_iter()
    }
}

impl Default for CompactUniverseList {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for CompactUniverseList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "ActiveUniverses. Empty slots are not printed. 0 = Discovery.")?;
        writeln!(f, "indecies  (amount): values")?;
        for (idx, entry) in self.inner.iter().enumerate() {
            if *entry != 0 {
                writeln!(
                    f,
                    "{:06}-{:06} ({:02}): {:064b}",
                    idx * 64,
                    idx * 64 + 63,
                    entry.count_ones(),
                    entry
                )?
            }
        }

        Ok(())
    }
}

impl<'a> IntoIterator for &'a CompactUniverseList {
    type Item = UniverseId;
    type IntoIter = CompactUniverseListIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            universes: &self.inner,
            byte_idx: 0,
            value: self.inner[0],
        }
    }
}

/// Note: If the discovery universe is marked, it will be the first entry to be returned.
/// This is because internally it is mapped to bit 0.
/// This is done because it saves on 4 bytes.
#[derive(Debug)]
pub struct CompactUniverseListIter<'a> {
    universes: &'a [u64; CompactUniverseList::CAPACITY as usize],
    byte_idx: u16,
    value: u64,
}

impl Iterator for CompactUniverseListIter<'_> {
    type Item = UniverseId;

    /// check if byte_index is or will be out of range, if true:
    ///   return None,
    ///
    /// check if current value is 0. then:
    ///   increase byte_index by 1,
    ///   update current value
    ///   go to start
    /// else:
    ///   find index of lowest 1-bit in current value
    ///   erase lowest 1-bit from current value
    ///   return index
    fn next(&mut self) -> Option<Self::Item> {
        // find non-0 entry
        while self.value == 0 {
            if self.byte_idx >= CompactUniverseList::CAPACITY - 1 {
                return None;
            }
            self.byte_idx += 1;
            self.value = self.universes[self.byte_idx as usize];
        }

        // find index
        let idx = self.value.trailing_zeros() as u16;
        // erase 1-bit
        self.value ^= 1 << idx;

        let universe = self.byte_idx * 64 + idx;
        let universe = match universe {
            0 => UniverseId::DISCOVERY,
            u => unsafe { UniverseId::unchecked_new(u) },
        };

        Some(universe)
    }
}

#[cfg(test)]
mod test_universe_types {
    use super::*;

    #[test]
    fn test_compact_universe_storage() {
        let mut active_universes = CompactUniverseList::new();
        assert_eq!(active_universes.marked_count(), 0);
        assert_eq!(active_universes.unmarked_count(), 64_000);

        active_universes.mark(UniverseId::MIN);
        assert_eq!(active_universes.marked_count(), 1);
        assert_eq!(active_universes.unmarked_count(), 63_999);
        assert!(active_universes.is_marked(UniverseId::MIN));

        active_universes.mark(UniverseId::new(63).unwrap());
        assert_eq!(active_universes.marked_count(), 2);
        assert_eq!(active_universes.unmarked_count(), 63_998);
        assert!(active_universes.is_marked(UniverseId::new(63).unwrap()));

        active_universes.mark(UniverseId::new(64).unwrap());
        assert_eq!(active_universes.marked_count(), 3);
        assert_eq!(active_universes.unmarked_count(), 63_997);
        assert!(active_universes.is_marked(UniverseId::new(64).unwrap()));

        active_universes.mark(UniverseId::new(65).unwrap());
        assert_eq!(active_universes.marked_count(), 4);
        assert_eq!(active_universes.unmarked_count(), 63_996);
        assert!(active_universes.is_marked(UniverseId::new(65).unwrap()));

        active_universes.mark(UniverseId::MAX);
        assert_eq!(active_universes.marked_count(), 5);
        assert_eq!(active_universes.unmarked_count(), 63_995);
        assert!(active_universes.is_marked(UniverseId::MAX));

        active_universes.mark(UniverseId::DISCOVERY);
        assert_eq!(active_universes.marked_count(), 6);
        assert_eq!(active_universes.unmarked_count(), 63_994);
        assert!(active_universes.is_marked(UniverseId::DISCOVERY));

        active_universes.unmark_slice(&[UniverseId::MIN, UniverseId::MAX]);
        assert_eq!(active_universes.marked_count(), 4);
        assert_eq!(active_universes.unmarked_count(), 63_996);

        assert!(active_universes.is_marked(UniverseId::new(63).unwrap()));
        assert!(active_universes.is_marked(UniverseId::new(64).unwrap()));
        assert!(active_universes.is_marked(UniverseId::new(65).unwrap()));
        assert!(active_universes.is_marked(UniverseId::DISCOVERY));

        assert!(!active_universes.is_marked(UniverseId::MIN));
        assert!(!active_universes.is_marked(UniverseId::MAX));

        active_universes.clear();
        assert_eq!(active_universes.marked_count(), 0);
        assert_eq!(active_universes.unmarked_count(), 64_000);
    }

    #[test]
    fn test_compact_universe_storage_iter() {
        let mut list = CompactUniverseList::new();
        list.mark(UniverseId::new(1).unwrap());
        list.mark(UniverseId::new(2).unwrap());
        list.mark(UniverseId::new(3).unwrap());

        let mut iter = list.iter();
        assert_eq!(iter.next(), Some(UniverseId::new(1).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(2).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(3).unwrap()));
        assert_eq!(iter.next(), None);

        list.mark(UniverseId::new(63).unwrap());
        list.mark(UniverseId::new(64).unwrap());
        list.mark(UniverseId::new(65).unwrap());

        list.mark(UniverseId::new(127).unwrap());
        list.mark(UniverseId::new(128).unwrap());
        list.mark(UniverseId::new(129).unwrap());

        let mut iter = list.iter();
        assert_eq!(iter.next(), Some(UniverseId::new(1).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(2).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(3).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(63).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(64).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(65).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(127).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(128).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(129).unwrap()));
        assert_eq!(iter.next(), None);

        list.mark(UniverseId::MAX);
        list.mark(UniverseId::DISCOVERY);

        let mut iter = list.iter();
        assert_eq!(iter.next(), Some(UniverseId::DISCOVERY));
        assert_eq!(iter.next(), Some(UniverseId::new(1).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(2).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(3).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(63).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(64).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(65).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(127).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(128).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::new(129).unwrap()));
        assert_eq!(iter.next(), Some(UniverseId::MAX));
        assert_eq!(iter.next(), None);
    }
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
