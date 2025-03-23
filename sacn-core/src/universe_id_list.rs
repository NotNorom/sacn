use core::{
    fmt::Display,
    ops::{Div, Rem},
};

use crate::universe_id::UniverseId;

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
pub struct UniverseIdList64000 {
    inner: [u64; Self::CAPACITY as usize],
}

impl UniverseIdList64000 {
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
    pub fn iter(&self) -> UniverseList64000Iter<'_> {
        self.into_iter()
    }
}

impl Default for UniverseIdList64000 {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for UniverseIdList64000 {
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

impl<'a> IntoIterator for &'a UniverseIdList64000 {
    type Item = UniverseId;
    type IntoIter = UniverseList64000Iter<'a>;
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
pub struct UniverseList64000Iter<'a> {
    universes: &'a [u64; UniverseIdList64000::CAPACITY as usize],
    byte_idx: u16,
    value: u64,
}

impl Iterator for UniverseList64000Iter<'_> {
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
            if self.byte_idx >= UniverseIdList64000::CAPACITY - 1 {
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
        let mut active_universes = UniverseIdList64000::new();
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
        let mut list = UniverseIdList64000::new();
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
