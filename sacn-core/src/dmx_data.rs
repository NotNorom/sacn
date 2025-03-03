#![warn(missing_docs)]
//! This module contains types that deal with the actual dmx data
//!
//! DMX data is not juste the 512 data values, but also:
//! - which universe it was sent on
//! - a potential sync universe
//! - the priority
//! - a potential source cid
//! - is it preview data?
//! - when was it received

use core::cmp::Ordering;

use heapless::Vec;
use uuid::Uuid;

use crate::{e131_definitions::UNIVERSE_CHANNEL_CAPACITY, priority::Priority, timestamp::Timestamp, universe::Universe};

/// Holds a universes worth of DMX data.
#[derive(Debug)]
pub struct DMXData {
    /// The universe that the data was sent to.
    pub universe: Universe,

    /// The actual universe data, if less than 512 values in length then implies trailing 0's to pad to a full-universe of data.
    pub values: Vec<u8, UNIVERSE_CHANNEL_CAPACITY>,

    /// The universe the data is (or was if now acted upon) waiting for a synchronisation packet from.
    /// 0 indicates it isn't waiting for a universe synchronisation packet.
    pub sync_uni: Option<Universe>,

    /// The priority of the data, this may be useful for receivers which want to implement their own implementing merge algorithms.
    /// Must be less than packet::E131_MAX_PRIORITY.
    pub priority: Priority,

    /// The unique id of the source of the data, this may be useful for receivers which want to implement their own merge algorithms
    /// which use the identity of the source to decide behaviour.
    /// A value of None indicates that there is no clear source, for example if a merge algorithm has merged data from 2 or more sources together.
    pub src_cid: Option<Uuid>,

    /// Indicates if the data is marked as 'preview' data indicating it is for use by visualisers etc. as per ANSI E1.31-2018 Section 6.2.6.
    pub preview: bool,

    /// The timestamp that the data was received.
    pub recv_timestamp: Timestamp,
}

impl DMXData {
    /// Create new DMXData with parameters
    pub fn new(
        universe: Universe,
        values: Vec<u8, UNIVERSE_CHANNEL_CAPACITY>,
        sync_uni: Option<Universe>,
        priority: Priority,
        src_cid: Option<Uuid>,
        preview: bool,
        recv_timestamp: Timestamp,
    ) -> Self {
        Self {
            universe,
            values,
            sync_uni,
            priority,
            src_cid,
            preview,
            recv_timestamp,
        }
    }
}

impl Clone for DMXData {
    fn clone(&self) -> DMXData {
        DMXData {
            universe: self.universe,
            values: self.values.clone(),
            sync_uni: self.sync_uni,
            priority: self.priority,
            src_cid: self.src_cid,
            preview: self.preview,
            recv_timestamp: self.recv_timestamp,
        }
    }
}

/// DMXData has a total ordering based on the universe, then sync-universe and finally values.
impl Ord for DMXData {
    fn cmp(&self, other: &Self) -> Ordering {
        self.universe
            .cmp(&other.universe)
            .then(self.sync_uni.cmp(&other.sync_uni))
            .then(self.values.cmp(&other.values))
    }
}

/// See [Ord] trait implementation for DMXData.
impl PartialOrd for DMXData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// [DMXData] is taken to be equivalent iff:
///     - The universes are the same
///     - The synchronisation universes are the same
///     - The values are all the same
impl PartialEq for DMXData {
    fn eq(&self, other: &Self) -> bool {
        self.universe == other.universe && self.sync_uni == other.sync_uni && self.values == other.values
    }
}

/// See [PartialEq] trait implementation for DMXData.
impl Eq for DMXData {}

/// A fixed size continer for dmx values
///
/// Has storage for exactly 512 u8's.
pub struct DMXValues {
    inner: Vec<u8, { Self::CAPACITY }>,
}

impl core::ops::Deref for DMXValues {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DMXValues {
    /// The maximum amount of values
    pub const CAPACITY: usize = 512;

    /// Create a new container with uninitialized values
    pub const fn new_empty() -> Self {
        Self { inner: Vec::new() }
    }

    /// Try to create a [DMXValues] container from a slice of u8.
    ///
    /// Fails if the slice is longer than 512 bytes
    pub fn from_slice(values: &[u8]) -> Result<Self, ()> {
        let inner = Vec::from_slice(values)?;
        Ok(Self { inner })
    }

    /// Create [Self] from a slice of u8, truncating any excess data
    ///
    /// If a slice longer than 512 elements is passed, everything past the 512th element is ignored
    pub fn from_slice_truncating(values: &[u8]) -> Self {
        let max_len = values.len().min(Self::CAPACITY);

        let inner = Vec::from_slice(&values[..max_len]).expect("works because we are below our capacity limit");
        Self { inner }
    }

    /// Returns the inner container
    pub fn inner(&self) -> &Vec<u8, { Self::CAPACITY }> {
        &self.inner
    }
}

/// List of known start codes that don't belong to companies
///
/// Taken from these sources on 2025-03-02:
/// - <https://tsp.esta.org/tsp/working_groups/CP/DMXAlternateCodes.php>
/// - ANSI E1.11 – 2024, section: Annex D (Normative) - Reserved Alternate START Codes
#[repr(u8)]
pub enum DMXStartCode {
    /// Null Start Code for Dimmers per DMX512 & DMX512/1990
    DMX = 0x00,
    /// ANSI E1.11 Text Packet
    TextAscii = 0x17,
    /// Test Packet
    Test = 0x55,
    /// UTF-8 Text Packet
    TextUtf8 = 0x90,
    /// 2-byte Manufacturer ID serves as an identifier that the data following in that packet is proprietary to that entity and should be ignored by all others
    ManufacturerId = 0x91,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x92 = 0x92,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x93 = 0x93,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x94 = 0x94,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x95 = 0x95,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x96 = 0x96,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x97 = 0x97,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x98 = 0x98,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x99 = 0x99,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x9A = 0x9A,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x9B = 0x9B,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x9C = 0x9C,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x9D = 0x9D,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x9E = 0x9E,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0x9F = 0x9F,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xA0 = 0xA0,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xA1 = 0xA1,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xA2 = 0xA2,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xA3 = 0xA3,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xA4 = 0xA4,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xA5 = 0xA5,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xA6 = 0xA6,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xA7 = 0xA7,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xA8 = 0xA8,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xA9 = 0xA9,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xAB = 0xAB,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xAC = 0xAC,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xAD = 0xAD,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xAE = 0xAE,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xAF = 0xAF,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xB0 = 0xB0,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xB1 = 0xB1,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xB2 = 0xB2,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xB3 = 0xB3,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xB4 = 0xB4,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xB5 = 0xB5,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xB6 = 0xB6,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xB7 = 0xB7,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xB8 = 0xB8,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xB9 = 0xB9,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xBA = 0xBA,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xBB = 0xBB,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xBC = 0xBC,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xBD = 0xBD,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xBE = 0xBE,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xBF = 0xBF,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xC0 = 0xC0,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xC1 = 0xC1,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xC2 = 0xC2,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xC3 = 0xC3,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xC4 = 0xC4,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xC5 = 0xC5,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xC6 = 0xC6,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xC7 = 0xC7,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xC8 = 0xC8,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xC9 = 0xC9,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xCA = 0xCA,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xCB = 0xCB,
    /// E1.20 (RDM) start code
    RDM = 0xCC,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xCD = 0xCD,
    /// Reserved for Future Expansion of the DMX512 Standard
    Reserved0xCE = 0xCE,
    /// ANSI E1.11 System Information Packet
    SystemInformationPacket = 0xCF,
}
