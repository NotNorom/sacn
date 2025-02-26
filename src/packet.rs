// Copyright 2020 sacn Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// This file was modified as part of a University of St Andrews Computer Science BSC Senior Honours Dissertation Project.

#![warn(missing_docs)]

//! Parsing of sacn network packets.
//!
//! The packets live within the scope of the ACN protocol suite.
//!
//! # Examples
//!
//! ```
//! # use uuid::Uuid;
//! # use sacn::packet::{AcnRootLayerProtocol, E131RootLayer, E131RootLayerData, DataPacketFramingLayer, DataPacketDmpLayer};
//! # use sacn::priority::Priority;
//! # use sacn::universe::Universe;
//! # use core::str::FromStr;
//! # fn main() {
//! # {
//! let packet = AcnRootLayerProtocol {
//!     pdu: E131RootLayer {
//!         cid: Uuid::new_v4(),
//!         data: E131RootLayerData::DataPacket(DataPacketFramingLayer {
//!             source_name: FromStr::from_str("Source_A").unwrap(),
//!             priority: Priority::default(),
//!             synchronization_address: Some(Universe::new(7962).unwrap()),
//!             sequence_number: 154,
//!             preview_data: false,
//!             stream_terminated: false,
//!             force_synchronization: false,
//!             universe: Universe::new(1).unwrap(),
//!             data: DataPacketDmpLayer {
//!                 property_values: heapless::Vec::from_slice(&[0, 1, 2, 3]).unwrap(),
//!             },
//!         }),
//!     },
//! };
//!
//! let mut buf = [0; 638];
//! packet.pack(&mut buf).unwrap();
//!
//! assert_eq!(
//!     AcnRootLayerProtocol::parse(&buf).unwrap(),
//!     packet
//! );
//! # }}
//! ```

/// The core crate is used for string processing during packet parsing/packing as well as to provide access to the Hash trait.
use core::hash::{self, Hash};

/// The byteorder crate is used for marshalling data on/off the network in Network Byte Order.
use byteorder::{ByteOrder, NetworkEndian};
use heapless::Vec;
/// The uuid crate is used for working with/generating UUIDs which sACN uses as part of the cid field in the protocol.
use uuid::Uuid;

use crate::{
    e131_definitions::{
        DISCOVERY_UNI_PER_PAGE, E131_ACN_PACKET_IDENTIFIER, E131_CID_END_INDEX, E131_CID_FIELD_LENGTH,
        E131_DATA_PACKET_DMP_LAYER_ADDRESS_DATA_FIELD_LENGTH, E131_DATA_PACKET_DMP_LAYER_ADDRESS_INCREMENT,
        E131_DATA_PACKET_DMP_LAYER_ADDRESS_INCREMENT_FIELD_LENGTH, E131_DATA_PACKET_DMP_LAYER_FIRST_PROPERTY_ADDRESS_FIELD_LENGTH,
        E131_DATA_PACKET_DMP_LAYER_FIRST_PROPERTY_FIELD, E131_DATA_PACKET_DMP_LAYER_PROPERTY_VALUE_COUNT_FIELD_LENGTH,
        E131_DATA_PACKET_DMP_LAYER_VECTOR_FIELD_LENGTH, E131_DISCOVERY_FRAMING_LAYER_RESERVE_FIELD_LENGTH,
        E131_DISCOVERY_LAYER_LAST_PAGE_FIELD_LENGTH, E131_DISCOVERY_LAYER_PAGE_FIELD_LENGTH, E131_DISCOVERY_LAYER_VECTOR_FIELD_LENGTH,
        E131_DMP_LAYER_ADDRESS_DATA_FIELD, E131_FORCE_SYNCHRONISATION_OPTION_BIT_MASK, E131_FRAMING_LAYER_VECTOR_LENGTH,
        E131_OPTIONS_FIELD_LENGTH, E131_PDU_FLAGS, E131_PDU_LENGTH_FLAGS_LENGTH, E131_POSTAMBLE_SIZE, E131_PREAMBLE_SIZE,
        E131_PREVIEW_DATA_OPTION_BIT_MASK, E131_PRIORITY_FIELD_LENGTH, E131_ROOT_LAYER_VECTOR_LENGTH, E131_SEQ_NUM_FIELD_LENGTH,
        E131_SOURCE_NAME_FIELD_LENGTH, E131_STREAM_TERMINATION_OPTION_BIT_MASK, E131_SYNC_ADDR_FIELD_LENGTH,
        E131_SYNC_FRAMING_LAYER_RESERVE_FIELD_LENGTH, E131_SYNC_FRAMING_LAYER_SEQ_NUM_FIELD_LENGTH,
        E131_UNIVERSE_DISCOVERY_FRAMING_LAYER_MIN_LENGTH, E131_UNIVERSE_DISCOVERY_LAYER_MAX_LENGTH,
        E131_UNIVERSE_DISCOVERY_LAYER_MIN_LENGTH, E131_UNIVERSE_FIELD_LENGTH, E131_UNIVERSE_SYNC_PACKET_FRAMING_LAYER_LENGTH,
        MAXIMUM_PACKET_SIZE, UNIVERSE_CHANNEL_CAPACITY, VECTOR_DMP_SET_PROPERTY, VECTOR_E131_DATA_PACKET, VECTOR_E131_EXTENDED_DISCOVERY,
        VECTOR_E131_EXTENDED_SYNCHRONIZATION, VECTOR_ROOT_E131_DATA, VECTOR_ROOT_E131_EXTENDED, VECTOR_UNIVERSE_DISCOVERY_UNIVERSE_LIST,
    },
    priority::Priority,
    sacn_parse_pack_error::{InsufficientData, InvalidData, ParsePackError},
    source_name::SourceName,
    universe::Universe,
};

/// Fills the given array of bytes with the given length n with bytes of value 0.
#[inline]
fn zeros(buf: &mut [u8], n: usize) {
    for b in buf.iter_mut().take(n) {
        *b = 0;
    }
}

/// Root layer protocol of the Architecture for Control Networks (ACN) protocol.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct AcnRootLayerProtocol {
    /// The PDU this packet carries.
    pub pdu: E131RootLayer,
}

impl AcnRootLayerProtocol {
    /// Parse the packet from the given buffer.
    pub fn parse(buf: &[u8]) -> Result<AcnRootLayerProtocol, ParsePackError> {
        if buf.len() < (E131_PREAMBLE_SIZE as usize) {
            Err(InsufficientData::TooShortForPreamble)?;
        }

        // Preamble Size
        if NetworkEndian::read_u16(&buf[0..2]) != E131_PREAMBLE_SIZE {
            Err(ParsePackError::ParseInvalidData("invalid Preamble Size"))?;
        }

        // Post-amble Size
        if NetworkEndian::read_u16(&buf[2..4]) != E131_POSTAMBLE_SIZE {
            Err(ParsePackError::ParseInvalidData("invalid Post-amble Size"))?;
        }

        // ACN Packet Identifier
        if buf[4..(E131_PREAMBLE_SIZE as usize)] != E131_ACN_PACKET_IDENTIFIER {
            Err(ParsePackError::ParseInvalidData("invalid ACN packet identifier"))?;
        }

        // PDU block
        Ok(AcnRootLayerProtocol {
            pdu: E131RootLayer::parse(&buf[(E131_PREAMBLE_SIZE as usize)..])?,
        })
    }

    /// Packs the packet into a new allocated Vec on the stack.
    pub fn pack_alloc(&self) -> Result<heapless::Vec<u8, MAXIMUM_PACKET_SIZE>, ParsePackError> {
        let mut buf = heapless::Vec::new();
        self.pack_vec(&mut buf)?;
        Ok(buf)
    }

    /// Packs the packet into the given vector.
    pub fn pack_vec(&self, buf: &mut heapless::Vec<u8, MAXIMUM_PACKET_SIZE>) -> Result<(), ParsePackError> {
        if buf.capacity() < self.len() {
            return Err(ParsePackError::PackBufferInsufficient("fuck"));
        }

        buf.clear();
        buf.resize_default(MAXIMUM_PACKET_SIZE).expect("set len to exactly its capacity");

        self.pack(buf)
    }

    /// Packs the packet into the given buffer.
    pub fn pack(&self, buf: &mut [u8]) -> Result<(), ParsePackError> {
        if buf.len() < self.len() {
            Err(ParsePackError::ParseInvalidData("invalid ACN packet identifier"))?;
        }

        // Preamble Size
        NetworkEndian::write_u16(&mut buf[0..2], 0x0010);

        // Post-amble Size
        zeros(&mut buf[2..4], 2);

        // ACN Packet Identifier
        buf[4..16].copy_from_slice(b"ASC-E1.17\x00\x00\x00");

        // PDU block
        self.pdu.pack(&mut buf[16..])
    }

    /// The length of the packet when packed.
    pub fn len(&self) -> usize {
        // Preamble Field Size (Bytes)
        2 +
        // Post-amble Field Size (Bytes)
        2 +
        // ACN Packet Identifier Field Size (Bytes)
        E131_ACN_PACKET_IDENTIFIER.len() +
        // PDU block
        self.pdu.len()
    }
}

/// Represents the data contained with the PduInfo section that appears at the start of a layer in an sACN packet.
struct PduInfo {
    /// The length in bytes of this layer inclusive of the PduInfo.
    length: usize,
    /// The vector which indicates what the layer is, context dependent.
    vector: u32,
}

impl PduInfo {
    /// Takes the given byte buffer and parses the flags, length and vector fields into a PduInfo struct.
    ///
    /// # Arguments
    /// buf: The raw byte buffer.
    ///
    /// vector_length: The length of the vectorfield in bytes.
    ///
    /// # Errors
    /// ParseInsufficientData: If the length of the buffer is less than the flag, length and vector fields (E131_PDU_LENGTH_FLAGS_LENGTH + vector_length).
    ///
    /// ParsePduInvalidFlags: If the flags parsed don't match the flags expected for an ANSI E1.31-2018 packet as per ANSI E1.31-2018 Section 4 Table 4-1, 4-2, 4-3.
    pub fn new(buf: &[u8], vector_length: usize) -> Result<PduInfo, ParsePackError> {
        if buf.len() < E131_PDU_LENGTH_FLAGS_LENGTH + vector_length {
            Err(InsufficientData::PduInfoTooShort)?;
        }

        // Flags
        let flags = buf[0] & 0xf0; // Flags are stored in the top 4 bits.
        if flags != E131_PDU_FLAGS {
            Err(ParsePackError::ParsePduInvalidFlags(flags))?;
        }
        // Length
        let length = (NetworkEndian::read_u16(&buf[0..E131_PDU_LENGTH_FLAGS_LENGTH]) & 0x0fff) as usize;

        // Vector
        let vector = NetworkEndian::read_uint(&buf[E131_PDU_LENGTH_FLAGS_LENGTH..], vector_length) as u32;

        Ok(PduInfo { length, vector })
    }
}

trait Pdu: Sized {
    fn parse(buf: &[u8]) -> Result<Self, ParsePackError>;

    fn pack(&self, buf: &mut [u8]) -> Result<(), ParsePackError>;

    fn len(&self) -> usize;
}

/// Payload of the Root Layer PDU.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum E131RootLayerData {
    /// DMX data packet.
    DataPacket(DataPacketFramingLayer),

    /// Synchronization packet.
    SynchronizationPacket(SynchronizationPacketFramingLayer),

    /// Universe discovery packet.
    UniverseDiscoveryPacket(UniverseDiscoveryPacketFramingLayer),
}

/// Root layer protocol data unit (PDU).
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct E131RootLayer {
    /// Sender UUID.
    pub cid: Uuid,
    /// Data carried by the Root Layer PDU.
    pub data: E131RootLayerData,
}

impl Pdu for E131RootLayer {
    fn parse(buf: &[u8]) -> Result<E131RootLayer, ParsePackError> {
        // Length and Vector
        let PduInfo { length, vector } = PduInfo::new(buf, E131_ROOT_LAYER_VECTOR_LENGTH)?;
        if buf.len() < length {
            Err(InsufficientData::BufferTooShortBasedOnRootLayer)?;
        }

        if vector != VECTOR_ROOT_E131_DATA && vector != VECTOR_ROOT_E131_EXTENDED {
            Err(ParsePackError::PduInvalidVector(vector))?;
        }

        // CID
        let cid = Uuid::from_slice(&buf[E131_PDU_LENGTH_FLAGS_LENGTH + E131_ROOT_LAYER_VECTOR_LENGTH..E131_CID_END_INDEX])?;

        // Data
        let data = match vector {
            VECTOR_ROOT_E131_DATA => E131RootLayerData::DataPacket(DataPacketFramingLayer::parse(&buf[E131_CID_END_INDEX..length])?),
            VECTOR_ROOT_E131_EXTENDED => {
                let data_buf = &buf[E131_CID_END_INDEX..length];
                let PduInfo { length, vector } = PduInfo::new(data_buf, E131_FRAMING_LAYER_VECTOR_LENGTH)?;
                if buf.len() < length {
                    Err(InsufficientData::BufferTooShortBasedOnE131FramingLayer)?;
                }

                match vector {
                    VECTOR_E131_EXTENDED_SYNCHRONIZATION => {
                        E131RootLayerData::SynchronizationPacket(SynchronizationPacketFramingLayer::parse(data_buf)?)
                    }
                    VECTOR_E131_EXTENDED_DISCOVERY => {
                        E131RootLayerData::UniverseDiscoveryPacket(UniverseDiscoveryPacketFramingLayer::parse(data_buf)?)
                    }
                    vector => Err(ParsePackError::PduInvalidVector(vector))?,
                }
            }
            vector => Err(ParsePackError::PduInvalidVector(vector))?,
        };

        Ok(E131RootLayer { cid, data })
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ParsePackError> {
        if buf.len() < self.len() {
            Err(ParsePackError::PackBufferInsufficient(""))?
        }

        // Flags and Length, flags are stored in the top 4 bits.
        let flags_and_length = NetworkEndian::read_u16(&[E131_PDU_FLAGS, 0x0]) | (self.len() as u16) & 0x0fff;
        NetworkEndian::write_u16(&mut buf[0..E131_PDU_LENGTH_FLAGS_LENGTH], flags_and_length);

        // Vector
        match self.data {
            E131RootLayerData::DataPacket(_) => NetworkEndian::write_u32(
                &mut buf[E131_PDU_LENGTH_FLAGS_LENGTH..E131_PDU_LENGTH_FLAGS_LENGTH + E131_ROOT_LAYER_VECTOR_LENGTH],
                VECTOR_ROOT_E131_DATA,
            ),
            E131RootLayerData::SynchronizationPacket(_) | E131RootLayerData::UniverseDiscoveryPacket(_) => NetworkEndian::write_u32(
                &mut buf[E131_PDU_LENGTH_FLAGS_LENGTH..E131_PDU_LENGTH_FLAGS_LENGTH + E131_ROOT_LAYER_VECTOR_LENGTH],
                VECTOR_ROOT_E131_EXTENDED,
            ),
        }

        // CID
        buf[E131_PDU_LENGTH_FLAGS_LENGTH + E131_ROOT_LAYER_VECTOR_LENGTH..E131_CID_END_INDEX].copy_from_slice(self.cid.as_bytes());

        // Data
        match self.data {
            E131RootLayerData::DataPacket(ref data) => Ok(data.pack(&mut buf[E131_CID_END_INDEX..])?),
            E131RootLayerData::SynchronizationPacket(ref data) => Ok(data.pack(&mut buf[E131_CID_END_INDEX..])?),
            E131RootLayerData::UniverseDiscoveryPacket(ref data) => Ok(data.pack(&mut buf[E131_CID_END_INDEX..])?),
        }
    }

    fn len(&self) -> usize {
        // Length and Flags
        E131_PDU_LENGTH_FLAGS_LENGTH +
                // Vector
                E131_ROOT_LAYER_VECTOR_LENGTH +
                // CID
                E131_CID_FIELD_LENGTH +
                // Data
                match self.data {
                    E131RootLayerData::DataPacket(ref data) => data.len(),
                    E131RootLayerData::SynchronizationPacket(ref data) => data.len(),
                    E131RootLayerData::UniverseDiscoveryPacket(ref data) => data.len(),
                }
    }
}

/// Framing layer PDU for sACN data packets.
#[derive(Eq, PartialEq, Debug)]
pub struct DataPacketFramingLayer {
    /// The name of the source.
    pub source_name: SourceName,

    /// Priority of this data packet.
    pub priority: Priority,

    /// Synchronization address.
    pub synchronization_address: Option<Universe>,

    /// The sequence number of this packet.
    pub sequence_number: u8,

    /// If this packets data is preview data.
    pub preview_data: bool,

    /// If transmission on this universe is terminated.
    pub stream_terminated: bool,

    /// Force synchronization if no synchronization packets are received.
    pub force_synchronization: bool,

    /// The universe DMX data is transmitted for.
    pub universe: Universe,

    /// DMP layer containing the DMX data.
    pub data: DataPacketDmpLayer,
}

// Calculate the indexes of the fields within the buffer based on the size of the fields previous.
// Constants are replaced inline so this increases readability by removing magic numbers without affecting runtime performance.
// Theses indexes are only valid within the scope of this part of the protocol (DataPacketFramingLayer).
const SOURCE_NAME_INDEX: usize = E131_PDU_LENGTH_FLAGS_LENGTH + E131_FRAMING_LAYER_VECTOR_LENGTH;
const PRIORITY_INDEX: usize = SOURCE_NAME_INDEX + E131_SOURCE_NAME_FIELD_LENGTH;
const SYNC_ADDR_INDEX: usize = PRIORITY_INDEX + E131_PRIORITY_FIELD_LENGTH;
const SEQ_NUM_INDEX: usize = SYNC_ADDR_INDEX + E131_SYNC_ADDR_FIELD_LENGTH;
const OPTIONS_FIELD_INDEX: usize = SEQ_NUM_INDEX + E131_SEQ_NUM_FIELD_LENGTH;
const UNIVERSE_INDEX: usize = OPTIONS_FIELD_INDEX + E131_OPTIONS_FIELD_LENGTH;
const DATA_INDEX: usize = UNIVERSE_INDEX + E131_UNIVERSE_FIELD_LENGTH;

impl Pdu for DataPacketFramingLayer {
    fn parse(buf: &[u8]) -> Result<DataPacketFramingLayer, ParsePackError> {
        // Length and Vector
        let PduInfo { length, vector } = PduInfo::new(buf, E131_FRAMING_LAYER_VECTOR_LENGTH)?;
        if buf.len() < length {
            Err(InsufficientData::BufferTooShortBasedOnDataFramingLayer)?;
        }

        if vector != VECTOR_E131_DATA_PACKET {
            Err(ParsePackError::PduInvalidVector(vector))?;
        }

        // Source Name
        let source_name = SourceName::try_from(&buf[SOURCE_NAME_INDEX..PRIORITY_INDEX])?;

        // Priority
        let priority = buf[PRIORITY_INDEX].try_into()?;

        // Synchronization Address
        let synchronization_address = {
            let raw = NetworkEndian::read_u16(&buf[SYNC_ADDR_INDEX..SEQ_NUM_INDEX]);
            match raw {
                0 => None,
                _ => Some(Universe::new(raw)?),
            }
        };

        // Sequence Number
        let sequence_number = buf[SEQ_NUM_INDEX];

        // Options, Stored as bit flag.
        let preview_data = buf[OPTIONS_FIELD_INDEX] & E131_PREVIEW_DATA_OPTION_BIT_MASK != 0;
        let stream_terminated = buf[OPTIONS_FIELD_INDEX] & E131_STREAM_TERMINATION_OPTION_BIT_MASK != 0;
        let force_synchronization = buf[OPTIONS_FIELD_INDEX] & E131_FORCE_SYNCHRONISATION_OPTION_BIT_MASK != 0;

        // Universe
        let universe = NetworkEndian::read_u16(&buf[UNIVERSE_INDEX..DATA_INDEX]).try_into()?;

        // Data layer.
        let data = DataPacketDmpLayer::parse(&buf[DATA_INDEX..length])?;

        Ok(DataPacketFramingLayer {
            source_name,
            priority,
            synchronization_address,
            sequence_number,
            preview_data,
            stream_terminated,
            force_synchronization,
            universe,
            data,
        })
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ParsePackError> {
        if buf.len() < self.len() {
            Err(ParsePackError::PackBufferInsufficient(""))?;
        }

        // Flags and Length
        let flags_and_length = NetworkEndian::read_u16(&[E131_PDU_FLAGS, 0x0]) | (self.len() as u16) & 0x0fff;
        NetworkEndian::write_u16(&mut buf[0..E131_PDU_LENGTH_FLAGS_LENGTH], flags_and_length);

        // Vector
        NetworkEndian::write_u32(&mut buf[E131_PDU_LENGTH_FLAGS_LENGTH..SOURCE_NAME_INDEX], VECTOR_E131_DATA_PACKET);

        // Source Name, padded with 0's up to the required 64 byte length.
        zeros(&mut buf[SOURCE_NAME_INDEX..PRIORITY_INDEX], E131_SOURCE_NAME_FIELD_LENGTH);
        buf[SOURCE_NAME_INDEX..SOURCE_NAME_INDEX + self.source_name.len()].copy_from_slice(self.source_name.as_bytes());

        // Priority
        buf[PRIORITY_INDEX] = self.priority.get();

        // Synchronization Address

        NetworkEndian::write_u16(
            &mut buf[SYNC_ADDR_INDEX..SEQ_NUM_INDEX],
            self.synchronization_address.map(|u| u.get()).unwrap_or_default(),
        );

        // Sequence Number
        buf[SEQ_NUM_INDEX] = self.sequence_number;

        // Options, zero out all the bits to start including bits 0-4 as per ANSI E1.31-2018 Section 6.2.6.
        buf[OPTIONS_FIELD_INDEX] = 0;

        // Preview Data
        if self.preview_data {
            buf[OPTIONS_FIELD_INDEX] = E131_PREVIEW_DATA_OPTION_BIT_MASK;
        }

        // Stream Terminated
        if self.stream_terminated {
            buf[OPTIONS_FIELD_INDEX] |= E131_STREAM_TERMINATION_OPTION_BIT_MASK;
        }

        // Force Synchronization
        if self.force_synchronization {
            buf[OPTIONS_FIELD_INDEX] |= E131_FORCE_SYNCHRONISATION_OPTION_BIT_MASK;
        }

        // Universe
        NetworkEndian::write_u16(&mut buf[UNIVERSE_INDEX..DATA_INDEX], self.universe.get());

        // Data
        self.data.pack(&mut buf[DATA_INDEX..])
    }

    fn len(&self) -> usize {
        // Length and Flags
        E131_PDU_LENGTH_FLAGS_LENGTH +
        // Vector
        E131_FRAMING_LAYER_VECTOR_LENGTH +
        // Source Name
        E131_SOURCE_NAME_FIELD_LENGTH +
        // Priority
        E131_PRIORITY_FIELD_LENGTH +
        // Synchronization Address
        E131_SYNC_ADDR_FIELD_LENGTH +
        // Sequence Number
        E131_SEQ_NUM_FIELD_LENGTH +
        // Options
        E131_OPTIONS_FIELD_LENGTH +
        // Universe
        E131_UNIVERSE_FIELD_LENGTH +
        // Data
        self.data.len()
    }
}

impl Clone for DataPacketFramingLayer {
    fn clone(&self) -> Self {
        DataPacketFramingLayer {
            source_name: self.source_name.clone(),
            priority: self.priority,
            synchronization_address: self.synchronization_address,
            sequence_number: self.sequence_number,
            preview_data: self.preview_data,
            stream_terminated: self.stream_terminated,
            force_synchronization: self.force_synchronization,
            universe: self.universe,
            data: self.data.clone(),
        }
    }
}

impl Hash for DataPacketFramingLayer {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (*self.source_name).hash(state);
        self.priority.hash(state);
        self.synchronization_address.hash(state);
        self.sequence_number.hash(state);
        self.preview_data.hash(state);
        self.stream_terminated.hash(state);
        self.force_synchronization.hash(state);
        self.universe.hash(state);
        self.data.hash(state);
    }
}

/// Device Management Protocol PDU with SET PROPERTY vector.
///
/// Used for sACN data packets.
#[derive(Eq, PartialEq, Debug)]
pub struct DataPacketDmpLayer {
    /// DMX data property values (DMX start coder + 512 slots).
    pub property_values: Vec<u8, UNIVERSE_CHANNEL_CAPACITY>,
}

// Calculate the indexes of the fields within the buffer based on the size of the fields previous.
// Constants are replaced inline so this increases readability by removing magic numbers without affecting runtime performance.
// Theses indexes are only valid within the scope of this part of the protocol (DataPacketDmpLayer).
const VECTOR_FIELD_INDEX: usize = E131_PDU_LENGTH_FLAGS_LENGTH;
const ADDRESS_DATA_FIELD_INDEX: usize = VECTOR_FIELD_INDEX + E131_DATA_PACKET_DMP_LAYER_VECTOR_FIELD_LENGTH;
const FIRST_PRIORITY_FIELD_INDEX: usize = ADDRESS_DATA_FIELD_INDEX + E131_DATA_PACKET_DMP_LAYER_ADDRESS_DATA_FIELD_LENGTH;
const ADDRESS_INCREMENT_FIELD_INDEX: usize = FIRST_PRIORITY_FIELD_INDEX + E131_DATA_PACKET_DMP_LAYER_FIRST_PROPERTY_ADDRESS_FIELD_LENGTH;
const PROPERTY_VALUE_COUNT_FIELD_INDEX: usize = ADDRESS_INCREMENT_FIELD_INDEX + E131_DATA_PACKET_DMP_LAYER_ADDRESS_INCREMENT_FIELD_LENGTH;
const PROPERTY_VALUES_FIELD_INDEX: usize = PROPERTY_VALUE_COUNT_FIELD_INDEX + E131_DATA_PACKET_DMP_LAYER_PROPERTY_VALUE_COUNT_FIELD_LENGTH;

impl Pdu for DataPacketDmpLayer {
    fn parse(buf: &[u8]) -> Result<DataPacketDmpLayer, ParsePackError> {
        // Length and Vector
        let PduInfo { length, vector } = PduInfo::new(buf, E131_DATA_PACKET_DMP_LAYER_VECTOR_FIELD_LENGTH)?;
        if buf.len() < length {
            Err(InsufficientData::BufferTooShortBasedOnDataDmpLayer)?;
        }

        if vector != u32::from(VECTOR_DMP_SET_PROPERTY) {
            Err(ParsePackError::PduInvalidVector(vector))?;
        }

        // Address and Data Type
        if buf[ADDRESS_DATA_FIELD_INDEX] != E131_DMP_LAYER_ADDRESS_DATA_FIELD {
            Err(ParsePackError::ParseInvalidData("invalid Address and Data Type"))?;
        }

        // First Property Address
        if NetworkEndian::read_u16(&buf[FIRST_PRIORITY_FIELD_INDEX..ADDRESS_INCREMENT_FIELD_INDEX])
            != E131_DATA_PACKET_DMP_LAYER_FIRST_PROPERTY_FIELD
        {
            Err(ParsePackError::ParseInvalidData("invalid First Property Address"))?;
        }

        // Address Increment
        if NetworkEndian::read_u16(&buf[ADDRESS_INCREMENT_FIELD_INDEX..PROPERTY_VALUE_COUNT_FIELD_INDEX])
            != E131_DATA_PACKET_DMP_LAYER_ADDRESS_INCREMENT
        {
            Err(ParsePackError::ParseInvalidData("invalid Address Increment"))?;
        }

        // Property value count
        let property_value_count = NetworkEndian::read_u16(&buf[PROPERTY_VALUE_COUNT_FIELD_INDEX..PROPERTY_VALUES_FIELD_INDEX]);

        // Check that the property value count matches the expected count based on the pdu length given previously.
        if property_value_count as usize + PROPERTY_VALUES_FIELD_INDEX != length {
            Err(InsufficientData::InvalidDmpLayerPropertyCount {
                should_be: length,
                actual: property_value_count as usize,
            })?;
        }

        // Property values
        // The property value length is only of the property values and not the headers so start counting at the index that the property values start.
        let property_values_length = length - PROPERTY_VALUES_FIELD_INDEX;
        if property_values_length > UNIVERSE_CHANNEL_CAPACITY {
            Err(ParsePackError::ParseInvalidData("only 512 DMX slots allowed"))?;
        }

        let property_values = Vec::from_slice(&buf[PROPERTY_VALUES_FIELD_INDEX..length]).expect("should be enough capacity");

        Ok(DataPacketDmpLayer {
            property_values: property_values.into(),
        })
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ParsePackError> {
        if self.property_values.len() > UNIVERSE_CHANNEL_CAPACITY {
            Err(InvalidData::TooManyDmxValues)?;
        }

        if buf.len() < self.len() {
            Err(ParsePackError::PackBufferInsufficient(
                "DataPacketDmpLayer pack buffer length insufficient",
            ))?;
        }

        // Flags and Length
        let flags_and_length = NetworkEndian::read_u16(&[E131_PDU_FLAGS, 0x0]) | (self.len() as u16) & 0x0fff;
        NetworkEndian::write_u16(&mut buf[0..E131_PDU_LENGTH_FLAGS_LENGTH], flags_and_length);

        // Vector
        buf[VECTOR_FIELD_INDEX] = VECTOR_DMP_SET_PROPERTY;

        // Address and Data Type
        buf[ADDRESS_DATA_FIELD_INDEX] = E131_DMP_LAYER_ADDRESS_DATA_FIELD;

        // First Property Address
        zeros(
            &mut buf[FIRST_PRIORITY_FIELD_INDEX..ADDRESS_INCREMENT_FIELD_INDEX],
            E131_DATA_PACKET_DMP_LAYER_FIRST_PROPERTY_ADDRESS_FIELD_LENGTH,
        );

        // Address Increment
        NetworkEndian::write_u16(
            &mut buf[ADDRESS_INCREMENT_FIELD_INDEX..PROPERTY_VALUE_COUNT_FIELD_INDEX],
            E131_DATA_PACKET_DMP_LAYER_ADDRESS_INCREMENT,
        );

        // Property value count
        NetworkEndian::write_u16(
            &mut buf[PROPERTY_VALUE_COUNT_FIELD_INDEX..PROPERTY_VALUES_FIELD_INDEX],
            self.property_values.len() as u16,
        );

        // Property values
        buf[PROPERTY_VALUES_FIELD_INDEX..PROPERTY_VALUES_FIELD_INDEX + self.property_values.len()].copy_from_slice(&self.property_values);

        Ok(())
    }

    fn len(&self) -> usize {
        // Length and Flags
        E131_PDU_LENGTH_FLAGS_LENGTH +
        // Vector
        E131_DATA_PACKET_DMP_LAYER_VECTOR_FIELD_LENGTH +
        // Address and Data Type
        E131_DATA_PACKET_DMP_LAYER_ADDRESS_DATA_FIELD_LENGTH +
        // First Property Address
        E131_DATA_PACKET_DMP_LAYER_FIRST_PROPERTY_ADDRESS_FIELD_LENGTH +
        // Address Increment
        E131_DATA_PACKET_DMP_LAYER_ADDRESS_INCREMENT_FIELD_LENGTH +
        // Property value count
        E131_DATA_PACKET_DMP_LAYER_PROPERTY_VALUE_COUNT_FIELD_LENGTH +
        // Property values
        self.property_values.len()
    }
}

impl Clone for DataPacketDmpLayer {
    fn clone(&self) -> Self {
        DataPacketDmpLayer {
            property_values: self.property_values.clone(),
        }
    }
}

impl Hash for DataPacketDmpLayer {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (*self.property_values).hash(state);
    }
}

/// sACN synchronization packet PDU.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Copy)]
pub struct SynchronizationPacketFramingLayer {
    /// The sequence number of the packet.
    pub sequence_number: u8,

    /// The address to synchronize.
    ///
    /// None indicates a raw value of 0.
    pub synchronization_address: Option<Universe>,
}

// Calculate the indexes of the fields within the buffer based on the size of the fields previous.
// Constants are replaced inline so this increases readability by removing magic numbers without affecting runtime performance.
// Theses indexes are only valid within the scope of this part of the protocol (SynchronisationPacketFramingLayer).
const E131_SYNC_FRAMING_LAYER_VECTOR_FIELD_INDEX: usize = E131_PDU_LENGTH_FLAGS_LENGTH;
const E131_SYNC_FRAMING_LAYER_SEQ_NUM_FIELD_INDEX: usize = E131_SYNC_FRAMING_LAYER_VECTOR_FIELD_INDEX + E131_FRAMING_LAYER_VECTOR_LENGTH;
const E131_SYNC_FRAMING_LAYER_SYNC_ADDRESS_FIELD_INDEX: usize =
    E131_SYNC_FRAMING_LAYER_SEQ_NUM_FIELD_INDEX + E131_SYNC_FRAMING_LAYER_SEQ_NUM_FIELD_LENGTH;
const E131_SYNC_FRAMING_LAYER_RESERVE_FIELD_INDEX: usize = E131_SYNC_FRAMING_LAYER_SYNC_ADDRESS_FIELD_INDEX + E131_SYNC_ADDR_FIELD_LENGTH;
const E131_SYNC_FRAMING_LAYER_END_INDEX: usize = E131_SYNC_FRAMING_LAYER_RESERVE_FIELD_INDEX + E131_SYNC_FRAMING_LAYER_RESERVE_FIELD_LENGTH;

impl Pdu for SynchronizationPacketFramingLayer {
    fn parse(buf: &[u8]) -> Result<SynchronizationPacketFramingLayer, ParsePackError> {
        // Length and Vector
        let PduInfo { length, vector } = PduInfo::new(buf, E131_FRAMING_LAYER_VECTOR_LENGTH)?;
        if buf.len() < length {
            Err(InsufficientData::BufferTooShortBasedOnSyncFramingLayer)?;
        }

        if vector != VECTOR_E131_EXTENDED_SYNCHRONIZATION {
            Err(ParsePackError::PduInvalidVector(vector))?;
        }

        if length != E131_UNIVERSE_SYNC_PACKET_FRAMING_LAYER_LENGTH {
            Err(ParsePackError::PduInvalidLength(length))?;
        }

        // Sequence Number
        let sequence_number = buf[E131_SYNC_FRAMING_LAYER_SEQ_NUM_FIELD_INDEX];

        // Synchronization Address
        let synchronization_address = {
            let raw = NetworkEndian::read_u16(
                &buf[E131_SYNC_FRAMING_LAYER_SYNC_ADDRESS_FIELD_INDEX..E131_SYNC_FRAMING_LAYER_RESERVE_FIELD_INDEX],
            );
            let universe = Universe::new(raw)?;
            Some(universe)
        };

        // Reserved fields (2 bytes right immediately after the synchronisation address) should be ignored by receivers as per
        // ANSI E1.31-2018 Section 6.3.4.

        Ok(SynchronizationPacketFramingLayer {
            sequence_number,
            synchronization_address,
        })
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ParsePackError> {
        if buf.len() < self.len() {
            Err(ParsePackError::PackBufferInsufficient(
                "SynchronizationPacketFramingLayer pack buffer length insufficient",
            ))?;
        }

        // Flags and Length
        let flags_and_length = NetworkEndian::read_u16(&[E131_PDU_FLAGS, 0x0]) | (self.len() as u16) & 0x0fff;
        NetworkEndian::write_u16(&mut buf[0..E131_PDU_LENGTH_FLAGS_LENGTH], flags_and_length);

        // Vector
        NetworkEndian::write_u32(
            &mut buf[E131_SYNC_FRAMING_LAYER_VECTOR_FIELD_INDEX..E131_SYNC_FRAMING_LAYER_SEQ_NUM_FIELD_INDEX],
            VECTOR_E131_EXTENDED_SYNCHRONIZATION,
        );

        // Sequence Number
        buf[E131_SYNC_FRAMING_LAYER_SEQ_NUM_FIELD_INDEX] = self.sequence_number;

        // Synchronization Address
        NetworkEndian::write_u16(
            &mut buf[E131_SYNC_FRAMING_LAYER_SYNC_ADDRESS_FIELD_INDEX..E131_SYNC_FRAMING_LAYER_RESERVE_FIELD_INDEX],
            self.synchronization_address.map(|u| u.get()).unwrap_or_default(),
        );

        // Reserved, transmitted as zeros as per ANSI E1.31-2018 Section 6.3.4.
        zeros(
            &mut buf[E131_SYNC_FRAMING_LAYER_RESERVE_FIELD_INDEX..E131_SYNC_FRAMING_LAYER_END_INDEX],
            E131_SYNC_FRAMING_LAYER_RESERVE_FIELD_LENGTH,
        );

        Ok(())
    }

    fn len(&self) -> usize {
        // Length and Flags
        E131_PDU_LENGTH_FLAGS_LENGTH +
        // Vector
        E131_FRAMING_LAYER_VECTOR_LENGTH +
        // Sequence Number
        E131_SYNC_FRAMING_LAYER_SEQ_NUM_FIELD_LENGTH +
        // Synchronization Address
        E131_SYNC_ADDR_FIELD_LENGTH +
        // Reserved
        E131_SYNC_FRAMING_LAYER_RESERVE_FIELD_LENGTH
    }
}

/// Framing layer PDU for sACN universe discovery packets.
#[derive(Eq, PartialEq, Debug)]
pub struct UniverseDiscoveryPacketFramingLayer {
    /// Name of the source.
    pub source_name: SourceName,

    /// Universe discovery layer.
    pub data: UniverseDiscoveryPacketUniverseDiscoveryLayer,
}

// Calculate the indexes of the fields within the buffer based on the size of the fields previous.
// Constants are replaced inline so this increases readability by removing magic numbers without affecting runtime performance.
// Theses indexes are only valid within the scope of this part of the protocol (UniverseDiscoveryPacketFramingLayer).
const E131_DISCOVERY_FRAMING_LAYER_VECTOR_FIELD_INDEX: usize = E131_PDU_LENGTH_FLAGS_LENGTH;
const E131_DISCOVERY_FRAMING_LAYER_SOURCE_NAME_FIELD_INDEX: usize =
    E131_DISCOVERY_FRAMING_LAYER_VECTOR_FIELD_INDEX + E131_FRAMING_LAYER_VECTOR_LENGTH;
const E131_DISCOVERY_FRAMING_LAYER_RESERVE_FIELD_INDEX: usize =
    E131_DISCOVERY_FRAMING_LAYER_SOURCE_NAME_FIELD_INDEX + E131_SOURCE_NAME_FIELD_LENGTH;
const E131_DISCOVERY_FRAMING_LAYER_DATA_INDEX: usize =
    E131_DISCOVERY_FRAMING_LAYER_RESERVE_FIELD_INDEX + E131_DISCOVERY_FRAMING_LAYER_RESERVE_FIELD_LENGTH;

impl Pdu for UniverseDiscoveryPacketFramingLayer {
    fn parse(buf: &[u8]) -> Result<UniverseDiscoveryPacketFramingLayer, ParsePackError> {
        // Length and Vector
        let PduInfo { length, vector } = PduInfo::new(buf, E131_FRAMING_LAYER_VECTOR_LENGTH)?;
        if buf.len() < length {
            Err(InsufficientData::BufferTooShortBasedOnDiscoveryFramingLayer)?;
        }

        if vector != VECTOR_E131_EXTENDED_DISCOVERY {
            Err(ParsePackError::PduInvalidVector(vector))?;
        }

        if length < E131_UNIVERSE_DISCOVERY_FRAMING_LAYER_MIN_LENGTH {
            Err(ParsePackError::PduInvalidLength(length))?;
        }

        // Source Name
        let source_name = SourceName::try_from(
            &buf[E131_DISCOVERY_FRAMING_LAYER_SOURCE_NAME_FIELD_INDEX..E131_DISCOVERY_FRAMING_LAYER_RESERVE_FIELD_INDEX],
        )?;

        // Reserved data (immediately after source_name) ignored as per ANSI E1.31-2018 Section 6.4.3.

        // The universe discovery data.
        let data = UniverseDiscoveryPacketUniverseDiscoveryLayer::parse(&buf[E131_DISCOVERY_FRAMING_LAYER_DATA_INDEX..length])?;

        Ok(UniverseDiscoveryPacketFramingLayer { source_name, data })
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ParsePackError> {
        if buf.len() < self.len() {
            Err(ParsePackError::PackBufferInsufficient(
                "UniverseDiscoveryPacketFramingLayer pack buffer length insufficient",
            ))?;
        }

        // Flags and Length
        let flags_and_length = NetworkEndian::read_u16(&[E131_PDU_FLAGS, 0x0]) | (self.len() as u16) & 0x0fff;
        NetworkEndian::write_u16(&mut buf[0..E131_DISCOVERY_FRAMING_LAYER_VECTOR_FIELD_INDEX], flags_and_length);

        // Vector
        NetworkEndian::write_u32(
            &mut buf[E131_DISCOVERY_FRAMING_LAYER_VECTOR_FIELD_INDEX..E131_DISCOVERY_FRAMING_LAYER_SOURCE_NAME_FIELD_INDEX],
            VECTOR_E131_EXTENDED_DISCOVERY,
        );

        // Source Name
        zeros(
            &mut buf[E131_DISCOVERY_FRAMING_LAYER_SOURCE_NAME_FIELD_INDEX..E131_DISCOVERY_FRAMING_LAYER_RESERVE_FIELD_INDEX],
            E131_SOURCE_NAME_FIELD_LENGTH,
        );
        buf[E131_DISCOVERY_FRAMING_LAYER_SOURCE_NAME_FIELD_INDEX
            ..E131_DISCOVERY_FRAMING_LAYER_SOURCE_NAME_FIELD_INDEX + self.source_name.len()]
            .copy_from_slice(self.source_name.as_bytes());

        // Reserved
        zeros(
            &mut buf[E131_DISCOVERY_FRAMING_LAYER_RESERVE_FIELD_INDEX..E131_DISCOVERY_FRAMING_LAYER_DATA_INDEX],
            E131_DISCOVERY_FRAMING_LAYER_RESERVE_FIELD_LENGTH,
        );

        // Data
        self.data.pack(&mut buf[E131_DISCOVERY_FRAMING_LAYER_DATA_INDEX..])
    }

    fn len(&self) -> usize {
        // Length and Flags
        E131_PDU_LENGTH_FLAGS_LENGTH +
        // Vector
        E131_FRAMING_LAYER_VECTOR_LENGTH +
        // Source Name
        E131_SOURCE_NAME_FIELD_LENGTH +
        // Reserved
        E131_DISCOVERY_FRAMING_LAYER_RESERVE_FIELD_LENGTH +
        // Data
        self.data.len()
    }
}

impl Clone for UniverseDiscoveryPacketFramingLayer {
    fn clone(&self) -> Self {
        UniverseDiscoveryPacketFramingLayer {
            source_name: self.source_name.clone(),
            data: self.data.clone(),
        }
    }
}

impl Hash for UniverseDiscoveryPacketFramingLayer {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        (*self.source_name).hash(state);
        self.data.hash(state);
    }
}

/// Universe discovery layer PDU.
#[derive(Eq, PartialEq, Debug)]
pub struct UniverseDiscoveryPacketUniverseDiscoveryLayer {
    /// Current page of the discovery packet.
    pub page: u8,

    /// The number of the final page.
    pub last_page: u8,

    /// List of universes.
    pub universes: Vec<Universe, DISCOVERY_UNI_PER_PAGE>,
}

// Calculate the indexes of the fields within the buffer based on the size of the fields previous.
// Constants are replaced inline so this increases readability by removing magic numbers without affecting runtime performance.
// Theses indexes are only valid within the scope of this part of the protocol (UniverseDiscoveryPacketUniverseDiscoveryLayer).
const E131_DISCOVERY_LAYER_VECTOR_FIELD_INDEX: usize = E131_PDU_LENGTH_FLAGS_LENGTH;
const E131_DISCOVERY_LAYER_PAGE_FIELD_INDEX: usize = E131_DISCOVERY_LAYER_VECTOR_FIELD_INDEX + E131_DISCOVERY_LAYER_VECTOR_FIELD_LENGTH;
const E131_DISCOVERY_LAYER_LAST_PAGE_FIELD_INDEX: usize = E131_DISCOVERY_LAYER_PAGE_FIELD_INDEX + E131_DISCOVERY_LAYER_PAGE_FIELD_LENGTH;
const E131_DISCOVERY_LAYER_UNIVERSE_LIST_FIELD_INDEX: usize =
    E131_DISCOVERY_LAYER_LAST_PAGE_FIELD_INDEX + E131_DISCOVERY_LAYER_LAST_PAGE_FIELD_LENGTH;

impl Pdu for UniverseDiscoveryPacketUniverseDiscoveryLayer {
    fn parse(buf: &[u8]) -> Result<UniverseDiscoveryPacketUniverseDiscoveryLayer, ParsePackError> {
        // Length and Vector
        let PduInfo { length, vector } = PduInfo::new(buf, E131_DISCOVERY_LAYER_VECTOR_FIELD_LENGTH)?;
        if buf.len() != length {
            Err(InsufficientData::InvalidAmountOfDataBytes {
                should_be: length,
                actual: buf.len(),
            })?;
        }

        if vector != VECTOR_UNIVERSE_DISCOVERY_UNIVERSE_LIST {
            Err(ParsePackError::PduInvalidVector(vector))?;
        }

        if !(E131_UNIVERSE_DISCOVERY_LAYER_MIN_LENGTH..=E131_UNIVERSE_DISCOVERY_LAYER_MAX_LENGTH).contains(&length) {
            Err(ParsePackError::PduInvalidLength(length))?;
        }

        // Page
        let page = buf[E131_DISCOVERY_LAYER_PAGE_FIELD_INDEX];

        // Last Page
        let last_page = buf[E131_DISCOVERY_LAYER_LAST_PAGE_FIELD_INDEX];

        if page > last_page {
            Err(ParsePackError::ParseInvalidPage("Page value higher than last_page"))?;
        }

        // The number of universes, calculated by dividing the remaining space in the packet by the size of a single universe.
        let universes_length = (length - E131_DISCOVERY_LAYER_UNIVERSE_LIST_FIELD_INDEX) / E131_UNIVERSE_FIELD_LENGTH;
        let universes = parse_universe_list(&buf[E131_DISCOVERY_LAYER_UNIVERSE_LIST_FIELD_INDEX..], universes_length)?;

        Ok(UniverseDiscoveryPacketUniverseDiscoveryLayer {
            page,
            last_page,
            universes,
        })
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ParsePackError> {
        if self.universes.len() > DISCOVERY_UNI_PER_PAGE {
            Err(InvalidData::TooManyUniversesInDiscoveryPage)?;
        }

        if buf.len() < self.len() {
            Err(ParsePackError::PackBufferInsufficient(
                "UniverseDiscoveryPacketUniverseDiscoveryLayer pack buffer insufficient",
            ))?;
        }

        // Flags and Length
        let flags_and_length = NetworkEndian::read_u16(&[E131_PDU_FLAGS, 0x0]) | (self.len() as u16) & 0x0fff;
        NetworkEndian::write_u16(&mut buf[0..E131_DISCOVERY_FRAMING_LAYER_VECTOR_FIELD_INDEX], flags_and_length);

        // Vector
        NetworkEndian::write_u32(
            &mut buf[E131_DISCOVERY_LAYER_VECTOR_FIELD_INDEX..E131_DISCOVERY_LAYER_PAGE_FIELD_INDEX],
            VECTOR_UNIVERSE_DISCOVERY_UNIVERSE_LIST,
        );

        // Page
        buf[E131_DISCOVERY_LAYER_PAGE_FIELD_INDEX] = self.page;

        // Last Page
        buf[E131_DISCOVERY_LAYER_LAST_PAGE_FIELD_INDEX] = self.last_page;

        // Universes
        // todo!("logic bug. when self.universes is not sorted, the uniqueness check fails");
        for i in 1..self.universes.len() {
            if self.universes[i] == self.universes[i - 1] {
                Err(InvalidData::UniversesNotUnique)?;
            }
            if self.universes[i] <= self.universes[i - 1] {
                Err(InvalidData::UniversesNotSorted)?;
            }
        }

        let universes: Vec<u16, DISCOVERY_UNI_PER_PAGE> = self.universes.iter().map(Universe::get).collect();
        NetworkEndian::write_u16_into(
            &universes,
            &mut buf[E131_DISCOVERY_LAYER_UNIVERSE_LIST_FIELD_INDEX
                ..E131_DISCOVERY_LAYER_UNIVERSE_LIST_FIELD_INDEX + self.universes.len() * E131_UNIVERSE_FIELD_LENGTH],
        );

        Ok(())
    }

    fn len(&self) -> usize {
        // Length and Flags
        E131_PDU_LENGTH_FLAGS_LENGTH +
        // Vector
        E131_DISCOVERY_LAYER_VECTOR_FIELD_LENGTH +
        // Page
        E131_DISCOVERY_LAYER_PAGE_FIELD_LENGTH +
        // Last Page
        E131_DISCOVERY_LAYER_LAST_PAGE_FIELD_LENGTH +
        // Universes
        self.universes.len() * E131_UNIVERSE_FIELD_LENGTH
    }
}

impl Clone for UniverseDiscoveryPacketUniverseDiscoveryLayer {
    fn clone(&self) -> Self {
        UniverseDiscoveryPacketUniverseDiscoveryLayer {
            page: self.page,
            last_page: self.last_page,
            universes: self.universes.clone(),
        }
    }
}

impl Hash for UniverseDiscoveryPacketUniverseDiscoveryLayer {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.page.hash(state);
        self.last_page.hash(state);
        (*self.universes).hash(state);
    }
}

/// Takes the given buffer representing the "List of Universe" field in an ANSI E1.31-2018 discovery packet and parses it into the universe values.
///
/// This enforces the requirement from ANSI E1.31-2018 Section 8.5 that the universes must be numerically sorted.
///
/// # Arguments
/// buf: The byte buffer to parse into the universe.
/// length: The number of universes to attempt to parse from the buffer.
///
/// # Errors
/// ParseInvalidUniverseOrder: If the universes are not sorted in ascending order with no duplicates.
///
/// ParseInsufficientData: If the buffer doesn't contain sufficient bytes and so cannot be parsed into the specified number of u16 universes.
fn parse_universe_list(buf: &[u8], length: usize) -> Result<Vec<Universe, DISCOVERY_UNI_PER_PAGE>, ParsePackError> {
    let mut universes = Vec::new();
    let mut i = 0;

    // Last_universe starts as a placeholder value that is guaranteed to be less than the lowest possible advertised universe.
    // Cannot use 0 even though under ANSI E1.31-2018 it cannot be used for data or as a sync_address as it is reserved for future use
    // so may be used in future.
    let mut last_universe: i32 = -1;

    if buf.len() < length * E131_UNIVERSE_FIELD_LENGTH {
        Err(InsufficientData::BufferTooShortForNumberOfUniverses {
            should_be: buf.len(),
            actual: length,
        })?;
    }

    while i < (length * E131_UNIVERSE_FIELD_LENGTH) {
        let u = NetworkEndian::read_u16(&buf[i..i + E131_UNIVERSE_FIELD_LENGTH]);

        if (u as i32) > last_universe {
            // Enforce assending ordering of universes as per ANSI E1.31-2018 Section 8.5.
            universes.push(Universe::try_from(u)?).expect("should be enough capacity");
            last_universe = u as i32;
            i += E131_UNIVERSE_FIELD_LENGTH; // Jump to the next universe.
        } else {
            Err(ParsePackError::ParseInvalidUniverseOrder(Universe::try_from(u)?))?;
        }
    }

    Ok(universes.into())
}

#[cfg(test)]
mod test {
    use core::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
        time::Duration,
    };

    use super::*;
    use crate::{
        e131_definitions::{
            ACN_SDT_MULTICAST_PORT, E131_NETWORK_DATA_LOSS_TIMEOUT, E131_UNIVERSE_DISCOVERY_INTERVAL, VECTOR_DMP_SET_PROPERTY,
            VECTOR_E131_DATA_PACKET, VECTOR_E131_EXTENDED_DISCOVERY, VECTOR_E131_EXTENDED_SYNCHRONIZATION,
            VECTOR_UNIVERSE_DISCOVERY_UNIVERSE_LIST,
        },
        universe::UniverseError,
    };

    /// The universe_to tests below check that the conversion from a universe to an IPv6 or IPv4 multicast address is done as
    /// per ANSI E1.31-2018 Section 9.3.1 Table 9-10 (IPv4) and ANSI E1.31-2018 Section 9.3.2 Table 9-11 + Table 9-12.
    #[test]
    fn test_universe_to_ipv4_lowest_byte_normal() {
        let val: u16 = 119;
        let universe = Universe::try_from(val).expect("Valid value for universe");

        let address = universe.to_ipv4_multicast_addr();
        assert!(address.as_socket().unwrap().ip().is_multicast());

        assert_eq!(
            address.as_socket_ipv4().unwrap(),
            SocketAddrV4::new(
                Ipv4Addr::new(239, 255, (val / 256) as u8, (val % 256) as u8),
                ACN_SDT_MULTICAST_PORT
            )
        );
    }

    #[test]
    fn test_universe_to_ip_ipv4_both_bytes_normal() {
        let val: u16 = 300;
        let universe = Universe::try_from(val).expect("Valid value for universe");

        let address = universe.to_ipv4_multicast_addr();
        assert!(address.as_socket().unwrap().ip().is_multicast());

        assert_eq!(
            address.as_socket_ipv4().unwrap(),
            SocketAddrV4::new(
                Ipv4Addr::new(239, 255, (val / 256) as u8, (val % 256) as u8),
                ACN_SDT_MULTICAST_PORT
            )
        );
    }

    #[test]
    fn test_universe_to_ip_ipv4_limit_high() {
        let res = Universe::E131_MAX_MULTICAST_UNIVERSE.to_ipv4_multicast_addr();
        assert!(res.as_socket().unwrap().ip().is_multicast());

        assert_eq!(
            res.as_socket_ipv4().unwrap(),
            SocketAddrV4::new(
                Ipv4Addr::new(
                    239,
                    255,
                    (Universe::E131_MAX_MULTICAST_UNIVERSE_RAW / 256) as u8,
                    (Universe::E131_MAX_MULTICAST_UNIVERSE_RAW % 256) as u8
                ),
                ACN_SDT_MULTICAST_PORT
            )
        );
    }

    #[test]
    fn test_universe_to_ip_ipv4_limit_low() {
        let res = Universe::E131_MIN_MULTICAST_UNIVERSE.to_ipv4_multicast_addr();

        assert!(res.as_socket().unwrap().ip().is_multicast());

        assert_eq!(
            res.as_socket_ipv4().unwrap(),
            SocketAddrV4::new(
                Ipv4Addr::new(
                    239,
                    255,
                    (Universe::E131_MIN_MULTICAST_UNIVERSE_RAW / 256) as u8,
                    (Universe::E131_MIN_MULTICAST_UNIVERSE_RAW % 256) as u8
                ),
                ACN_SDT_MULTICAST_PORT
            )
        );
    }

    #[test]
    fn test_universe_to_ip_ipv4_out_range_low() {
        let result = Universe::try_from(0);

        assert!(
            matches!(result, Err(UniverseError::InvalidValue(_))),
            "Universe must be higher than {}",
            Universe::E131_MIN_MULTICAST_UNIVERSE_RAW
        );
    }

    #[test]
    fn test_universe_to_ip_ipv4_out_range_high() {
        let result = Universe::try_from(Universe::E131_MAX_MULTICAST_UNIVERSE_RAW + 10);
        // let result = universe_to_ipv4_multicast_addr(E131_MAX_MULTICAST_UNIVERSE + 10);

        assert!(
            matches!(result, Err(UniverseError::InvalidValue(_))),
            "Universe must be lower than {}",
            Universe::E131_MAX_MULTICAST_UNIVERSE_RAW
        );
    }

    #[test]
    fn test_universe_to_ipv6_lowest_byte_normal() {
        let val: u16 = 119;

        let universe = Universe::try_from(val).expect("Valid value for universe");
        let address = universe.to_ipv6_multicast_addr();

        assert!(address.as_socket().unwrap().ip().is_multicast());

        let low_16: u16 = ((val / 256) << 8) | (val % 256);

        assert_eq!(
            address.as_socket_ipv6().unwrap(),
            SocketAddrV6::new(Ipv6Addr::new(0xFF18, 0, 0, 0, 0, 0, 0x8300, low_16), ACN_SDT_MULTICAST_PORT, 0, 0)
        );
    }

    #[test]
    fn test_universe_to_ip_ipv6_both_bytes_normal() {
        let val: u16 = 300;
        let universe = Universe::try_from(val).expect("Valid value for universe");
        let address = universe.to_ipv6_multicast_addr();

        assert!(address.as_socket().unwrap().ip().is_multicast());

        let low_16: u16 = ((val / 256) << 8) | (val % 256);

        assert_eq!(
            address.as_socket_ipv6().unwrap(),
            SocketAddrV6::new(Ipv6Addr::new(0xFF18, 0, 0, 0, 0, 0, 0x8300, low_16), ACN_SDT_MULTICAST_PORT, 0, 0)
        );
    }

    #[test]
    fn test_universe_to_ip_ipv6_limit_high() {
        let address = Universe::E131_MAX_MULTICAST_UNIVERSE.to_ipv6_multicast_addr();

        assert!(address.as_socket().unwrap().ip().is_multicast());

        let low_16: u16 = ((Universe::E131_MAX_MULTICAST_UNIVERSE_RAW / 256) << 8) | (Universe::E131_MAX_MULTICAST_UNIVERSE_RAW % 256);

        assert_eq!(
            address.as_socket_ipv6().unwrap(),
            SocketAddrV6::new(Ipv6Addr::new(0xFF18, 0, 0, 0, 0, 0, 0x8300, low_16), ACN_SDT_MULTICAST_PORT, 0, 0)
        );
    }

    #[test]
    fn test_universe_to_ip_ipv6_limit_low() {
        let address = Universe::E131_MIN_MULTICAST_UNIVERSE.to_ipv6_multicast_addr();

        assert!(address.as_socket().unwrap().ip().is_multicast());

        let low_16: u16 = ((Universe::E131_MIN_MULTICAST_UNIVERSE_RAW / 256) << 8) | (Universe::E131_MIN_MULTICAST_UNIVERSE_RAW % 256);

        assert_eq!(
            address.as_socket_ipv6().unwrap(),
            SocketAddrV6::new(Ipv6Addr::new(0xFF18, 0, 0, 0, 0, 0, 0x8300, low_16), ACN_SDT_MULTICAST_PORT, 0, 0)
        );
    }

    #[test]
    fn test_universe_to_ip_ipv6_out_range_low() {
        let result = Universe::try_from(0);

        assert!(
            matches!(result, Err(UniverseError::InvalidValue(_))),
            "Universe must be higher than {}",
            Universe::E131_MIN_MULTICAST_UNIVERSE_RAW
        );
    }

    #[test]
    fn test_universe_to_ip_ipv6_out_range_high() {
        let result = Universe::try_from(Universe::E131_MAX_MULTICAST_UNIVERSE_RAW + 10);

        assert!(
            matches!(result, Err(UniverseError::InvalidValue(_))),
            "Universe must be lower than {}",
            Universe::E131_MAX_MULTICAST_UNIVERSE_RAW
        );
    }

    /// Verifies that the parameters are set correctly as per ANSI E1.31-2018 Appendix A: Defined Parameters (Normative).
    /// This test is particularly useful at the maintenance stage as it will flag up if any protocol defined constant is changed.
    #[test]
    fn check_ansi_e131_2018_parameter_values() {
        assert_eq!(VECTOR_ROOT_E131_DATA, 0x0000_0004);
        assert_eq!(VECTOR_ROOT_E131_EXTENDED, 0x0000_0008);
        assert_eq!(VECTOR_DMP_SET_PROPERTY, 0x02);
        assert_eq!(VECTOR_E131_DATA_PACKET, 0x0000_0002);
        assert_eq!(VECTOR_E131_EXTENDED_SYNCHRONIZATION, 0x0000_0001);
        assert_eq!(VECTOR_E131_EXTENDED_DISCOVERY, 0x0000_0002);
        assert_eq!(VECTOR_UNIVERSE_DISCOVERY_UNIVERSE_LIST, 0x0000_0001);
        assert_eq!(E131_UNIVERSE_DISCOVERY_INTERVAL, Duration::from_secs(10));
        assert_eq!(E131_NETWORK_DATA_LOSS_TIMEOUT, Duration::from_millis(2500));
        assert_eq!(Universe::E131_DISCOVERY_UNIVERSE_RAW, 64214);
        assert_eq!(ACN_SDT_MULTICAST_PORT, 5568);
    }
}
