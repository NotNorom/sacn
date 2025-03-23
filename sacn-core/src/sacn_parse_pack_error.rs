//! The errors within the sACN crate related to parse/pack errors.

// Copyright 2020 sacn Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// This file was created as part of a University of St Andrews Computer Science BSC Senior Honours Dissertation Project.

use core::str::Utf8Error;

use crate::{
    e131_definitions::{DISCOVERY_UNI_PER_PAGE, UNIVERSE_CHANNEL_CAPACITY},
    priority::PriorityError,
    source_name::SourceNameError,
    universe::{UniverseId, UniverseError},
};

/// The errors used within the SacnLibrary specifically those related to parsing and packeting packets received/sent on the network.
#[derive(Debug, thiserror::Error)]
pub enum ParsePackError {
    /// When parsing packet invalid data encountered.
    ///
    /// # Arguments
    /// msg: A message providing further details (if any) as to what data was invalid.
    #[error("Error when parsing data into packet, msg: {0}")]
    ParseInvalidData(&'static str),

    /// Attempted to parse a priority value that is outwith the allowed range of [0, E131_MAX_PRIORITY].
    /// As per ANSI E1.31-2018 Section 6.2.3
    ///
    /// # Arguments
    /// msg: A message providing further details (if any) as to why the priority valid was invalid.
    #[error("Attempted to parse a priority value that is outwith the allowed range of [0, 200], msg: {0}")]
    ParseInvalidPriority(#[from] PriorityError),

    /// Attempted to parse a page value that is invalid - e.g. the page value is higher than the last_page value.
    ///
    /// # Arguments
    /// A message providing further details (if any) as to why the page was invalid.
    #[error("Error when parsing page value, msg: {0}")]
    ParseInvalidPage(&'static str),

    /// Attempted to parse a universe value that is outwith the allowed range of [1, E131_MAX_MULTICAST_UNIVERSE].
    /// As per ANSI E1.31-2018 Section 9.1.1.
    ///
    /// # Arguments
    /// A message providing further details (if any) as to why the universe field was invalid.
    #[error("Attempted to parse a universe value that is outwith the allowed range of [1, 63999], msg: {0}")]
    ParseInvalidUniverse(#[from] UniverseError),

    /// Attempted to parse a packet with an invalid ordering of universes.
    /// For example a discovery packet where the universes aren't correctly ordered in assending order.
    ///
    /// # Arguments
    /// The universe that's out of order
    #[error("Universe {} is out of order, discovery packet universe list must be in accending order!", .0)]
    ParseInvalidUniverseOrder(UniverseId),

    /// When packing a packet into a buffer invalid data encountered.
    ///
    /// # Arguments
    /// A message providing further details (if any) as to why the data couldn't be packed.
    #[error("When packing a packet into a buffer invalid data encountered, msg: {0}")]
    PackInvalidData(#[from] InvalidData),

    /// Too many universes in a universe discovery page
    #[error("Maximum {DISCOVERY_UNI_PER_PAGE} universes allowed per discovery page, but got {0}")]
    TooManyDiscoveryUniverses(usize),

    /// Too many values in a dmx data packet
    #[error("Too many DMX values. Maximum amount is {}", UNIVERSE_CHANNEL_CAPACITY - 1)]
    TooManyDMXValues(usize),

    /// Supplied buffer is not large enough to pack packet into.
    ///
    /// # Arguments
    /// msg: A message providing further details (if any) as to why the pack buffer is insufficient.
    #[error("Supplied buffer is not large enough to pack packet into, msg: {0}")]
    PackBufferInsufficient(&'static str),

    /// Supplied buffer does not contain enough data.
    ///
    /// # Arguments
    /// msg: A message providing further details (if any) as to why there was insufficient data for parsing.
    #[error("Supplied buffer does not contain enough data, msg: {0}")]
    ParseInsufficientData(#[from] InsufficientData),

    /// Received PDU flags are invalid for parsing.
    ///
    /// # Arguments
    /// flags: The flags that were found which are invalid.
    #[error("PDU Flags {0:#b} are invalid for parsing")]
    ParsePduInvalidFlags(u8),

    /// Received PDU length is invalid.
    ///
    /// # Arguments
    /// len: The length provided in the Pdu which is invalid.
    #[error("PDU Length {0} is invalid")]
    PduInvalidLength(usize),

    /// Received PDU vector is invalid/unsupported by this library.
    ///
    /// # Arguments
    /// vec: The vector parsed which is invalid / cannot be used.
    #[error("Vector {0:#x} not supported")]
    PduInvalidVector(u32),

    /// Error parsing the received UUID.
    ///
    /// # Arguments
    /// msg: A message providing further details (if any) as to why the uuid (used for CID) couldn't be parsed.
    #[error("Error parsing the received UUID, msg: {0}")]
    Uuid(#[from] uuid::Error),

    /// Error parsing received UTF8 string.
    ///
    /// # Arguments
    /// msg: A message providing further details (if any) as to why the string couldn't be parsed.
    #[error("Error parsing received UTF8 string, msg: {0}")]
    Utf8(#[from] Utf8Error),

    /// Source name in packet was invalid, for example due to not being null terminated.
    ///
    /// # Arguments
    /// msg: A message providing further details (if any) as to why the source name was invalid.
    #[error("Attempted to parse invalid source name, msg: {0}")]
    SourceName(#[from] SourceNameError),
}

/// Specific reasons why data is invalid
#[derive(Debug, thiserror::Error)]
pub enum InvalidData {
    /// Universes are not unique
    #[error("Universes are not unique")]
    UniversesNotUnique,
    /// Universes are not sorted
    #[error("Universes are not sorted")]
    UniversesNotSorted,
    /// Too many universes in discovery page
    #[error("Too many universes in discovery page. Max is {}", DISCOVERY_UNI_PER_PAGE)]
    TooManyUniversesInDiscoveryPage,
    /// Too many DMX values in package
    #[error("Too many DMX values. Max is {}", UNIVERSE_CHANNEL_CAPACITY)]
    TooManyDmxValues,
}

/// Specific reasons why there is not enough data
#[derive(Debug, thiserror::Error)]
pub enum InsufficientData {
    /// Insufficient data when parsing pdu_info, no flags or length field
    #[error("Insufficient data when parsing pdu_info, no flags or length field")]
    PduInfoTooShort,
    /// Buffer contains insufficient data based on E131 framing layer pdu length field
    #[error("Buffer contains insufficient data based on E131 framing layer pdu length field")]
    BufferTooShortBasedOnE131FramingLayer,
    /// Buffer contains insufficient data based on data packet framing layer pdu length field
    #[error("Buffer contains insufficient data based on data packet framing layer pdu length field")]
    BufferTooShortBasedOnDataFramingLayer,
    /// Buffer contains insufficient data based on data packet dmp layer pdu length field
    #[error("Buffer contains insufficient data based on data packet dmp layer pdu length field")]
    BufferTooShortBasedOnDataDmpLayer,
    /// Buffer contains insufficient data based on synchronisation packet framing layer pdu length field
    #[error("Buffer contains insufficient data based on synchronisation packet framing layer pdu length field")]
    BufferTooShortBasedOnSyncFramingLayer,
    /// Buffer contains insufficient data based on universe discovery packet framing layer pdu length field
    #[error("Buffer contains insufficient data based on universe discovery packet framing layer pdu length field")]
    BufferTooShortBasedOnDiscoveryFramingLayer,
    /// Buffer contains insufficient data based on ACN root layer pdu length field
    #[error("Buffer contains insufficient data based on ACN root layer pdu length field")]
    BufferTooShortBasedOnRootLayer,
    /// Insufficient data for ACN root layer preamble
    #[error("Insufficient data for ACN root layer preamble")]
    TooShortForPreamble,
    /// Invalid data packet dmp layer property value count
    #[error(
        "Invalid data packet dmp layer property value count, pdu length indicates {} property values, property value count field indicates {} property values",
        should_be,
        actual
    )]
    InvalidDmpLayerPropertyCount {
        /// amount of expected property values
        should_be: usize,
        /// amount of actual property values
        actual: usize,
    },
    /// Buffer contains incorrect amount of data based on universe discovery packet universe discovery layer pdu length field
    #[error(
        "Buffer contains incorrect amount of data ({} bytes) based on universe discovery packet universe discovery layer pdu length field ({} bytes)",
        actual,
        should_be
    )]
    InvalidAmountOfDataBytes {
        /// amount of expected bytes
        should_be: usize,
        /// amount of actual bytes
        actual: usize,
    },
    /// The given buffer cannot be parsed into the given number of universes
    #[error(
        "The given buffer of length {} bytes cannot be parsed into the given number of universes {}",
        buffer_length,
        universe_count
    )]
    BufferTooShortForNumberOfUniverses {
        /// amount of expected universes
        universe_count: usize,
        /// size of buffer
        buffer_length: usize,
    },
}
