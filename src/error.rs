// Copyright 2020 sacn Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// This file was created as part of a University of St Andrews Computer Science BSC Senior Honours Dissertation Project.

//! The errors used within the SacnLibrary. The ErrorKind subsection of this within the documentation contains details of all the errors.
//!
//! Errors from external sources are wrapped within this error-chain.
//!
//! Io errors from std::io::Error are wrapped within Io(::std::io::Error)
//!
//! String errors from std::str::Utf8Error are wrapped within Str(::std::str::Utf8Error)
//!
//! Uuid errors from uuid::ParseError are wrapped within Uuid(uuid::ParseError)
//!
//!
//! ParsePack related errors come within their own family wrapped inside this error to allow easy matching (can just match for SacnParsePackError rather than a specific).
//!
//! SacnParsePackError(sacn_parse_pack_error::Error, sacn_parse_pack_error::ErrorKind)
//!
//! Uses the error-chain crate to allow errors to allow more informative backtraces through error chaining.
//! https://docs.rs/error-chain/0.12.2/error_chain/

/// UUID library used to handle the UUID's used in the CID fields, used here so that error can include the cid in messages.
use uuid::Uuid;

use crate::{
    priority::PriorityError,
    sacn_parse_pack_error::ParsePackError,
    source_name::SourceNameError,
    universe::{Universe, UniverseError},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // Allow IO errors to be used with the error-chain system.
    #[error("std error: {0:?}")]
    Io(#[from] std::io::Error),

    // Allow standard string library errors to be used with the error-chain system.
    #[error("str error: {0:?}")]
    Utf8(#[from] core::str::Utf8Error),

    // Allow UUID library to be used with error-chain system.
    #[error("uuid error: {0:?}")]
    Uuid(#[from] uuid::Error),

    /// All parse/pack errors live within the same chain ('family') of errors as described in sacn_parse_packet_error.
    #[error("sacn parse error: {0:?}")]
    SacnParsePackError(#[from] ParsePackError),

    /// Error with source
    #[error("source error: {0:?}")]
    SourceError(#[from] SourceNameError),

    /// Error with universe
    #[error("universe error: {0:?}")]
    UniverseError(#[from] UniverseError),

    /// Attempted to perform an action using a priority value that is invalid. For example sending with a priority > 200.
    /// This is distinct from the SacnParsePackError(ParseInvalidPriority) as it is for a local use of an invalid priority
    /// rather than receiving an invalid priority from another source.
    #[error("sync address error: {0:?}")]
    PriorityError(#[from] PriorityError),

    /// Failed to send sync packet
    #[error("Failed to send sync packet")]
    SendSyncPacket(#[source] std::io::Error),

    /// Failed to unicast data
    #[error("Failed to unicast data")]
    SendUnicastData(#[source] std::io::Error),

    /// Failed to multicast data
    #[error("Failed to multicast data")]
    SendMulticastData(#[source] std::io::Error),

    /// Synchronisation universe not allowed
    #[error("Synchronisation universe not allowed")]
    SyncUniverseNotAllowed(#[source] alloc::boxed::Box<Error>),

    /// Failed to sent a timeout value for the receiver
    #[error("Failed to sent a timeout value for the receiver")]
    SendTimeoutValue(#[source] alloc::boxed::Box<Error>),

    /// Used to indicate that the limit for the number of supported sources has been reached.
    /// This is based on unique CID values.
    /// as per ANSI E1.31-2018 Section 6.2.3.3.
    ///
    /// # Arguments
    /// msg: A string describing why the sources exceeded error was returned.
    #[error("Limit for the number of supported sources has been reached, msg: {0}")]
    SourcesExceededError(String),

    /// A source was discovered by a receiver with the announce_discovery_flag set to true.
    ///
    /// # Arguments
    /// source_name: The name of the source discovered.
    #[error("A source was discovered by a receiver with the announce_discovery_flag set to true, source name: {0}")]
    SourceDiscovered(String),

    /// Attempted to exceed the capacity of a single universe (packet::UNIVERSE_CHANNEL_CAPACITY).
    ///
    /// # Arguments
    /// msg: A string describing why/how the universe capacity was exceeded.
    #[error("Attempted to exceed the capacity of a single universe, msg: {0}")]
    ExceedUniverseCapacity(String),

    /// Attempted to use a universe that wasn't first registered for use.
    /// To send from a universe with a sender it must first be registered. This allows universe discovery adverts to include the universe.
    ///
    /// # Arguments
    /// msg: A string describing why the error was returned.
    #[error("Attempted to use a universe that wasn't first registered for use, msg: {0}")]
    UniverseNotRegistered(Universe),

    /// Attempted to call [`crate::receive::SacnReceiver::recv``] with only the discovery universe being registered.
    ///
    /// This means that having no timeout may lead to no data ever being received and so this method blocking forever
    /// to prevent this likely unintended behaviour this error is thrown
    #[error("Attempted to use receive only the discovery universe.")]
    OnlyDiscoveryUniverseRegistered,

    /// Ip version (ipv4 or ipv6) used when the other is expected.
    ///
    /// # Arguments
    /// msg: A string describing the situation where the wrong IpVersion was encountered.
    #[error("Ip version (ipv4 or ipv6) used when the other is expected, msg: {0}")]
    IpVersionError(String),

    /// Attempted to use an unsupported (not Ipv4 or Ipv6) IP version.
    ///
    /// # Arguments
    /// msg: A string describing the situation where an unsupported IP version is used.
    #[error("Attempted to use an unsupported (not Ipv4 or Ipv6) IP version, msg: {0}")]
    UnsupportedIpVersion(String),

    /// Attempted to use a sender which has already been terminated.
    ///
    /// # Arguments
    /// msg: A string describing why the error was returned.
    #[error("Attempted to use a sender which has already been terminated, msg: {0}")]
    SenderAlreadyTerminated(String),

    /// An error was encountered when attempting to merge DMX data together.
    ///
    /// # Arguments
    /// msg: A string describing why the error was returned.
    #[error("Error when merging DMX data, msg: {0}")]
    DmxMergeError(String),

    /// Packet was received out of sequence and so should be discarded.
    ///
    /// # Arguments
    /// msg: A string describing why the error was returned.
    #[error("Packet was received out of sequence and so should be discarded, msg: {0}")]
    OutOfSequence(String),

    /// A source terminated a universe and this was detected when trying to receive data.
    /// This is only returned if the announce_stream_termination flag is set to true (default false).
    ///
    /// # Arguments
    ///
    /// src_cid: The CID of the source which sent the termination packet.
    ///
    /// uni: The universe that the termination packet is for.
    #[error("Source cid: {src_cid:?} terminated universe: {universe}")]
    UniverseTerminated { src_cid: Uuid, universe: Universe },

    /// A source universe timed out as no data was received on that universe within E131_NETWORK_DATA_LOSS_TIMEOUT as per ANSI E1.31-2018 Section 6.7.1.
    ///
    /// # Arguments
    ///
    /// src_cid: The CID of the source which timed out.
    ///
    /// uni: The universe that timed out.
    #[error("(Source,Universe) timed out: ({src_cid},{universe})")]
    UniverseTimeout { src_cid: Uuid, universe: Universe },

    /// When looking for a specific universe it wasn't found. This might happen for example if trying to mute a universe on a receiver that
    /// wasn't being listened to.
    ///
    /// # Arguments
    /// msg: A message describing why this error was returned.
    #[error("When looking for a specific universe it wasn't found, msg: {0}")]
    UniverseNotFound(String),

    /// Attempted to find a source and failed. This might happen on a receiver for example if trying to remove a source which was never
    /// registered or discovered.
    ///
    /// # Arguments
    /// msg: A message describing why this error was returned / when the source was not found.
    #[error("Source not found, msg: {0}")]
    SourceNotFound(String),

    /// Thrown to indicate that the operation attempted is unsupported on the current OS
    /// For example this is used to indicate that multicast-IPv6 isn't supported current on Windows.
    ///
    /// # Arguments
    /// msg: A message describing why this error was returned / the operation that was not supported.
    #[error("Operation attempted is unsupported on the current OS, msg: {0}")]
    OsOperationUnsupported(String),

    /// Thrown to indicate that the source has corrupted for the reason specified by the error chain.
    /// This is currently only thrown if the source mutex is poisoned by a thread with access panic-ing.
    /// This prevents the panic propagating to the user of this library and allows them to handle it appropriately
    /// such as by creating a new source.
    ///
    /// # Arguments
    /// msg: A message providing further details (if any) as to why the SourceCorrupt error was returned.
    #[error("The sACN source has corrupted due to an internal panic! and should no longer be used, {0}")]
    SourceCorrupt(String),
}
