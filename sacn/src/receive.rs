//! The receive module handles the receiving of sACN on the network.

// Copyright 2020 sacn Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// This file was created as part of a University of St Andrews Computer Science BSC Senior Honours Dissertation Project.

// Report point: There is no guarantees made by the protocol that different sources will have different names.
// As names are used to match universe discovery packets this means that if 2 sources have the same name it won't
// be clear which one is sending what universes as they will appear as one source.

// Report point: partially discovered sources are only marked as discovered when a full set of discovery packets has been
// received, if a discovery packet is received but there are more pages the source won't be discovered until all the pages are received.
// If a page is lost this therefore means the source update / discovery in its entirety will be lost - implementation detail.

use core::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use std::{collections::HashMap, io::Read};

use sacn_core::{
    discovery::{DiscoveredSacnSource, UniversePage},
    dmx_data::{DMXData, MergeError},
    e131_definitions::{ACN_SDT_MULTICAST_PORT, MAXIMUM_PACKET_SIZE},
    source_name::SourceName,
    time::{Duration, Timestamp},
};
/// Socket 2 used for the underlying UDP socket that sACN is sent over.
use socket2::{Domain, SockAddr, Socket, Type};
/// The uuid crate is used for working with/generating UUIDs which sACN uses as part of the cid field in the protocol.
/// This is used for uniquely identifying sources when counting sequence numbers.
use uuid::Uuid;

use crate::{
    e131_definitions::{
        E131_NETWORK_DATA_LOSS_TIMEOUT, E131_SEQ_DIFF_DISCARD_LOWER_BOUND, E131_SEQ_DIFF_DISCARD_UPPER_BOUND,
        UNIVERSE_DISCOVERY_SOURCE_TIMEOUT,
    },
    error::ReceiveError,
    packet::{
        AcnRootLayerProtocol, DataPacketFramingLayer, E131RootLayer, E131RootLayerData, SynchronizationPacketFramingLayer,
        UniverseDiscoveryPacketFramingLayer, UniverseDiscoveryPacketUniverseDiscoveryLayer,
    },
    universe_id::UniverseId,
};

/// The default size of the buffer used to receive E1.31 packets.
/// 1143 bytes is biggest packet required as per Section 8 of ANSI E1.31-2018, aligned to 64 bit that is 1144 bytes.
pub const RCV_BUF_DEFAULT_SIZE: usize = MAXIMUM_PACKET_SIZE;

/// DMX payload size in bytes (512 bytes of data + 1 byte start code).
pub const DMX_PAYLOAD_SIZE: usize = 513;

/// The default value of the process_preview_data flag.
const PROCESS_PREVIEW_DATA_DEFAULT: bool = false;

/// The default value of the announce_source_discovery flag.
/// Defaults to false based on the assumption that often receivers won't have any immediate response/checks to do on a source
/// announcing itself (every source does this approximately every 10 seconds as per the E131_DISCOVERY_INTERVAL).
const ANNOUNCE_SOURCE_DISCOVERY_DEFAULT: bool = false;

/// The default value of the announce_stream_termination flag.
/// Defaults to false based on the assumption that often receivers will want to ignore termination from a source based on there
/// being multiple possible sources.
const ANNOUNCE_STREAM_TERMINATION_DEFAULT: bool = false;

/// The default value of the announce_timeout flag.
const ANNOUNCE_TIMEOUT_DEFAULT: bool = false;

/// The sequence number assigned by the receiver to a new source before it has processed the sequence numbers of any data from that source.
///
/// This should be set to the value before the initial expected sequence number from a source. Can't do this using underflow as forbidden in Rust.
const INITIAL_SEQUENCE_NUMBER: u8 = 255;

/// If a packet for a universe is waiting to be synchronised and then another packet is received with the same universe and synchronisation address
/// this situation must be handled. By default the implementation discards the lowest priority packet and if equal priority it discards the oldest
/// packet as per ANSI E1.31-2018 Section 6.2.3.
///
/// This can be changed by providing a new function to handle the situation of the user implementing a custom merge/arbitration algorithm as per
/// ANSI E1.31-2018 Section 6.2.3.2.
const DEFAULT_MERGE_FUNC: fn(&DMXData, &DMXData) -> Result<DMXData, MergeError> = DMXData::merge_discard_lowest_priority_then_previous;

/// Allows receiving dmx or other (different startcode) data using sacn.
///
/// # Examples
///
/// ```
/// // Example showing creation of a receiver and receiving some data, as there is no sender this receiver then handles the timeout.
/// use sacn::receive::SacnReceiver;
/// use sacn::e131_definitions::ACN_SDT_MULTICAST_PORT;
/// use sacn::universe::Universe;
/// use sacn::time::Duration;
///
/// use core::net::{IpAddr, Ipv4Addr, SocketAddr};
///
/// let universe1: Universe = Universe::new(1).expect("in range");
/// let timeout: Option<Duration> = Some(Duration::from_secs(1)); // A timeout of None means blocking behaviour, some indicates the actual timeout.
///
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
///
/// let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();
///
/// dmx_rcv.listen_universes(&[universe1]).unwrap();
///
/// match dmx_rcv.recv(timeout) {
///     Err(e) => {
///         // Print out the error.
///         println!("{:?}", e);
///     }
///     Ok(p) => {
///         // Print out the packet.
///         println!("{:?}", p);
///     }
/// }
/// ```
pub struct SacnReceiver {
    /// The SacnNetworkReceiver used for handling communication with UDP / Network / Transport layer.
    receiver: SacnNetworkReceiver,

    /// Data that hasn't been passed up yet as it is waiting e.g. due to universe synchronisation.
    /// Key is the universe. A receiver may not have more than one packet waiting per data_universe.
    /// Data_universe used as key as oppose to sync universe because multiple packets might be waiting on the same sync universe
    /// and adding data by data universe is at least as common as retrieving data by sync address because in a normal setup
    /// 1 or more bits of data wait for 1 sync.
    waiting_data: HashMap<UniverseId, DMXData>,

    /// Universes that this receiver is currently listening for.
    universes: Vec<UniverseId>,

    /// Sacn sources that have been discovered by this receiver through universe discovery packets.
    discovered_sources: Vec<DiscoveredSacnSource>,

    /// The merge function used by this receiver if DMXData for the same universe and synchronisation universe is received while there
    /// is already DMXData waiting for that universe and synchronisation address.
    merge_func: fn(&DMXData, &DMXData) -> Result<DMXData, MergeError>,

    /// Sacn sources that have been partially discovered by only some of their universes being discovered so far with more pages to go.
    partially_discovered_sources: Vec<DiscoveredSacnSource>,

    /// The limit to the number of sources for which to track sequence numbers.
    /// A new source after this limit will cause a SourcesExceededError as per ANSI E1.31-2018 Section 6.2.3.3.
    source_limit: Option<usize>,

    /// The sequence numbers being tracked by this receiver for each packet type, source and universe.
    sequences: SequenceNumbering,

    /// Flag that indicates if this receiver should process packets marked as preview data.
    /// If true then the receiver will process theses packets.
    /// Returned data contains a flag to indicate if it is preview_data which can be used by the implementer to use/discard as required.
    process_preview_data: bool,

    /// Flag which indicates if a SourceDiscovered error should be thrown when receiving data and a source is discovered.
    announce_source_discovery: bool,

    /// Flag which indicates if a StreamTerminated error should be thrown if a receiver receives a stream terminated packet.
    announce_stream_termination: bool,

    /// Flag which indicates if an UniverseTimeout error should be thrown if it is detected that a source has timed out.
    announce_timeout: bool,
}

/// Used for receiving dmx or other data on a particular universe using multicast.
#[derive(Debug)]
struct SacnNetworkReceiver {
    /// The underlying UDP network socket used.
    socket: Socket,

    /// The address that this SacnNetworkReceiver is bound to.
    addr: SocketAddr,

    /// If true then this receiver supports multicast, is false then it does not.
    /// This flag is set when the receiver is created as not all environments currently support IP multicast.
    /// E.g. IPv6 Windows IP Multicast is currently unsupported.
    is_multicast_enabled: bool,
}

impl fmt::Debug for SacnReceiver {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.receiver)?;
        write!(f, "{:?}", self.waiting_data)?;
        write!(f, "{:?}", self.universes)?;
        write!(f, "{:?}", self.discovered_sources)?;
        write!(f, "{:?}", self.partially_discovered_sources)
    }
}

impl SacnReceiver {
    /// Creates a new SacnReceiver.
    ///
    /// SacnReceiverInternal is used for actually receiving the sACN data but is wrapped in SacnReceiver to allow the update thread to handle
    /// timeout etc.
    ///
    /// By default for an IPv6 address this will only receive IPv6 data but IPv4 can also be enabled by calling set_ipv6_only(false).
    /// A receiver with an IPv4 address will only receive IPv4 data.
    ///
    /// IPv6 multicast is unsupported on Windows in Rust. This is due to the underlying library (Socket2) not providing support.
    /// Since UniverseDiscovery is primarily based around multicast to receive the UniverseDiscovery packets this mechanism is expected
    /// to have limited usage when running in an Ipv6 Windows environment. The is_multicast_enabled method can be used to see if multicast
    /// is enabled or not.
    ///
    /// Arguments:
    ///     ip: The address of the interface for this receiver to join, by default this address should use the ACN_SDT_MULTICAST_PORT as defined in
    ///         ANSI E1.31-2018 Appendix A: Defined Parameters (Normative) however another address might be used in some situations.
    ///     source_limit: The limit to the number of sources, past this limit a new source will cause a SourcesExceededError as per ANSI E1.31-2018 Section 6.2.3.3.
    ///                     A source limit of None means no limit to the number of sources.
    ///
    /// # Errors
    /// Will return an InvalidInput error if the source_limit has a value of Some(0) which would indicate this receiver can never receive from any source.
    ///
    /// Will return an error if the SacnReceiver fails to bind to a socket with the given ip.
    /// For more details see socket2::Socket::new().
    ///
    /// Will return an error if the created SacnReceiver fails to listen to the E1.31_DISCOVERY_UNIVERSE.
    /// For more details see SacnReceiver::listen_universes().
    pub fn with_ip(ip: SocketAddr, source_limit: Option<usize>) -> Result<SacnReceiver, ReceiveError> {
        if let Some(x) = source_limit {
            if x == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Source_limit has a value of Some(0) which would indicate this receiver can never receive from any source",
                ))?;
            }
        }
        let mut sri = SacnReceiver {
            receiver: SacnNetworkReceiver::new(ip)?,
            waiting_data: HashMap::new(),
            universes: Vec::new(),
            discovered_sources: Vec::new(),
            merge_func: DEFAULT_MERGE_FUNC,
            partially_discovered_sources: Vec::new(),
            process_preview_data: PROCESS_PREVIEW_DATA_DEFAULT,
            source_limit,
            sequences: SequenceNumbering::new(),
            announce_source_discovery: ANNOUNCE_SOURCE_DISCOVERY_DEFAULT,
            announce_stream_termination: ANNOUNCE_STREAM_TERMINATION_DEFAULT,
            announce_timeout: ANNOUNCE_TIMEOUT_DEFAULT,
        };

        sri.listen_universes(&[UniverseId::DISCOVERY])?;

        Ok(sri)
    }

    /// Sets the value of the is_multicast_enabled flag to the given value.
    ///
    /// If set to false then the receiver won't attempt to join any more multicast groups.
    ///
    /// This method does not attempt to leave multicast groups already joined through previous listen_universe calls.
    ///
    /// # Arguments
    /// val: The new value for the is_multicast_enabled flag.
    ///
    /// # Errors
    /// Will return an OsOperationUnsupported error if attempting to set the flag to true in an environment that multicast
    /// isn't supported i.e. Ipv6 on Windows.
    pub fn set_is_multicast_enabled(&mut self, val: bool) -> Result<(), ReceiveError> {
        self.receiver.set_is_multicast_enabled(val)
    }

    /// Returns true if multicast is enabled on this receiver and false if not.
    /// This flag is set when the receiver is created as not all environments currently support IP multicast.
    /// E.g. IPv6 Windows IP Multicast is currently unsupported.
    pub fn is_multicast_enabled(&self) -> bool {
        self.receiver.is_multicast_enabled()
    }

    /// Wipes the record of discovered and sequence number tracked sources.
    /// This is one way to handle a sources exceeded condition.
    ///
    /// If you want to wipe data awaiting synchronisation then see (clear_all_waiting_data)[Self::clear_all_waiting_data].
    pub fn reset_sources(&mut self) {
        self.sequences.clear();
        self.partially_discovered_sources.clear();
        self.discovered_sources.clear();
    }

    /// Deletes all data currently waiting to be passed up - e.g. waiting for a synchronisation packet.
    ///
    /// This allows clearing all data awaiting synchronisation but without forgetting sequence numbers. To wipe sequence numbers
    /// and discovered sources see (reset_sources)[Self::reset_sources].
    ///
    /// To clear only a specific universe of waiting data see (clear_waiting_data)[Self::clear_waiting_data].
    pub fn clear_all_waiting_data(&mut self) {
        self.waiting_data.clear();
    }

    /// Clears data (if any) waiting to be passed up for the specific universe.
    ///
    /// Returns true if data was removed and false if there wasn't any data to remove for this universe.
    ///
    /// # Arguments
    /// universe: The universe that the data that is waiting was sent to.
    pub fn clear_waiting_data(&mut self, universe: UniverseId) -> bool {
        self.waiting_data.remove(&universe).is_some()
    }

    /// Sets the merge function to be used by this receiver.
    ///
    /// This merge function is called if data is waiting for a universe e.g. for synchronisation and then further data for that universe with the same
    /// synchronisation address arrives.
    ///
    /// This merge function MUST return a DmxMergeError if there is a problem merging. This error can optionally encapsulate further errors using the Error-chain system
    ///     to provide a more informative backtrace.
    ///
    /// Arguments:
    /// func: The merge function to use. Should take 2 DMXData references as arguments and return a `Result<DMXData>`.
    pub fn set_merge_fn(&mut self, func: fn(&DMXData, &DMXData) -> Result<DMXData, MergeError>) {
        self.merge_func = func;
    }

    /// Allow only receiving on Ipv6.
    pub fn set_ipv6_only(&mut self, val: bool) -> Result<(), ReceiveError> {
        self.receiver.set_only_v6(val)
    }

    /// Allows receiving from the given universe and starts listening to the multicast addresses which corresponds to the given universe.
    ///
    /// Note that if the is_multicast_enabled flag is set to false then this method will only register the universe to listen to and won't
    /// attempt to join any multicast groups.
    ///
    /// If 1 or more universes in the list are already being listened to this method will have no effect for those universes only.
    pub fn listen_universes(&mut self, universes: &[UniverseId]) -> Result<(), ReceiveError> {
        for u in universes {
            if let Err(i) = self.universes.binary_search(u) {
                // Value not found, i is the position it should be inserted
                self.universes.insert(i, *u);

                if self.is_multicast_enabled() {
                    self.receiver.listen_multicast_universe(*u)?;
                } else {
                    // If value found then don't insert to avoid duplicates.
                }
            }
        }

        Ok(())
    }

    /// Stops listening to the given universe.
    ///
    /// # Errors
    ///
    /// Returns UniverseNotFound if the given universe wasn't already being listened to.
    pub fn mute_universe(&mut self, universe: UniverseId) -> Result<(), ReceiveError> {
        match self.universes.binary_search(&universe) {
            Err(_) => {
                // Universe isn't found.
                Err(ReceiveError::UniverseNotFound(
                    "Attempted to mute a universe that wasn't already being listened to".to_string(),
                ))?
            }
            Ok(i) => {
                // If value found then don't insert to avoid duplicates.
                self.universes.remove(i);
                self.receiver.mute_multicast_universe(universe)
            }
        }
    }

    /// Stops listening to all universes.
    ///
    /// This will go through all universes in _reverse_ so every successfully
    /// muted universe can be removed without having to realloc the vec
    pub fn mute_all_universes(&mut self) -> Result<(), ReceiveError> {
        let mut end = self.universes.len();
        while end > 0 {
            end -= 1;

            let universe = self.universes[end];
            self.receiver.mute_multicast_universe(universe)?;
            self.universes.pop();
        }
        Ok(())
    }

    /// Set the process_preview_data flag to the given value.
    ///
    /// This flag indicates if this receiver should process packets marked as preview_data or should ignore them.
    ///
    /// Argument:
    /// val: The new value of process_preview_data flag.
    pub fn set_process_preview_data(&mut self, val: bool) {
        self.process_preview_data = val;
    }

    /// Checks if this receiver is currently listening to the given universe.
    ///
    /// A receiver is 'listening' to a universe if it allows that universe to be received without filtering it out.
    /// This does not mean that the multicast address for that universe is or isn't being listened to.
    ///
    /// Arguments:
    /// universe: The sACN universe to check
    ///
    /// Returns:
    /// True if the universe is being listened to by this receiver, false if not.
    pub fn is_listening(&self, universe: &UniverseId) -> bool {
        self.universes.contains(universe)
    }

    /// Attempt to receive data from any of the registered universes.
    /// This is the main method for receiving data.
    /// Any data returned will be ready to act on immediately i.e. waiting e.g. for universe synchronisation
    /// is already handled.
    ///
    /// # Errors
    /// This method will return a WouldBlock (unix) or TimedOut (windows) error if there is no data ready within the given timeout.
    /// A timeout of duration 0 will do timeout checks but otherwise will return a WouldBlock/TimedOut error without checking for data.
    ///
    /// Will return Error::SourceDiscovered error if the announce_source_discovery flag is set and a universe discovery
    /// packet is received and a source fully discovered.
    ///
    /// Will return a UniverseNotRegistered error if this method is called with an infinite timeout, no
    /// registered data universes and the announce_discovered_sources flag set to off. This is to protect the user from
    /// making this mistake leading to the method never being able to return.
    ///
    /// The method may also return an error if there is an issue setting a timeout on the receiver. See
    /// SacnNetworkReceiver::set_timeout for details.
    ///
    /// The method may also return an error if there is an issue handling the data as either a Data, Synchronisation or Discovery packet.
    /// See the SacnReceiver::handle_data_packet, SacnReceiver::handle_sync_packet and SacnReceiver::handle_universe_discovery_packet methods
    /// for details.
    ///
    /// If the announce_timeout flag is set then the recv will return a UniverseTimeout error if a source fails to send on a universe within the timeout
    /// specified by E131_NETWORK_DATA_LOSS_TIMEOUT (ANSI E1.31-2018 Appendix A).  This may not be detected immediately unless data is received for the timed-out
    /// universe from the source. If it isn't detected immediately it will be detected within an interval of E131_NETWORK_DATA_LOSS_TIMEOUT (assuming code
    /// executes in zero time).
    pub fn recv(&mut self, timeout: Option<Duration>) -> Result<Vec<DMXData>, ReceiveError> {
        let mut timeout = timeout;

        loop {
            let result = self.recv_internal(timeout);
            match result {
                Ok(ok) => match ok {
                    DataOrRetry::Data(data) => return Ok(data),
                    DataOrRetry::Retry(new_timeout) => timeout = new_timeout,
                },
                Err(err) => return Err(err),
            }
        }
    }

    /// See [Self::recv]
    fn recv_internal(&mut self, timeout: Option<Duration>) -> Result<DataOrRetry, ReceiveError> {
        if self.universes.len() == 1 && self.universes[0] == UniverseId::DISCOVERY && timeout.is_none() && !self.announce_source_discovery {
            return Err(ReceiveError::OnlyDiscoveryUniverseRegistered);
        }

        self.sequences.check_timeouts(self.announce_timeout)?;
        self.remove_expired_data();

        if timeout == Some(Duration::from_secs(0)) {
            if cfg!(target_os = "windows") {
                // Use the right expected error for the operating system.
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "No data available in given timeout",
                ))?;
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "No data available in given timeout",
                ))?;
            };
        }

        // Forces the actual timeout used for receiving from the underlying network to never exceed E131_NETWORK_DATA_LOSS_TIMEOUT.
        // This means that the timeouts for the sequence numbers will be checked at least every E131_NETWORK_DATA_LOSS_TIMEOUT even if
        // recv is called with a longer timeout.
        let actual_timeout = timeout.map_or(E131_NETWORK_DATA_LOSS_TIMEOUT, |value| value.min(E131_NETWORK_DATA_LOSS_TIMEOUT));

        self.receiver
            .set_timeout(Some(actual_timeout))
            .map_err(ReceiveError::SetTimeoutValue)?;
        let start_time = Timestamp::now();

        let mut buf: [u8; RCV_BUF_DEFAULT_SIZE] = [0; RCV_BUF_DEFAULT_SIZE];
        match self.receiver.recv(&mut buf) {
            Ok(pkt) => {
                let pdu: E131RootLayer = pkt.pdu;
                let data: E131RootLayerData = pdu.data;
                let res = match data {
                    E131RootLayerData::DataPacket(d) => self.handle_data_packet(pdu.cid, d)?,
                    E131RootLayerData::SynchronizationPacket(s) => self.handle_sync_packet(pdu.cid, s)?,
                    E131RootLayerData::UniverseDiscoveryPacket(u) => {
                        let discovered_src = self.handle_universe_discovery_packet(u);

                        match (discovered_src, self.announce_source_discovery) {
                            (Some(src), true) => return Err(ReceiveError::SourceDiscovered(src)),
                            _ => None,
                        }
                    }
                };

                if let Some(data) = res {
                    return Ok(DataOrRetry::Data(data));
                }

                let Some(timeout_duration) = timeout else {
                    // If the timeout was none then would keep looping till data is returned as the method should keep blocking till then.
                    return Ok(DataOrRetry::Retry(timeout));
                };

                // Indicates that there is no data ready to pass up yet even if a packet was received.
                // To stop recv blocking forever with a non-None timeout due to packets being received consistently (that reset the timeout)
                // within the receive timeout (e.g. universe discovery packets if the discovery interval < timeout) the timeout needs to be
                // adjusted to account for the time already taken.
                match timeout_duration.checked_sub(start_time.elapsed()) {
                    None => {
                        // Indicates that elapsed is bigger than timeout so its time to return.
                        Err(std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "No data available in given timeout",
                        ))?
                    }
                    Some(new_timeout) => Ok(DataOrRetry::Retry(Some(new_timeout))),
                }
            }
            Err(err) => self.handle_recv_error(err, timeout, start_time),
        }
    }

    /// Handles errors from calling recv on the inner socket
    fn handle_recv_error(&self, err: ReceiveError, timeout: Option<Duration>, start_time: Timestamp) -> Result<DataOrRetry, ReceiveError> {
        let ReceiveError::Io(ref s) = err else {
            // Not a timeout/wouldblock error meaning the recv should stop with the given error.
            return Err(err);
        };

        // Windows and Unix use different error types (WouldBlock/TimedOut) for the same error.
        let (std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) = s.kind() else {
            // Not a timeout/wouldblock error meaning the recv should stop with the given error.
            return Err(err);
        };

        let Some(timeout_duration) = timeout else {
            // If the timeout was none then would keep looping till data is returned as the method should keep blocking till then.
            return Ok(DataOrRetry::Retry(timeout));
        };

        match timeout_duration.checked_sub(start_time.elapsed()) {
            None => {
                // Indicates that elapsed is bigger than timeout so its time to return.
                if cfg!(target_os = "windows") {
                    // Use the right expected error for the operating system.
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "No data available in given timeout",
                    ))?
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "No data available in given timeout",
                    ))?
                }
            }
            Some(new_timeout) => Ok(DataOrRetry::Retry(Some(new_timeout))),
        }
    }

    /// Returns the current value of the announce_source_discovery flag.
    /// See (set_announce_source_discovery)[Self::set_announce_source_discovery] for an explanation of the flag.
    pub fn get_announce_source_discovery(&self) -> bool {
        self.announce_source_discovery
    }

    /// Gets all discovered sources without checking if any are timed out.
    /// As the sources may be timed out get_discovered_sources is the preferred method but this is included
    /// to allow receivers to disable universe discovery source timeouts which may be useful in very high latency networks.
    pub fn get_discovered_sources_no_check(&mut self) -> Vec<DiscoveredSacnSource> {
        self.discovered_sources.clone()
    }

    /// Returns a list of the sources that have been discovered on the network by this receiver through the E1.31 universe discovery mechanism.
    pub fn get_discovered_sources(&mut self) -> Vec<DiscoveredSacnSource> {
        self.remove_expired_sources();
        self.discovered_sources.clone()
    }

    /// Sets the value of the announce_source_discovery flag to the given value.
    ///
    /// By default this flag is false which indicates that when receiving data discovered sources through universe discovery
    ///  won't be announced by the recv method and the receivers list of discovered universes will be updated silently.
    /// If set to true then it means that a SourceDiscovered error will be thrown whenever a source is discovered through a
    ///  complete universe discovery packet.
    ///
    /// # Arguments:
    /// new_val: The new value for the announce_source_discovery flag.
    pub fn set_announce_source_discovery(&mut self, new_val: bool) {
        self.announce_source_discovery = new_val;
    }

    /// Returns the current value of the announce_timeout flag.
    /// See (set_announce_timeout)[Self::set_announce_timeout] for an explanation of the flag.
    pub fn get_announce_timeout(&self) -> bool {
        self.announce_timeout
    }

    /// Sets the value of the announce_timeout flag to the given value.
    ///
    /// By default this flag is false which means that if a universe for a source times out due to data not being sent then
    /// this will be updated on the receiver silently.
    /// If set to true then a UniverseTimeout error will be thrown when attempting to receive if it is detected that a source universe has
    /// timed out as per ANSI E1.31-2018 Section 6.7.1.
    ///
    /// # Arguments:
    /// new_val: The new value for the announce_timeout flag.
    pub fn set_announce_timeout(&mut self, new_val: bool) {
        self.announce_timeout = new_val;
    }

    /// Returns the current value of the announce_stream_termination flag.
    /// See (set_announce_stream_termination)[Self::set_announce_stream_termination] for an explanation of the flag.
    pub fn get_announce_stream_termination(&self) -> bool {
        self.announce_stream_termination
    }

    /// Sets the value of the announce_stream_termination flag to the given value.
    ///
    /// By default this flag is false. This indicates that if a source sends a stream termination packet it will be handled silently by the receiver.
    /// If set to true then a UniverseTermination error will be thrown when attempting to receive if a termination packet is received as per
    /// ANSI E1.31-2018 Section 6.2.6.
    pub fn set_announce_stream_termination(&mut self, new_val: bool) {
        self.announce_stream_termination = new_val;
    }

    /// Handles the given data packet for this DMX receiver.
    ///
    /// Returns the universe data if successful.
    /// If the returned value is None it indicates that the data was received successfully but isn't ready to act on.
    ///
    /// Synchronised data packets handled as per ANSI E1.31-2018 Section 6.2.4.1.
    ///
    /// Arguments:
    /// data_pkt: The sACN data packet to handle.
    ///
    /// # Errors
    /// Returns an OutOfSequence error if a packet is received out of order as detected by the different between
    /// the packets sequence number and the expected sequence number as specified in ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
    ///
    /// Returns a UniversesTerminated error if a packet is received with the stream_terminated flag set indicating that the source is no longer
    /// sending on that universe and the announce_stream_termination_flag is set to true.
    ///
    /// Will return an DmxMergeError if there is an issue merging or replacing new and existing waiting data.
    fn handle_data_packet(&mut self, cid: Uuid, data_pkt: DataPacketFramingLayer) -> Result<Option<Vec<DMXData>>, ReceiveError> {
        if data_pkt.preview_data && !self.process_preview_data {
            // Don't process preview data unless receiver has process_preview_data flag set.
            return Ok(None);
        }

        if data_pkt.stream_terminated {
            self.terminate_stream(cid, &data_pkt.source_name, data_pkt.universe);
            if self.announce_stream_termination {
                Err(ReceiveError::UniverseTerminated {
                    src_cid: cid,
                    universe: data_pkt.universe,
                })?;
            }
            return Ok(None);
        }

        if !self.is_listening(&data_pkt.universe) {
            return Ok(None); // If not listening for this universe then ignore the packet.
        }

        // Preview data and stream terminated both get precedence over checking the sequence number.
        // This is as per ANSI E1.31-2018 Section 6.2.6, Stream_Terminated: Bit 6, 'Any property values
        // in an E1.31 Data Packet containing this bit shall be ignored'

        self.sequences.check_data_seq_number(
            self.source_limit,
            cid,
            data_pkt.sequence_number,
            data_pkt.universe,
            self.announce_timeout,
        )?;

        if data_pkt.synchronization_address.is_none() {
            self.clear_waiting_data(data_pkt.universe);

            let vals = data_pkt.data.property_values;
            let dmx_data: DMXData = DMXData {
                universe: data_pkt.universe,
                values: vals,
                sync_uni: data_pkt.synchronization_address,
                priority: data_pkt.priority,
                src_cid: Some(cid),
                preview: data_pkt.preview_data,
                recv_timestamp: Timestamp::now(),
            };

            Ok(Some(vec![dmx_data]))
        } else {
            // As per ANSI E1.31-2018 Appendix B.2 the receiver should listen at the synchronisation address when a data packet is received with a non-zero
            // synchronisation address.
            self.listen_universes(&[data_pkt.synchronization_address.unwrap()])?;

            let vals = data_pkt.data.property_values;
            let dmx_data: DMXData = DMXData {
                universe: data_pkt.universe,
                values: vals,
                sync_uni: data_pkt.synchronization_address,
                priority: data_pkt.priority,
                src_cid: Some(cid),
                preview: data_pkt.preview_data,
                recv_timestamp: Timestamp::now(),
            };
            self.store_waiting_data(dmx_data)?;
            Ok(None)
        }
    }

    /// Removes the given universe from the discovered sACN source with the given name, also stops tracking
    /// sequence numbers for that universe / sender combination.
    ///
    /// Note this is just a record keeping operation, it doesn't actually effect the real sACN sender it
    /// just updates the record of what universes are expected on this receiver.
    ///
    /// If the src_cid/source_name/universe isn't currently registered then this method has no effect.
    /// This is intentional as it allows calling this function multiple times without worrying about failure because
    /// it comes to the same result.
    ///     E.g. when a source terminates it sends 3 termination packets but a receiver should only terminate once.
    ///
    /// # Arguments:
    ///
    /// src_cid: The CID of the source which is terminating a universe.
    ///
    /// source_name: The human readable name of the sACN source to remove the universe from.
    ///
    /// universe:    The sACN universe to remove.
    fn terminate_stream(&mut self, src_cid: Uuid, source_name: &str, universe: UniverseId) {
        // Will only return an error if the source/universe wasn't found which is acceptable because as it
        // comes to the same result.
        let _ = self.sequences.remove_seq_numbers(src_cid, universe);

        if let Some(index) = find_discovered_src(&self.discovered_sources, source_name) {
            self.discovered_sources[index].terminate_universe(universe);
        } else {
            // As with sequence numbers the source might not be found which is acceptable.
        }
    }

    /// Takes the given data and tries to add it to the waiting data.
    ///
    /// Note that a receiver will only store a single packet of data per data_universe at once.
    ///
    /// If there is waiting data for the same universe as the data then it will be merged as per the
    /// merge_func which by default keeps the highest priority data, if the data has the same priority
    /// then the newest data is kept.
    ///
    /// # Errors
    /// Will return an DmxMergeError if there is an issue merging or replacing new and existing waiting data.
    fn store_waiting_data(&mut self, data: DMXData) -> Result<(), MergeError> {
        match self.waiting_data.remove(&data.universe) {
            Some(existing) => {
                self.waiting_data.insert(data.universe, ((self.merge_func)(&existing, &data))?);
            }
            None => {
                self.waiting_data.insert(data.universe, data);
            }
        }
        Ok(())
    }

    /// Handles the given synchronisation packet for this DMX receiver.
    ///
    /// Synchronisation packets handled as described by ANSI E1.31-2018 Section 6.2.4.1.
    ///
    /// Returns the released / previously blocked data if successful.
    /// If the returned Vec is empty it indicates that no data was waiting.
    ///
    /// E1.31 Synchronization Packets occur on specific universes. Upon receipt, they indicate that any data advertising that universe as its Synchronization Address must be acted upon.
    /// In an E1.31 Data Packet, a value of 0 in the Synchronization Address indicates that the universe data is not synchronized. If a receiver is presented with an E1.31 Data Packet
    /// containing a Synchronization Address of 0, it shall discard any data waiting to be processed and immediately act on that Data Packet.
    ///
    /// If the Synchronization Address field is not 0, and the receiver is receiving an active synchronization stream for that Synchronization Address,
    /// it shall hold that E1.31 Data Packet until the arrival of the appropriate E1.31 Synchronization Packet before acting on it.
    ///
    /// Arguments:
    /// sync_pkt: The E1.31 synchronisation part of the synchronisation packet to handle.
    ///
    /// # Errors
    /// Returns an OutOfSequence error if a packet is received out of order as detected by the different between
    /// the packets sequence number and the expected sequence number as specified in ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
    fn handle_sync_packet(&mut self, cid: Uuid, sync_pkt: SynchronizationPacketFramingLayer) -> Result<Option<Vec<DMXData>>, ReceiveError> {
        let universe = match sync_pkt.synchronization_address {
            Some(universe) => universe,
            None => return Ok(None),
        };

        if !self.is_listening(&universe) {
            return Ok(None); // If not listening for this universe then ignore the packet.
        }

        self.sequences
            .check_sync_seq_number(self.source_limit, cid, sync_pkt.sequence_number, universe, self.announce_timeout)?;

        let res = self.rtrv_waiting_data(universe);
        if res.is_empty() { Ok(None) } else { Ok(Some(res)) }
    }

    /// Retrieves and removes the DMX data of all waiting data with a synchronisation address matching the one provided.
    /// Returns an empty Vec if there is no data waiting.
    ///
    /// Arguments:
    /// sync_uni: The synchronisation universe of the data that should be retrieved.
    fn rtrv_waiting_data(&mut self, sync_uni: UniverseId) -> Vec<DMXData> {
        // Get the universes (used as keys) to remove and then move the corresponding data out of the waiting data and into the result.
        // This prevents having to copy DMXData.
        // Cannot do both actions at once as cannot modify a data structure while iterating over it.
        let mut keys = Vec::new();

        for (uni, data) in &self.waiting_data {
            if matches!(data.sync_uni, Some(universe) if universe == sync_uni) {
                keys.push(*uni)
            }
        }

        let mut res: Vec<DMXData> = Vec::new();
        for k in keys {
            let data = self.waiting_data.remove(&k).unwrap();
            if data.recv_timestamp.elapsed() < E131_NETWORK_DATA_LOSS_TIMEOUT {
                res.push(data);
            }
        }

        res
    }

    /// Takes the given DiscoveredSacnSource and updates the record of discovered sacn sources.
    ///
    /// This adds the new source deleting any previous source with the same name.
    ///
    /// Arguments:
    /// src: The DiscoveredSacnSource to update the record of discovered sacn sources with.
    fn update_discovered_srcs(&mut self, src: DiscoveredSacnSource) {
        if let Some(index) = find_discovered_src(&self.discovered_sources, &src.name) {
            self.discovered_sources.remove(index);
        }
        self.discovered_sources.push(src);
    }

    /// Handles the given universe discovery packet.
    ///
    /// This universe discovery packet might be the whole thing or may be just one page of a discovery packet.
    /// This method puts the pages to produce the DiscoveredSacnSource which is stored in the receiver.
    ///
    /// Returns the source name if a source was fully discovered or None if the source was only partially discovered.
    ///
    /// Arguments:
    /// discovery_pkt: The universe discovery part of the universe discovery packet to handle.
    fn handle_universe_discovery_packet(&mut self, discovery_pkt: UniverseDiscoveryPacketFramingLayer) -> Option<SourceName> {
        let UniverseDiscoveryPacketUniverseDiscoveryLayer {
            page,
            last_page,
            universes,
        } = discovery_pkt.data;

        let uni_page: UniversePage = UniversePage {
            page,
            universes: *universes,
        };

        // See if some pages that belong to the source that this page belongs to have already been received.
        match find_discovered_src(&self.partially_discovered_sources, &discovery_pkt.source_name) {
            Some(index) => {
                // Some pages have already been received from this source.
                self.partially_discovered_sources[index]
                    .pages
                    .push(uni_page)
                    .expect("enough capacity");
                self.partially_discovered_sources[index].last_updated = Timestamp::now();
                if self.partially_discovered_sources[index].has_all_pages() {
                    let discovered_src: DiscoveredSacnSource = self.partially_discovered_sources.remove(index);
                    self.update_discovered_srcs(discovered_src);
                    return Some(discovery_pkt.source_name);
                }
            }
            None => {
                // This is the first page received from this source.
                let discovered_src: DiscoveredSacnSource = DiscoveredSacnSource {
                    name: discovery_pkt.source_name.clone(),
                    last_page,
                    pages: Box::new(heapless::Vec::from_slice(&[uni_page]).unwrap()),
                    last_updated: Timestamp::now(),
                };

                if page == 0 && page == last_page {
                    // Indicates that this is a single page universe discovery packet.
                    self.update_discovered_srcs(discovered_src);
                    return Some(discovery_pkt.source_name);
                } else {
                    // Indicates that this is a page in a set of pages as part of a sources universe discovery.
                    self.partially_discovered_sources.push(discovered_src);
                }
            }
        }

        None // No source fully discovered.
    }

    /// Goes through all the waiting data and removes any which has timed out as a sync-packet for it hasn't been received within the [E131_NETWORK_DATA_LOSS_TIMEOUT]
    /// period as specified by ANSI E1.31-2018 Section 11.1.2.
    fn remove_expired_data(&mut self) {
        self.waiting_data
            .retain(|_uni, data| data.recv_timestamp.elapsed() < E131_NETWORK_DATA_LOSS_TIMEOUT);
    }

    /// Goes through all discovered sources and removes any that have timed out after this period: [UNIVERSE_DISCOVERY_SOURCE_TIMEOUT]
    fn remove_expired_sources(&mut self) {
        self.partially_discovered_sources
            .retain(|s| s.last_updated.elapsed() < UNIVERSE_DISCOVERY_SOURCE_TIMEOUT);
        self.discovered_sources
            .retain(|s| s.last_updated.elapsed() < UNIVERSE_DISCOVERY_SOURCE_TIMEOUT);
    }
}

/// By implementing the Drop trait for SacnNetworkReceiver it means that the user doesn't have to explicitly clean up the receiver
/// and if it goes out of reference it will clean itself up.
impl Drop for SacnReceiver {
    fn drop(&mut self) {
        // Cannot return an error or pass it onto the user because drop might be called during a panic.
        // Therefore if there is an error cleaning up the only options are ignore, notify or panic.
        // Notify using stdout might pollute the application using the library so would require a flag to enable/disable but the function of this
        // is unclear and the problem isn't solved if the flag is disabled.
        // A panic might be unnecessary or pollute another in-progress panic hiding the true problem. It would also prevent muting the other
        // universes.
        // The error is therefore ignored as it can't be fixed eitherway as the SacnReceiver has gone out of scope and won't lead to memory un-safety.
        let _ = self.mute_all_universes();
    }
}

/// Searches for the discovered source with the given name in the given vector of discovered sources and
/// returns the index of the src in the Vec or None if not found.
///
/// Arguments:
/// srcs: The Vec of DiscoveredSacnSources to search.
/// name: The human readable name of the source to find.
fn find_discovered_src(srcs: &[DiscoveredSacnSource], name: &str) -> Option<usize> {
    srcs.iter().position(|source| *source.name == *name)
}

/// Windows and linux handle multicast sockets differently.
/// This is built for / tested with Fedora 30/31.
impl SacnNetworkReceiver {
    /// Creates a new DMX receiver on the interface specified by the given address.
    ///
    /// If the given address is an IPv4 address then communication will only work between IPv4 devices, if the given address is IPv6 then communication
    /// will only work between IPv6 devices by default but IPv4 receiving can be enabled using set_ipv6_only(false).
    ///
    /// # Errors
    /// Will return an Io error if the SacnReceiver fails to bind to a socket with the given ip.
    /// For more details see socket2::Socket::new().
    fn new(ip: SocketAddr) -> Result<SacnNetworkReceiver, ReceiveError> {
        Ok(SacnNetworkReceiver {
            socket: create_socket(ip)?,
            addr: ip,
            is_multicast_enabled: true,
        })
    }

    /// Connects this SacnNetworkReceiver to the multicast address which corresponds to the given universe to allow receiving packets for that universe.
    ///
    /// # Errors
    /// Will return an Error if the given universe cannot be converted to an IPv4 or IPv6 multicast_addr depending on if the Receiver is bound to an
    /// IPv4 or IPv6 address. See packet::universe_to_ipv4_multicast_addr and packet::universe_to_ipv6_multicast_addr.
    ///
    /// Will return an Io error if cannot join the universes corresponding multicast group address.
    fn listen_multicast_universe(&self, universe: UniverseId) -> Result<(), ReceiveError> {
        let multicast_addr = if self.addr.is_ipv4() {
            universe.to_ipv4_multicast_addr()
        } else {
            universe.to_ipv6_multicast_addr()
        };
        #[cfg(target_os = "windows")]
        {
            join_multicast(&self.socket, &multicast_addr, None)
        }

        #[cfg(not(target_os = "windows"))]
        {
            join_multicast(&self.socket, &multicast_addr, Some(self.addr.ip()))
        }
    }

    /// Removes this SacnNetworkReceiver from the multicast group which corresponds to the given universe.
    ///
    /// # Errors
    /// Will return an Error if the given universe cannot be converted to an Ipv4 or Ipv6 multicast_addr depending on if the Receiver is bound to an
    /// IPv4 or IPv6 address. See packet::universe_to_ipv4_multicast_addr and packet::universe_to_ipv6_multicast_addr.
    fn mute_multicast_universe(&mut self, universe: UniverseId) -> Result<(), ReceiveError> {
        let multicast_addr = if self.addr.is_ipv4() {
            universe.to_ipv4_multicast_addr()
        } else {
            universe.to_ipv6_multicast_addr()
        };

        #[cfg(target_os = "windows")]
        {
            leave_multicast(&self.socket, &multicast_addr, None)
        }

        #[cfg(not(target_os = "windows"))]
        {
            leave_multicast(&self.socket, &multicast_addr, Some(self.addr.ip()))
        }
    }

    /// Sets the value of the is_multicast_enabled flag to the given value.
    ///
    /// If set to false then the receiver won't attempt to join any more multicast groups.
    ///
    /// This method does not attempt to leave multicast groups already joined through previous listen_universe calls.
    ///
    /// # Arguments
    /// val: The new value for the is_multicast_enabled flag.
    ///
    /// # Errors
    /// Will return an OsOperationUnsupported error if attempting to set the flag to true in an environment that multicast
    /// isn't supported i.e. Ipv6 on Windows. Note that this is the UNIX implementation
    fn set_is_multicast_enabled(&mut self, val: bool) -> Result<(), ReceiveError> {
        #[cfg(target_os = "windows")]
        {
            if val && self.addr.is_ipv6() {
                Err(ReceiveError::OsOperationUnsupported(
                    "IPv6 multicast is currently unsupported on Windows".to_string(),
                ))?;
            }
        }

        self.is_multicast_enabled = val;
        Ok(())
    }

    /// Returns true if multicast is enabled on this receiver and false if not.
    /// This flag is set when the receiver is created as not all environments currently support IP multicast.
    /// E.g. IPv6 Windows IP Multicast is currently unsupported.
    fn is_multicast_enabled(&self) -> bool {
        self.is_multicast_enabled
    }

    /// If set to true then only receive over IPv6. If false then receiving will be over both IPv4 and IPv6.
    /// This will return an error if the SacnReceiver wasn't created using an IPv6 address to bind to.
    fn set_only_v6(&mut self, val: bool) -> Result<(), ReceiveError> {
        if self.addr.is_ipv4() {
            Err(ReceiveError::IpVersionError("No data available in given timeout".to_string()))
        } else {
            Ok(self.socket.set_only_v6(val)?)
        }
    }

    /// Returns a packet if there is one available.
    ///
    /// The packet may not be ready to transmit if it is awaiting synchronisation.
    /// Will only block if set_timeout was called with a timeout of None so otherwise (and by default) it won't
    /// block so may return a WouldBlock/TimedOut error to indicate that there was no data ready.
    ///
    /// Arguments:
    /// buf: The buffer to use for storing the received data into. This buffer shouldn't be accessed or used directly as the data
    /// is returned formatted properly in the AcnRootLayerProtocol. This buffer is used as memory space for the returned AcnRootLayerProtocol.
    ///
    /// # Errors
    /// May return an error if there is an issue receiving data from the underlying socket, see (recv)[fn.recv.Socket].
    ///
    /// May return an error if there is an issue parsing the data from the underlying socket, see (parse)[fn.AcnRootLayerProtocol::parse.packet].
    fn recv(&mut self, buf: &mut [u8; RCV_BUF_DEFAULT_SIZE]) -> Result<AcnRootLayerProtocol, ReceiveError> {
        let _ = self.socket.read(buf)?;

        Ok(AcnRootLayerProtocol::parse(buf)?)
    }

    /// Set the timeout for the recv operation.
    ///
    /// Arguments:
    /// timeout: The new timeout for the receive operation, a value of None means the recv operation will become blocking.
    ///
    /// Errors:
    /// A timeout with Duration 0 will cause an error. See (set_read_timeout)[fn.set_read_timeout.Socket].
    fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<(), std::io::Error> {
        self.socket.set_read_timeout(timeout.map(Into::into))
    }
}

/// Creates a new Socket2 socket bound to the given address.
///
/// Returns the created socket.
///
/// Arguments:
/// addr: The address that the newly created socket should bind to.
///
/// # Errors
/// Will return an error if the socket cannot be created, see (Socket::new)[fn.new.Socket].
///
/// Will return an error if the socket cannot be bound to the given address, see (bind)[fn.bind.Socket2].
fn create_socket(addr: SocketAddr) -> Result<Socket, ReceiveError> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, None)?;

    // Multiple different processes might want to listen to the sACN stream so therefore need to allow re-using the ACN port.
    #[cfg(not(target_os = "windows"))]
    {
        socket.set_reuse_port(true)?;
    }

    socket.set_reuse_address(true)?;

    let ip = match addr.ip() {
        // after many many MANY hours of testing and research I figured out:
        // for receiving multicast you need to bind to 0.0.0.0, or ::
        // If you pass a regular ip address here because you thought: "hey, I wanna listen to
        // the interface that this IP belongs to" then don't. It will not receive any packets
        // and you will be left wondering why the hell it doesn't.
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    let socket_addr = SocketAddr::new(ip, ACN_SDT_MULTICAST_PORT);

    socket.bind(&socket_addr.into())?;
    Ok(socket)
}

/// Joins the multicast group with the given address using the given socket.
///
/// Arguments:
/// socket: The socket to join to the multicast group.
/// addr:   The address of the multicast group to join.
///
/// # Errors
/// Will return an error if the given socket cannot be joined to the given multicast group address.
///     See join_multicast_v4[fn.join_multicast_v4.Socket] and join_multicast_v6[fn.join_multicast_v6.Socket]
///
/// Will return an IpVersionError if addr and interface_addr are not the same IP version.
fn join_multicast(socket: &Socket, multicast_addr: &SockAddr, interface_addr: Option<IpAddr>) -> Result<(), ReceiveError> {
    match multicast_addr.as_socket().unwrap() {
        SocketAddr::V4(addr) => {
            match interface_addr {
                Some(IpAddr::V4(ref interface_v4)) => {
                    socket.join_multicast_v4(addr.ip(), interface_v4)?;
                }
                Some(IpAddr::V6(_)) => {
                    Err(ReceiveError::IpVersionError(
                        "Multicast address and interface_addr not same IP version".to_string(),
                    ))?;
                }
                None => socket.join_multicast_v4(addr.ip(), &Ipv4Addr::UNSPECIFIED)?,
            };
        }
        SocketAddr::V6(addr) => match interface_addr {
            Some(IpAddr::V4(_)) => {
                Err(ReceiveError::IpVersionError(
                    "Multicast address and interface_addr not same IP version".to_string(),
                ))?;
            }
            Some(IpAddr::V6(_)) => socket.join_multicast_v6(addr.ip(), 0)?,
            None => socket.join_multicast_v6(addr.ip(), 0)?,
        },
    }

    Ok(())
}

/// Leaves the multicast group with the given address using the given socket.
///
/// Arguments:
/// socket: The socket to leave the multicast group.
/// addr:   The address of the multicast group to leave.
///
/// # Errors
/// Will return an error if the given socket cannot leave the given multicast group address.
///     See leave_multicast_v4[fn.leave_multicast_v4.Socket] and leave_multicast_v6[fn.leave_multicast_v6.Socket]
///
/// Will return an IpVersionError if addr and interface_addr are not the same IP version.
fn leave_multicast(socket: &Socket, addr: &SockAddr, interface_addr: Option<IpAddr>) -> Result<(), ReceiveError> {
    match addr.as_socket().unwrap() {
        SocketAddr::V4(addr) => match interface_addr {
            Some(IpAddr::V4(ref interface_v4)) => {
                socket.leave_multicast_v4(addr.ip(), interface_v4)?;
            }
            Some(IpAddr::V6(ref _interface_v6)) => {
                Err(ReceiveError::IpVersionError(
                    "Multicast address and interface_addr not same IP version".to_string(),
                ))?;
            }
            None => {
                socket.leave_multicast_v4(addr.ip(), &Ipv4Addr::UNSPECIFIED)?;
            }
        },
        SocketAddr::V6(addr) => match interface_addr {
            Some(IpAddr::V4(_)) => {
                Err(ReceiveError::IpVersionError(
                    "Multicast address and interface_addr not same IP version".to_string(),
                ))?;
            }
            Some(IpAddr::V6(_)) => socket.leave_multicast_v6(addr.ip(), 0)?,
            None => socket.leave_multicast_v6(addr.ip(), 0)?,
        },
    };

    Ok(())
}

/// Stores a sequence number and a timestamp.
///
/// Used internally within SequenceNumbering for tracking the last received timestamps of each packet-type, source, universe combination.
///
/// This is then used to workout timeouts to trigger network data loss as per ANSI E1.31-2018 Section 6.7.1.
#[derive(Copy, Clone)]
struct TimedStampedSeqNo {
    sequence_number: u8,
    last_recv: Timestamp,
}

impl TimedStampedSeqNo {
    fn new(sequence_number: u8, last_recv: Timestamp) -> TimedStampedSeqNo {
        TimedStampedSeqNo {
            sequence_number,
            last_recv,
        }
    }
}

/// Stores information about the current expected sequence numbers for each source, universe and packet type.
///
/// Also handles timeouts of sources.
///
/// Abstracts over the internal data-structures/mechanisms used allowing them be changed.
struct SequenceNumbering {
    /// The sequence numbers used for data packets, keeps a reference of the last sequence number received for each universe.
    /// Sequence numbers are always in the range [0, 255] inclusive.
    /// Each type of packet is tracked differently with respect to sequence numbers as per ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
    /// The uuid refers to the source that is sending the data.
    data_sequences: HashMap<Uuid, HashMap<UniverseId, TimedStampedSeqNo>>,

    /// The sequence numbers used for synchronisation packets, keeps a reference of the last sequence number received for each universe.
    /// Sequence numbers are always in the range [0, 255] inclusive.
    /// Each type of packet is tracked differently with respect to sequence numbers as per ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
    /// The uuid refers to the source that is sending the data.
    sync_sequences: HashMap<Uuid, HashMap<UniverseId, TimedStampedSeqNo>>,
}

impl SequenceNumbering {
    /// Creates a new SequenceNumbering for tracking sequence numbers for the various types of packets.
    ///
    /// This implementation uses HashMaps internally to allow O(1) checking and updating of sequence numbers.
    fn new() -> SequenceNumbering {
        SequenceNumbering {
            data_sequences: HashMap::new(),
            sync_sequences: HashMap::new(),
        }
    }

    /// Clears the sequence number records completely removing all sources/universes for all types of packet.
    fn clear(&mut self) {
        self.data_sequences.clear();
        self.sync_sequences.clear();
    }

    /// Checks the timeouts for all packet types, sources and universes with sequence numbers registed.
    /// Removes any universes for which the last_recv time was at least the given timeout amount of time ago.
    /// Any sources which have no universes after this operation are also removed.
    ///
    /// #Arguments
    ///
    /// announce_timeout: A flag, if true it indicates than a UniverseTimeout error should be thrown if a universe times out on a source.
    ///  
    fn check_timeouts(&mut self, announce_timeout: bool) -> Result<(), ReceiveError> {
        check_timeouts(&mut self.data_sequences, E131_NETWORK_DATA_LOSS_TIMEOUT, announce_timeout)?;
        check_timeouts(&mut self.sync_sequences, E131_NETWORK_DATA_LOSS_TIMEOUT, announce_timeout)
    }

    /// Checks the sequence number is correct for a data packet with the given sequence_number and universe from the given source with given cid.
    /// Uses the given source_limit to check that it isn't exceeded.
    ///
    /// Returns Ok(()) if the packet is detected in-order.
    ///
    /// # Arguments
    /// source_limit: The limit on the number of sources which are allowed, None indicates no limit, if there is a limit then a SourcesExceededError may be returned.
    ///
    /// cid:    The Uuid of the source that send the packet.
    ///
    /// sequence_number: The sequence number of the packet to check.
    ///
    /// universe: The data universe of the packet.
    ///
    /// # Errors
    /// Returns an OutOfSequence error if a packet is received out of order as detected by the different between
    /// the packets sequence number and the expected sequence number as specified in ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
    ///
    /// Return a SourcesExceededError if the cid of the source is new and would cause the number of sources to exceed the given source_limit.
    fn check_data_seq_number(
        &mut self,
        source_limit: Option<usize>,
        cid: Uuid,
        sequence_number: u8,
        universe: UniverseId,
        announce_timeout: bool,
    ) -> Result<(), ReceiveError> {
        check_seq_number(
            &mut self.data_sequences,
            source_limit,
            cid,
            sequence_number,
            universe,
            announce_timeout,
        )
    }

    /// Checks the sequence number is correct for a sync packet with the given sequence_number and universe from the given source with given cid.
    /// Uses the given source_limit to check that it isn't exceeded.
    ///
    /// Returns Ok(()) if the packet is detected in-order.
    ///
    /// # Arguments
    /// source_limit: The limit on the number of sources which are allowed, None indicates no limit, if there is a limit then a SourcesExceededError may be returned.
    ///
    /// cid:    The Uuid of the source that send the packet.
    ///
    /// sequence_number: The sequence number of the packet to check.
    ///
    /// universe: The sync universe of the packet
    ///
    /// # Errors
    /// Returns an OutOfSequence error if a packet is received out of order as detected by the different between
    /// the packets sequence number and the expected sequence number as specified in ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
    ///
    /// Return a SourcesExceededError if the cid of the source is new and would cause the number of sources to exceed the given source_limit.
    fn check_sync_seq_number(
        &mut self,
        source_limit: Option<usize>,
        cid: Uuid,
        sequence_number: u8,
        sync_uni: UniverseId,
        announce_timeout: bool,
    ) -> Result<(), ReceiveError> {
        check_seq_number(
            &mut self.sync_sequences,
            source_limit,
            cid,
            sequence_number,
            sync_uni,
            announce_timeout,
        )
    }

    /// Removes the sequence number tracking for the given source / universe combination.
    /// This applies to both data and sync packets.
    ///
    /// # Arguments:
    ///
    /// src_cid: The CID of the source to remove the sequence numbers of.
    ///
    /// universe: The universe being sent by the source from which to remove the sequence numbers.
    fn remove_seq_numbers(&mut self, src_cid: Uuid, universe: UniverseId) -> Result<(), ReceiveError> {
        remove_source_universe_seq(&mut self.data_sequences, src_cid, universe)?;
        remove_source_universe_seq(&mut self.sync_sequences, src_cid, universe)
    }
}

/// Checks the given sequence number for the given universe against the given expected sequence numbers.
///
/// Returns Ok(()) if the packet is detected in-order.
///
/// # Arguments
/// src_sequences: A mutable hashmap which relates sources identified by Uuid to another hashmap which itself relates universes to sequence numbers. The given hashmap of
///                 sequences should be for the specific packet-type being checked as different packet-types have their own sequence numbers even from the same source.
/// source_limit: The limit on the number of sources which are allowed, None indicates no limit, if there is a limit then a SourcesExceededError may be returned.
/// cid:    The Uuid of the source that send the packet.
/// sequence_number: The sequence number of the packet to check.
/// universe: The universe of the packet (this is the data universe for data packets and the sync universe for synchronisation packets).
///
/// # Errors
/// Returns an OutOfSequence error if a packet is received out of order as detected by the different between
/// the packets sequence number and the expected sequence number as specified in ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
///
/// Return a SourcesExceededError if the cid of the source is new and would cause the number of sources to exceed the given source_limit.
fn check_seq_number(
    src_sequences: &mut HashMap<Uuid, HashMap<UniverseId, TimedStampedSeqNo>>,
    source_limit: Option<usize>,
    cid: Uuid,
    sequence_number: u8,
    universe: UniverseId,
    announce_timeout: bool,
) -> Result<(), ReceiveError> {
    // Check all the timeouts at the start.
    // This is done for all sources/universes rather than just the source that sent the packet because a completely dead (no packets being sent) universe
    // would not be removed otherwise and would continue to take up space. This comes at the cost of increased processing time complexity as each
    // source is checked every time.
    check_timeouts(src_sequences, E131_NETWORK_DATA_LOSS_TIMEOUT, announce_timeout)?;

    if src_sequences.get(&cid).is_none() {
        // New source not previously received from.
        if source_limit.is_none() || src_sequences.len() < source_limit.unwrap() {
            src_sequences.insert(cid, HashMap::new());
        } else {
            Err(ReceiveError::SourcesExceeded(src_sequences.len()))?;
        }
    };

    let expected_seq = match src_sequences.get(&cid) {
        Some(src) => {
            let seq_num = match src.get(&universe) {
                // Get the sequence number within the source for the specific universe.
                Some(s) => {
                    // Indicates that the source / universe combination is known.
                    *s
                }
                None => {
                    // Indicates that this is the first time (or the first time since it timed out) the universe has been received from this source.
                    TimedStampedSeqNo::new(INITIAL_SEQUENCE_NUMBER, Timestamp::now())
                }
            };
            seq_num
        }
        None => {
            // Previously checked that cid is present (and added if not), if None is returned now it indicates that between that check and this
            // function the cid key value has been removed. This can only happen if there is a memory corruption/thread-interleaving or similar external
            // event which the receiver cannot be expected to handle / doesn't support.
            // The rust typing system forces this possibility to be acknowledged when in some languages this possibility would still exist but it would be hidden
            // within the code.
            // While a panic!() call here isn't ideal it shows the strength in the explictness of the rust system and points to an area of
            // potential later improvement within the code by not hiding the problem. As normal if the panic must be caught then rust allows this later on by utilising
            // a mechanism such as catch unwind https://doc.rust-lang.org/std/panic/fn.catch_unwind.html.
            // Another possibility here could be to retry the method but this could end with an infinite loop.
            // Returning an error could also be done but that could confuse error handling as this should not occur and the receiver would be in an inconsistent
            // state.
            panic!();
        }
    };

    let seq_diff: isize = (sequence_number as isize) - (expected_seq.sequence_number as isize);

    if seq_diff <= E131_SEQ_DIFF_DISCARD_UPPER_BOUND && seq_diff > E131_SEQ_DIFF_DISCARD_LOWER_BOUND {
        // Reject the out of order packet as per ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
        return Err(ReceiveError::OutOfSequence(
            format!(
                "Packet received with sequence number {} is out of sequence, last {}, seq-diff {}",
                sequence_number, expected_seq.sequence_number, seq_diff
            )
            .to_string(),
        ));
    }

    match src_sequences.get_mut(&cid) {
        Some(src) => {
            // Replace the old sequence number with the new and reset the timeout.
            src.insert(universe, TimedStampedSeqNo::new(sequence_number, Timestamp::now()));
        }
        None => {
            // See previous node regarding panic previously in this method.
            panic!();
        }
    };

    Ok(())
}

/// Checks the timeouts for all sources and universes for the given sequences.
/// Removes any universes for which the last_recv time was at least the given timeout amount of time ago.
/// Any sources which have no universes after this operation are also removed.
///
/// #Arguments
///
/// src_sequences: The source sequence numbers to check the timeout of.
///
/// timeout: The exclusive length of time permitted since a source last sent on a universe.
///     If the time elapsed since the last received data that is equal to or great than the timeout then the source is said to have timed out.
///  
fn check_timeouts(
    src_sequences: &mut HashMap<Uuid, HashMap<UniverseId, TimedStampedSeqNo>>,
    timeout: Duration,
    announce_timeout: bool,
) -> Result<(), ReceiveError> {
    if announce_timeout {
        let mut timedout_src_id: Option<Uuid> = None;
        let mut timedout_uni: Option<UniverseId> = None;
        for (src_id, universes) in src_sequences.iter_mut() {
            for (uni, seq_num) in universes.iter() {
                if seq_num.last_recv.elapsed() >= timeout {
                    timedout_src_id = Some(*src_id);
                    timedout_uni = Some(*uni);
                    break;
                }
            }
            if timedout_uni.is_none() {
                break;
            }
        }
        if timedout_uni.is_some() {
            // If None then it indicates nothing timed out.
            let uni_to_remove = timedout_uni.unwrap();
            let src_universes = src_sequences.get_mut(&timedout_src_id.unwrap());
            if src_universes.is_some() {
                let universes = src_universes.unwrap();
                universes.remove(&uni_to_remove);
                if universes.is_empty() {
                    // Remove source if all its universes have timed out
                    src_sequences.remove(&timedout_src_id.unwrap());
                }
                Err(ReceiveError::UniverseTimeout {
                    src_cid: timedout_src_id.unwrap(),
                    universe: timedout_uni.unwrap(),
                })?;
            }
        }

        Ok(())
    } else {
        for (_src_id, universes) in src_sequences.iter_mut() {
            universes.retain(|_uni, seq_num| seq_num.last_recv.elapsed() < timeout);
        }
        // Remove all empty sources.
        src_sequences.retain(|_src_id, universes| !universes.is_empty());
        Ok(())
    }
}

/// Removes the sequence number entry from the given sequences for the given source cid and universe.
///
/// This removes the source entirely if there are no universes left.
///
/// # Arguments
/// src_sequences: The sequence numbers for each source and universe.
///
/// src_cid:       The CID for the source to remove the universe from.
///
/// universe:      The universe to remove from the source.
///
/// # Errors
/// Returns a SourceNotFound error if the given src_cid isn't in the given collection of sources/sequence-numbers.
///
/// Returns a UniverseNotFound error if the given universe isn't registered to the given source and so cannot be removed.
fn remove_source_universe_seq(
    src_sequences: &mut HashMap<Uuid, HashMap<UniverseId, TimedStampedSeqNo>>,
    src_cid: Uuid,
    universe: UniverseId,
) -> Result<(), ReceiveError> {
    match src_sequences.get_mut(&src_cid) {
        Some(x) => {
            match x.remove(&universe) {
                Some(_) => {
                    if x.is_empty() {
                        // Remove the source if there are no universes registered to it.
                        match src_sequences.remove(&src_cid) {
                            Some(_x) => Ok(()),
                            None => Err(ReceiveError::SourceNotFound(
                                "Could not find the source so could not remove it".to_string(),
                            )),
                        }
                    } else {
                        Ok(())
                    }
                }
                None => Err(ReceiveError::UniverseNotFound(
                    "Could not find universe within source in sequence numbers so could not remove it".to_string(),
                )),
            }
        }
        None => Err(ReceiveError::SourceNotFound(
            "Could not find the source in the sequence numbers so could not remove it".to_string(),
        )),
    }
}

/// Action after receiving
enum DataOrRetry {
    /// OK variant
    Data(Vec<DMXData>),
    /// Retry with new timeout
    Retry(Option<Duration>),
}

#[cfg(test)]
mod test {
    use core::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
    };

    use heapless::Vec;
    use sacn_core::{priority::Priority, time::Timestamp};
    use uuid::Uuid;

    use super::*;
    use crate::{
        e131_definitions::ACN_SDT_MULTICAST_PORT, packet::DataPacketDmpLayer, source_name::SourceName, universe_id::slice_to_universes,
    };

    const TEST_DATA_SINGLE_UNIVERSE: [u8; 512] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3,
        4, 5, 6, 7, 8, 9, 10, 11, 12,
    ];

    #[test]
    fn test_handle_single_page_discovery_packet() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        let name = "Test Src 1";
        let page: u8 = 0;
        let last_page: u8 = 0;
        let universes = heapless::Vec::from_slice(slice_to_universes(&[1, 2, 3, 4, 5]).expect("in range")).unwrap();

        let discovery_pkt: UniverseDiscoveryPacketFramingLayer = UniverseDiscoveryPacketFramingLayer {
            source_name: SourceName::from_str(name).unwrap(),

            // Universe discovery layer.
            data: UniverseDiscoveryPacketUniverseDiscoveryLayer {
                page,

                // The number of the final page.
                last_page,

                // List of universes.
                universes: Box::new(universes.clone()),
            },
        };
        let res = dmx_rcv.handle_universe_discovery_packet(discovery_pkt);

        assert!(res.is_some());
        assert_eq!(*res.unwrap(), name);

        assert_eq!(dmx_rcv.discovered_sources.len(), 1);

        assert_eq!(*dmx_rcv.discovered_sources[0].name, name);
        assert_eq!(dmx_rcv.discovered_sources[0].last_page, last_page);
        assert_eq!(dmx_rcv.discovered_sources[0].pages.len(), 1);
        assert_eq!(dmx_rcv.discovered_sources[0].pages[0].page, page);
        assert_eq!(dmx_rcv.discovered_sources[0].pages[0].universes, universes);
    }

    #[test]
    fn test_handle_multi_page_discovery_packet() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        let name = "Test Src 1";
        let last_page: u8 = 1;
        let mut universes_page_1 = Vec::new();
        let mut universes_page_2 = Vec::new();

        for i in 1..513 {
            universes_page_1
                .push(UniverseId::new(i).expect("in range"))
                .expect("Should have enough capacity");
        }

        for i in 513..1024 {
            universes_page_2
                .push(UniverseId::new(i).expect("in range"))
                .expect("Should have enough capacity");
        }

        let discovery_pkt_1: UniverseDiscoveryPacketFramingLayer = UniverseDiscoveryPacketFramingLayer {
            source_name: SourceName::from_str(name).unwrap(),

            // Universe discovery layer.
            data: UniverseDiscoveryPacketUniverseDiscoveryLayer {
                page: 0,

                // The number of the final page.
                last_page,

                // List of universes.
                universes: universes_page_1.clone().into(),
            },
        };

        let discovery_pkt_2: UniverseDiscoveryPacketFramingLayer = UniverseDiscoveryPacketFramingLayer {
            source_name: SourceName::from_str(name).unwrap(),

            // Universe discovery layer.
            data: UniverseDiscoveryPacketUniverseDiscoveryLayer {
                page: 1,

                // The number of the final page.
                last_page,

                // List of universes.
                universes: universes_page_2.clone().into(),
            },
        };
        let res = dmx_rcv.handle_universe_discovery_packet(discovery_pkt_1);

        assert!(res.is_none()); // Should be none because first packet isn't complete as its only the first page.

        let res2 = dmx_rcv.handle_universe_discovery_packet(discovery_pkt_2);

        assert!(res2.is_some()); // Source should be discovered because the second and last page is now received.
        assert_eq!(*res2.unwrap(), name);

        assert_eq!(dmx_rcv.discovered_sources.len(), 1);

        assert_eq!(*dmx_rcv.discovered_sources[0].name, name);
        assert_eq!(dmx_rcv.discovered_sources[0].last_page, last_page);
        assert_eq!(dmx_rcv.discovered_sources[0].pages.len(), 2);
        assert_eq!(dmx_rcv.discovered_sources[0].pages[0].page, 0);
        assert_eq!(dmx_rcv.discovered_sources[0].pages[1].page, 1);
        assert_eq!(dmx_rcv.discovered_sources[0].pages[0].universes, universes_page_1);
        assert_eq!(dmx_rcv.discovered_sources[0].pages[1].universes, universes_page_2);
    }

    #[test]
    fn test_store_retrieve_waiting_data() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        let sync_uni = UniverseId::new(1).expect("in range");
        let universe = UniverseId::new(1).expect("in range");
        let vals = heapless::Vec::from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();

        let dmx_data = DMXData {
            universe,
            values: vals.clone(),
            sync_uni: Some(sync_uni),
            priority: Priority::default(),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now(),
        };

        dmx_rcv.store_waiting_data(dmx_data).unwrap();

        let res = dmx_rcv.rtrv_waiting_data(sync_uni);

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].universe, universe);
        assert_eq!(res[0].sync_uni, Some(sync_uni));
        assert_eq!(res[0].values, vals);
    }

    #[test]
    fn test_store_2_retrieve_1_waiting_data() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        let sync_uni = UniverseId::new(1).expect("in range");
        let universe = UniverseId::new(1).expect("in range");
        let universe2 = UniverseId::new(2).expect("in range");
        let vals = heapless::Vec::from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();

        let dmx_data = DMXData {
            universe,
            values: vals.clone(),
            sync_uni: Some(sync_uni),
            priority: Priority::default(),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now(),
        };

        let dmx_data2 = DMXData {
            universe: universe2,
            values: vals.clone(),
            sync_uni: Some(universe2),
            priority: Priority::default(),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now(),
        };

        dmx_rcv.store_waiting_data(dmx_data).unwrap();
        dmx_rcv.store_waiting_data(dmx_data2).unwrap();

        let res = dmx_rcv.rtrv_waiting_data(sync_uni);

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].universe, universe);
        assert_eq!(res[0].sync_uni, Some(sync_uni));
        assert_eq!(res[0].values, vals);
    }

    #[test]
    fn test_store_2_retrieve_2_waiting_data() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        let sync_uni = UniverseId::new(1).expect("in range");
        let universe = UniverseId::new(1).expect("in range");
        let universe2 = UniverseId::new(2).expect("in range");

        let vals = heapless::Vec::from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();

        let dmx_data = DMXData {
            universe,
            values: vals.clone(),
            sync_uni: Some(sync_uni),
            priority: Priority::default(),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now(),
        };

        let vals2 = heapless::Vec::from_slice(&[0, 9, 7, 3, 2, 4, 5, 6, 5, 1, 2, 3]).unwrap();

        let dmx_data2 = DMXData {
            universe: universe2,
            values: vals2.clone(),
            sync_uni: Some(universe2),
            priority: Priority::default(),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now(),
        };

        dmx_rcv.store_waiting_data(dmx_data).unwrap();
        dmx_rcv.store_waiting_data(dmx_data2).unwrap();

        let res = dmx_rcv.rtrv_waiting_data(sync_uni);

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].universe, universe);
        assert_eq!(res[0].sync_uni, Some(sync_uni));
        assert_eq!(res[0].values, vals);

        let res2 = dmx_rcv.rtrv_waiting_data(UniverseId::new(2).expect("in range"));

        assert_eq!(res2.len(), 1);
        assert_eq!(res2[0].universe, universe2);
        assert_eq!(res2[0].sync_uni, Some(universe2));
        assert_eq!(res2[0].values, vals2);
    }

    #[test]
    fn test_store_2_same_universe_same_priority_waiting_data() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        let sync_uni = UniverseId::new(1).expect("in range");
        let universe = UniverseId::new(1).expect("in range");
        let vals = heapless::Vec::from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();

        let dmx_data = DMXData {
            universe,
            values: vals.clone(),
            sync_uni: Some(sync_uni),
            priority: Priority::default(),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now(),
        };

        let vals2 = heapless::Vec::from_slice(&[0, 9, 7, 3, 2, 4, 5, 6, 5, 1, 2, 3]).unwrap();

        let dmx_data2 = DMXData {
            universe,
            values: vals2.clone(),
            sync_uni: Some(sync_uni),
            priority: Priority::default(),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now(),
        };

        dmx_rcv.store_waiting_data(dmx_data).unwrap();
        dmx_rcv.store_waiting_data(dmx_data2).unwrap();

        let res2 = dmx_rcv.rtrv_waiting_data(sync_uni);

        assert_eq!(res2.len(), 1);
        assert_eq!(res2[0].universe, universe);
        assert_eq!(res2[0].sync_uni, Some(sync_uni));
        assert_eq!(res2[0].values, vals2);

        assert_eq!(dmx_rcv.rtrv_waiting_data(sync_uni).len(), 0);
    }

    #[test]
    fn test_store_2_same_universe_diff_priority_waiting_data() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        let sync_uni = UniverseId::new(1).expect("in range");
        let universe = UniverseId::MIN;
        let vals = heapless::Vec::from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();

        let dmx_data = DMXData {
            universe,
            values: vals.clone(),
            sync_uni: Some(sync_uni),
            priority: Priority::new(120).expect("in range"),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now(),
        };

        let vals2 = heapless::Vec::from_slice(&[0, 9, 7, 3, 2, 4, 5, 6, 5, 1, 2, 3]).unwrap();

        let dmx_data2 = DMXData {
            universe,
            values: vals2.clone(),
            sync_uni: Some(sync_uni),
            priority: Priority::default(),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now(),
        };

        dmx_rcv.store_waiting_data(dmx_data).unwrap();
        dmx_rcv.store_waiting_data(dmx_data2).unwrap(); // Won't be added as lower priority than already waiting data.

        let res = dmx_rcv.rtrv_waiting_data(sync_uni);

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].universe, universe);
        assert_eq!(res[0].sync_uni, Some(sync_uni));
        assert_eq!(res[0].values, vals);

        assert_eq!(dmx_rcv.rtrv_waiting_data(sync_uni).len(), 0);
    }

    /// Generates a data packet framing layer with arbitrary values except for the sequence number which is set to the given value.
    /// This is used for tests targeted at checking sequence number behaviour that don't care about other fields.
    /// The generated data packet framing layer has structure
    /// DataPacketFramingLayer {
    ///     source_name: "Source_A".into(),
    ///     priority: Priority::default(),
    ///     synchronization_address: <given sequence number>,
    ///     sequence_number: sequence_number,
    ///     preview_data: false,
    ///     stream_terminated: false,
    ///     force_synchronization: false,
    ///     universe: <given universe>,
    ///     data: DataPacketDmpLayer {
    ///         property_values: Cow::from(&TEST_DATA_SINGLE_UNIVERSE[0..]),
    ///     },
    /// }
    fn generate_data_packet_framing_layer_seq_num(universe: UniverseId, sequence_number: u8) -> DataPacketFramingLayer {
        DataPacketFramingLayer {
            source_name: SourceName::from_str("Source_A").unwrap(),
            priority: Priority::default(),
            synchronization_address: None,
            sequence_number,
            preview_data: false,
            stream_terminated: false,
            force_synchronization: false,
            universe,
            data: Box::new(DataPacketDmpLayer {
                property_values: Vec::from_slice(&TEST_DATA_SINGLE_UNIVERSE[0..]).unwrap(),
            }),
        }
    }

    /// Generates a sync packet framing layer with arbitrary values except for the sequence number which is set to the given value.
    /// This is used for tests targeted at checking sequence number behaviour that don't care about other fields.
    /// The generated Generates a sync packet framing layer has structure:
    /// SynchronizationPacketFramingLayer {
    ///     sequence_number: <given sequence number>,
    ///     synchronization_address: <given synchronisation address>
    /// }
    fn generate_sync_packet_framing_layer_seq_num(
        sync_address: Option<UniverseId>,
        sequence_number: u8,
    ) -> SynchronizationPacketFramingLayer {
        SynchronizationPacketFramingLayer {
            sequence_number,
            synchronization_address: sync_address,
        }
    }

    /// Creates a receiver and then makes it handle 2 data packets with sequence numbers 0 and 1 respectively.
    /// The receiver is then given a data packet with sequence number 0 which is the lower than the expected value of 2 so should be rejected.
    ///
    /// This shows that sequence numbers are correctly evaluated and packets rejected if the sequence number is too low for data packets.
    ///  
    #[test]
    fn test_data_packet_sequence_number_below_expected() {
        const UNIVERSE1: UniverseId = UniverseId::MIN;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        dmx_rcv.listen_universes(&[UNIVERSE1]).unwrap();

        let src_cid: Uuid = Uuid::from_bytes([
            0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
        ]);

        let data_packet = generate_data_packet_framing_layer_seq_num(UNIVERSE1, 0);
        let data_packet2 = generate_data_packet_framing_layer_seq_num(UNIVERSE1, 1);
        let data_packet3 = generate_data_packet_framing_layer_seq_num(UNIVERSE1, 0); // This data packet has a sequence number lower than the expected value of 2 so should be rejected.

        // Not interested in specific return values from this test, just assert the data is processed successfully.
        assert!(
            dmx_rcv.handle_data_packet(src_cid, data_packet).unwrap().is_some(),
            "Receiver incorrectly rejected first data packet"
        );
        assert!(
            dmx_rcv.handle_data_packet(src_cid, data_packet2).unwrap().is_some(),
            "Receiver incorrectly rejected second data packet"
        );

        // Check that the third data packet with the low sequence number is rejected correctly with the expected OutOfSequence error.
        match dmx_rcv.handle_data_packet(src_cid, data_packet3) {
            Err(ReceiveError::OutOfSequence(_)) => {
                assert!(true, "Receiver correctly rejected third data packet with correct error");
            }
            Ok(_) => {
                assert!(false, "Receiver incorrectly accepted third data packet");
            }
            Err(e) => {
                assert!(
                    false,
                    "Receiver correctly rejected third data packet but with unexpected error: {}",
                    e
                );
            }
        }
    }

    /// Creates a receiver and then makes it handle 2 data packets with sequence numbers 0 and 1 respectively meaning the next expected sequence number should be 2.
    /// The receiver is then given a data packet with sequence number x.
    /// This is repeated for all x in [0, 255].
    ///
    /// This exhaustively checks that only sequence numbers outwith the reject range as specified by ANSI E1.31-2018 Section 6.7.2 are accepted for
    /// data packets specifically.
    #[test]
    fn test_data_packet_sequence_number_exhaustive() {
        const UNIVERSE1: UniverseId = UniverseId::MIN;
        // The inclusive lower limit used for the sequence numbers tried. Chosen as the minimum value that can fit in an unsigned byte.
        const SEQ_NUM_LOWER_BOUND: u8 = 0;
        // The inclusive upper limit used for the sequence numbers tried. Chosen as the maximum value that can fit in an unsigned byte.
        const SEQ_NUM_UPPER_BOUND: u8 = 255;

        // The last sequence number received before the exhaustive checking.
        const LAST_SEQ_NUM: u8 = 1;

        // Reject range set as per ANSI E1.31-2018 Section 6.7.2 "Having first received a packet with sequence number A, a second packet with sequence number B
        // arrives. If, using signed 8-bit binary arithmetic, B - A is less than or equal to 0, but greater than -20, then
        // the packet containing sequence number B shall be deemed out of sequence and discarded."

        // The inclusive upper bound on the diff values (new_packet_seq_num - last_packet_seq_num) that will be rejected.
        const REJECT_RANGE_UPPER_BOUND: i16 = 0;

        // The exclusive lower bound on the diff values (new_packet_seq_num - last_packet_seq_num) that will be rejected.
        const REJECT_RANGE_LOWER_BOUND: i16 = -20;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
        let src_cid: Uuid = Uuid::from_bytes([
            0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
        ]);

        for i in SEQ_NUM_LOWER_BOUND..SEQ_NUM_UPPER_BOUND {
            // Create the receiver.
            let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();
            dmx_rcv.listen_universes(&[UNIVERSE1]).unwrap();

            // Generate the packets used to put the receiver in a known start state.
            let data_packet = generate_data_packet_framing_layer_seq_num(UNIVERSE1, LAST_SEQ_NUM - 1);
            let data_packet2 = generate_data_packet_framing_layer_seq_num(UNIVERSE1, LAST_SEQ_NUM);

            // Not interested in specific return values from this test, just assert the data is processed successfully.
            assert!(
                dmx_rcv.handle_data_packet(src_cid, data_packet).unwrap().is_some(),
                "Receiver incorrectly rejected first data packet"
            );
            assert!(
                dmx_rcv.handle_data_packet(src_cid, data_packet2).unwrap().is_some(),
                "Receiver incorrectly rejected second data packet"
            );

            // The receiver is now setup correctly ready for the test with a known start state that expects the next data packet sequence number
            // to be 2.

            let res = dmx_rcv.handle_data_packet(src_cid, generate_data_packet_framing_layer_seq_num(UNIVERSE1, i));

            let diff: i16 = (i as i16) - (LAST_SEQ_NUM as i16);

            match res {
                Err(ReceiveError::OutOfSequence(_)) => {
                    // Data packet was rejected due to sequence number.
                    if (diff <= REJECT_RANGE_UPPER_BOUND) && (diff > REJECT_RANGE_LOWER_BOUND) {
                        assert!(true, "Rejection is correct as per ANSI E1.31-2018 Section 6.7.2");
                    } else {
                        assert!(false, "Data packet with sequence number: {} was rejected incorrectly", i);
                    }
                }
                Ok(_p) => {
                    // Data packet and therefore sequence number was accepted.
                    if (diff <= REJECT_RANGE_UPPER_BOUND) && (diff > REJECT_RANGE_LOWER_BOUND) {
                        assert!(false, "Data packet with sequence number: {} was accepted incorrectly", 1);
                    } else {
                        assert!(true, "Acceptance is correct as per ANSI E1.31-2018 Section 6.7.2");
                    }
                }
                Err(e) => {
                    // This is never expected and always means test failure.
                    assert!(false, "Receiver produced unexpected error: {}", e);
                }
            }
        }
    }

    /// Exactly the same as test_data_packet_sequence_number_exhaustive but using synchronisation packets.
    ///
    /// This exhaustively checks that only sequence numbers outwith the reject range as specified by ANSI E1.31-2018 Section 6.7.2 are accepted for
    /// synchronisation packets specifically.
    ///
    /// As shown by test_sequence_number_packet_type_independence sequence numbers are treated independently for data and synchronisation packets so
    /// therefore appropriate to test separately. Could have been combined with the data packet variant of this test but by keeping them separate
    /// it more clearly shows that data and sync packet sequence numbers should be treated independently and it report errors independently.
    ///  
    #[test]
    fn test_sync_packet_sequence_number_exhaustive() {
        let sync_addr = UniverseId::new(1).expect("in range");
        // The inclusive lower limit used for the sequence numbers tried. Chosen as the minimum value that can fit in an unsigned byte.
        const SEQ_NUM_LOWER_BOUND: u8 = 0;
        // The inclusive upper limit used for the sequence numbers tried. Chosen as the maximum value that can fit in an unsigned byte.
        const SEQ_NUM_UPPER_BOUND: u8 = 255;

        // The last sequence number received before the exhaustive checking.
        const LAST_SEQ_NUM: u8 = 1;

        // Reject range set as per ANSI E1.31-2018 Section 6.7.2 "Having first received a packet with sequence number A, a second packet with sequence number B
        // arrives. If, using signed 8-bit binary arithmetic, B - A is less than or equal to 0, but greater than -20, then
        // the packet containing sequence number B shall be deemed out of sequence and discarded."

        // The inclusive upper bound on the diff values (new_packet_seq_num - last_packet_seq_num) that will be rejected.
        const REJECT_RANGE_UPPER_BOUND: i16 = 0;

        // The exclusive lower bound on the diff values (new_packet_seq_num - last_packet_seq_num) that will be rejected.
        const REJECT_RANGE_LOWER_BOUND: i16 = -20;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
        let src_cid: Uuid = Uuid::from_bytes([
            0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
        ]);

        for i in SEQ_NUM_LOWER_BOUND..SEQ_NUM_UPPER_BOUND {
            // Create the receiver.
            let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();
            dmx_rcv.listen_universes(&[sync_addr.try_into().expect("in range")]).unwrap();

            // Generate the packets used to put the receiver in a known start state.
            let sync_packet = generate_sync_packet_framing_layer_seq_num(Some(sync_addr), LAST_SEQ_NUM - 1);
            let sync_packet2 = generate_sync_packet_framing_layer_seq_num(Some(sync_addr), LAST_SEQ_NUM);

            // Not interested in specific return values from this test, just assert the sync packet is processed successfully.
            assert!(
                dmx_rcv.handle_sync_packet(src_cid, sync_packet).unwrap().is_none(),
                "Receiver incorrectly rejected first sync packet"
            );
            assert!(
                dmx_rcv.handle_sync_packet(src_cid, sync_packet2).unwrap().is_none(),
                "Receiver incorrectly rejected second sync packet"
            );

            // The receiver is now setup correctly ready for the test with a known start state that expects the next sync packet sequence number
            // to be 2.

            let res = dmx_rcv.handle_sync_packet(src_cid, generate_sync_packet_framing_layer_seq_num(Some(sync_addr), i));

            // Cannot do straight 8 bit arithmetic that relies on underflows/overflows as this is undefined behaviour in rust forbidden by the compiler.
            let diff: i16 = (i as i16) - (LAST_SEQ_NUM as i16);

            match res {
                Err(ReceiveError::OutOfSequence(_)) => {
                    // Sync packet was rejected due to sequence number.
                    if (diff <= REJECT_RANGE_UPPER_BOUND) && (diff > REJECT_RANGE_LOWER_BOUND) {
                        assert!(true, "Rejection is correct as per ANSI E1.31-2018 Section 6.7.2");
                    } else {
                        assert!(false, "Sync packet with sequence number: {} was rejected incorrectly", i);
                    }
                }
                Ok(_p) => {
                    // Sync packet and therefore sequence number was accepted.
                    if (diff <= REJECT_RANGE_UPPER_BOUND) && (diff > REJECT_RANGE_LOWER_BOUND) {
                        assert!(false, "Sync packet with sequence number: {} was accepted incorrectly", i);
                    } else {
                        assert!(true, "Acceptance is correct as per ANSI E1.31-2018 Section 6.7.2");
                    }
                }
                Err(e) => {
                    // This is never expected and always means test failure.
                    assert!(false, "Receiver produced unexpected error: {}", e);
                }
            }
        }
    }

    /// Creates a receiver and then makes it handle 2 sync packets with sequence numbers 0 and 1 respectively.
    /// The receiver is then given a sync packet with sequence number 0 which is the lower than the expected value of 2 so should be rejected.
    ///
    /// This shows that sequence numbers are correctly evaluated and packets rejected if the sequence number is too low for synchronisation packets.
    ///  
    #[test]
    fn test_sync_packet_sequence_number_below_expected() {
        let universe1 = UniverseId::new(1).expect("in range");
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        dmx_rcv.listen_universes(&[universe1]).unwrap();

        let src_cid: Uuid = Uuid::from_bytes([
            0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
        ]);

        let sync_packet = generate_sync_packet_framing_layer_seq_num(universe1.into(), 0);
        let sync_packet2 = generate_sync_packet_framing_layer_seq_num(universe1.into(), 1);
        let sync_packet3 = generate_sync_packet_framing_layer_seq_num(universe1.into(), 0); // This sync packet has a sequence number lower than the expected value of 2 so should be rejected.

        // Not interested in specific return values from this test, just assert the packets are processed successfully.
        assert!(
            dmx_rcv.handle_sync_packet(src_cid, sync_packet).unwrap().is_none(),
            "Receiver incorrectly rejected first sync packet"
        );
        assert!(
            dmx_rcv.handle_sync_packet(src_cid, sync_packet2).unwrap().is_none(),
            "Receiver incorrectly rejected second sync packet"
        );

        // Check that the third sync packet with the low sequence number is rejected correctly with the expected OutOfSequence error.
        match dmx_rcv.handle_sync_packet(src_cid, sync_packet3) {
            Err(ReceiveError::OutOfSequence(_)) => {
                assert!(true, "Receiver correctly rejected third sync packet with correct error");
            }
            Ok(_) => {
                assert!(false, "Receiver incorrectly accepted third sync packet");
            }
            Err(e) => {
                assert!(
                    false,
                    "Receiver correctly rejected third sync packet but with unexpected error: {}",
                    e
                );
            }
        }
    }

    /// Creates a receiver and then makes it handle 2 sync packets with sequence numbers 0 and 1 respectively.
    /// The receiver then resets the sequence number counters and then handles a sync packet with sequence number 0. This would normally be rejected
    /// as per test_sync_packet_sequence_number_below_expected but because of the reset it shouldn't be.
    ///
    /// This checks that the sync packet sequence numbers are reset correctly.
    #[test]
    fn test_sync_packet_sequence_number_reset() {
        let universe1 = UniverseId::new(1).expect("in range");
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        dmx_rcv.listen_universes(&[universe1]).unwrap();

        let src_cid: Uuid = Uuid::from_bytes([
            0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
        ]);

        let sync_packet = generate_sync_packet_framing_layer_seq_num(universe1.into(), 0);
        let sync_packet2 = generate_sync_packet_framing_layer_seq_num(universe1.into(), 1);
        let sync_packet3 = generate_sync_packet_framing_layer_seq_num(universe1.into(), 0); // This sync packet has a sequence number lower than the expected value of 2 so should be rejected.

        // Not interested in specific return values from this test, just assert the packets are processed successfully.
        assert!(
            dmx_rcv.handle_sync_packet(src_cid, sync_packet).unwrap().is_none(),
            "Receiver incorrectly rejected first sync packet"
        );
        assert!(
            dmx_rcv.handle_sync_packet(src_cid, sync_packet2).unwrap().is_none(),
            "Receiver incorrectly rejected second sync packet"
        );

        dmx_rcv.reset_sources();

        // Packet shouldn't be rejected.
        assert!(
            dmx_rcv.handle_sync_packet(src_cid, sync_packet3).unwrap().is_none(),
            "Receiver incorrectly rejected third sync packet"
        );
    }

    /// Creates a receiver and then makes it handle 2 data packets with sequence numbers 0 and 1 respectively.
    /// The receiver then resets the sequence number counters and then handles a data packet with sequence number 0. This would normally be rejected
    /// as per test_data_packet_sequence_number_below_expected but because of the reset it shouldn't be.
    ///
    /// This checks that the data packet sequence numbers are reset correctly.
    #[test]
    fn test_data_packet_sequence_number_reset() {
        let universe1 = UniverseId::new(1).expect("in range");
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        dmx_rcv.listen_universes(&[universe1]).unwrap();

        let src_cid: Uuid = Uuid::from_bytes([
            0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
        ]);

        let data_packet = generate_data_packet_framing_layer_seq_num(universe1, 0);
        let data_packet2 = generate_data_packet_framing_layer_seq_num(universe1, 1);
        let data_packet3 = generate_data_packet_framing_layer_seq_num(universe1, 0); // This data packet has a sequence number lower than the expected value of 2 so should be rejected.

        // Not interested in specific return values from this test, just assert the data is processed successfully.
        assert!(
            dmx_rcv.handle_data_packet(src_cid, data_packet).unwrap().is_some(),
            "Receiver incorrectly rejected first data packet"
        );
        assert!(
            dmx_rcv.handle_data_packet(src_cid, data_packet2).unwrap().is_some(),
            "Receiver incorrectly rejected second data packet"
        );

        dmx_rcv.reset_sources();

        // Packet shouldn't be rejected.
        assert!(
            dmx_rcv.handle_data_packet(src_cid, data_packet3).unwrap().is_some(),
            "Receiver incorrectly rejected third data packet"
        );
    }

    /// Creates a receiver and then makes it handle 2 data packets with sequence numbers 0 and 1.
    /// This then means the receiver will reject another data packet with sequence number 0.
    /// The receiver is then passed a sync packet with sequence number 0 which shouldn't be rejected as it is a different packet type.
    ///
    /// Shows sequence numbers are evaluated separately for each packet type as per ANSI E1.31-2018 Section 6.7.2.
    #[test]
    fn test_sequence_number_packet_type_independence() {
        let universe = UniverseId::new(1).expect("in range");

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        dmx_rcv.listen_universes(&[universe]).unwrap();

        let src_cid: Uuid = Uuid::from_bytes([
            0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
        ]);

        let data_packet = generate_data_packet_framing_layer_seq_num(universe, 0);
        let data_packet2 = generate_data_packet_framing_layer_seq_num(universe, 1);

        let sync_packet = generate_sync_packet_framing_layer_seq_num(universe.into(), 0);

        // Not interested in specific return values from this test, just assert the data is processed successfully.
        assert!(
            dmx_rcv.handle_data_packet(src_cid, data_packet).unwrap().is_some(),
            "Receiver incorrectly rejected first data packet"
        );
        assert!(
            dmx_rcv.handle_data_packet(src_cid, data_packet2).unwrap().is_some(),
            "Receiver incorrectly rejected second data packet"
        );

        // At this point the receiver should be expecting data_packet sequence number 2.
        // Pass the receiver a sync packet with sequence number 0.
        // If this isn't rejected it shows that the receiver correctly treats different packet types individually.
        assert!(
            dmx_rcv.handle_sync_packet(src_cid, sync_packet).unwrap().is_none(),
            "Receiver incorrectly rejected synchronisation packet"
        );
    }

    /// Creates a receiver and then makes it handle 2 data packets for the same universe with sequence numbers 0 and 1.
    /// This then means the receiver will reject another data packet for that universe with sequence number 0.
    /// The receiver is then passed a data packet with sequence number 0 for a different universe which shouldn't be rejected as it is for a different universe.
    ///
    /// Shows sequence numbers are evaluated separately for each universe as per ANSI E1.31-2018 Section 6.7.2.
    #[test]
    fn test_data_packet_sequence_number_universe_independence() {
        let universe1 = UniverseId::new(1).expect("in range");
        let universe2 = UniverseId::new(2).expect("in range");
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        dmx_rcv.listen_universes(&[universe1, universe2]).unwrap();

        let src_cid: Uuid = Uuid::from_bytes([
            0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
        ]);

        let data_packet = generate_data_packet_framing_layer_seq_num(universe1, 0);
        let data_packet2 = generate_data_packet_framing_layer_seq_num(universe1, 1);
        let data_packet3 = generate_data_packet_framing_layer_seq_num(universe2, 0);

        // Not interested in specific return values from this test, just assert the data is processed successfully.
        assert!(
            dmx_rcv.handle_data_packet(src_cid, data_packet).unwrap().is_some(),
            "Receiver incorrectly rejected first data packet"
        );
        assert!(
            dmx_rcv.handle_data_packet(src_cid, data_packet2).unwrap().is_some(),
            "Receiver incorrectly rejected second data packet"
        );

        // At this point the receiver will (as shown by test_data_packet_sequence_number_below_expected) reject a data packet to UNIVERSE1 with sequence number 0
        // however this data packet is for UNIVERSE2 and so therefore should be accepted.
        assert!(
            dmx_rcv.handle_data_packet(src_cid, data_packet3).unwrap().is_some(),
            "Receiver incorrectly rejected third data packet"
        );
    }

    /// Creates a receiver and then makes it handle 2 sync packets for the same synchronisation address with sequence numbers 0 and 1.
    /// This then means the receiver will reject another sync packet for that universe with sequence number 0.
    /// The receiver is then passed a sync packet with sequence number 0 for a different synchronisation address which shouldn't be rejected as it is for
    /// a different synchronisation address.
    ///
    /// Shows sequence numbers are evaluated separately for each synchronisation address individually as per ANSI E1.31-2018 Section 6.7.2.
    #[test]
    fn test_sync_packet_sequence_number_universe_independence() {
        let sync_addr_1 = UniverseId::new(1).expect("in range");
        let sync_addr_2 = UniverseId::new(2).expect("in range");
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);

        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        dmx_rcv.listen_universes(&[sync_addr_1, sync_addr_2]).unwrap();

        let src_cid: Uuid = Uuid::from_bytes([
            0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
        ]);

        let sync_packet = generate_sync_packet_framing_layer_seq_num(Some(sync_addr_1), 0);
        let sync_packet2 = generate_sync_packet_framing_layer_seq_num(Some(sync_addr_1), 1);
        let sync_packet3 = generate_sync_packet_framing_layer_seq_num(Some(sync_addr_2), 0);

        // Not interested in specific return values from this test, just assert the data is processed successfully.
        assert!(
            dmx_rcv.handle_sync_packet(src_cid, sync_packet).unwrap().is_none(),
            "Receiver incorrectly rejected first sync packet"
        );
        assert!(
            dmx_rcv.handle_sync_packet(src_cid, sync_packet2).unwrap().is_none(),
            "Receiver incorrectly rejected second sync packet"
        );

        // At this point the receiver will (as shown by test_sync_packet_sequence_number_below_expected) reject a sync packet for SYNC_ADDR_1 with sequence number 0
        // however this sync packet is for SYNC_ADDR_2 and so therefore should be accepted.
        assert!(
            dmx_rcv.handle_sync_packet(src_cid, sync_packet3).unwrap().is_none(),
            "Receiver incorrectly rejected third sync packet"
        );
    }

    #[test]
    fn test_source_limit_0() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
        let source_limit: Option<usize> = Some(0);

        match SacnReceiver::with_ip(addr, source_limit) {
            Err(e) => match e {
                ReceiveError::Io(x) => match x.kind() {
                    std::io::ErrorKind::InvalidInput => {
                        assert!(true, "Correct error returned");
                    }
                    _ => {
                        assert!(false, "Expected error returned");
                    }
                },
                _ => {
                    assert!(false, "Unexpected error type returned");
                }
            },
            _ => {
                assert!(false, "SacnReceiver accepted 0 source limit when it shouldn't");
            }
        }
    }

    #[test]
    fn test_is_multicast_enabled() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
        let dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        assert!(dmx_rcv.is_multicast_enabled(), "Multicast not enabled by default");
    }

    #[test]
    fn test_set_is_multicast_enabled() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        dmx_rcv.set_is_multicast_enabled(false).unwrap();

        assert!(!dmx_rcv.is_multicast_enabled(), "Multicast not disabled correctly");
    }

    #[test]
    fn test_clear_waiting_data() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        let sync_addr = UniverseId::new(1).expect("in range");

        let data: DMXData = DMXData {
            universe: UniverseId::new(1).expect("in range"), // @todo this used to be 0, not 1.
            values: heapless::Vec::from_slice(&[1, 2, 3]).unwrap(),
            sync_uni: Some(sync_addr),
            priority: Priority::default(),
            src_cid: Some(Uuid::new_v4()),
            preview: false,
            recv_timestamp: Timestamp::now(),
        };

        dmx_rcv.store_waiting_data(data).unwrap();

        dmx_rcv.clear_all_waiting_data();

        assert!(dmx_rcv.rtrv_waiting_data(sync_addr).is_empty(), "Data was not reset as expected");
    }

    #[test]
    fn test_get_announce_source_discovery() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
        let dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        assert!(
            !dmx_rcv.get_announce_source_discovery(),
            "Announce source discovery is true by default when should be false"
        );
    }

    #[test]
    fn test_get_announce_timeout() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
        let dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        assert!(
            !dmx_rcv.get_announce_timeout(),
            "Announce timeout flag is true by default when should be false"
        );
    }

    #[test]
    fn test_get_announce_stream_termination() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
        let dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        assert!(
            !dmx_rcv.get_announce_stream_termination(),
            "Announce termination flag is true by default when should be false"
        );
    }

    /// Tests handling a sync packet for a synchronisation address which isn't currently being listened to.
    #[test]
    fn test_handle_sync_packet_not_listening_to_sync_addr() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT);
        let mut dmx_rcv = SacnReceiver::with_ip(addr, None).unwrap();

        let res = dmx_rcv
            .handle_sync_packet(
                Uuid::new_v4(),
                SynchronizationPacketFramingLayer {
                    sequence_number: 0,
                    synchronization_address: Some(UniverseId::new(1).expect("in range")),
                },
            )
            .unwrap(); // Checks that no error is produced.

        assert_eq!(
            res, None,
            "Sync packet produced output when should have been ignored as for an address that isn't being listened to"
        );
    }

    /// Tests the equivalence of 2 DMXDatas which are only similar in the aspects used for checking equivalence.
    #[test]
    fn test_dmx_data_eq() {
        let universe = UniverseId::new(1).expect("in range");
        let values = heapless::Vec::from_slice(&[1, 2, 3]).unwrap();
        let sync_addr = UniverseId::new(1).expect("in range");
        let priority = Priority::default();
        let preview = false;

        let data1 = DMXData {
            universe,
            values: values.clone(),
            sync_uni: Some(sync_addr),

            // The below values can be different for 2 DMXData to be taken as equivalent.
            priority,
            src_cid: Some(Uuid::new_v4()),
            preview,
            recv_timestamp: Timestamp::now(),
        };

        let data2 = DMXData {
            universe,
            values,
            sync_uni: Some(sync_addr),

            // The below values can be different for 2 DMXData to be taken as equivalent.
            priority: Priority::new(150).expect("in range"),
            src_cid: None,
            preview: !preview,
            recv_timestamp: Timestamp::now(),
        };

        assert_eq!(data1, data2, "DMX data not seen as equivalent when should be");
    }
}
