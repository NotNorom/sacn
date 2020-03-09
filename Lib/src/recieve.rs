#![warn(missing_docs)]

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
    // receieved, if a discovery packet is receieved but there are more pages the source won't be discovered until all the pages are receieved.
    // If a page is lost this therefore means the source update / discovery in its entirety will be lost - implementation detail.


use error::errors::{*, ErrorKind::*};

/// Socket 2 used for the underlying UDP socket that sACN is sent over.
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

// Mass import as a very large amount of packet is used here (upwards of 20 items) and this is much cleaner.
use packet::{*, E131RootLayerData::*};

use std::cell::RefCell;
use std::collections::HashMap;
use std::cmp::{max, Ordering};
use std::time;
use std::time::{Duration, Instant};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::borrow::Cow;
use std::fmt;

/// The default size of the buffer used to recieve E1.31 packets.
/// 1143 bytes is biggest packet required as per Section 8 of ANSI E1.31-2018, aligned to 64 bit that is 1144 bytes.
pub const RCV_BUF_DEFAULT_SIZE: usize = 1144;

/// DMX payload size in bytes (512 bytes of data + 1 byte start code).
pub const DMX_PAYLOAD_SIZE: usize = 513;

/// By default shouldn't check for packets send over the network using unicast.
pub const CHECK_UNICAST_DEFAULT: bool = false;

/// By default should check for packets sent over the network using multicast.
pub const CHECK_MUTLICAST_DEFAULT: bool = true;

/// By default shouldn't check for packets sent over the network using broadcast.
pub const CHECK_BROADCAST_DEFAULT: bool = false;

/// The name of the thread which runs periodically to perform actions on the receiver such as update discovered universes.
pub const RCV_UPDATE_THREAD_NAME: &'static str = "rust_sacn_rcv_update_thread"; 

/// The default value of the process_preview_data flag.
const PROCESS_PREVIEW_DATA_DEFAULT: bool = false;

/// The default value for the reading timeout for a SacnNetworkReceiver.
pub const DEFAULT_RECV_TIMEOUT: Option<Duration> = Some(time::Duration::from_millis(500));

/// Allows receiving dmx or other (different startcode) data using sacn.
pub struct SacnReceiver {

    /// The SacnNetworkReceiver used for handling communication with UDP / Network / Transport layer.
    receiver: SacnNetworkReceiver,
    
    /// Data that hasn't been passed up yet as it is waiting e.g. due to universe synchronisation.
    waiting_data: Vec<DMXData>, 
    
    /// Universes that this receiver is currently listening for
    universes: Vec<u16>, 
    
    /// Sacn sources that have been discovered by this receiver through universe discovery packets.
    discovered_sources: Vec<DiscoveredSacnSource>, 

    /// The merge function used by this receiver if DMXData for the same universe and synchronisation universe is received while there
    /// is already DMXData waiting for that universe and synchronisation address.
    merge_func: fn(&DMXData, &DMXData) -> Result<DMXData>,
    
    /// Sacn sources that have been partially discovered by only some of their universes being discovered so far with more pages to go.
    partially_discovered_sources: Vec<DiscoveredSacnSource>, 
    
    /// Flag that indicates if this receiver should process packets marked as preview data. 
    /// If true then the receiver will process theses packets.
    process_preview_data: bool,

    /// The sequence numbers used for data packets, keeps a reference of the last sequence number received for each universe.
    /// Sequence numbers are always in the range [0, 255] inclusive.
    /// Each type of packet is tracked differently with respect to sequence numbers as per ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
    data_sequences: RefCell<HashMap<u16, u8>>,

    /// The sequence numbers used for synchronisation packets, keeps a reference of the last sequence number received for each universe.
    /// Sequence numbers are always in the range [0, 255] inclusive.
    /// Each type of packet is tracked differently with respect to sequence numbers as per ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
    sync_sequences: RefCell<HashMap<u16, u8>>,
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
    /// By default for an IPv6 address this will only receieve IPv6 data but IPv4 can also be enabled by calling set_ipv6_only(false).
    /// A receiver with an IPv4 address will only receive IPv4 data.
    /// 
    /// Bind to the unspecified address - allows receiving from any multicast address joined with the right port - as described in background.
    /// let addr = SocketAddr::new(IpAddr::UNSPECIFIED, ACN_SDT_MULTICAST_PORT)
    /// 
    /// # Errors
    /// Will return an error if the SacnReceiver fails to bind to a socket with the given ip. 
    /// For more details see socket2::Socket::new().
    /// 
    /// Will return an error if the created SacnReceiver fails to listen to the E1.31_DISCOVERY_UNIVERSE.
    /// For more details see SacnReceiver::listen_universes().
    /// 
    pub fn with_ip(ip: SocketAddr) -> Result<SacnReceiver> {
        let mut sri = SacnReceiver {
                receiver: SacnNetworkReceiver::new(ip).chain_err(|| "Failed to create SacnNetworkReceiver")?,
                waiting_data: Vec::new(),
                universes: Vec::new(),
                discovered_sources: Vec::new(),
                merge_func: htp_dmx_merge,
                partially_discovered_sources: Vec::new(),
                process_preview_data: PROCESS_PREVIEW_DATA_DEFAULT,
                data_sequences: RefCell::new(HashMap::new()),
                sync_sequences: RefCell::new(HashMap::new()),
        };

        sri.listen_universes(&[E131_DISCOVERY_UNIVERSE]).chain_err(|| "Failed to listen to discovery universe")?;

        
        Ok(sri)
    }
    
    /// Sets the merge function to be used by this receiver.
    /// 
    /// This merge function is called if data is waiting for a universe e.g. for syncronisation and then further data for that universe with the same
    /// syncronisation address arrives.
    /// 
    /// Arguments:
    /// func: The merge function to use. Should take 2 DMXData references as arguments and return a Result<DMXData>.
    pub fn set_merge_fn(&mut self, func: fn(&DMXData, &DMXData) -> Result<DMXData>) -> Result<()> {
        self.merge_func = func;
        Ok(())
    }

    /// Allow only receiving on Ipv6. 
    pub fn set_ipv6_only(&mut self, val: bool) -> Result<()>{
        self.receiver.set_only_v6(val)
    }

    /// Deletes all data currently waiting to be passed up - e.g. waiting for a synchronisation packet.
    pub fn clear_waiting_data(&mut self){
        self.waiting_data.clear();
    }

    /// Starts listening to the multicast addresses which corresponds to the given universe to allow recieving packets for that universe.
    /// 
    /// If 1 or more universes in the list are already being listened to this method will have no effect for those universes only.
    /// 
    /// # Errors
    /// Returns an ErrorKind::IllegalUniverse error if the given universe is outwith the allowed range of universes,
    /// see (is_universe_in_range)[fn.is_universe_in_range.packet].
    /// 
    /// Will also return an Error if there is an issue listening to the multicast universe, see SacnNetworkReceiver::listen_multicast_universe().
    /// 
    pub fn listen_universes(&mut self, universes: &[u16]) -> Result<()>{
        for u in universes {
            is_universe_in_range(*u)?;
        }

        for u in universes {
            match self.universes.binary_search(u) { 
                Err(i) => { // Value not found, i is the position it should be inserted
                    self.universes.insert(i, *u);
                    self.receiver.listen_multicast_universe(*u).chain_err(|| "Failed to listen to multicast universe")?;
                }
                Ok(_) => { // If value found then don't insert to avoid duplicates.
                }
            }
        }

        Ok(())
    }

    /// Set the process_preview_data flag to the given value.
    /// 
    /// This flag indicates if this receiver should process packets marked as preview_data or should ignore them.
    /// 
    /// Argument:
    /// val: The new value of process_preview_data flag.
    fn set_process_preview_data(&mut self, val: bool) {
        self.process_preview_data = val;
    }

    /// Removes the given universe from the discovered sACN source with the given name.
    /// 
    /// Note this is just a record keeping operation, it doesn't actually effect the real sACN sender it 
    /// just updates the record of what universes are expected on this receiver.
    /// 
    /// Arguments:
    /// source_name: The human readable name of the sACN source to remove the universe from.
    /// universe:    The sACN universe to remove.
    fn terminate_stream<'a>(&mut self, source_name: Cow<'a, str>, universe: u16){
        match find_discovered_src(&self.discovered_sources, &source_name.to_string()){
            Some(index) => {
                self.discovered_sources[index].terminate_universe(universe);
            },
            None => {}
        }
    }

    /// Handles the given data packet for this DMX reciever.
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
    /// sending on that universe.
    /// 
    fn handle_data_packet(&mut self, data_pkt: DataPacketFramingLayer) -> Result<Option<Vec<DMXData>>>{
        if data_pkt.preview_data && !self.process_preview_data {
            // Don't process preview data unless receiver has process_preview_data flag set.
            return Ok(None);
        }

        if data_pkt.stream_terminated {
            self.terminate_stream(data_pkt.source_name, data_pkt.universe);
            bail!(ErrorKind::UniverseTerminated("A source terminated a universe and this was detected when trying to receive data".to_string()));
        }

        // Preview data and stream terminated both get precedence over checking the sequence number.
        // This is as per ANSI E1.31-2018 Section 6.2.6, Stream_Terminated: Bit 6, 'Any property values 
        // in an E1.31 Data Packet containing this bit shall be ignored'
        check_seq_number(&self.data_sequences, data_pkt.sequence_number, data_pkt.universe)?;

        if data_pkt.synchronization_address == E131_NO_SYNC_ADDR {
            self.clear_waiting_data();

            let vals: Vec<u8> = data_pkt.data.property_values.into_owned();
            let dmx_data: DMXData = DMXData {
                universe: data_pkt.universe, 
                values: vals.to_vec(),
                sync_uni: data_pkt.synchronization_address
            };

            return Ok(Some(vec![dmx_data]));
        } else {
            let vals: Vec<u8> = data_pkt.data.property_values.into_owned();
            let dmx_data: DMXData = DMXData {
                universe: data_pkt.universe,
                values: vals.to_vec(),
                sync_uni: data_pkt.synchronization_address
            };

            self.store_waiting_data(dmx_data);
            
            Ok(None)
        }
    }

    /// Takes the given data and stores it in the buffer of data waiting to be passed up.
    /// 
    /// Note that multiple bits of data for the same universe can be buffered at one time as long as the data is 
    /// waiting for different synchronisation universes. Only if the data is for the same universe and is waiting 
    /// for the same synchronisation universe is it merged.
    /// 
    fn store_waiting_data(&mut self, data: DMXData){
        for i in 0 .. self.waiting_data.len() {
            if self.waiting_data[i].universe == data.universe && self.waiting_data[i].sync_uni == data.sync_uni { 
                
                self.waiting_data[i] = ((self.merge_func)(&self.waiting_data[i], &data)).unwrap();
                return;
            }
        }

        self.waiting_data.push(data);
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
    /// 
    fn handle_sync_packet(&mut self, sync_pkt: SynchronizationPacketFramingLayer) -> Result<Option<Vec<DMXData>>>{
        check_seq_number(&self.sync_sequences, sync_pkt.sequence_number, sync_pkt.synchronization_address)?;

        let res = self.rtrv_waiting_data(sync_pkt.synchronization_address);
        if res.len() == 0 {
            Ok(None)
        } else {
            Ok(Some(res))
        }
    }

    /// Retrieves and removes the DMX data of all waiting data with a synchronisation address matching the one provided.
    /// Returns an empty Vec if there is no data waiting.
    /// 
    /// Arguments:
    /// sync_uni: The synchronisation universe of the data that should be retrieved.
    fn rtrv_waiting_data(&mut self, sync_uni: u16) -> Vec<DMXData> {
        let mut res: Vec<DMXData> = Vec::new();

        let mut i: usize = 0;
        let mut len: usize = self.waiting_data.len();

        while i < len {
            if self.waiting_data[i].sync_uni == sync_uni { 
                res.push(self.waiting_data.remove(i));
                len = len - 1;
            } else {
                i = i + 1;
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
        match find_discovered_src(&self.discovered_sources, &src.name){
            Some(index) => {
                self.discovered_sources.remove(index);
            },
            None => {}
        }
        self.discovered_sources.push(src);
    }

    /// Handles the given universe discovery packet.
    /// 
    /// This universe discovery packet might be the whole thing or may be just one page of a discovery packet.
    /// This method puts the pages to produce the DiscoveredSacnSource which is stored in the receiver.
    /// 
    /// Returns None as this will never produce data.
    /// 
    /// Arguments:
    /// discovery_pkt: The universe discovery part of the universe discovery packet to handle.
    /// 
    fn handle_universe_discovery_packet(&mut self, discovery_pkt: UniverseDiscoveryPacketFramingLayer) -> Option<Vec<DMXData>>{
        let data: UniverseDiscoveryPacketUniverseDiscoveryLayer = discovery_pkt.data;

        let page: u8 = data.page;
        let last_page: u8 = data.last_page;

        let universes = data.universes;

        let uni_page: UniversePage = UniversePage {
                page: page,
                universes: universes.into()
            };

        // See if some pages that belong to the source that this page belongs to have already been received.
        match find_discovered_src(&self.partially_discovered_sources, &discovery_pkt.source_name.to_string()) {
            Some(index) => { // Some pages have already been received from this source.
                self.partially_discovered_sources[index].pages.push(uni_page);
                self.partially_discovered_sources[index].last_updated = Instant::now();
                if self.partially_discovered_sources[index].has_all_pages() {
                    let discovered_src: DiscoveredSacnSource = self.partially_discovered_sources.remove(index);
                    self.update_discovered_srcs(discovered_src);
                }
            }
            None => { // This is the first page received from this source.
                let discovered_src: DiscoveredSacnSource = DiscoveredSacnSource {
                    name: discovery_pkt.source_name.to_string(),
                    last_page: last_page,
                    pages: vec![uni_page],
                    last_updated: Instant::now()
                };

                if page == 0 && page == last_page { // Indicates that this is a single page universe discovery packet.
                    self.update_discovered_srcs(discovered_src);
                } else { // Indicates that this is a page in a set of pages as part of a sources universe discovery.
                    self.partially_discovered_sources.push(discovered_src);
                }
            }
        }

        None
    }

    /// Attempt to recieve data from any of the registered universes.
    /// This is the main method for receiving data.
    /// Any data returned will be ready to act on immediately i.e. waiting e.g. for universe synchronisation
    /// is already handled.
    /// 
    /// # Errors
    /// This method will return a WouldBlock error if there is no data ready within the given timeout.
    /// A timeout of duration 0 will instantly return a WouldBlock error without checking for data.
    /// 
    /// The method may also return an error if there is an issue setting a timeout on the receiver. See 
    /// SacnNetworkReceiver::set_timeout for details.
    /// 
    /// The method may also return an error if there is an issue handling the data as either a Data, Syncronisation or Discovery packet.
    /// See the SacnReceiver::handle_data_packet, SacnReceiver::handle_sync_packet and SacnReceiver::handle_universe_discovery_packet methods 
    /// for details. 
    pub fn recv(&mut self, timeout: Option<Duration>) -> Result<Vec<DMXData>> {
        let mut buf: [u8; RCV_BUF_DEFAULT_SIZE ] = [0; RCV_BUF_DEFAULT_SIZE];

        if timeout == Some(Duration::from_secs(0)) {
            bail!(std::io::Error::new(std::io::ErrorKind::WouldBlock, "No data avaliable in given timeout"));
        }

        self.receiver.set_timeout(timeout).chain_err(|| "Failed to sent a timeout value for the receiver")?;
            let start_time = Instant::now();

            match self.receiver.recv(&mut buf){
                Ok(pkt) => {
                    let pdu: E131RootLayer = pkt.pdu;
                    let data: E131RootLayerData = pdu.data;
                    let res = match data {
                        DataPacket(d) => self.handle_data_packet(d).chain_err(|| "Failed to handle data packet")?,
                        SynchronizationPacket(s) => self.handle_sync_packet(s).chain_err(|| "Failed to handle sync packet")?,
                        UniverseDiscoveryPacket(u) => self.handle_universe_discovery_packet(u)
                    };
                    match res {
                        Some(r) => {
                            Ok(r)
                        },
                        None => { // Indicates that there is no data ready to pass up yet even if a packet was received.
                            // To stop recv blocking forever with a non-None timeout due to packets being received consistently (that reset the timeout)
                            // within the receive timeout (e.g. universe discovery packets if the discovery interval < timeout) the timeout needs to be 
                            // adjusted to account for the time already taken.
                            if !timeout.is_none() {
                                let elapsed = start_time.elapsed();
                                match timeout.unwrap().checked_sub(elapsed) {
                                    None => { // Indicates that elapsed is bigger than timeout so its time to return.
                                        bail!(std::io::Error::new(std::io::ErrorKind::WouldBlock, "No data avaliable in given timeout"));
                                    }
                                    Some(new_timeout) => {
                                        return self.recv(Some(new_timeout))
                                    }
                                }
                            } else {
                                // If the timeout was none then would keep looping till data is returned as the method should keep blocking till then.
                                self.recv(timeout)
                            }
                        } 
                    }
                }
                Err(err) => {
                    Err(err)
                }
            }
    }

    /// Returns a list of the sources that have been discovered on the network by this receiver through the E1.31 universe discovery mechanism.
    pub fn get_discovered_sources(&mut self) -> Vec<DiscoveredSacnSource>{
        self.remove_expired_sources();
        self.discovered_sources.clone()
    }

    /// Gets all discovered sources without checking if any are timed out. 
    /// As the sources may be timed out get_discovered_sources is the preferred method but this is included 
    /// to allow receivers to disable source timeouts which may be useful in very high latency networks.
    pub fn get_discovered_sources_no_check(&mut self) -> Vec<DiscoveredSacnSource> {
        self.discovered_sources.clone()
    }

    /// Goes through all discovered sources and removes any that have timed out
    fn remove_expired_sources(&mut self) {
        self.partially_discovered_sources.retain(|s| s.last_updated.elapsed() < UNIVERSE_DISCOVERY_SOURCE_TIMEOUT);
        self.discovered_sources.retain(|s| s.last_updated.elapsed() < UNIVERSE_DISCOVERY_SOURCE_TIMEOUT);
    }
}

/// Searches for the discovered source with the given name in the given vector of discovered sources and 
/// returns the index of the src in the Vec or None if not found.
/// 
/// Arguments:
/// srcs: The Vec of DiscoveredSacnSources to search.
/// name: The human readable name of the source to find.
/// 
fn find_discovered_src(srcs: &Vec<DiscoveredSacnSource>, name: &String) -> Option<usize> {
    for i in 0 .. srcs.len() {
        if srcs[i].name == *name {
            return Some(i);
        }
    }
    None
}

/// In general the lower level transport layer is handled by SacnNetworkReceiver (which itself wraps a Socket). 
impl SacnNetworkReceiver {
    /// Creates a new DMX receiver on the interface specified by the given address.
    /// 
    /// If the given address is an IPv4 address then communication will only work between IPv4 devices, if the given address is IPv6 then communication
    /// will only work between IPv6 devices by default but IPv4 receiving can be enabled using set_ipv6_only(false).
    /// 
    /// # Errors
    /// Will return an error if the SacnReceiver fails to bind to a socket with the given ip. 
    /// For more details see socket2::Socket::new().
    /// 
    pub fn new (ip: SocketAddr) -> Result<SacnNetworkReceiver> {
        Ok(
            SacnNetworkReceiver {
                socket: create_socket(ip)?,
                addr: ip
            }
        )
    }

    /// Connects a socket to the multicast address which corresponds to the given universe to allow recieving packets for that universe.
    /// Returns as a Result containing a SacnNetworkReceiver if Ok which recieves multicast packets for the given universe.
    /// 
    /// # Errors
    /// Will return an Error if the given universe cannot be converted to an Ipv4 or Ipv6 multicast_addr depending on if the Receiver is bound to an 
    /// IPv4 or IPv6 address. See packet::universe_to_ipv4_multicast_addr and packet::universe_to_ipv6_multicast_addr.
    /// 
    pub fn listen_multicast_universe(&self, universe: u16) -> Result<()> {
        let multicast_addr;

        if self.addr.is_ipv4() {
            multicast_addr = universe_to_ipv4_multicast_addr(universe).chain_err(|| "Failed to convert universe to IPv4 multicast addr")?;
        } else {
            multicast_addr = universe_to_ipv6_multicast_addr(universe).chain_err(|| "Failed to convert universe to IPv6 multicast addr")?;
        }

        Ok(join_multicast(&self.socket, multicast_addr).chain_err(|| "Failed to join multicast")?)
    }

    /// If set to true then only receieve over IPv6. If false then receiving will be over both IPv4 and IPv6. 
    /// This will return an error if the SacnReceiver wasn't created using an IPv6 address to bind to.
    pub fn set_only_v6(&mut self, val: bool) -> Result<()>{
        if self.addr.is_ipv4() {
            bail!(IpVersionError("No data avaliable in given timeout".to_string()))
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
    /// IMPORTANT NOTE:
    /// An explicit lifetime is given to the AcnRootLayerProtocol which comes from the lifetime of the given buffer.
    /// The compiler will prevent usage of the returned AcnRootLayerProtocol after the buffer is dropped.
    /// 
    /// Arguments:
    /// buf: The buffer to use for storing the received data into. This buffer shouldn't be accessed or used directly as the data
    /// is returned formatted properly in the AcnRootLayerProtocol. This buffer is used as memory space for the returned AcnRootLayerProtocol.
    /// 
    /// # Errors
    /// May return an error if there is an issue receiving data from the underlying socket, see (recv)[fn.recv.Socket].
    /// 
    /// May return an error if there is an issue parsing the data from the underlying socket, see (parse)[fn.AcnRootLayerProtocol::parse.packet].
    /// 
    fn recv<'a>(&self, buf: &'a mut [u8; RCV_BUF_DEFAULT_SIZE]) -> Result<AcnRootLayerProtocol<'a>> {
        self.socket.recv(&mut buf[0..])?;

        Ok(AcnRootLayerProtocol::parse(buf)?)
    }

    /// Set the timeout for the recv operation.
    /// 
    /// Arguments:
    /// timeout: The new timeout for the receive operation, a value of None means the recv operation will become blocking.
    /// 
    /// Errors:
    /// A timeout with Duration 0 will cause an error. See (set_read_timeout)[fn.set_read_timeout.Socket].
    /// 
    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        Ok(self.socket.set_read_timeout(timeout)?)
    }

    /// Returns the current read timeout for the receiver.
    /// 
    /// A timeout of None indicates infinite blocking behaviour.
    /// 
    pub fn read_timeout(&self) -> Result<Option<Duration>> {
        Ok(self.socket.read_timeout()?)
    }
}

/// Holds a universes worth of DMX data.
#[derive(Debug)]
pub struct DMXData{
    /// The universe that the data was sent to.
    pub universe: u16,
    
    /// The actual universe data, if less than 512 values in length then implies trailing 0's to pad to a full-universe of data.
    pub values: Vec<u8>,

    /// The universe the data is (or was if now acted upon) waiting for a synchronisation packet from.
    /// 0 indicates it isn't waiting for a universe synchronisation packet. 
    pub sync_uni: u16 
}

impl Clone for DMXData {
    fn clone(&self) -> DMXData {
        let new_vals = self.values.to_vec(); // https://stackoverflow.com/questions/21369876/what-is-the-idiomatic-rust-way-to-copy-clone-a-vector-in-a-parameterized-functio (26/12/2019)
        
        DMXData {
            universe: self.universe,
            values: new_vals,
            sync_uni: self.sync_uni
        }
    }
}

/// DMXData has a total ordering based on the unvierse, then sync-universe and finally values.
impl Ord for DMXData {
    fn cmp(&self, other: &Self) -> Ordering {
        self.universe.cmp(&other.universe).then(self.sync_uni.cmp(&other.sync_uni)).then(self.values.cmp(&other.values))
    }
}

/// See Ord trait implementation for DMXData.
impl PartialOrd for DMXData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// DMXData is taken to be equivalent iff:
///     - The universes are the same
///     - The synchronisation universes are the same
///     - The values are all the same
impl PartialEq for DMXData {
    fn eq(&self, other: &Self) -> bool {
        self.universe == other.universe &&
        self.sync_uni == other.sync_uni &&
        self.values == other.values
    }
}

/// See PartialEq trait implementation for DMXData.
impl Eq for DMXData {}

/// Used for receiving dmx or other data on a particular universe using multicast.
#[derive(Debug)]
struct SacnNetworkReceiver{
    socket: Socket,
    addr: SocketAddr
}

/// Represents an sACN source/sender on the network that has been discovered by this sACN receiver by receiving universe discovery packets.
#[derive(Clone, Debug)]
pub struct DiscoveredSacnSource {
    /// The name of the source, no protocol guarantee this will be unique but if it isn't then universe discovery may not work correctly.
    pub name: String,

    /// The time at which the discovered source was last updated / a discovery packet was received by the source.
    pub last_updated: Instant,

    /// The pages that have been sent so far by this source when enumerating the universes it is currently sending on.   
    pages: Vec<UniversePage>,
    
    /// The last page that will be sent by this source.
    last_page: u8,
}

/// Universe discovery packets are broken down into pages to allow sending a large list of universes, each page contains a list of universes and
/// which page it is. The receiver then puts the pages together to get the complete list of universes that the discovered source is sending on.
/// 
/// The concept of pages is intentionally hidden from the end-user of the library as they are a network realisation of what is just an
/// abstract list of universes and don't play any part out-side of the protocol.
#[derive(Eq, Ord, PartialEq, PartialOrd, Clone, Debug)]
struct UniversePage {
    /// The page number of this page.
    page: u8,

    /// The universes that the source is transmitting that are on this page, this may or may-not be a complete list of all universes being sent 
    /// depending on if there are more pages.
    universes: Vec<u16>
}

impl DiscoveredSacnSource {
    /// Returns true if all the pages sent by this DiscoveredSacnSource have been receieved. 
    /// 
    /// This is based on each page containing a last-page value which indicates the number of the last page expected.
    pub fn has_all_pages(&mut self) -> bool {
        // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/sorting.html (31/12/2019)
        self.pages.sort_by(|a, b| a.page.cmp(&b.page));
        for i in 0 .. (self.last_page + 1) {
            if self.pages[i as usize].page != i {
                return false;
            }
        }

        return true;
    }

    /// Returns all the universes being send by this SacnSource as discovered through the universe discovery mechanism.
    /// 
    /// Intentionally abstracts over the underlying concept of pages as this is purely an E1.31 Universe Discovery concept and is otherwise transparent.
    pub fn get_all_universes(&self) -> Vec<u16> {
        let mut uni: Vec<u16> = Vec::new();
        for p in &self.pages {
            uni.extend_from_slice(&p.universes);
        }
        uni
    }

    /// Removes the given universe from the list of universes being sent by this discovered source.
    pub fn terminate_universe(&mut self, universe: u16) {
        for p in &mut self.pages {
            p.universes.retain(|x| *x != universe)
        }
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
/// Will return an error if the socket cannot be bound to the given address, see (bind)[fn.bind.Socket].
pub fn create_socket(addr: SocketAddr) -> Result<Socket> {
    if addr.is_ipv4() {
        let socket = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))?;
        socket.bind(&SockAddr::from(addr))?;
        Ok(socket)
    } else {
        let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;
        socket.bind(&SockAddr::from(addr))?;
        Ok(socket)
    }
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
fn join_multicast(socket: &Socket, addr: SocketAddr) -> Result<()> {
    match addr.ip() {
        IpAddr::V4(ref mdns_v4) => {
            socket.join_multicast_v4(mdns_v4, &Ipv4Addr::new(0,0,0,0)).chain_err(|| "Failed to join IPv4 multicast")?;
        }
        IpAddr::V6(ref mdns_v6) => {
            socket.join_multicast_v6(mdns_v6, 0).chain_err(|| "Failed to join IPv6 multicast")?;
        }
    };

    Ok(())
}

/// Checks the given sequence number for the given universe against the given expected sequence numbers.
/// 
/// Returns Ok(()) if the packet is detected in-order.
/// 
/// # Errors
/// Returns an OutOfSequence error if a packet is received out of order as detected by the different between 
/// the packets sequence number and the expected sequence number as specified in ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
///
fn check_seq_number(sequences: &RefCell<HashMap<u16, u8>>, sequence_number: u8, universe: u16) -> Result<()>{
    let expected_seq = match sequences.borrow().get(&universe) {
        Some(s) => *s,
        None => 255, // Should be set to the value before the initial sequence number. Can't do this using underflow as forbidden in rust.
    };

    let seq_diff: isize = (sequence_number as isize) - (expected_seq as isize);

    if seq_diff <= E131_SEQ_DIFF_DISCARD_UPPER_BOUND && seq_diff > E131_SEQ_DIFF_DISCARD_LOWER_BOUND {
        // Reject the out of order packet as per ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
        bail!(ErrorKind::OutOfSequence(
            format!("Packet recieved with sequence number {} is out of sequence, last {}, seq-diff {}", 
            sequence_number, expected_seq, seq_diff).to_string()));
    }

    sequences.borrow_mut().insert(universe, sequence_number);
    Ok(())
}

/// Performs a HTP DMX merge of data.
/// The first argument (i) is the existing data, n is the new data.
/// This function is only valid if both inputs have the same universe, sync addr, start_code and the data contains at least the first value (the start code).
/// If this doesn't hold an error will be returned.
/// Other merge functions may allow merging different start codes or not check for them.
pub fn htp_dmx_merge(i: &DMXData, n: &DMXData) -> Result<DMXData>{
    if i.values.len() < 1 || 
        n.values.len() < 1 || 
        i.universe != n.universe || 
        i.values[0] != n.values[0] || 
        i.sync_uni != n.sync_uni {
            bail!(DmxMergeError("Attempted DMX merge on dmx data with different universes, syncronisation universes or data with no values".to_string()));
    }

    let mut r: DMXData = DMXData{
        universe: i.universe,
        values: Vec::new(),
        sync_uni: i.sync_uni
    };

    let mut i_iter = i.values.iter();
    let mut n_iter = n.values.iter();

    let mut i_val = i_iter.next();
    let mut n_val = n_iter.next();

    while (i_val.is_some()) || (n_val.is_some()){
        if i_val == None {
            r.values.push(*n_val.unwrap());
        } else if n_val == None {
            r.values.push(*i_val.unwrap());
        } else {
            r.values.push(max(*n_val.unwrap(), *i_val.unwrap()));
        }

        i_val = i_iter.next();
        n_val = n_iter.next();
    }

    Ok(r)
}

#[test]
fn test_handle_single_page_discovery_packet() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT); 

    let mut dmx_rcv = SacnReceiver::with_ip(addr).unwrap();

    let name = "Test Src 1";
    let page: u8 = 0;
    let last_page: u8 = 0;
    let universes: Vec<u16> = vec![0, 1, 2, 3, 4, 5];

    let discovery_pkt: UniverseDiscoveryPacketFramingLayer = UniverseDiscoveryPacketFramingLayer {
        source_name: name.into(),

        /// Universe discovery layer.
        data: UniverseDiscoveryPacketUniverseDiscoveryLayer {
            page: page,

            /// The number of the final page.
            last_page: last_page,

            /// List of universes.
            universes: universes.clone().into(),
        },
    };
    
    let res: Option<Vec<DMXData>> = dmx_rcv.handle_universe_discovery_packet(discovery_pkt).unwrap();

    assert!(res.is_none());

    assert_eq!(dmx_rcv.discovered_sources.len(), 1);

    assert_eq!(dmx_rcv.discovered_sources[0].name, name);
    assert_eq!(dmx_rcv.discovered_sources[0].last_page, last_page);
    assert_eq!(dmx_rcv.discovered_sources[0].pages.len(), 1);
    assert_eq!(dmx_rcv.discovered_sources[0].pages[0].page, page);
    assert_eq!(dmx_rcv.discovered_sources[0].pages[0].universes, universes);
}

#[test]
fn test_store_retrieve_waiting_data(){
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT); 

    let mut dmx_rcv = SacnReceiver::with_ip(addr).unwrap();

    let sync_uni: u16 = 1;
    let universe: u16 = 0;
    let vals: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let dmx_data = DMXData {
        universe: universe,
        values: vals.clone(),
        sync_uni: sync_uni 
    };

    dmx_rcv.store_waiting_data(dmx_data).unwrap();

    let res: Vec<DMXData> = dmx_rcv.rtrv_waiting_data(sync_uni).unwrap();

    assert_eq!(res.len(), 1);
    assert_eq!(res[0].universe, universe);
    assert_eq!(res[0].sync_uni, sync_uni);
    assert_eq!(res[0].values, vals);
}

#[test]
fn test_store_2_retrieve_1_waiting_data(){
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT); 

    let mut dmx_rcv = SacnReceiver::with_ip(addr).unwrap();

    let sync_uni: u16 = 1;
    let universe: u16 = 0;
    let vals: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let dmx_data = DMXData {
        universe: universe,
        values: vals.clone(),
        sync_uni: sync_uni 
    };

    let dmx_data2 = DMXData {
        universe: universe + 1,
        values: vals.clone(),
        sync_uni: sync_uni + 1 
    };

    dmx_rcv.store_waiting_data(dmx_data).unwrap();
    dmx_rcv.store_waiting_data(dmx_data2).unwrap();

    let res: Vec<DMXData> = dmx_rcv.rtrv_waiting_data(sync_uni).unwrap();

    assert_eq!(res.len(), 1);
    assert_eq!(res[0].universe, universe);
    assert_eq!(res[0].sync_uni, sync_uni);
    assert_eq!(res[0].values, vals);
}

#[test]
fn test_store_2_retrieve_2_waiting_data(){
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ACN_SDT_MULTICAST_PORT); 

    let mut dmx_rcv = SacnReceiver::with_ip(addr).unwrap();

    let sync_uni: u16 = 1;
    let universe: u16 = 0;
    let vals: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let dmx_data = DMXData {
        universe: universe,
        values: vals.clone(),
        sync_uni: sync_uni 
    };

    let vals2: Vec<u8> = vec![0, 9, 7, 3, 2, 4, 5, 6, 5, 1, 2, 3];

    let dmx_data2 = DMXData {
        universe: universe + 1,
        values: vals2.clone(),
        sync_uni: sync_uni + 1 
    };

    dmx_rcv.store_waiting_data(dmx_data).unwrap();
    dmx_rcv.store_waiting_data(dmx_data2).unwrap();

    let res: Vec<DMXData> = dmx_rcv.rtrv_waiting_data(sync_uni).unwrap();

    assert_eq!(res.len(), 1);
    assert_eq!(res[0].universe, universe);
    assert_eq!(res[0].sync_uni, sync_uni);
    assert_eq!(res[0].values, vals);

    let res2: Vec<DMXData> = dmx_rcv.rtrv_waiting_data(sync_uni + 1).unwrap();

    assert_eq!(res2.len(), 1);
    assert_eq!(res2[0].universe, universe + 1);
    assert_eq!(res2[0].sync_uni, sync_uni + 1);
    assert_eq!(res2[0].values, vals2);
}
