// Copyright 2020 sacn Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// This file was created as part of a University of St Andrews Computer Science BSC Senior Honours Dissertation Project.
#![cfg(feature = "std")]

use std::{
    convert::TryInto,
    io::Read,
    iter,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str,
    sync::{
        mpsc,
        mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender},
    },
    thread,
};

use sacn::{
    dmx_data::DMXData,
    e131_definitions::{
        ACN_SDT_MULTICAST_PORT, E131_NETWORK_DATA_LOSS_TIMEOUT, E131_SYNC_PACKET_LENGTH, E131_UNIVERSE_DISCOVERY_INTERVAL,
        UNIVERSE_CHANNEL_CAPACITY,
    },
    error::{ReceiveError, SourceError},
    packet::*,
    priority::Priority,
    receive::SacnReceiver,
    source::SacnSource,
    time::{Duration, Timestamp, sleep},
    universe_id::{UniverseId, slice_to_universes},
};
/// Socket2 used to create sockets for testing.
use socket2::{Domain, Socket, Type};
/// UUID library used to handle the UUID's used in the CID fields.
use uuid::Uuid;

/// For some tests to work multiple instances of the protocol must be on the same network with the same port for example to test multiple simultaneous receivers, this means multiple IP's are needed.
/// This is achieved by assigning multiple static IP's to the test machine and theses IP's are specified below.
/// Theses must be changed depending on the network that the test machine is on.
pub const TEST_NETWORK_INTERFACE_IPV4: [&str; 3] = ["192.168.0.6", "192.168.0.7", "192.168.0.8"];

pub const TEST_DATA_PARTIAL_CAPACITY_UNIVERSE: [u8; 313] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1,
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
];

pub const TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE: [u8; 513] = [
    1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1,
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
];

pub const TEST_DATA_SINGLE_UNIVERSE: [u8; 513] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1,
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
];

pub const TEST_DATA_MULTIPLE_ALTERNATIVE_STARTCODE_UNIVERSE: [u8; 714] = [
    1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1,
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 3, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100,
];

pub const TEST_DATA_MULTIPLE_UNIVERSE: [u8; 714] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1,
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100,
];
pub const TEST_DATA_FULL_CAPACITY_MULTIPLE_UNIVERSE: [u8; 1026] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1,
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
];

// Note: For this test to work the PC must be capable of connecting to the network on 2 IP's, this was done in windows by adding another static IP so the PC was connecting through
// 2 different IP's to the network. Theses IPs are manually specified in the TEST_NETWORK_INTERFACE_IPV4 constant and so to run it must be changed
// depending on the environment.
#[test]
#[ignore]
fn test_send_single_universe_multiple_receivers_multicast_ipv4() {
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread1_tx = tx.clone();
    let thread2_tx = tx.clone();

    let universe = UniverseId::new(1).expect("in range");

    let rcv_thread1 = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&[universe]).unwrap();

        thread1_tx.send(Ok(Vec::new())).unwrap();

        thread1_tx.send(dmx_recv.recv(None)).unwrap();
    });

    let rcv_thread2 = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[1].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&[universe]).unwrap();

        thread2_tx.send(Ok(Vec::new())).unwrap();

        thread2_tx.send(dmx_recv.recv(None)).unwrap();
    });

    rx.recv().unwrap().unwrap(); // Blocks until both receivers say they are ready.
    rx.recv().unwrap().unwrap();

    let ip: SocketAddr = SocketAddr::new(
        IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
        ACN_SDT_MULTICAST_PORT + 1,
    );

    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    let priority = Priority::default();

    src.register_universe(universe).unwrap();

    src.send(&[universe], &TEST_DATA_SINGLE_UNIVERSE, Some(priority), None, None)
        .unwrap();

    let received_result1: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();
    let received_result2: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();

    rcv_thread1.join().unwrap();
    rcv_thread2.join().unwrap();

    assert!(received_result1.is_ok(), "Failed: Error when receiving data");
    let received_data1: Vec<DMXData> = received_result1.unwrap();
    assert_eq!(received_data1.len(), 1); // Check only 1 universe received as expected.
    let received_universe1: DMXData = received_data1[0].clone();
    assert_eq!(received_universe1.universe, universe); // Check that the universe received is as expected.
    assert_eq!(
        received_universe1.values, TEST_DATA_SINGLE_UNIVERSE,
        "Received payload values don't match sent!"
    );

    assert!(received_result2.is_ok(), "Failed: Error when receiving data");
    let received_data2: Vec<DMXData> = received_result2.unwrap();
    assert_eq!(received_data2.len(), 1); // Check only 1 universe received as expected.
    let received_universe2: DMXData = received_data2[0].clone();
    assert_eq!(received_universe2.universe, universe); // Check that the universe received is as expected.
    assert_eq!(
        received_universe2.values, TEST_DATA_SINGLE_UNIVERSE,
        "Received payload values don't match sent!"
    );
}

#[test]
#[ignore]
fn test_send_across_universe_multiple_receivers_sync_multicast_ipv4() {
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread1_tx = tx.clone();
    let thread2_tx = tx.clone();

    let universe1 = UniverseId::new(1).expect("in range");
    let universe2 = UniverseId::new(2).expect("in range");

    let sync_uni = UniverseId::new(3).expect("in range");

    let rcv_thread1 = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&[universe1]).unwrap();
        dmx_recv.listen_universes(&[sync_uni]).unwrap();

        thread1_tx.send(Ok(Vec::new())).unwrap();

        thread1_tx.send(dmx_recv.recv(None)).unwrap();
    });

    let rcv_thread2 = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[1].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&[universe2]).unwrap();
        dmx_recv.listen_universes(&[sync_uni]).unwrap();

        thread2_tx.send(Ok(Vec::new())).unwrap();

        thread2_tx.send(dmx_recv.recv(None)).unwrap();
    });

    rx.recv().unwrap().unwrap(); // Blocks until both receivers say they are ready.
    rx.recv().unwrap().unwrap();

    let ip: SocketAddr = SocketAddr::new(
        IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
        ACN_SDT_MULTICAST_PORT + 1,
    );

    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    let priority = Priority::default();

    src.register_universe(universe1).unwrap();
    src.register_universe(universe2).unwrap();
    src.register_universe(sync_uni).unwrap();

    src.send(
        &[universe1],
        &TEST_DATA_MULTIPLE_UNIVERSE[..513],
        Some(priority),
        None,
        Some(sync_uni),
    )
    .unwrap();
    src.send(
        &[universe2],
        &TEST_DATA_MULTIPLE_UNIVERSE[513..],
        Some(priority),
        None,
        Some(sync_uni),
    )
    .unwrap();

    // Waiting to receive, if anything is received it indicates one of the receivers progressed without waiting for synchronisation.
    // This has the issue that is is possible that even though they could have progressed the receive threads may not have leading them to pass this part
    // when they shouldn't. This is difficult to avoid using this method of testing. It is also possible for the delay on the network to be so high that it
    // causes the timeout, this is also difficult to avoid. Both of these reasons should be considered if this test passes occasionally but not consistently.
    // The timeout should be large enough to make this unlikely although must be lower than the protocol's in-built timeout.
    const WAIT_RECV_TIMEOUT: u64 = 2;
    let attempt_recv = rx.recv_timeout(Duration::from_secs(WAIT_RECV_TIMEOUT).inner());

    match attempt_recv {
        Ok(_) => {
            assert!(false, "Receivers received without waiting for sync");
        }
        Err(e) => assert_eq!(e, RecvTimeoutError::Timeout),
    }

    src.send_sync_packet(sync_uni, None).unwrap();

    let received_result1: Vec<DMXData> = rx.recv().unwrap().unwrap();
    let received_result2: Vec<DMXData> = rx.recv().unwrap().unwrap();

    rcv_thread1.join().unwrap();
    rcv_thread2.join().unwrap();

    assert_eq!(received_result1.len(), 1); // Check only 1 universe received as expected.
    assert_eq!(received_result2.len(), 1); // Check only 1 universe received as expected.

    let mut results = [received_result1[0].clone(), received_result2[0].clone()];
    results.sort_unstable(); // Ordering of received data is undefined, to make it easier to check sort first.

    assert_eq!(results[0].universe, universe1); // Check that the universe 1 received is as expected.
    assert_eq!(results[1].universe, universe2); // Check that the universe 2 received is as expected.

    assert_eq!(results[0].values, TEST_DATA_MULTIPLE_UNIVERSE[..513]);
    assert_eq!(results[1].values, TEST_DATA_MULTIPLE_UNIVERSE[513..]);
}

#[test]
#[ignore]
fn test_send_recv_single_universe_unicast_ipv4() {
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread_tx = tx.clone();

    let universe = UniverseId::new(1).expect("in range");

    let rcv_thread = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ACN_SDT_MULTICAST_PORT), None).unwrap();

        dmx_recv.listen_universes(&[universe]).unwrap();

        thread_tx.send(Ok(Vec::new())).unwrap();

        thread_tx.send(dmx_recv.recv(None)).unwrap();
    });

    let _ = rx.recv().unwrap(); // Blocks until the receiver says it is ready.

    let ip: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ACN_SDT_MULTICAST_PORT + 1);
    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    let priority = Priority::default();

    src.register_universe(universe).unwrap();

    let dst_ip: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ACN_SDT_MULTICAST_PORT);

    src.send(&[universe], &TEST_DATA_SINGLE_UNIVERSE, Some(priority), Some(dst_ip), None)
        .unwrap();

    let received_result: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();

    rcv_thread.join().unwrap();

    assert!(received_result.is_ok(), "Failed: Error when receiving data");

    let received_data: Vec<DMXData> = received_result.unwrap();

    assert_eq!(received_data.len(), 1); // Check only 1 universe received as expected.

    let received_universe: DMXData = received_data[0].clone();

    assert_eq!(received_universe.universe, universe); // Check that the universe received is as expected.

    assert_eq!(
        received_universe.values, TEST_DATA_SINGLE_UNIVERSE,
        "Received payload values don't match sent!"
    );
}

/// A test showing a single universe of data being sent from a sender to a receiver over multicast on IPv4.
/// This test has more comments than usage as it is used as an example.
#[test]
#[ignore]
fn test_send_recv_single_universe_multicast_ipv4() {
    // The universe and priority of the data used in this test.
    let universe = UniverseId::new(1).expect("in range");
    let priority = Priority::default();

    // Allows control of the receiver and sender so that they can be put into the correct state for the test.
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();
    let thread_tx = tx.clone();

    // A simulated receiver, this is independent from the sender (apart from the communication channel for syncing states).
    let rcv_thread = thread::spawn(move || {
        // The receiver binds to a test IP and the ACN port. This port is the ported used for this protocol so the receiver must bind to it.
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&[universe]).unwrap();

        // A control message is sent now that the receiver is ready so that the sender can progress.
        thread_tx.send(Ok(Vec::new())).unwrap();

        // The receiver then waits until it receives the data.
        let result = dmx_recv.recv(None);

        // The SacnResult of the receiver is then sent back to the original test thread using the control channel.
        // This allows the checking of the results to be done on the first test thread (having the assertions on the same thread behaves better with debug output).
        thread_tx.send(result).unwrap();
    });

    // Blocks until the receiver says it is ready. This stops the sender sending before the receiver is created meaning it would miss the data.
    rx.recv().unwrap().unwrap();

    // The sender is bound to an interface on the same network as the receiver but on a different port.
    let ip: SocketAddr = SocketAddr::new(
        IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[1].parse().unwrap()),
        ACN_SDT_MULTICAST_PORT + 1,
    );
    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    // The sender registers the universe for sending and then sends some test data.
    src.register_universe(universe).unwrap();
    src.send(&[universe], &TEST_DATA_SINGLE_UNIVERSE, Some(priority), None, None)
        .unwrap();

    // The data that the receiver received is sent back using the thread message passing channel.
    let received_result: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();
    rcv_thread.join().unwrap();

    // Check that the receiver received the data without error.
    assert!(received_result.is_ok(), "Failed: Error when receiving data");

    // Check that the data received is as expected.
    let received_data: Vec<DMXData> = received_result.unwrap();
    assert_eq!(received_data.len(), 1); // Check only 1 universe received as expected.

    let received_universe: DMXData = received_data[0].clone();
    assert_eq!(received_universe.priority, priority, "Received priority doesn't match expected");
    assert_eq!(received_universe.universe, universe, "Received universe doesn't match expected");
    assert_eq!(
        received_universe.values, TEST_DATA_SINGLE_UNIVERSE,
        "Received payload values don't match sent!"
    );
}

/// A single sender transfers 260 data packets to a single receiver.
/// Since the sequence number field is a single unsigned byte (highest value 255) this should over flow the sequence number and so therefore this
/// test checks that the implementations handle this as expected by continuing as normal.
#[test]
#[ignore]
fn test_send_recv_single_universe_overflow_sequence_number_multicast_ipv4() {
    let data_packets_to_send: usize = 260;

    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread_tx = tx.clone();

    let universe = UniverseId::new(1).expect("in range");

    // By having the receiver be 'remote' and then send back to the sender it means the sender can check the data it has sent is correct.
    let rcv_thread = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&[universe]).unwrap();

        thread_tx.send(Ok(Vec::new())).unwrap();

        for _ in 0..data_packets_to_send {
            thread_tx.send(dmx_recv.recv(None)).unwrap();
        }
    });

    rx.recv().unwrap().unwrap(); // Blocks until the receiver says it is ready.

    let ip: SocketAddr = SocketAddr::new(
        IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
        ACN_SDT_MULTICAST_PORT + 1,
    );
    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    src.register_universe(universe).unwrap();

    for i in 0..data_packets_to_send {
        src.send(&[universe], &TEST_DATA_SINGLE_UNIVERSE[0..i + 1], None, None, None)
            .unwrap(); // Vary the data each packet.
        let received_data: Vec<DMXData> = rx.recv().unwrap().unwrap(); // Asserts that the data was received successfully without error.
        assert_eq!(received_data.len(), 1); // Check only 1 universe received at a time as expected.
        let received_universe: DMXData = received_data[0].clone();

        assert_eq!(received_universe.universe, universe); // Check that the universe received is as expected.

        assert_eq!(
            received_universe.values,
            TEST_DATA_SINGLE_UNIVERSE[0..i + 1],
            "Received payload values don't match sent!"
        );
    }

    // Finished with the receiver.
    rcv_thread.join().unwrap();
}

/// Sends 2 packets with the same universe and synchronisation address from a sender to a receiver, the first packet has a priority of 110
/// and the second a priority of 109. The receiver should discard the second packet when received due to its higher priority as per ANSI E1.31-2018 Section 6.2.3.
/// A sync packet is then sent and the receiver output checked that the right packet was kept.
/// Tests that lower priority packets are correctly discarded.
#[test]
#[ignore]
fn test_send_recv_diff_priority_same_universe_multicast_ipv4() {
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread_tx = tx.clone();

    let universe = UniverseId::new(1).expect("in range");

    let rcv_thread = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&[universe]).unwrap();

        thread_tx.send(Ok(Vec::new())).unwrap();

        thread_tx.send(dmx_recv.recv(None)).unwrap();
    });

    rx.recv().unwrap().unwrap(); // Blocks until the receiver says it is ready.

    let ip: SocketAddr = SocketAddr::new(
        IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
        ACN_SDT_MULTICAST_PORT + 1,
    );
    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    let priority = Priority::new(110).expect("in range");
    let priority_2 = Priority::new(109).expect("in range");

    src.register_universe(universe).unwrap();

    src.send(&[universe], &TEST_DATA_SINGLE_UNIVERSE, Some(priority), None, Some(universe))
        .unwrap(); // First packet with higher priority.
    src.send(
        &[universe],
        &TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
        Some(priority_2),
        None,
        Some(universe),
    )
    .unwrap(); // Second packet with lower priority.
    src.send_sync_packet(universe, None).unwrap(); // Trigger the packet to be passed up on the receiver.

    let received_result: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();

    rcv_thread.join().unwrap();

    assert!(received_result.is_ok(), "Failed: Error when receiving data");

    let received_data: Vec<DMXData> = received_result.unwrap();

    assert_eq!(received_data.len(), 1); // Check only 1 universe received as expected.

    let received_universe: DMXData = received_data[0].clone();

    assert_eq!(received_universe.universe, universe); // Check that the universe received is as expected.

    assert_eq!(
        received_universe.values, TEST_DATA_SINGLE_UNIVERSE,
        "Received payload values don't match sent!"
    );
}

/// Sends 2 packets with the same universe, priority and synchronisation address from a sender to a receiver.
/// The receiver should discard the first packet when the second arrives as per ANSI E1.31-2018 Section 6.2.3.
/// A sync packet is then sent and the receiver output checked that the right packet was kept.
/// Tests that older packet is correctly discarded.
#[test]
#[ignore]
fn test_send_recv_two_packets_same_priority_same_universe_multicast_ipv4() {
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread_tx = tx.clone();

    let universe = UniverseId::new(1).expect("in range");

    let rcv_thread = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&[universe]).unwrap();

        thread_tx.send(Ok(Vec::new())).unwrap();

        thread_tx.send(dmx_recv.recv(None)).unwrap();
    });

    rx.recv().unwrap().unwrap(); // Blocks until the receiver says it is ready.

    let ip: SocketAddr = SocketAddr::new(
        IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
        ACN_SDT_MULTICAST_PORT + 1,
    );
    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    let priority = Priority::new(110).expect("in range");

    src.register_universe(universe).unwrap();

    src.send(&[universe], &TEST_DATA_SINGLE_UNIVERSE, Some(priority), None, Some(universe))
        .unwrap(); // First packet
    src.send(
        &[universe],
        &TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
        Some(priority),
        None,
        Some(universe),
    )
    .unwrap(); // Second packet which should override first.
    src.send_sync_packet(universe, None).unwrap(); // Trigger the packet to be passed up on the receiver.

    let received_result: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();

    rcv_thread.join().unwrap();

    assert!(received_result.is_ok(), "Failed: Error when receiving data");

    let received_data: Vec<DMXData> = received_result.unwrap();

    assert_eq!(received_data.len(), 1); // Check only 1 universe received as expected.

    let received_universe: DMXData = received_data[0].clone();

    assert_eq!(received_universe.universe, universe); // Check that the universe received is as expected.

    assert_eq!(
        received_universe.values, TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
        "Received payload values don't match sent!"
    );
}

/// Sends data 2 packets with the same universe. The first packet is a synchronised packet with a synchronisation address
/// that is > 0. The second packet isn't synchronised as it has a synchronisation address of 0. This second packet should
/// therefore override the waiting packet as per ANSI E1.31-2018 Section 6.2.4.1.
///
/// To check that the waiting data is discarded the receiver receives once to check the second packet gets through and then
/// the source sends a sync_packet and the receiver receives again, since the waiting data was discarded it is expected that the
/// sync packet should have no effect and the receiver will timeout.
#[test]
#[ignore]
fn test_send_recv_sync_then_nosync_packet_same_universe_multicast_ipv4() {
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread_tx = tx.clone();

    let universe = UniverseId::new(1).expect("in range");
    let timeout: Option<Duration> = Some(Duration::from_secs(2));

    let rcv_thread = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&[universe]).unwrap();

        thread_tx.send(Ok(Vec::new())).unwrap();

        thread_tx.send(dmx_recv.recv(None)).unwrap(); // Receive a packet, expected to be the second packet which has caused the first to be discarded.

        thread_tx.send(dmx_recv.recv(timeout)).unwrap(); // Attempt to receive a packet, expected to timeout because the other data packet was discarded.
    });

    rx.recv().unwrap().unwrap(); // Blocks until the receiver says it is ready.

    let ip: SocketAddr = SocketAddr::new(
        IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
        ACN_SDT_MULTICAST_PORT + 1,
    );
    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    src.register_universe(universe).unwrap();

    src.send(&[universe], &TEST_DATA_SINGLE_UNIVERSE, None, None, Some(universe))
        .unwrap(); // First packet, with sync.
    src.send(&[universe], &TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE, None, None, None)
        .unwrap(); // Second packet, no sync.

    src.send_sync_packet(universe, None).unwrap(); // Send a sync packet, if the first packet isn't discarded it should now be passed up.

    let first_received_result: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();
    let second_received_result: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();

    rcv_thread.join().unwrap(); // Finished with receiver

    // Check that the first lot of data received (which should be the second packet) is as expected.
    assert!(first_received_result.is_ok(), "Unexpected error when receiving first lot of data");
    let received_data: Vec<DMXData> = first_received_result.unwrap();
    assert_eq!(received_data.len(), 1); // Check only 1 universe received as expected.
    let received_universe: DMXData = received_data[0].clone();
    assert_eq!(received_universe.universe, universe); // Check that the universe received is as expected.
    assert_eq!(
        received_universe.values, TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
        "Received payload values don't match sent!"
    );

    match second_received_result {
        Err(e) => {
            match e {
                ReceiveError::Io(ref s) => {
                    match s.kind() {
                        std::io::ErrorKind::WouldBlock => {
                            // Expected to timeout.
                            // The different errors are due to windows and unix returning different errors for the same thing.
                            assert!(true, "Timed out as expected meaning waiting data was successfully discarded");
                        }
                        std::io::ErrorKind::TimedOut => {
                            assert!(true, "Timed out as expected meaning waiting data was successfully discarded");
                        }
                        _ => {
                            assert!(false, "Unexpected error returned");
                        }
                    }
                }
                _ => {
                    assert!(false, "Unexpected error returned");
                }
            }
        }
        Ok(_) => {
            assert!(
                false,
                "Second receive attempt didn't timeout as expected, indicates that the synchronised data packet wasn't discarded as expected"
            );
        }
    }
}

#[test]
#[ignore]
fn test_send_recv_two_universe_multicast_ipv4() {
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread_tx = tx.clone();

    let universes = slice_to_universes(&[1, 2]).expect("in range");

    let rcv_thread = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&universes).unwrap();

        thread_tx.send(Ok(Vec::new())).unwrap(); // Notify the sender that the receiver is ready.

        thread_tx.send(dmx_recv.recv(None)).unwrap(); // Receive and pass on 2 lots of data, blocking.
        thread_tx.send(dmx_recv.recv(None)).unwrap();
    });

    rx.recv().unwrap().unwrap(); // Blocks until the receiver says it is ready.

    let ip: SocketAddr = SocketAddr::new(
        IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
        ACN_SDT_MULTICAST_PORT + 1,
    );
    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    src.register_universes(&universes).unwrap();

    // Send 2 universes of data with default priority, no synchronisation and use multicast.
    src.send(&universes, &TEST_DATA_MULTIPLE_UNIVERSE, None, None, None).unwrap();

    // Get the data that was sent to the receiver.
    let received_result: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();
    let received_result_2: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();

    // Receiver can be terminated.
    rcv_thread.join().unwrap();

    assert!(received_result.is_ok(), "Failed: Error when receiving 1st universe of data");
    assert!(received_result_2.is_ok(), "Failed: Error when receiving 2nd universe of data");

    let received_data: Vec<DMXData> = received_result.unwrap();
    let received_data_2: Vec<DMXData> = received_result_2.unwrap();

    assert_eq!(received_data.len(), 1); // Check only 1 universe received from each individual recv() as expected, if this wasn't the case it would
    assert_eq!(received_data_2.len(), 1); // indicate that the data has been synchronised incorrectly or that less data than expected was received.

    assert_eq!(received_data[0].universe, universes[0]); // Check that the universe received is as expected.
    assert_eq!(received_data_2[0].universe, universes[1]);

    assert_eq!(received_data[0].values, TEST_DATA_MULTIPLE_UNIVERSE[..513]);
    assert_eq!(received_data_2[0].values, TEST_DATA_MULTIPLE_UNIVERSE[513..]);
}

#[test]
#[ignore]
fn test_send_recv_single_universe_alternative_startcode_multicast_ipv4() {
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread_tx = tx.clone();

    let universe = UniverseId::new(1).expect("in range");

    let rcv_thread = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(
            SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
            None,
        )
        .unwrap();

        dmx_recv.listen_universes(&[universe]).unwrap();

        thread_tx.send(Ok(Vec::new())).unwrap();

        thread_tx.send(dmx_recv.recv(None)).unwrap();
    });

    rx.recv().unwrap().unwrap(); // Blocks until the receiver says it is ready.

    let ip: SocketAddr = SocketAddr::new(
        IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
        ACN_SDT_MULTICAST_PORT + 1,
    );
    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    let priority = Priority::default();

    src.register_universe(universe).unwrap();

    src.send(
        &[universe],
        &TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
        Some(priority),
        None,
        None,
    )
    .unwrap();

    let received_result: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();

    rcv_thread.join().unwrap();

    assert!(received_result.is_ok(), "Failed: Error when receiving data");

    let received_data: Vec<DMXData> = received_result.unwrap();

    assert_eq!(received_data.len(), 1); // Check only 1 universe received as expected.

    let received_universe: DMXData = received_data[0].clone();

    assert_eq!(received_universe.universe, universe); // Check that the universe received is as expected.

    assert_eq!(
        received_universe.values, TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
        "Received payload values don't match sent!"
    );
}

/// Note: this test assumes perfect network conditions (0% reordering, loss, duplication etc.), this should be the case for
/// the loopback adapter with the low amount of data sent but this may be a possible cause if integration tests fail unexpectedly.
#[test]
#[ignore]
fn test_send_recv_across_universe_multicast_ipv4() {
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread_tx = tx.clone();

    let universes = slice_to_universes(&[2, 3]).expect("in range");

    let rcv_thread = thread::spawn(move || {
        let mut dmx_recv = SacnReceiver::with_ip(SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), ACN_SDT_MULTICAST_PORT), None).unwrap();

        dmx_recv.listen_universes(&universes).unwrap();

        thread_tx.send(Ok(Vec::new())).unwrap(); // Signal that the receiver is ready to receive.

        thread_tx.send(dmx_recv.recv(None)).unwrap(); // Receive the sync packet, the data packets shouldn't have caused .recv to return as forced to wait for sync.
    });

    let _ = rx.recv().unwrap(); // Blocks until the receiver says it is ready.

    let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), ACN_SDT_MULTICAST_PORT + 1);
    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    let priority = Priority::default();

    src.register_universes(&universes).unwrap();

    src.send(&universes, &TEST_DATA_MULTIPLE_UNIVERSE, Some(priority), None, Some(universes[0]))
        .unwrap();
    sleep(Duration::from_millis(500)); // Small delay to allow the data packets to get through as per NSI-E1.31-2018 Appendix B.1 recommendation. See other warnings about the possibility of theses tests failing if the network isn't perfect.
    src.send_sync_packet(universes[0], None).unwrap();

    let sync_pkt_res: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();

    rcv_thread.join().unwrap();

    assert!(sync_pkt_res.is_ok(), "Failed: Error when receiving packets");

    let mut received_data: Vec<DMXData> = sync_pkt_res.unwrap();

    received_data.sort(); // No guarantee on the ordering of the received data so sort it first to allow easier checking.

    assert_eq!(received_data.len(), 2); // Check 2 universes received as expected.

    assert_eq!(received_data[0].universe, 2); // Check that the universe received is as expected.

    assert_eq!(received_data[0].sync_uni.unwrap(), 2); // Check that the sync universe is as expected.

    assert_eq!(
        received_data[0].values,
        TEST_DATA_MULTIPLE_UNIVERSE[..UNIVERSE_CHANNEL_CAPACITY],
        "Universe 1 received payload values don't match sent!"
    );

    assert_eq!(received_data[1].universe, 3); // Check that the universe received is as expected.

    assert_eq!(received_data[1].sync_uni.unwrap(), 2); // Check that the sync universe is as expected.

    assert_eq!(
        received_data[1].values,
        TEST_DATA_MULTIPLE_UNIVERSE[UNIVERSE_CHANNEL_CAPACITY..],
        "Universe 2 received payload values don't match sent!"
    );
}

/// Note: this test assumes perfect network conditions (0% reordering, loss, duplication etc.), this should be the case for
/// the loopback adapter with the low amount of data sent but this may be a possible cause if integration tests fail unexpectedly.
#[test]
#[ignore]
fn test_send_recv_across_universe_unicast_ipv4() {
    let (tx, rx): (
        Sender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::channel();

    let thread_tx = tx.clone();

    let universes = slice_to_universes(&[2, 3]).expect("in range");

    let rcv_thread = thread::spawn(move || {
        let mut dmx_recv =
            SacnReceiver::with_ip(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), ACN_SDT_MULTICAST_PORT), None).unwrap();

        dmx_recv.listen_universes(&universes).unwrap();

        thread_tx.send(Ok(Vec::new())).unwrap(); // Signal that the receiver is ready to receive.

        thread_tx.send(dmx_recv.recv(None)).unwrap(); // Receive the sync packet, the data packets shouldn't have caused .recv to return as forced to wait for sync.
    });

    let _ = rx.recv().unwrap(); // Blocks until the receiver says it is ready.

    let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), ACN_SDT_MULTICAST_PORT + 1);
    let mut src = SacnSource::with_ip("Source", ip).unwrap();

    let priority = Priority::default();

    src.register_universes(&universes).unwrap();

    src.send(
        &universes,
        &TEST_DATA_MULTIPLE_UNIVERSE,
        Some(priority),
        Some(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), ACN_SDT_MULTICAST_PORT)),
        Some(universes[0]),
    )
    .unwrap();
    sleep(Duration::from_millis(500)); // Small delay to allow the data packets to get through as per NSI-E1.31-2018 Appendix B.1 recommendation.
    src.send_sync_packet(
        universes[0],
        Some(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), ACN_SDT_MULTICAST_PORT)),
    )
    .unwrap();

    let sync_pkt_res: Result<Vec<DMXData>, ReceiveError> = rx.recv().unwrap();

    rcv_thread.join().unwrap();

    assert!(sync_pkt_res.is_ok(), "Failed: Error when receiving packets");

    let mut received_data: Vec<DMXData> = sync_pkt_res.unwrap();

    received_data.sort(); // No guarantee on the ordering of the received data so sort it first to allow easier checking.

    assert_eq!(received_data.len(), 2); // Check 2 universes received as expected.

    assert_eq!(received_data[0].universe, 2); // Check that the universe received is as expected.

    assert_eq!(received_data[0].sync_uni.unwrap(), 2); // Check that the sync universe is as expected.

    assert_eq!(
        received_data[0].values,
        TEST_DATA_MULTIPLE_UNIVERSE[..UNIVERSE_CHANNEL_CAPACITY],
        "Universe 1 received payload values don't match sent!"
    );

    assert_eq!(received_data[1].universe, 3); // Check that the universe received is as expected.

    assert_eq!(received_data[1].sync_uni.unwrap(), 2); // Check that the sync universe is as expected.

    assert_eq!(
        received_data[1].values,
        TEST_DATA_MULTIPLE_UNIVERSE[UNIVERSE_CHANNEL_CAPACITY..],
        "Universe 2 received payload values don't match sent!"
    );
}

#[test]
#[ignore]
fn test_two_senders_one_recv_different_universes_multicast_ipv4() {
    let universe_1 = UniverseId::new(1).expect("in range");
    let universe_2 = UniverseId::new(2).expect("in range");

    let mut dmx_recv = SacnReceiver::with_ip(SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), ACN_SDT_MULTICAST_PORT), None).unwrap();

    dmx_recv.listen_universes(&[universe_1]).unwrap();
    dmx_recv.listen_universes(&[universe_2]).unwrap();

    let snd_thread_1 = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), ACN_SDT_MULTICAST_PORT + 1);
        let mut src = SacnSource::with_ip("Source", ip).unwrap();

        let priority = Priority::default();

        src.register_universe(universe_1).unwrap();

        src.send(&[universe_1], &TEST_DATA_SINGLE_UNIVERSE, Some(priority), None, None)
            .unwrap();
    });

    let snd_thread_2 = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), ACN_SDT_MULTICAST_PORT + 2);
        let mut src = SacnSource::with_ip("Source", ip).unwrap();

        let priority = Priority::default();

        src.register_universe(universe_2).unwrap();

        src.send(&[universe_2], &TEST_DATA_PARTIAL_CAPACITY_UNIVERSE, Some(priority), None, None)
            .unwrap();
    });

    let res1: Vec<DMXData> = dmx_recv.recv(None).unwrap();
    let res2: Vec<DMXData> = dmx_recv.recv(None).unwrap();

    snd_thread_1.join().unwrap();
    snd_thread_2.join().unwrap();

    assert_eq!(res1.len(), 1);
    assert_eq!(res2.len(), 1);

    let mut res = [res1[0].clone(), res2[0].clone()];
    res.sort_unstable();

    assert_eq!(res[0].universe, universe_1);
    assert_eq!(res[1].universe, universe_2);

    assert_eq!(res[0].values, TEST_DATA_SINGLE_UNIVERSE);
    assert_eq!(res[1].values, TEST_DATA_PARTIAL_CAPACITY_UNIVERSE);
}

#[test]
#[ignore]
fn test_two_senders_one_recv_same_universe_no_sync_multicast_ipv4() {
    let universe = UniverseId::new(1).expect("in range");

    let mut dmx_recv = SacnReceiver::with_ip(SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), ACN_SDT_MULTICAST_PORT), None).unwrap();

    dmx_recv.listen_universes(&[universe]).unwrap();

    let snd_thread_1 = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), ACN_SDT_MULTICAST_PORT + 1);
        let mut src = SacnSource::with_ip("Source", ip).unwrap();

        let priority = Priority::default();

        src.register_universe(universe).unwrap();

        src.send(&[universe], &TEST_DATA_SINGLE_UNIVERSE, Some(priority), None, None)
            .unwrap();
    });

    let snd_thread_2 = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), ACN_SDT_MULTICAST_PORT + 2);
        let mut src = SacnSource::with_ip("Source", ip).unwrap();

        let priority = Priority::default();

        src.register_universe(universe).unwrap();

        src.send(&[universe], &TEST_DATA_PARTIAL_CAPACITY_UNIVERSE, Some(priority), None, None)
            .unwrap();
    });

    let res1: Vec<DMXData> = dmx_recv.recv(None).unwrap();
    let res2: Vec<DMXData> = dmx_recv.recv(None).unwrap();

    snd_thread_1.join().unwrap();
    snd_thread_2.join().unwrap();

    assert_eq!(res1.len(), 1);
    assert_eq!(res2.len(), 1);

    let res = [res1[0].clone(), res2[0].clone()];

    assert_eq!(res[0].universe, universe);
    assert_eq!(res[1].universe, universe);

    if res[0].values == TEST_DATA_SINGLE_UNIVERSE {
        assert_eq!(res[1].values, TEST_DATA_PARTIAL_CAPACITY_UNIVERSE);
    } else {
        assert_eq!(res[0].values, TEST_DATA_PARTIAL_CAPACITY_UNIVERSE);
        assert_eq!(res[1].values, TEST_DATA_SINGLE_UNIVERSE);
    }
}

#[test]
#[ignore]
fn test_two_senders_one_recv_same_universe_custom_merge_fn_sync_multicast_ipv4() {
    let (tx, rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0); // Used for handshaking

    let snd_tx = tx.clone();

    let universe = UniverseId::new(1).expect("in range");
    let sync_uni = UniverseId::new(2).expect("in range");

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap(), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();

    dmx_recv.listen_universes(&[universe, sync_uni]).unwrap();

    dmx_recv.set_merge_fn(DMXData::merge_htp);

    let snd_thread_1 = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(
            IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[1].parse().unwrap()),
            ACN_SDT_MULTICAST_PORT + 1,
        );
        let mut src = SacnSource::with_ip("Source", ip).unwrap();

        let priority = Priority::default();

        src.register_universe(universe).unwrap();
        src.register_universe(sync_uni).unwrap();

        src.send(&[universe], &TEST_DATA_SINGLE_UNIVERSE, Some(priority), None, Some(sync_uni))
            .unwrap();
        snd_tx.send(()).unwrap();
    });

    let snd_thread_2 = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(
            IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[2].parse().unwrap()),
            ACN_SDT_MULTICAST_PORT + 2,
        );
        let mut src = SacnSource::with_ip("Source 2", ip).unwrap();

        let priority = Priority::default();

        src.register_universe(universe).unwrap();
        src.register_universe(sync_uni).unwrap();

        src.send(
            &[universe],
            &TEST_DATA_PARTIAL_CAPACITY_UNIVERSE,
            Some(priority),
            None,
            Some(sync_uni),
        )
        .unwrap();
        rx.recv().unwrap(); // Must only send once both threads have sent for this test to test what happens in that situation (where there will be a merge).
        src.send_sync_packet(sync_uni, None).unwrap();
    });

    let res1: Vec<DMXData> = dmx_recv.recv(None).unwrap();

    snd_thread_1.join().unwrap();
    snd_thread_2.join().unwrap();

    assert_eq!(res1.len(), 1);
    assert_eq!(
        res1[0].values,
        DMXData {
            universe,
            values: TEST_DATA_SINGLE_UNIVERSE.as_slice().try_into().unwrap(),
            sync_uni: Some(sync_uni),
            priority: Priority::default(),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now()
        }
        .merge_htp(&DMXData {
            universe,
            values: TEST_DATA_PARTIAL_CAPACITY_UNIVERSE.as_slice().try_into().unwrap(),
            sync_uni: Some(sync_uni),
            priority: Priority::default(),
            src_cid: None,
            preview: false,
            recv_timestamp: Timestamp::now()
        },)
        .unwrap()
        .values
    );
}

#[test]
#[ignore]
fn test_two_senders_two_recv_multicast_ipv4() {
    let num_snd_threads: usize = 2;
    let num_rcv_threads: usize = 2;
    let snd_data_len: usize = 100;

    let mut snd_data: Vec<Vec<u8>> = Vec::new();

    for i in 1..num_snd_threads + 1 {
        let mut d: Vec<u8> = Vec::new();
        for _k in 0..snd_data_len {
            d.push(i as u8);
        }
        snd_data.push(d);
    }

    let mut snd_threads = Vec::new();
    let mut rcv_threads = Vec::new();

    let (rcv_tx, rcv_rx): (
        SyncSender<Vec<Result<Vec<DMXData>, ReceiveError>>>,
        Receiver<Vec<Result<Vec<DMXData>, ReceiveError>>>,
    ) = mpsc::sync_channel(0);
    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0); // Used for handshaking, allows syncing the sender states.

    assert!(
        num_rcv_threads <= TEST_NETWORK_INTERFACE_IPV4.len(),
        "Number of test network interface ips less than number of recv threads!"
    );

    let base_universe = 2;

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        let data = snd_data[i].clone();

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );
            // https://www.programming-idioms.org/idiom/153/concatenate-string-with-integer/1975/rust (11/01/2020)
            let mut src = SacnSource::with_ip(&format!("Source {}", i), ip).unwrap();

            let priority = Priority::default();

            let universe = UniverseId::new((i as u16) + base_universe).expect("in range");

            src.register_universe(universe).unwrap(); // Senders all send on different universes.

            tx.send(()).unwrap(); // Forces each sender thread to wait till the controlling thread receives which stops sending before the receivers are ready.

            src.send(&[universe], &data, Some(priority), None, None).unwrap();
        }));
    }

    for i in 0..num_rcv_threads {
        let tx = rcv_tx.clone();

        rcv_threads.push(thread::spawn(move || {
            // Port kept the same so must use multiple IP's.
            let mut dmx_recv = SacnReceiver::with_ip(
                SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[i].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
                None,
            )
            .unwrap();

            // Receivers listen to all universes
            for i in base_universe..((num_snd_threads as u16) + base_universe) {
                dmx_recv.listen_universes(&[UniverseId::new(i).expect("in range")]).unwrap();
            }

            let mut res: Vec<Result<Vec<DMXData>, ReceiveError>> = Vec::new();

            tx.send(Vec::new()).unwrap(); // Receiver notifies controlling thread it is ready.

            for _i in 0..num_snd_threads {
                // Receiver should receive from every universe.
                res.push(dmx_recv.recv(None)); // Receiver won't complete this until it receives from the senders which are all held waiting on the controlling thread.
            }

            // results of each receive are sent back, this allows checking that each receive was an expected universe, all universes were received and there were no errors.
            tx.send(res).unwrap();
        }));

        assert_eq!(rcv_rx.recv().unwrap().len(), 0); // Wait till the receiver has notified controlling thread it is ready.
    }

    for _i in 0..num_snd_threads {
        snd_rx.recv().unwrap(); // Allow each sender to progress
    }

    for _i in 0..num_rcv_threads {
        let res: Vec<Result<Vec<DMXData>, ReceiveError>> = rcv_rx.recv().unwrap();

        assert_eq!(res.len(), num_snd_threads);

        let mut rcv_dmx_datas: Vec<DMXData> = Vec::new();

        for r in res {
            let data: Vec<DMXData> = r.unwrap(); // Check that there are no errors when receiving.
            assert_eq!(data.len(), 1); // Check that each universe was received separately.
            rcv_dmx_datas.push(data[0].clone());
        }

        rcv_dmx_datas.sort_unstable(); // Sorting by universe allows easier checking as order received may vary depending on network.

        for k in 0..num_snd_threads {
            assert_eq!(rcv_dmx_datas[k].universe, ((k as u16) + base_universe)); // Check that the universe received is as expected.

            assert_eq!(rcv_dmx_datas[k].values, *snd_data[k], "Received payload values don't match sent!");
        }
    }

    for s in snd_threads {
        s.join().unwrap();
    }

    for r in rcv_threads {
        r.join().unwrap();
    }
}

#[test]
#[ignore]
fn test_three_senders_two_recv_multicast_ipv4() {
    let num_snd_threads: usize = 3;
    let num_rcv_threads: usize = 2;
    let snd_data_len: usize = 100;

    let mut snd_data: Vec<Vec<u8>> = Vec::new();

    for i in 1..num_snd_threads + 1 {
        let mut d: Vec<u8> = Vec::new();
        for _k in 0..snd_data_len {
            d.push(i as u8);
        }
        snd_data.push(d);
    }

    let mut snd_threads = Vec::new();
    let mut rcv_threads = Vec::new();

    let (rcv_tx, rcv_rx): (
        SyncSender<Vec<Result<Vec<DMXData>, ReceiveError>>>,
        Receiver<Vec<Result<Vec<DMXData>, ReceiveError>>>,
    ) = mpsc::sync_channel(0);
    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0); // Used for handshaking, allows syncing the sender states.

    assert!(
        num_rcv_threads <= TEST_NETWORK_INTERFACE_IPV4.len(),
        "Number of test network interface ips less than number of recv threads!"
    );

    let base_universe = 2;

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        let data = snd_data[i].clone();

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );
            // https://www.programming-idioms.org/idiom/153/concatenate-string-with-integer/1975/rust (11/01/2020)
            let mut src = SacnSource::with_ip(&format!("Source {}", i), ip).unwrap();

            let priority = Priority::default();

            let universe = UniverseId::new((i as u16) + base_universe).expect("in range");

            src.register_universe(universe).unwrap(); // Senders all send on different universes.

            tx.send(()).unwrap(); // Forces each sender thread to wait till the controlling thread receives which stops sending before the receivers are ready.

            src.send(&[universe], &data, Some(priority), None, None).unwrap();
        }));
    }

    for i in 0..num_rcv_threads {
        let tx = rcv_tx.clone();

        rcv_threads.push(thread::spawn(move || {
            // Port kept the same so must use multiple IP's.
            let mut dmx_recv = SacnReceiver::with_ip(
                SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[i].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
                None,
            )
            .unwrap();

            // Receivers listen to all universes
            for i in base_universe..((num_snd_threads as u16) + base_universe) {
                dmx_recv.listen_universes(&[UniverseId::new(i).expect("in range")]).unwrap();
            }

            let mut res: Vec<Result<Vec<DMXData>, ReceiveError>> = Vec::new();

            tx.send(Vec::new()).unwrap(); // Receiver notifies controlling thread it is ready.

            for _i in 0..num_snd_threads {
                // Receiver should receive from every universe.
                res.push(dmx_recv.recv(None)); // Receiver won't complete this until it receives from the senders which are all held waiting on the controlling thread.
            }

            // results of each receive are sent back, this allows checking that each receiver was an expected universe, all universes were received and there were no errors.
            tx.send(res).unwrap();
        }));

        assert_eq!(rcv_rx.recv().unwrap().len(), 0); // Wait till the receiver has notified controlling thread it is ready.
    }

    for _i in 0..num_snd_threads {
        snd_rx.recv().unwrap(); // Allow each sender to progress
    }

    for _i in 0..num_rcv_threads {
        let res: Vec<Result<Vec<DMXData>, ReceiveError>> = rcv_rx.recv().unwrap();

        assert_eq!(res.len(), num_snd_threads);

        let mut rcv_dmx_datas: Vec<DMXData> = Vec::new();

        for r in res {
            let data: Vec<DMXData> = r.unwrap(); // Check that there are no errors when receiving.
            assert_eq!(data.len(), 1); // Check that each universe was received separately.
            rcv_dmx_datas.push(data[0].clone());
        }

        rcv_dmx_datas.sort_unstable(); // Sorting by universe allows easier checking as order received may vary depending on network.

        for k in 0..num_snd_threads {
            assert_eq!(rcv_dmx_datas[k].universe, ((k as u16) + base_universe)); // Check that the universe received is as expected.

            assert_eq!(rcv_dmx_datas[k].values, *snd_data[k], "Received payload values don't match sent!");
        }
    }

    for s in snd_threads {
        s.join().unwrap();
    }

    for r in rcv_threads {
        r.join().unwrap();
    }
}

#[test]
#[ignore]
fn test_two_senders_three_recv_multicast_ipv4() {
    let num_snd_threads: usize = 2;
    let num_rcv_threads: usize = 3;
    let snd_data_len: usize = 100;

    let mut snd_data: Vec<Vec<u8>> = Vec::new();

    for i in 1..num_snd_threads + 1 {
        let mut d: Vec<u8> = Vec::new();
        for _k in 0..snd_data_len {
            d.push(i as u8);
        }
        snd_data.push(d);
    }

    let mut snd_threads = Vec::new();
    let mut rcv_threads = Vec::new();

    let (rcv_tx, rcv_rx): (
        SyncSender<Vec<Result<Vec<DMXData>, ReceiveError>>>,
        Receiver<Vec<Result<Vec<DMXData>, ReceiveError>>>,
    ) = mpsc::sync_channel(0);
    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0); // Used for handshaking, allows syncing the sender states.

    assert!(
        num_rcv_threads <= TEST_NETWORK_INTERFACE_IPV4.len(),
        "Number of test network interface ips less than number of recv threads!"
    );

    let base_universe = 2;

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        let data = snd_data[i].clone();

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );
            // https://www.programming-idioms.org/idiom/153/concatenate-string-with-integer/1975/rust (11/01/2020)
            let mut src = SacnSource::with_ip(&format!("Source {}", i), ip).unwrap();

            let priority = Priority::default();

            let universe = UniverseId::new((i as u16) + base_universe).expect("in range");

            src.register_universe(universe).unwrap(); // Senders all send on different universes.

            tx.send(()).unwrap(); // Forces each sender thread to wait till the controlling thread receives which stops sending before the receivers are ready.

            src.send(&[universe], &data, Some(priority), None, None).unwrap();
        }));
    }

    for i in 0..num_rcv_threads {
        let tx = rcv_tx.clone();

        rcv_threads.push(thread::spawn(move || {
            // Port kept the same so must use multiple IP's.
            let mut dmx_recv = SacnReceiver::with_ip(
                SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[i].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
                None,
            )
            .unwrap();

            // Receivers listen to all universes
            for i in base_universe..((num_snd_threads as u16) + base_universe) {
                dmx_recv.listen_universes(&[UniverseId::new(i).expect("in range")]).unwrap();
            }

            let mut res: Vec<Result<Vec<DMXData>, ReceiveError>> = Vec::new();

            tx.send(Vec::new()).unwrap(); // Receiver notifies controlling thread it is ready.

            for _i in 0..num_snd_threads {
                // Receiver should receive from every universe.
                res.push(dmx_recv.recv(None)); // Receiver won't complete this until it receives from the senders which are all held waiting on the controlling thread.
            }

            // results of each receive are sent back, this allows checking that each receive was an expected universe, all universes were received and there were no errors.
            tx.send(res).unwrap();
        }));

        assert_eq!(rcv_rx.recv().unwrap().len(), 0); // Wait till the receiver has notified controlling thread it is ready.
    }

    for _i in 0..num_snd_threads {
        snd_rx.recv().unwrap(); // Allow each sender to progress
    }

    for _i in 0..num_rcv_threads {
        let res: Vec<Result<Vec<DMXData>, ReceiveError>> = rcv_rx.recv().unwrap();

        assert_eq!(res.len(), num_snd_threads);

        let mut rcv_dmx_datas: Vec<DMXData> = Vec::new();

        for r in res {
            let data: Vec<DMXData> = r.unwrap(); // Check that there are no errors when receiving.
            assert_eq!(data.len(), 1); // Check that each universe was received separately.
            rcv_dmx_datas.push(data[0].clone());
        }

        rcv_dmx_datas.sort_unstable(); // Sorting by universe allows easier checking as order received may vary depending on network.

        for k in 0..num_snd_threads {
            assert_eq!(rcv_dmx_datas[k].universe, ((k as u16) + base_universe)); // Check that the universe received is as expected.

            assert_eq!(rcv_dmx_datas[k].values, *snd_data[k], "Received payload values don't match sent!");
        }
    }

    for s in snd_threads {
        s.join().unwrap();
    }

    for r in rcv_threads {
        r.join().unwrap();
    }
}

#[test]
#[ignore]
fn test_three_senders_three_recv_multicast_ipv4() {
    let num_snd_threads: usize = 3;
    let num_rcv_threads: usize = 3;
    let snd_data_len: usize = 100;

    let mut snd_data: Vec<Vec<u8>> = Vec::new();

    for i in 1..num_snd_threads + 1 {
        let mut d: Vec<u8> = Vec::new();
        for _k in 0..snd_data_len {
            d.push(i as u8);
        }
        snd_data.push(d);
    }

    let mut snd_threads = Vec::new();
    let mut rcv_threads = Vec::new();

    let (rcv_tx, rcv_rx): (
        SyncSender<Vec<Result<Vec<DMXData>, ReceiveError>>>,
        Receiver<Vec<Result<Vec<DMXData>, ReceiveError>>>,
    ) = mpsc::sync_channel(0);
    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0); // Used for handshaking, allows syncing the sender states.

    assert!(
        num_rcv_threads <= TEST_NETWORK_INTERFACE_IPV4.len(),
        "Number of test network interface ips less than number of recv threads!"
    );

    let base_universe = 2;

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        let data = snd_data[i].clone();

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );
            // https://www.programming-idioms.org/idiom/153/concatenate-string-with-integer/1975/rust (11/01/2020)
            let mut src = SacnSource::with_ip(&format!("Source {}", i), ip).unwrap();

            let priority = Priority::default();

            let universe = UniverseId::new((i as u16) + base_universe).expect("in range");

            src.register_universe(universe).unwrap(); // Senders all send on different universes.

            tx.send(()).unwrap(); // Forces each sender thread to wait till the controlling thread receives which stops sending before the receivers are ready.

            src.send(&[universe], &data, Some(priority), None, None).unwrap();
        }));
    }

    for i in 0..num_rcv_threads {
        let tx = rcv_tx.clone();

        rcv_threads.push(thread::spawn(move || {
            // Port kept the same so must use multiple IP's.
            let mut dmx_recv = SacnReceiver::with_ip(
                SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[i].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
                None,
            )
            .unwrap();

            // Receivers listen to all universes
            for i in base_universe..((num_snd_threads as u16) + base_universe) {
                dmx_recv.listen_universes(&[UniverseId::new(i).expect("in range")]).unwrap();
            }

            let mut res: Vec<Result<Vec<DMXData>, ReceiveError>> = Vec::new();

            tx.send(Vec::new()).unwrap(); // Receiver notifies controlling thread it is ready.

            for _i in 0..num_snd_threads {
                // Receiver should receive from every universe.
                res.push(dmx_recv.recv(None)); // Receiver won't complete this until it receives from the senders which are all held waiting on the controlling thread.
            }

            // results of each receive are sent back, this allows checking that each receive was an expected universe, all universes were received and there were no errors.
            tx.send(res).unwrap();
        }));

        assert_eq!(rcv_rx.recv().unwrap().len(), 0); // Wait till the receiver has notified controlling thread it is ready.
    }

    for _i in 0..num_snd_threads {
        snd_rx.recv().unwrap(); // Allow each sender to progress
    }

    for _i in 0..num_rcv_threads {
        let res: Vec<Result<Vec<DMXData>, ReceiveError>> = rcv_rx.recv().unwrap();

        assert_eq!(res.len(), num_snd_threads);

        let mut rcv_dmx_datas: Vec<DMXData> = Vec::new();

        for r in res {
            let data: Vec<DMXData> = r.unwrap(); // Check that there are no errors when receiving.
            assert_eq!(data.len(), 1); // Check that each universe was received separately.
            rcv_dmx_datas.push(data[0].clone());
        }

        rcv_dmx_datas.sort_unstable(); // Sorting by universe allows easier checking as order received may vary depending on network.

        for k in 0..num_snd_threads {
            assert_eq!(rcv_dmx_datas[k].universe, ((k as u16) + base_universe)); // Check that the universe received is as expected.

            assert_eq!(rcv_dmx_datas[k].values, *snd_data[k], "Received payload values don't match sent!");
        }
    }

    for s in snd_threads {
        s.join().unwrap();
    }

    for r in rcv_threads {
        r.join().unwrap();
    }
}

#[test]
#[ignore]
fn test_universe_discovery_one_universe_one_source_ipv4() {
    let num_snd_threads: usize = 1;
    let base_universe = 2;
    let universe_count: usize = 1;
    let source_names: [&str; 1] = ["Source 1"];

    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let mut snd_threads = Vec::new();

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );

            let mut src = SacnSource::with_ip(source_names[i], ip).unwrap();

            let mut universes = Vec::new();
            for j in 0..universe_count {
                universes.push(UniverseId::new(((i + j) as u16) + base_universe).expect("in range"));
            }

            src.register_universes(&universes).unwrap();

            tx.send(()).unwrap(); // Used to force the sender to wait till the receiver has received a universe discovery.
        }));
    }

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();

    loop {
        let result = dmx_recv.recv(Some(Duration::from_secs(2)));
        match result {
            Err(e) => {
                match e {
                    ReceiveError::Io(ref s) => {
                        match s.kind() {
                            std::io::ErrorKind::WouldBlock => {
                                // Expected to timeout / would block.
                                // The different errors are due to windows and unix returning different errors for the same thing.
                            }
                            std::io::ErrorKind::TimedOut => {}
                            _ => {
                                assert!(false, "Unexpected error returned");
                            }
                        }
                    }
                    _ => {
                        assert!(false, "Unexpected error returned");
                    }
                }
            }
            Ok(_) => {
                assert!(false, "No data should have been passed up!");
            }
        }

        let discovered = dmx_recv.get_discovered_sources();

        if !discovered.is_empty() {
            assert_eq!(discovered.len(), 1);
            assert_eq!(*discovered[0].name, source_names[0]);
            let universes = discovered[0].get_all_universes();
            assert_eq!(universes.len(), universe_count);
            for j in 0..universe_count {
                assert_eq!(universes[j], (j as u16) + base_universe);
            }
            break;
        }
    }

    snd_rx.recv().unwrap();

    for s in snd_threads {
        s.join().unwrap();
    }
}

/// Measures the time taken in milliseconds between 2 discovery packets to check that the interval fits with expected.
#[test]
#[ignore]
fn test_universe_discovery_interval_ipv4() {
    let num_snd_threads: usize = 1;
    let base_universe = 1;
    let source_names: [&str; 1] = ["Source 1"];
    let interval_expected_millis: u128 = E131_UNIVERSE_DISCOVERY_INTERVAL.as_millis(); // Expected discovery packet interval is every 10 seconds (10000 milliseconds).
    let interval_tolerance_millis: u128 = 1000; // Allow up to a second either side of this interval to account for random variations.

    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let mut snd_threads = Vec::new();

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );

            tx.send(()).unwrap(); // Force the send thread to wait before creating the sender, should sync once the receiver has been created.

            let mut src = SacnSource::with_ip(source_names[i], ip).unwrap();

            src.register_universes(&[UniverseId::new(base_universe).expect("in range")])
                .unwrap();

            tx.send(()).unwrap(); // Used to force the sender to wait till the receiver has received a universe discovery.
        }));
    }

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();
    dmx_recv.set_announce_source_discovery(true); // Make the receiver explicitly notify when it receives a universe discovery packet.

    snd_rx.recv().unwrap(); // Receiver created and ready so allow the sender to be created.

    let mut interval_start = Timestamp::now(); // Assignment never used.

    match dmx_recv.recv(None) {
        Err(e) => {
            match e {
                ReceiveError::SourceDiscovered(_) => {
                    // Measure the time between the first and second discovery packets, this removes the uncertainty in the time taken for the sender to start.
                    interval_start = Timestamp::now();
                }
                k => {
                    assert!(false, "Unexpected error kind, {:?}", k);
                }
            }
        }
        Ok(d) => {
            assert!(false, "No data expected, {:?}", d);
        }
    }

    match dmx_recv.recv(None) {
        Err(e) => match e {
            ReceiveError::SourceDiscovered(_) => {
                let interval = interval_start.elapsed();
                let interval_millis = interval.as_millis();
                assert!(
                    interval_millis > (interval_expected_millis - interval_tolerance_millis),
                    "Discovery interval is shorter than expected, {} ms",
                    interval_millis
                );
                assert!(
                    interval_millis < (interval_expected_millis + interval_tolerance_millis),
                    "Discovery interval is longer than expected, {} ms",
                    interval_millis
                );
            }
            k => {
                assert!(false, "Unexpected error kind, {:?}", k);
            }
        },
        Ok(d) => {
            assert!(false, "No data expected, {:?}", d);
        }
    }

    snd_rx.recv().unwrap(); // Allow sender to finish.
}

/// Sets up a sender and a receiver, the sender then updates its sending universes multiple times within an ANSI E1.31-2018
/// E131_UNIVERSE_DISCOVERY_INTERVAL and the receiver asserts that it only receives updates on the interval as expected / compliant
/// with ANSI E1.31-2018 Section 4.3
#[test]
#[ignore]
fn test_universe_discovery_interval_with_updates_ipv4() {
    let number_of_snd_threads: usize = 1;
    let base_universe = UniverseId::new(1).expect("in range");
    let source_names: [&str; 1] = ["Source 1"];
    let interval_expected_millis: u128 = E131_UNIVERSE_DISCOVERY_INTERVAL.as_millis(); // Expected discovery packet interval is every 10 seconds (10000 milliseconds).
    let interval_tolerance_millis: u128 = 1000; // Allow up to a second either side of this interval to account for random variations.
    let sender_register_delay: Duration = Duration::from_secs(1); // The time between registering new universe on the sender.
    let universes_to_register: usize = 5; // The number of universes to register on the src.

    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let mut snd_threads = Vec::new();

    for i in 0..number_of_snd_threads {
        let tx = snd_tx.clone();

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );

            tx.send(()).unwrap(); // Force the send thread to wait before creating the sender, should sync once the receiver has been created.

            let mut src = SacnSource::with_ip(source_names[i], ip).unwrap();

            for _ in 0..universes_to_register {
                src.register_universes(&[base_universe]).unwrap();
                sleep(sender_register_delay.into());
            }

            tx.send(()).unwrap(); // Used to force the sender to wait till the receiver has received a universe discovery.
        }));
    }

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();
    dmx_recv.set_announce_source_discovery(true); // Make the receiver explicitly notify when it receives a universe discovery packet.

    snd_rx.recv().unwrap(); // Receiver created and ready so allow the sender to be created.

    let mut interval_start = Timestamp::now(); // Assignment never used.

    match dmx_recv.recv(None) {
        Err(e) => {
            match e {
                ReceiveError::SourceDiscovered(_) => {
                    // Measure the time between the first and second discovery packets, this removes the uncertainty in the time taken for the sender to start.
                    interval_start = Timestamp::now();
                }
                k => {
                    assert!(false, "Unexpected error kind, {:?}", k);
                }
            }
        }
        Ok(d) => {
            assert!(false, "No data expected, {:?}", d);
        }
    }

    match dmx_recv.recv(None) {
        Err(e) => match e {
            ReceiveError::SourceDiscovered(_) => {
                let interval = interval_start.elapsed();
                let interval_millis = interval.as_millis();
                assert!(
                    interval_millis > (interval_expected_millis - interval_tolerance_millis),
                    "Discovery interval is shorter than expected, {} ms",
                    interval_millis
                );
                assert!(
                    interval_millis < (interval_expected_millis + interval_tolerance_millis),
                    "Discovery interval is longer than expected, {} ms",
                    interval_millis
                );
            }
            k => {
                assert!(false, "Unexpected error kind, {:?}", k);
            }
        },
        Ok(d) => {
            assert!(false, "No data expected, {:?}", d);
        }
    }

    snd_rx.recv().unwrap(); // Allow sender to finish.
}

#[test]
#[ignore]
fn test_universe_discovery_multiple_universe_one_source_ipv4() {
    let num_snd_threads: usize = 1;
    let base_universe = 2;
    let universe_count: usize = 5;
    let source_names: [&str; 1] = ["Source 1"];

    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let mut snd_threads = Vec::new();

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );

            let mut src = SacnSource::with_ip(source_names[i], ip).unwrap();

            let mut universes = Vec::new();
            for j in 0..universe_count {
                universes.push(UniverseId::new(((i + j) as u16) + base_universe).expect("in range"));
            }

            src.register_universes(&universes).unwrap();

            tx.send(()).unwrap(); // Used to force the sender to wait till the receiver has received a universe discovery.
        }));
    }

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();

    loop {
        let result = dmx_recv.recv(Some(Duration::from_secs(2)));
        match result {
            Err(e) => {
                match e {
                    ReceiveError::Io(ref s) => {
                        match s.kind() {
                            std::io::ErrorKind::WouldBlock => {
                                // Expected to timeout / would block.
                                // The different errors are due to windows and unix returning different errors for the same thing.
                            }
                            std::io::ErrorKind::TimedOut => {}
                            _ => {
                                assert!(false, "Unexpected error returned");
                            }
                        }
                    }
                    _ => {
                        assert!(false, "Unexpected error returned");
                    }
                }
            }
            Ok(_) => {
                assert!(false, "No data should have been passed up!");
            }
        }

        let discovered = dmx_recv.get_discovered_sources();

        if !discovered.is_empty() {
            assert_eq!(discovered.len(), 1);
            assert_eq!(*discovered[0].name, source_names[0]);

            let universes = discovered[0].get_all_universes();
            assert_eq!(universes.len(), universe_count);
            for j in 0..universe_count {
                assert_eq!(universes[j], (j as u16) + base_universe);
            }
            break;
        }
    }

    snd_rx.recv().unwrap();

    for s in snd_threads {
        s.join().unwrap();
    }
}

#[test]
#[ignore]
fn test_universe_discovery_multiple_pages_one_source_ipv4() {
    let num_snd_threads: usize = 1;
    let base_universe = 2;
    let universe_count: usize = 600;
    let source_names: [&str; 1] = ["Source 1"];

    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let mut snd_threads = Vec::new();

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );

            let mut src = SacnSource::with_ip(source_names[i], ip).unwrap();

            src.set_is_sending_discovery(false); // To stop universe discovery packets being sent until all universes are registered.

            let mut universes = Vec::new();
            for j in 0..universe_count {
                universes.push(UniverseId::new(((i + j) as u16) + base_universe).expect("in range"));
            }

            src.register_universes(&universes).unwrap();

            src.set_is_sending_discovery(true);

            tx.send(()).unwrap(); // Used to force the sender to wait till the receiver has received a universe discovery.
        }));
    }

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();

    loop {
        let result = dmx_recv.recv(Some(Duration::from_secs(2)));

        match result {
            Err(e) => {
                match e {
                    ReceiveError::Io(ref s) => {
                        match s.kind() {
                            std::io::ErrorKind::WouldBlock => {
                                // Expected to timeout / would block.
                                // The different errors are due to windows and unix returning different errors for the same thing.
                            }
                            std::io::ErrorKind::TimedOut => {}
                            _ => {
                                assert!(false, "Unexpected error returned");
                            }
                        }
                    }
                    _ => {
                        assert!(false, "Unexpected error returned");
                    }
                }
            }
            Ok(_) => {
                assert!(false, "No data should have been passed up!");
            }
        }

        let discovered = dmx_recv.get_discovered_sources();

        if !discovered.is_empty() {
            assert_eq!(discovered.len(), 1);
            assert_eq!(*discovered[0].name, source_names[0]);
            let universes = discovered[0].get_all_universes();
            assert_eq!(universes.len(), universe_count);
            for j in 0..universe_count {
                assert_eq!(universes[j], (j as u16) + base_universe);
            }
            break;
        }
    }

    snd_rx.recv().unwrap();

    for s in snd_threads {
        s.join().unwrap();
    }
}

/// Creates a sender and a receiver with the sender having no registered universes.
/// Receiver waits for a discovery packet from the sender and uses it to show that the sender is transmitting
/// an empty list of universes as expected.
#[test]
#[ignore]
fn test_universe_discovery_no_universes_ipv4() {
    let num_snd_threads: usize = 1;
    let source_names: [&str; 1] = ["Source 1"];
    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let mut snd_threads = Vec::new();

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );

            tx.send(()).unwrap(); // Force the send thread to wait before creating the sender, should sync once the receiver has been created.

            let mut src = SacnSource::with_ip(source_names[i], ip).unwrap();

            // Explicitly make sure that the src is sending discovery packets (by default not).
            src.set_is_sending_discovery(true);

            // No universes registered so should transmit an empty list.

            tx.send(()).unwrap(); // Used to force the sender to wait till the receiver has received a universe discovery.
        }));
    }

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();
    dmx_recv.set_announce_source_discovery(true); // Make the receiver explicitly notify when it receives a universe discovery packet.

    snd_rx.recv().unwrap(); // Receiver created and ready so allow the sender to be created.

    match dmx_recv.recv(None) {
        Err(e) => match e {
            ReceiveError::SourceDiscovered(src_name) => {
                assert_eq!(*src_name, source_names[0], "Name of source discovered doesn't match expected");
                let sources = dmx_recv.get_discovered_sources();
                assert_eq!(sources.len(), 1, "Number of sources discovered doesn't match expected (1)");
                assert!(
                    sources[0].get_all_universes().is_empty(),
                    "Number of universes on source is greater than expected (0)"
                );
            }
            k => {
                assert!(false, "Unexpected error kind, {:?}", k);
            }
        },
        Ok(d) => {
            assert!(false, "No data expected, {:?}", d);
        }
    }

    snd_rx.recv().unwrap(); // Allow sender to finish.
}

/// Creates a receiver with a source limit of 2 and then creates 3 sources to trigger a sources exceeded condition.
#[test]
#[ignore]
fn test_receiver_sources_exceeded_3() {
    let num_snd_threads: usize = 3;
    let num_rcv_threads: usize = 1;
    let src_limit: Option<usize> = Some(2);
    let timeout: Option<Duration> = Some(Duration::from_secs(3));

    let mut snd_threads = Vec::new();

    // Separate message queues used so threads don't take messages to allow them to proceed as a message to allow finishing.
    // This is less efficient than using different message types within a single queue however as this is a test the priority is simplicity.
    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0); // Used for handshaking, allows syncing the sender states.
    let (finish_snd_tx, finish_snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0); // Used for handshaking to tell the source threads to finish.

    assert!(
        num_rcv_threads <= TEST_NETWORK_INTERFACE_IPV4.len(),
        "Number of test network interface ips less than number of recv threads!"
    );

    let base_universe = 2;

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();
        let fin_tx = finish_snd_tx.clone();

        let data = [1, 2, 3];

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );
            // https://www.programming-idioms.org/idiom/153/concatenate-string-with-integer/1975/rust (11/01/2020)
            let mut src = SacnSource::with_ip(&format!("Source {}", i), ip).unwrap();

            let priority = Priority::default();

            let universe = UniverseId::new((i as u16) + base_universe).expect("in range");

            src.register_universe(universe).unwrap(); // Senders all send on different universes.

            tx.send(()).unwrap(); // Forces each sender thread to wait till the controlling thread receives which stops sending before the receivers are ready.

            src.send(&[universe], &data, Some(priority), None, None).unwrap();

            fin_tx.send(()).unwrap(); // Forces each sender to wait and not terminate.
        }));
    }

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
        src_limit,
    )
    .unwrap();

    // Receivers listen to all universes
    for i in base_universe..((num_snd_threads as u16) + base_universe) {
        dmx_recv.listen_universes(&[UniverseId::new(i).expect("in range")]).unwrap();
    }

    for _ in 0..num_snd_threads {
        snd_rx.recv().unwrap(); // Allow each sender to progress
    }

    // Asserts that the first 2 recv attempts are successful.
    dmx_recv.recv(timeout).unwrap();
    dmx_recv.recv(timeout).unwrap();

    // On receiving the third time from the third source the sources exceeded error should be thrown.
    match dmx_recv.recv(timeout) {
        Err(e) => match e {
            ReceiveError::SourcesExceeded(_) => {
                assert!(true, "Expected error returned");
            }
            _ => {
                assert!(false, "Unexpected error type returned");
            }
        },
        Ok(_) => {
            assert!(false, "Recv was successful even though source limit was exceeded");
        }
    }

    // Allow the senders to finish / terminate.
    for _ in 0..num_snd_threads {
        finish_snd_rx.recv().unwrap();
    }

    for _ in 0..num_snd_threads {
        snd_threads.pop().unwrap().join().unwrap();
    }
}

/// Creates a receiver with a source limit of 2 and then creates 2 sources which send to the receiver.
/// This shouldn't trigger a SourcesExceededCondition
#[test]
#[ignore]
fn test_receiver_source_limit_2() {
    let num_snd_threads: usize = 2;
    let num_rcv_threads: usize = 1;
    let src_limit: Option<usize> = Some(2);

    let mut snd_threads = Vec::new();

    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0); // Used for handshaking, allows syncing the sender states.

    assert!(
        num_rcv_threads <= TEST_NETWORK_INTERFACE_IPV4.len(),
        "Number of test network interface ips less than number of recv threads!"
    );

    let base_universe = 2;

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        let data = [1, 2, 3];

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );
            let mut src = SacnSource::with_ip(&format!("Source {}", i), ip).unwrap();

            let priority = Priority::default();

            let universe = UniverseId::new((i as u16) + base_universe).expect("in range");

            src.register_universe(universe).unwrap(); // Senders all send on different universes.

            tx.send(()).unwrap(); // Forces each sender thread to wait till the controlling thread receives which stops sending before the receivers are ready.

            // Each source sends twice (meaning 4 packets total), this checks that the receiver isn't using the number of packets as the way to check for the number
            // of sources.
            src.send(&[universe], &data, Some(priority), None, None).unwrap();
            src.send(&[universe], &data, Some(priority), None, None).unwrap();
        }));
    }

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
        src_limit,
    )
    .unwrap();

    // Receivers listen to all universes
    for i in base_universe..((num_snd_threads as u16) + base_universe) {
        let universe = UniverseId::new(i).expect("in range");
        dmx_recv.listen_universes(&[universe]).unwrap();
    }

    for _i in 0..num_snd_threads {
        snd_rx.recv().unwrap(); // Allow each sender to progress
    }

    // Asserts that the recv attempts are successful.
    dmx_recv.recv(None).unwrap();
    dmx_recv.recv(None).unwrap();
    dmx_recv.recv(None).unwrap();
    dmx_recv.recv(None).unwrap();
}

/// Creates a receiver with a source limit of 2 and then creates 2 sources which send to the receiver.
/// A source then terminates and another source is created.
/// At all points the total source count was less than or equal to the limit of 2 sources as specified by the receiver
/// so this should not cause a SourcesExceededCondition.
#[test]
#[ignore]
fn test_receiver_source_limit_2_termination_check() {
    let num_snd_threads: usize = 2;
    let src_limit: Option<usize> = Some(2);
    let recv_timeout: Option<Duration> = Some(Duration::from_secs(5));

    let mut snd_threads = Vec::new();

    let (snd_tx, snd_rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0); // Used for handshaking, allows syncing the sender states.

    let base_universe = UniverseId::new(2).expect("in range");

    for i in 0..num_snd_threads {
        let tx = snd_tx.clone();

        let data = [1, 2, 3];

        snd_threads.push(thread::spawn(move || {
            let ip: SocketAddr = SocketAddr::new(
                IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
                ACN_SDT_MULTICAST_PORT + 1 + (i as u16),
            );
            let mut src = SacnSource::with_ip(&format!("Source {}", i), ip).unwrap();

            let priority = Priority::default();

            let universe = UniverseId::new((i as u16) + base_universe.get()).expect("in range");

            src.register_universe(universe).unwrap(); // Senders all send on different universes.

            tx.send(()).unwrap(); // Forces each sender thread to wait till the controlling thread receives which stops sending before the receivers are ready.

            // Each source sends twice (meaning 4 packets total), this checks that the receiver isn't using the number of packets as the way to check for the number
            // of sources.
            src.send(&[universe], &data, Some(priority), None, None).unwrap();
            src.send(&[universe], &data, Some(priority), None, None).unwrap();

            if i == 0 {
                // Forces the first thread not to terminate and to wait. The second thread will finish and terminate the source.
                tx.send(()).unwrap();
            }
        }));
    }

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
        src_limit,
    )
    .unwrap();

    // Receivers listen to all universes
    for i in base_universe.get()..((num_snd_threads as u16) + base_universe.get()) {
        let universe = UniverseId::new(i).expect("in range");
        dmx_recv.listen_universes(&[universe]).unwrap();
    }

    snd_rx.recv().unwrap();
    snd_rx.recv().unwrap();

    // Asserts that the recv attempts are successful.
    dmx_recv.recv(recv_timeout).unwrap();
    dmx_recv.recv(recv_timeout).unwrap();
    dmx_recv.recv(recv_timeout).unwrap();
    dmx_recv.recv(recv_timeout).unwrap();

    // The first source is held back from terminating but the second source should terminate.
    let second_thread = snd_threads.remove(1);
    second_thread.join().unwrap();

    // Create a new source which sends to the receiver.
    let data = [1, 2, 3];
    let new_src_thread = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(
            IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
            ACN_SDT_MULTICAST_PORT + 1 + 3_u16,
        );
        let mut src = SacnSource::with_ip(&format!("Source {}", 3), ip).unwrap();

        src.register_universe(base_universe).unwrap();

        // New source now sends twice which the receiver should receive.
        src.send(&[base_universe], &data, None, None, None).unwrap();
        src.send(&[base_universe], &data, None, None, None).unwrap();
    });

    // Asserts that the recv attempts are successful (no source exceeded).
    dmx_recv.recv(recv_timeout).unwrap();
    dmx_recv.recv(recv_timeout).unwrap();

    // Allow the first source to progress and finish.
    snd_rx.recv().unwrap();
    let first_thread = snd_threads.remove(0);
    first_thread.join().unwrap();

    // Finish the new source.
    new_src_thread.join().unwrap();
}

/// Create 2 receivers with a single sender, one receiver listens to preview_data and the other doesn't.
/// The sender then sends data with the preview flag set and not and the receivers check they receive the data correctly.
#[test]
#[ignore]
fn test_preview_data_2_receiver_1_sender() {
    let num_recv_threads: usize = 2;
    let universe = UniverseId::new(1).expect("in range");
    let normal_data: [u8; 4] = [0, 1, 2, 3];
    let preview_data: [u8; 4] = [9, 10, 11, 12];
    let timeout: Option<Duration> = Some(Duration::from_secs(3));

    let mut rcv_threads = Vec::new();

    let (rcv_tx, rcv_rx): (
        SyncSender<Result<Vec<DMXData>, ReceiveError>>,
        Receiver<Result<Vec<DMXData>, ReceiveError>>,
    ) = mpsc::sync_channel(0);

    // Check that the test setup is correct.
    assert!(
        num_recv_threads <= TEST_NETWORK_INTERFACE_IPV4.len(),
        "Number of test network interface ips less than number of recv threads!"
    );

    for i in 0..num_recv_threads {
        let tx = rcv_tx.clone();

        rcv_threads.push(thread::spawn(move || {
            // Port kept the same so must use multiple IP's.
            let mut dmx_recv = SacnReceiver::with_ip(
                SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[i].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
                None,
            )
            .unwrap();

            if i == 0 {
                dmx_recv.set_process_preview_data(true); // The first receiver should listen for preview data.
            }

            // Receivers listen to the same universe
            dmx_recv.listen_universes(&[universe]).unwrap();

            tx.send(Ok(Vec::new())).unwrap(); // Receiver notifies controlling thread it is ready.

            let result = dmx_recv.recv(None).unwrap();

            assert_eq!(result.len(), 1);

            let data = &result[0];

            assert_eq!(data.universe, universe);
            assert_eq!(data.values, normal_data);

            assert!(!data.preview);

            if i == 0 {
                // The receiver listening to preview_data will receive twice.
                let preview_result = dmx_recv.recv(None).unwrap();
                assert_eq!(preview_result.len(), 1);

                let preview_result_data = &preview_result[0];

                assert_eq!(preview_result_data.universe, universe);
                assert_eq!(preview_result_data.values, preview_data);
                assert!(preview_result_data.preview);
            } else {
                // The other receiver should not.
                match dmx_recv.recv(timeout) {
                    Err(e) => {
                        match e {
                            ReceiveError::Io(ref s) => {
                                match s.kind() {
                                    std::io::ErrorKind::WouldBlock => {
                                        // Expected to timeout / would block.
                                        // The different errors are due to windows and unix returning different errors for the same thing.
                                    }
                                    std::io::ErrorKind::TimedOut => {}
                                    _ => {
                                        assert!(false, "Unexpected error returned");
                                    }
                                }
                            }
                            _ => {
                                assert!(false, "Unexpected error returned");
                            }
                        }
                    }
                    Ok(_) => {
                        assert!(false, "Non-preview receiver received preview data");
                    }
                }
            }
        }));
    }

    // Sender waits for both receivers to be ready.
    for _ in 0..num_recv_threads {
        rcv_rx.recv().unwrap().unwrap();
    }

    let ip: SocketAddr = SocketAddr::new(
        IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()),
        ACN_SDT_MULTICAST_PORT + 1,
    );
    let mut src = SacnSource::with_ip("Source", ip).unwrap();
    src.register_universe(universe).unwrap();

    // Send data without the preview flag.
    src.send(&[universe], &normal_data, None, None, None).unwrap();

    src.set_preview_mode(true).unwrap();

    // Send data with the preview flag.
    src.send(&[universe], &preview_data, None, None, None).unwrap();

    // Finish with the receive threads.
    for r in rcv_threads {
        r.join().unwrap();
    }
}

/// Creates a receiver and a sender. The sender sends a data packet to the receiver and then holds.
/// The receiver (with announce_timeout flag set to true) then waits for the timeout notification to happen.
/// This shows that the timeout mechanism for a source works.
#[test]
#[ignore]
fn test_source_1_universe_timeout() {
    // Allow the timeout notification to come up to 2.5 seconds too late compared to the expected 2.5 seconds.
    // (2.5s base as per ANSI E1.31-2018 Appendix A E131_NETWORK_DATA_LOSS_TIMEOUT, tolerance as per documentation for recv() method).
    // Both tolerances allow 50 ms for code execution time.
    let acceptable_lower_bound: Duration = E131_NETWORK_DATA_LOSS_TIMEOUT - Duration::from_millis(50);
    let acceptable_upper_bound: Duration = 2 * E131_NETWORK_DATA_LOSS_TIMEOUT + Duration::from_millis(50);

    let (tx, rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let thread_tx = tx.clone();

    let universe = UniverseId::new(1).expect("in range");

    let snd_thread = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ACN_SDT_MULTICAST_PORT + 1);
        let mut src = SacnSource::with_ip("Source", ip).unwrap();
        let priority = Priority::default();

        src.register_universe(universe).unwrap();

        let dst_ip: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ACN_SDT_MULTICAST_PORT);

        thread_tx.send(()).unwrap(); // Sender waits till the receiver says it is ready.

        src.send(&[universe], &TEST_DATA_SINGLE_UNIVERSE, Some(priority), Some(dst_ip), None)
            .unwrap();

        // Sender waits till the receiver says it can terminate, this prevents the automatic stream_terminated packets being sent.
        thread_tx.send(()).unwrap();
    });

    let mut dmx_recv = SacnReceiver::with_ip(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ACN_SDT_MULTICAST_PORT), None).unwrap();
    dmx_recv.listen_universes(&[universe]).unwrap();

    // Want to know when the source times out.
    dmx_recv.set_announce_timeout(true);

    // Receiver created successfully so allow the sender to progress.
    rx.recv().unwrap();

    // Get the packet of data and check that it is correct.
    let received_data: Vec<DMXData> = dmx_recv.recv(None).unwrap();

    assert_eq!(received_data.len(), 1); // Check only 1 universe received as expected.
    assert_eq!(received_data[0].universe, universe); // Check that the universe received is as expected.
    assert_eq!(
        received_data[0].values, TEST_DATA_SINGLE_UNIVERSE,
        "Received payload values don't match sent!"
    );

    let start_time: Timestamp = Timestamp::now();
    match dmx_recv.recv(Some(acceptable_upper_bound)) {
        // This will return a WouldBlock/Timedout error if the timeout takes too long.
        Err(e) => match e {
            ReceiveError::UniverseTimeout {
                src_cid: _,
                universe: timedout_uni,
            } => {
                if start_time.elapsed() < acceptable_lower_bound {
                    assert!(false, "Timeout came quicker than expected");
                }
                assert_eq!(timedout_uni, universe, "Timed out universe doesn't match expected");
                assert!(true, "Universe timed out as expected");
            }
            ReceiveError::Io(ref s) => match s.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    assert!(false, "Timeout took too long to come through");
                }
                _ => {
                    assert!(false, "Unexpected error returned");
                }
            },
            _ => {
                assert!(false, "Unexpected error returned");
            }
        },
        Ok(x) => {
            assert!(false, "Data received unexpectedly as none sent! {:?}", x);
        }
    }

    rx.recv().unwrap(); // Allow the sender to finish.
    snd_thread.join().unwrap();
}

/// Creates a receiver and a sender. The sender sends 2 data packets to the receiver on different universes and then waits a short time
/// (< E131_NETWORK_DATA_LOSS_TIMEOUT) and sends another data packet for the first universe allowing the second universe to timeout.
/// The receiver checks all 3 data packets are received correctly and that (with announce_timeout flag set to true) only the universe on which
/// a single packet was sent times out.
///
/// This shows that the timeout mechanism is per universe and not for an entire source as a single universe can timeout while other universe
/// continue as normal as per ANSI E1.31-2018 Section 6.7.1.
#[test]
#[ignore]
fn test_source_2_universe_1_timeout() {
    // Allow the timeout notification to come up to 2.5 seconds too late compared to the expected 2.5 seconds.
    // (2.5s base as per ANSI E1.31-2018 Appendix A E131_NETWORK_DATA_LOSS_TIMEOUT, tolerance as per documentation for recv() method).
    // Both tolerances allow 50 ms for code execution time.
    let acceptable_lower_bound: Duration = E131_NETWORK_DATA_LOSS_TIMEOUT - Duration::from_millis(50);
    let acceptable_upper_bound: Duration = 2 * E131_NETWORK_DATA_LOSS_TIMEOUT + Duration::from_millis(50);

    let (tx, rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let thread_tx = tx.clone();

    let universe_no_timeout = UniverseId::new(1).expect("in range");
    let universe_with_timeout = UniverseId::new(2).expect("in range");

    let snd_thread = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ACN_SDT_MULTICAST_PORT + 1);
        let mut src = SacnSource::with_ip("Source", ip).unwrap();
        let priority = Priority::default();

        src.register_universes(&[universe_no_timeout, universe_with_timeout]).unwrap();

        let dst_ip: SocketAddr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ACN_SDT_MULTICAST_PORT);

        thread_tx.send(()).unwrap(); // Sender waits till the receiver says it is ready.

        src.send(
            &[universe_no_timeout],
            &TEST_DATA_SINGLE_UNIVERSE,
            Some(priority),
            Some(dst_ip),
            None,
        )
        .unwrap();
        src.send(
            &[universe_with_timeout],
            &TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
            Some(priority),
            Some(dst_ip),
            None,
        )
        .unwrap();

        sleep(Duration::from_secs(1)); // Wait a small amount of time.

        // Send another packet to the universe that shouldn't timeout so that it doesn't timeout.
        src.send(
            &[universe_no_timeout],
            &TEST_DATA_SINGLE_UNIVERSE,
            Some(priority),
            Some(dst_ip),
            None,
        )
        .unwrap();

        sleep(Duration::from_secs(1)); // Wait a small amount of time.

        // Send another packet to the universe that shouldn't timeout so that it doesn't timeout.
        src.send(
            &[universe_no_timeout],
            &TEST_DATA_SINGLE_UNIVERSE,
            Some(priority),
            Some(dst_ip),
            None,
        )
        .unwrap();

        sleep(Duration::from_secs(1)); // Wait a small amount of time.

        // Send another packet to the universe that shouldn't timeout so that it doesn't timeout.
        src.send(
            &[universe_no_timeout],
            &TEST_DATA_SINGLE_UNIVERSE,
            Some(priority),
            Some(dst_ip),
            None,
        )
        .unwrap();

        sleep(Duration::from_secs(1)); // Wait a small amount of time.

        // Send another packet to the universe that shouldn't timeout so that it doesn't timeout.
        src.send(
            &[universe_no_timeout],
            &TEST_DATA_SINGLE_UNIVERSE,
            Some(priority),
            Some(dst_ip),
            None,
        )
        .unwrap();

        // Sender waits till the receiver says it can terminate, this prevents the automatic stream_terminated packets being sent.
        thread_tx.send(()).unwrap();
    });

    let mut dmx_recv = SacnReceiver::with_ip(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), ACN_SDT_MULTICAST_PORT), None).unwrap();
    dmx_recv.listen_universes(&[universe_no_timeout, universe_with_timeout]).unwrap();

    // Want to know when the source times out.
    dmx_recv.set_announce_timeout(true);

    // Receiver created successfully so allow the sender to progress.
    rx.recv().unwrap();

    // Get the packets of data and check that they are correct.
    let received_data: Vec<DMXData> = dmx_recv.recv(None).unwrap();
    assert_eq!(received_data.len(), 1); // Check only 1 universe of data received as expected.

    if received_data[0].universe == universe_no_timeout {
        assert_eq!(
            received_data[0].values, TEST_DATA_SINGLE_UNIVERSE,
            "Received payload values don't match sent!"
        );

        // Get the next data packet and check it is the other packet as expected.
        let received_data: Vec<DMXData> = dmx_recv.recv(None).unwrap();
        assert_eq!(received_data.len(), 1); // Check only 1 universe received as expected.
        if received_data[0].universe == universe_with_timeout {
            assert_eq!(
                received_data[0].values, TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
                "Received payload values don't match sent!"
            );
        } else {
            assert!(false, "Data packet from unexpected universe received");
        }
    } else if received_data[0].universe == universe_with_timeout {
        assert_eq!(
            received_data[0].values, TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
            "Received payload values don't match sent!"
        );

        // Get the next data packet and check it is the other packet as expected.
        let received_data: Vec<DMXData> = dmx_recv.recv(None).unwrap();
        assert_eq!(received_data.len(), 1); // Check only 1 universe received as expected.
        if received_data[0].universe == universe_no_timeout {
            assert_eq!(
                received_data[0].values, TEST_DATA_SINGLE_UNIVERSE,
                "Received payload values don't match sent!"
            );
        } else {
            assert!(false, "Data packet from unexpected universe received");
        }
    } else {
        assert!(false, "Data packet from unexpected universe received");
    }
    // Start the expected timeout timer.
    let start_time: Timestamp = Timestamp::now();

    loop {
        // Loop till a timeout happens, ignoring the data packets send to the non-timeout uni.
        match dmx_recv.recv(Some(acceptable_upper_bound)) {
            // This will return a WouldBlock/Timedout error if the timeout takes too long.
            Err(e) => {
                match e {
                    ReceiveError::UniverseTimeout { src_cid: _, universe } => {
                        if start_time.elapsed() < acceptable_lower_bound {
                            assert!(false, "Timeout came quicker than expected");
                        }
                        assert_eq!(universe, universe_with_timeout, "Unexpected universe timed out");
                        assert!(true, "Universe timed out as expected");

                        // Know that the timeout universe timed out as expected so check that the other universe hasn't timed out.
                        // Makes use of a timeout of 0 which should check the source timeouts without actually receiving any data as it times out Timestamply.
                        match dmx_recv.recv(Some(Duration::from_millis(0))) {
                            Err(e) => match e {
                                ReceiveError::Io(ref s) => match s.kind() {
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                                        assert!(true, "Other universe hasn't timedout as expected");
                                    }
                                    _ => {
                                        assert!(false, "Unexpected error returned");
                                    }
                                },
                                _ => {
                                    assert!(false, "Unexpected error returned");
                                }
                            },
                            Ok(x) => {
                                assert!(false, "Data received unexpectedly as none sent! {:?}", x);
                            }
                        }
                        break;
                    }
                    ReceiveError::Io(ref s) => match s.kind() {
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                            assert!(false, "Timeout took too long to come through: {:?}", start_time.elapsed());
                        }
                        _ => {
                            assert!(false, "Unexpected error returned");
                        }
                    },
                    _ => {
                        assert!(false, "Unexpected error returned");
                    }
                }
            }
            Ok(p) => {
                // Check that only data from the non-timed out universe is received.
                assert_eq!(p.len(), 1, "Data packet universe count doesn't match expected");
                assert_eq!(p[0].universe, universe_no_timeout, "Data packet universe doesn't match expected");
                assert_eq!(p[0].values, TEST_DATA_SINGLE_UNIVERSE, "Data packet values don't match expected");
            }
        }
    }

    rx.recv().unwrap(); // Allow the sender to finish.
    snd_thread.join().unwrap();
}

// A receiver listens to 2 universes. A sender then sends a packet on the multicast address for the first universe but with the packet
// being for the second universe.
// The receiver should process the packet for the second universe as normal because the multicast address used shouldn't be used to decide
// the universe of the packet.
#[test]
#[ignore]
fn test_send_recv_wrong_multicast_universe() {
    let timeout: Option<Duration> = Some(Duration::from_secs(3));

    let (tx, rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let thread_tx = tx.clone();

    let multicast_universe = UniverseId::new(1).expect("in range");
    let actual_universe = UniverseId::new(2).expect("in range");

    let snd_thread = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap(), ACN_SDT_MULTICAST_PORT + 1);
        let mut src = SacnSource::with_ip("Source", ip).unwrap();
        let priority = Priority::default();

        src.register_universes(&[multicast_universe, actual_universe]).unwrap();

        // The multicast address for the multicast universe as per ANSI E1.31-2018 Section 9.3.1 Table 9-10.
        let dst_ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 1)), ACN_SDT_MULTICAST_PORT);

        // Sender waits till the receiver says it is ready.
        thread_tx.send(()).unwrap();

        // Send the second universe using the multicast address for the first universe.
        src.send(&[actual_universe], &TEST_DATA_SINGLE_UNIVERSE, Some(priority), Some(dst_ip), None)
            .unwrap();
    });

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[1].parse().unwrap(), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();
    dmx_recv.listen_universes(&[multicast_universe, actual_universe]).unwrap();

    // Receiver created successfully so allow the sender to progress.
    rx.recv().unwrap();

    // Get the packets of data and check that they are correct.
    let received_data: Vec<DMXData> = dmx_recv.recv(timeout).unwrap();
    assert_eq!(received_data.len(), 1, "Data packet universe count doesn't match expected");

    // Particularly important that the universe is the actual universe of the data rather than the universe which corresponds to the multicast address.
    assert_eq!(received_data[0].universe, actual_universe, "Packet universe doesn't match expected");
    assert_eq!(
        received_data[0].values, TEST_DATA_SINGLE_UNIVERSE,
        "Data packet values don't match expected"
    );

    snd_thread.join().unwrap();
}

/// A receiver and a sender are created which both listen/register to multiple universes.
/// The sender then sends multiple data packets with different sync addresses and then follows up with the various sync packets.
/// The receiver checks that the right data packets are received in the right order based on the sync packets sent.
///
/// This shows that multiple synchronisation addresses can be used simultaneously.
#[test]
#[ignore]
fn test_send_recv_multiple_sync_universes() {
    let timeout: Option<Duration> = Some(Duration::from_secs(3));

    let (tx, rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let thread_tx = tx.clone();

    let universes = slice_to_universes(&[1, 2, 3]).expect("in range");

    let snd_thread = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap(), ACN_SDT_MULTICAST_PORT + 1);
        let mut src = SacnSource::with_ip("Source", ip).unwrap();

        src.register_universes(&universes).unwrap();

        // Sender waits till the receiver says it is ready.
        thread_tx.send(()).unwrap();

        // Send on all 3 universes, the first universe waits for a sync packet on the second, the second on the third and the third
        // universe waits for a sync packet on its own universe.
        src.send(&[universes[0]], &TEST_DATA_SINGLE_UNIVERSE, None, None, Some(universes[1]))
            .unwrap();
        src.send(
            &[universes[1]],
            &TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
            None,
            None,
            Some(universes[2]),
        )
        .unwrap();
        src.send(
            &[universes[2]],
            &TEST_DATA_PARTIAL_CAPACITY_UNIVERSE,
            None,
            None,
            Some(universes[2]),
        )
        .unwrap();

        src.send_sync_packet(universes[1], None).unwrap(); // Should trigger the first universe to be received.
        src.send_sync_packet(universes[2], None).unwrap(); // Should trigger the second and third universe to be received together.
    });

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[1].parse().unwrap(), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();
    dmx_recv.listen_universes(&universes).unwrap();

    // Receiver created successfully so allow the sender to progress.
    rx.recv().unwrap();

    // Get the packets of data and check that they are correct.

    // First set of data should be the first universe.
    let received_data: Vec<DMXData> = dmx_recv.recv(timeout).unwrap();
    assert_eq!(received_data.len(), 1, "First set of data universe count doesn't match expected");
    assert_eq!(received_data[0].universe, universes[0], "Packet universe doesn't match expected");
    assert_eq!(
        received_data[0].values, TEST_DATA_SINGLE_UNIVERSE,
        "Data packet values don't match expected"
    );

    // Second set of data should be the second and third universe.
    let received_data2: Vec<DMXData> = dmx_recv.recv(timeout).unwrap();
    assert_eq!(received_data2.len(), 2, "Second set of data universe count doesn't match expected");
    if received_data2[0].universe == universes[1] {
        // Allow the data to be in any order as no ordering enforced within a set of data.
        assert_eq!(
            received_data2[0].values, TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
            "Second set of data part 1 packet values don't match expected"
        );

        assert_eq!(
            received_data2[1].universe, universes[2],
            "Second set of data universes don't match expected"
        );
        assert_eq!(
            received_data2[1].values, TEST_DATA_PARTIAL_CAPACITY_UNIVERSE,
            "Second set of data part 2 packet values don't match expected"
        );
    } else if received_data2[0].universe == universes[2] {
        assert_eq!(
            received_data2[0].values, TEST_DATA_PARTIAL_CAPACITY_UNIVERSE,
            "Second set of data part 1 packet values don't match expected"
        );

        assert_eq!(
            received_data2[1].universe, universes[1],
            "Second set of data universes don't match expected"
        );
        assert_eq!(
            received_data2[1].values, TEST_DATA_SINGLE_ALTERNATIVE_STARTCODE_UNIVERSE,
            "Second set of data part 2 packet values don't match expected"
        );
    } else {
        assert!(false, "Unexpected universe of data received");
    }

    snd_thread.join().unwrap();
}

/// A receiver and a sender are created which both listen to a data universe and a sync universe.
/// The sender then sends a synchronised data packet, the sender then waits for slightly longer than the E131_NETWORK_DATA_LOSS_TIMEOUT before sending
/// the corresponding sync packet. As per ANSI E1.31-2018 Section 11.1.2 this data should be discarded as universe synchronisation should stop if the
/// sync packet isn't received within the E131_NETWORK_DATA_LOSS_TIMEOUT.
///
/// This shows that this timeout mechanism to stop universe synchronisation works.
///
/// Note that this library does not attempt to implement the force_synchronisation bit behaviour and so therefore always stops universe synchronisation if the
/// sync packet is not received within the timeout.
#[test]
#[ignore]
fn test_send_sync_timeout() {
    let timeout: Option<Duration> = Some(Duration::from_secs(5));

    // Need to wait slightly longer than the E131_NETWORK_DATA_LOSS_TIMEOUT so that the synchronised data packet should timeout.
    let sender_wait_period: Duration = E131_NETWORK_DATA_LOSS_TIMEOUT + Duration::from_millis(100);

    let (tx, rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let thread_tx = tx.clone();

    let data_universe = UniverseId::new(1).expect("in range");
    let sync_universe = UniverseId::new(2).expect("in range");

    let snd_thread = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap(), ACN_SDT_MULTICAST_PORT + 1);
        let mut src = SacnSource::with_ip("Source", ip).unwrap();

        src.register_universes(&[data_universe, sync_universe]).unwrap();

        // Sender waits till the receiver says it is ready.
        thread_tx.send(()).unwrap();

        // Sender sends a data packet synchronised to the synchronisation universe.
        src.send(&[data_universe], &TEST_DATA_SINGLE_UNIVERSE, None, None, Some(sync_universe))
            .unwrap();

        // Sender waits too long to send the sync packet meaning that the synchronisation should have timed out.
        sleep(sender_wait_period.into());

        // Since the data packet should have timed out this should have no effect on the receiver.
        src.send_sync_packet(sync_universe, None).unwrap();
    });

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[1].parse().unwrap(), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();
    dmx_recv.listen_universes(&[data_universe, sync_universe]).unwrap();

    // Receiver created successfully so allow the sender to progress.
    rx.recv().unwrap();

    // Data should never be passed up because the data packet should have timed-out before the sync packet is processed.
    match dmx_recv.recv(timeout) {
        Err(e) => {
            match e {
                ReceiveError::Io(ref s) => {
                    match s.kind() {
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                            // Timeout as expected because the data packet that is awaiting a sync packet has timed out.
                            // The different errors are due to windows and unix returning different errors for the same thing.
                            assert!(true, "Timed out as expected meaning synchronised data packet timed out as expected");
                        }
                        _ => {
                            assert!(false, "Unexpected error returned");
                        }
                    }
                }
                _ => {
                    assert!(false, "Unexpected error returned");
                }
            }
        }
        Ok(p) => {
            // println!("Elapsed {:?}", p[0].recv_timestamp.elapsed());
            assert!(false, "Received data unexpectedly: {:?}", p);
        }
    }
    snd_thread.join().unwrap();
}

/// Setups and runs through the scenario as described in ANSI E1.31-2018 Appendix B.
/// This asserts that the behaviour of this implementation is exactly as outlined within that section.
/// This shows that the implementation handles universe synchronisation in the way specified by the protocol document.
/// As the force synchronisation option is not implemented as part of this library that section is ignored.
#[test]
#[ignore]
fn test_ansi_e131_appendix_b_runthrough_ipv4() {
    // The number of set of (data packets + sync packet) to send.
    let sync_packet_count: usize = 5;

    // The number of data packets sent before each sync packet.
    let data_packets_per_sync_packet: usize = 2;

    // The 'slight pause' as specified by ANSI E1.31-2018 Section 11.2.2 between data and sync packets.
    let pause_period: Duration = Duration::from_millis(100);

    let (tx, rx): (SyncSender<()>, Receiver<()>) = mpsc::sync_channel(0);

    let thread_tx = tx.clone();

    let data_universes = slice_to_universes(&[1, 2]).expect("in range");
    let sync_universe = UniverseId::new(7962).expect("in range");
    let priority = Priority::default();
    let source_name = "Source_A";
    let data = [0x00, 0xe, 0x0, 0xc, 0x1, 0x7, 0x1, 0x4, 0x8, 0x0, 0xd, 0xa, 0x7, 0xa];
    let data2 = [0x00, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xa];
    let src_cid: Uuid = Uuid::from_bytes([
        0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
    ]);

    let snd_thread = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap(), ACN_SDT_MULTICAST_PORT + 1);
        let mut src = SacnSource::with_cid_ip(source_name, src_cid, ip).unwrap();

        src.register_universes(&data_universes).unwrap();
        src.register_universe(sync_universe).unwrap();

        // Sender waits till the receiver says it is ready.
        thread_tx.send(()).unwrap();

        for _ in 0..sync_packet_count {
            // Sender sends data packets to the 2 data universes using the same synchronisation address.
            src.send(&[data_universes[0]], &data, Some(priority), None, Some(sync_universe))
                .unwrap();
            src.send(&[data_universes[1]], &data2, Some(priority), None, Some(sync_universe))
                .unwrap();

            // Sender observes a slight pause to allow for processing delays (ANSI E1.31-2018 Section 11.2.2).
            sleep(pause_period.into());

            // Sender sends a synchronisation packet to the sync universe.
            src.send_sync_packet(sync_universe, None).unwrap();
        }

        // Sender sends a data packet to the data universe using a zero synchronisation address indicating synchronisation is now over.
        src.send(&[data_universes[0]], &data, Some(priority), None, None).unwrap();
        src.send(&[data_universes[1]], &data2, Some(priority), None, None).unwrap();
    });

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[1].parse().unwrap(), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();

    // Receiver only listening to the data universe, the sync universe should be joined automatically when a data packet that requires it arrives.
    dmx_recv.listen_universes(&data_universes).unwrap();

    // Receiver created successfully so allow the sender to progress.
    rx.recv().unwrap();

    for _ in 0..sync_packet_count {
        // "When the E1.31 Synchronization Packet arrives from Source A, Receiver B acts on the data."
        match dmx_recv.recv(None) {
            Ok(p) => {
                assert_eq!(p.len(), data_packets_per_sync_packet);
                if p[0].universe == data_universes[0] {
                    assert_eq!(
                        p[0].values, data,
                        "Unexpected data within first data packet of a set of synchronised packets"
                    );

                    assert_eq!(
                        p[1].universe, data_universes[1],
                        "Unrecognised universe as second data packet in set of synchronised packets"
                    );
                    assert_eq!(
                        p[1].values, data2,
                        "Unexpected data within second data packet of a set of synchronised packets"
                    );
                } else if p[0].universe == data_universes[1] {
                    assert_eq!(
                        p[0].values, data2,
                        "Unexpected data within first data packet of a set of synchronised packets"
                    );

                    assert_eq!(
                        p[1].universe, data_universes[0],
                        "Unrecognised universe as second data packet in set of synchronised packets"
                    );
                    assert_eq!(
                        p[1].values, data,
                        "Unexpected data within second data packet of a set of synchronised packets"
                    );
                } else {
                    assert!(false, "Unrecognised universe within data packet");
                }
            }
            Err(e) => {
                assert!(false, "Unexpected error returned: {:?}", e);
            }
        }
    }
    // "This process continues until Receiver B receives an E1.31 Data Packet with a Synchronization Address of 0."
    // "Receiver B may then unsubscribe from the synchronization multicast address" - This implementation does not automatically unsubscribe
    //        This is based on the reasoning that a synchronisation universe will be used multiple times and subscribing/un-subscribing is unneeded overhead.
    // Synchronisation is now over so should receive 2 packets individually.
    let rcv_data = dmx_recv.recv(None).unwrap();
    assert_eq!(rcv_data.len(), 1);
    assert_eq!(rcv_data[0].universe, data_universes[0]);
    assert_eq!(rcv_data[0].values, data);

    let rcv_data2 = dmx_recv.recv(None).unwrap();
    assert_eq!(rcv_data2.len(), 1);
    assert_eq!(rcv_data2[0].universe, data_universes[1]);
    assert_eq!(rcv_data2[0].values, data2);

    // "If, at any time, Receiver B receives more than one E1.31 Data Packet with the same Synchronization
    // Address in it, before receiving an E1.31 Universe Synchronization Packet, it will discard all but the most
    // recent E1.31 Data Packet. Those packets are only acted upon when the synchronization command
    // arrives."
    // This is taken to refer to a data packet within the same universe and synchronisation address not a packet with any universe
    // this assumption is based on the wording "Universe synchronization is required for applications where receivers require more than one universe to
    // be controlled, multiple receivers produce synchronized output, or unsynchronized control of receivers may
    // SacnResult in undesired visual effects." from ANSI E1.31-2018 Section 11. This wording indicates that one use case of synchronisation is to allow
    // receivers with more than one universe to be controlled however this would be impossible if the statement above (from ANSI E1.31-2018 Appendix B)
    // indicated that data packets for all but one universe should be discarded.

    // "Since the the Force_Synchronization bit in the Options field of the E1.31 Data Packet has been set to 0,
    // even if Source A times out the E131_NETWORK_DATA_LOSS_TIMEOUT, Receiver B will stay in its last
    // look until a new E1.31 Synchronization Packet arrives."
    // The implementation does not support the force synchronisation bit so always acts as if is set to 1 and times out.

    snd_thread.join().unwrap();
}

/// Sets up a single source and receiver. Like in a real-world scenario the source sends data continuously on 2 universes synchronised
/// on a third universe with a small interval between data sends.
/// The receiver starts with no knowledge of what universe the source is sending on so starts by using Universe Discovery to discover the universes
/// it then joins these universes and receives the data. The sender eventually stops sending data and terminates by sending stream termination packets.
/// The receiver receives these packets and also terminates.
/// This shows that the implementation works in a simulated scenario that makes use of multiple features / parts.
/// It also shows the receiver 'jumping into' a stream of data that has already started (meaning sequence numbers are already > 0).
#[test]
#[ignore]
fn test_discover_recv_sync_runthrough_ipv4() {
    // The number of set of (data packets + sync packet) to send.
    let sync_packet_count: usize = 250;

    // The number of data packets sent before each sync packet.
    let data_packets_per_sync_packet: usize = 2;

    // The 'slight pause' as specified by ANSI E1.31-2018 Section 11.2.2 between data and sync packets.
    let pause_period: Duration = Duration::from_millis(50);

    // The interval between sets of sync/data packets.
    let interval: Duration = Duration::from_millis(100);

    // The universes used for data.
    let data_universes = slice_to_universes(&[1, 2]).expect("in range");

    // The universe used for synchronisation packets.
    let sync_universe = UniverseId::new(4).expect("in range");

    // The source name
    let source_name: &str = "Test Source";

    // The data send on the first and second universes.
    let data: [u8; 16] = [0x00, 0xe, 0x0, 0xc, 0x1, 0x7, 0x1, 0x4, 0x8, 0x0, 0xd, 0xa, 0x7, 0xa, 0x9, 0x8];
    let data2: [u8; 16] = [0x00, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xa, 0x9, 0x8];

    // The source CID.
    let src_cid: Uuid = Uuid::from_bytes([
        0xef, 0x07, 0xc8, 0xdd, 0x00, 0x64, 0x44, 0x01, 0xa3, 0xa2, 0x45, 0x9e, 0xf8, 0xe6, 0x14, 0x3e,
    ]);

    let snd_thread = thread::spawn(move || {
        let ip: SocketAddr = SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap(), ACN_SDT_MULTICAST_PORT + 1);
        let mut src = SacnSource::with_cid_ip(source_name, src_cid, ip).unwrap();

        src.register_universes(&data_universes).unwrap();
        src.register_universe(sync_universe).unwrap();

        for _ in 0..sync_packet_count {
            // Sender sends data packets to the 2 data universes using the same synchronisation address.
            src.send(&[data_universes[0]], &data, None, None, Some(sync_universe)).unwrap();
            src.send(&[data_universes[1]], &data2, None, None, Some(sync_universe)).unwrap();

            // Sender observes a slight pause to allow for processing delays (ANSI E1.31-2018 Section 11.2.2).
            sleep(pause_period.into());

            // Sender sends a synchronisation packet to the sync universe.
            src.send_sync_packet(sync_universe, None).unwrap();

            sleep(interval.into());
        }

        // Sender goes out of scope so will automatically send termination packets.
    });

    let mut dmx_recv = SacnReceiver::with_ip(
        SocketAddr::new(TEST_NETWORK_INTERFACE_IPV4[1].parse().unwrap(), ACN_SDT_MULTICAST_PORT),
        None,
    )
    .unwrap();

    // Receiver starts by not listening to any data universes (automatically listens to discovery universe).

    dmx_recv.set_announce_source_discovery(true);

    let universes = match dmx_recv.recv(None) {
        Err(e) => {
            match e {
                ReceiveError::SourceDiscovered(_name) => {
                    let discovered_sources = dmx_recv.get_discovered_sources();
                    assert_eq!(discovered_sources.len(), 1);

                    // Found the source so don't want to be notified about other sources.
                    dmx_recv.set_announce_source_discovery(false);

                    // Do want to be notified about stream termination in this case.
                    dmx_recv.set_announce_stream_termination(true);

                    discovered_sources[0].get_all_universes()
                }
                _ => {
                    // A real-user would want to look at using more detailed error handling as appropriate to their use case but for this test panic
                    // (which will fail the test) is suitable.
                    panic!("Unexpected error");
                }
            }
        }
        Ok(_) => {
            panic!("Unexpected data packet before any data universes registered");
        }
    };

    dmx_recv.listen_universes(&universes).unwrap(); // Assert Successful

    loop {
        match dmx_recv.recv(None) {
            Err(e) => {
                match e {
                    ReceiveError::UniverseTerminated { src_cid: _, universe: _ } => {
                        // A real use-case may also want to not terminate when the source does and instead remain waiting but in this
                        // case the for the test the receiver terminates with the source.
                        break;
                    }
                    _ => {
                        assert!(false, "Unexpected error returned");
                    }
                }
            }
            Ok(rcv_data) => {
                assert_eq!(rcv_data.len(), data_packets_per_sync_packet);
                if rcv_data[0].universe == data_universes[0] {
                    assert_eq!(
                        rcv_data[0].values, data,
                        "Unexpected data within first data packet of a set of synchronised packets"
                    );

                    assert_eq!(
                        rcv_data[1].universe, data_universes[1],
                        "Unrecognised universe as second data packet in set of synchronised packets"
                    );
                    assert_eq!(
                        rcv_data[1].values, data2,
                        "Unexpected data within second data packet of a set of synchronised packets"
                    );
                } else if rcv_data[0].universe == data_universes[1] {
                    assert_eq!(
                        rcv_data[0].values, data2,
                        "Unexpected data within first data packet of a set of synchronised packets"
                    );

                    assert_eq!(
                        rcv_data[1].universe, data_universes[0],
                        "Unrecognised universe as second data packet in set of synchronised packets"
                    );
                    assert_eq!(
                        rcv_data[1].values, data,
                        "Unexpected data within second data packet of a set of synchronised packets"
                    );
                } else {
                    assert!(false, "Unrecognised universe within data packet");
                }
            }
        }
    }

    // Finished receiving from the sender.
    snd_thread.join().unwrap();
}

/// Generates a data packet as raw bytes with the given parameters.
/// Assert parameters are correct sizes / in-range as appropriate.
fn generate_data_packet_raw(
    cid: [u8; 16],
    universe: UniverseId,
    source_name: String,
    priority: Priority,
    seq_num: u8,
    options: u8,
    dmx_data: Vec<u8>,
) -> Vec<u8> {
    assert!(dmx_data.len() <= UNIVERSE_CHANNEL_CAPACITY);
    assert_eq!(source_name.len(), 64);

    // Root ACN Layer
    let mut packet = Vec::new();

    // Preamble Size
    packet.extend("\x00\x10".bytes());

    // Post-amble Size
    packet.extend("\x00\x00".bytes());

    // ACN Packet Identifier
    packet.extend("\x41\x53\x43\x2d\x45\x31\x2e\x31\x37\x00\x00\x00".bytes());

    // Flags and Length (22 + 343)
    packet.push(0b01110001);
    packet.push(0b01101101);

    // Vector
    packet.extend("\x00\x00\x00\x04".bytes());

    // CID
    packet.extend(&cid);

    // E1.31 Framing Layer
    // Flags and Length (77 + 266)
    packet.push(0b01110001);
    packet.push(0b01010111);

    // Vector
    packet.extend("\x00\x00\x00\x02".bytes());

    // Source Name
    packet.extend(source_name.bytes());

    // Priority
    packet.push(priority.get());

    // Reserved
    packet.extend("\x00\x00".bytes());

    // Sequence Number
    packet.push(seq_num);

    // Options
    packet.push(options);

    // Universe, conversion to BigEndian bytes as Network Byte Order is BigEndian.
    let universe_bytes = universe.get().to_be_bytes();
    packet.push(universe_bytes[0]);
    packet.push(universe_bytes[1]);

    // DMP Layer
    // Flags and Length (266)
    packet.push(0b01110001);
    packet.push(0b00001010);

    // Vector
    packet.push(0x02);

    // Address Type & Data Type
    packet.push(0xa1);

    // First Property Address
    packet.extend("\x00\x00".bytes());

    // Address Increment
    packet.extend("\x00\x01".bytes());

    // Property value count = 255.
    packet.push(0b1);
    packet.push(0b00000000);

    // Property values
    packet.extend(&dmx_data);

    packet
}

/// Generates a sync packet as raw bytes with the given parameters.
fn generate_sync_packet_raw(cid: [u8; 16], sync_addr: UniverseId, seq_num: u8) -> Vec<u8> {
    // Root ACN Layer
    let mut sync_packet = Vec::new();

    // Preamble Size
    sync_packet.extend("\x00\x10".bytes());

    // Post-amble Size
    sync_packet.extend("\x00\x00".bytes());

    // ACN Packet Identifier
    sync_packet.extend("\x41\x53\x43\x2d\x45\x31\x2e\x31\x37\x00\x00\x00".bytes());

    // Flags and Length (0x70, 33)
    sync_packet.push(0b01110000);
    sync_packet.push(0b00100001);

    // Vector, VECTOR_ROOT_E131_EXTENDED as per ANSI E1.31-2018 Section 4.2 Table 4-2.
    sync_packet.extend("\x00\x00\x00\x08".bytes());

    // CID
    sync_packet.extend(&cid);

    // E1.31 Framing Layer
    // Flags and Length (0x70, 11)
    sync_packet.push(0b01110000);
    sync_packet.push(0b00001011);

    // Vector, VECTOR_E131_EXTENDED_SYNCHRONISATION as per ANSI E1.31-2018 Appendix A.
    sync_packet.extend("\x00\x00\x00\x01".bytes());

    // Sequence Number
    sync_packet.push(seq_num);

    // Synchronisation Address, conversion to BigEndian bytes as Network Byte Order is BigEndian.
    let sync_addr_bytes = sync_addr.get().to_be_bytes();
    sync_packet.push(sync_addr_bytes[0]);
    sync_packet.push(sync_addr_bytes[1]);

    // Reserve bytes as 0 as per ANSI E1.31-2018 Section 6.3.4.
    sync_packet.push(0);
    sync_packet.push(0);

    sync_packet
}

/// Creates a test data packet and tests sending it to a udp socket and then checking that the output bytes match expected.
/// This shows that the SacnSource sends a data packet in the correct format.
/// 
/// The use of a UDP socket also shows that the protocol uses UDP at the transport layer.
/// 
#[test]
#[rustfmt::skip]
#[ignore]
fn test_data_packet_transmit_format() {
    let cid: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let options: u8 = 0; // Checks that the options field is transmitted as 0's.
    let priority = Priority::new(150).expect("in range");

    let universe = UniverseId::new(1).expect("in range");

    let source_name = "SourceName".to_string() +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0";

    let sequence = 0;
    let mut dmx_data: Vec<u8> = Vec::new();
    dmx_data.push(0); // Start code
    dmx_data.extend(iter::repeat(100).take(255));

    let packet = generate_data_packet_raw(cid, universe, source_name.clone(), priority, sequence, options, dmx_data.clone());

    let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), ACN_SDT_MULTICAST_PORT + 1);
    let mut source = SacnSource::with_cid_ip(&source_name.clone(), Uuid::from_slice(&cid).unwrap(), ip).unwrap();

    source.set_preview_mode(false).unwrap();
    source.set_multicast_loop_v4(true).unwrap();

    let mut recv_socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
    
    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);

    recv_socket.bind(&addr.into()).unwrap();

    recv_socket.join_multicast_v4(&Ipv4Addr::new(239, 255, 0, 1), &Ipv4Addr::new(0, 0, 0, 0))
                .unwrap();

    let mut recv_buf = [0; 1024];

    source.register_universes(&[universe]).unwrap();

    source.send(&[universe], &dmx_data, Some(priority), None, None).unwrap();
    let amt = recv_socket.read(&mut recv_buf).unwrap();

    assert_eq!(&packet[..], &recv_buf[0..amt]);
}

/// Follows a similar process to test_data_packet_transmit_format by creating a SacnSender and then a receiving socket. The sender
/// then terminates a stream and the receive socket receives and checks that the sender sent the correct number (3) of termination packets.
#[test]
#[ignore]
fn test_terminate_packet_transmit_format() {
    let cid = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT + 1);
    let mut source = SacnSource::with_cid_ip("Source", Uuid::from_slice(&cid).unwrap(), ip).unwrap();

    source.set_multicast_loop_v4(true).unwrap();

    let mut recv_socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();

    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);

    recv_socket.bind(&addr.into()).unwrap();

    recv_socket
        .join_multicast_v4(&Ipv4Addr::new(239, 255, 0, 1), &Ipv4Addr::new(0, 0, 0, 0))
        .unwrap();

    let mut recv_buf = [0; 1024];

    let start_code: u8 = 0;

    let universe = UniverseId::new(1).expect("in range");

    source.register_universes(&[universe]).unwrap();

    source.terminate_stream(universe, start_code).unwrap();
    for _ in 0..2 {
        recv_socket.read(&mut recv_buf).unwrap();
        assert!(match AcnRootLayerProtocol::parse(&recv_buf).unwrap().pdu.data {
            E131RootLayerData::DataPacket(data) => data.stream_terminated,
            _ => panic!(),
        })
    }
}

/// Similar to test_data_packet_transmit_format, creates a SacnSender and then a receiver socket. The sender then sends
/// a synchronisation packet and the receive socket receives the packet and checks that the format of the packet is as expected.
///
/// The use of a UDP socket also shows that the protocol uses UDP at the transport layer.
#[test]
#[ignore]
fn test_sync_packet_transmit_format() {
    let cid: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let sync_addr = UniverseId::new(1).expect("in range");

    // Sequence number of initial synchronisation packet is expected to be 0.
    let sequence_num: u8 = 0;

    let sync_packet = generate_sync_packet_raw(cid, sync_addr, sequence_num);

    let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT + 1);
    let mut source = SacnSource::with_cid_ip("Source", Uuid::from_slice(&cid).unwrap(), ip).unwrap();

    source.set_multicast_loop_v4(true).unwrap();

    // Create a standard udp receive socket to receive the packet sent by the source.
    let mut recv_socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();

    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);

    recv_socket.bind(&addr.into()).unwrap();

    recv_socket
        .join_multicast_v4(&Ipv4Addr::new(239, 255, 0, 1), &Ipv4Addr::new(0, 0, 0, 0))
        .unwrap();

    let mut recv_buf = [0; E131_SYNC_PACKET_LENGTH];

    // Send the synchronisation packet.
    source.register_universes(&[sync_addr]).unwrap();
    source.send_sync_packet(sync_addr, None).unwrap();

    // Receive the packet and compare its content to the expected.
    recv_socket.read(&mut recv_buf).unwrap();

    assert_eq!(
        recv_buf[..],
        sync_packet[..],
        "Sync packet sent by source doesn't match expected format"
    );
}

/// Similar to test_data_packet_transmit_format, creates a SacnSender and then a receiver socket. The sender then sends
/// a discovery packet and the receive socket receives the packet and checks that the format of the packet is as expected.
///
/// The use of a UDP socket also shows that the protocol uses UDP at the transport layer.
#[test]
#[ignore]
fn test_discovery_packet_transmit_format() {
    let cid: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    // Source name = "Controller"
    let source_name: [u8; 64] = [
        b'C', b'o', b'n', b't', b'r', b'o', b'l', b'l', b'e', b'r', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // Represents 3 16 bit universes.
    const UNIVERSES: [u8; 6] = [0x0, 0x1, 0x0, 0x2, 0x0, 0x3];

    // Discovery packet length 49 bytes as per ANSI E1.31-2018 Section 8 Table 8-9.
    const DISCOVERY_PACKET_LENGTH_EXPECTED: usize = 120 + UNIVERSES.len();

    // As the number of universes will fit on one page expect the page number and last page number to both be 0.
    let page: u8 = 0;
    let last_page: u8 = 0;

    // Root ACN Layer
    let mut discovery_packet = Vec::new();

    // Preamble Size
    discovery_packet.extend("\x00\x10".bytes());

    // Post-amble Size
    discovery_packet.extend("\x00\x00".bytes());

    // ACN Packet Identifier
    discovery_packet.extend("\x41\x53\x43\x2d\x45\x31\x2e\x31\x37\x00\x00\x00".bytes());

    // Flags and Length (0x70, 110)
    discovery_packet.push(0b01110000);
    discovery_packet.push(0b01101110);

    // Vector, VECTOR_ROOT_E131_EXTENDED as per ANSI E1.31-2018 Section 4.3 Table 4-3 and Appendix A.
    discovery_packet.extend("\x00\x00\x00\x08".bytes());

    // CID
    discovery_packet.extend(&cid);

    // E1.31 Framing Layer
    // Flags and Length (0x70, 88)
    discovery_packet.push(0b01110000);
    discovery_packet.push(0b01011000);

    // Vector, VECTOR_E131_EXTENDED_DISCOVERY as per ANSI E1.31-2018 Section 4.3 Table 4-3 and Appendix A.
    discovery_packet.extend("\x00\x00\x00\x02".bytes());

    // Source Name
    discovery_packet.extend(source_name.iter());

    // Reserve bytes, should be transmitted as 0's as per ANSI E1.31-2018 Section 6.4.3.
    discovery_packet.push(0);
    discovery_packet.push(0);
    discovery_packet.push(0);
    discovery_packet.push(0);

    // Universe Discovery Layer
    // Flags and Length (0x70, 14)
    discovery_packet.push(0b01110000);
    discovery_packet.push(0b00001110);

    // Vector, VECTOR_UNIVERSE_DISCOVERY_UNIVERSE_LIST as per ANSI E1.31-2018 Section 4.3 Table 4-3 and Appendix A.
    discovery_packet.extend("\x00\x00\x00\x01".bytes());

    // Page and last page
    discovery_packet.push(page);
    discovery_packet.push(last_page);

    // The list of universes that are being advertised by the discovery packet.
    discovery_packet.extend(UNIVERSES.iter());

    assert_eq!(
        discovery_packet.len(),
        DISCOVERY_PACKET_LENGTH_EXPECTED,
        "Example discovery packet length doesn't match expected"
    );

    let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT + 1);

    // Creates the source.
    let mut source = SacnSource::with_cid_ip(str::from_utf8(&source_name).unwrap(), Uuid::from_slice(&cid).unwrap(), ip).unwrap();

    source.set_multicast_loop_v4(true).unwrap();

    // Create a standard udp receive socket to receive the packet sent by the source.
    let mut recv_socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();

    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);

    recv_socket.bind(&addr.into()).unwrap();

    // Receiving on the discovery universe shows that the discovery universe is correctly used for discovery packets as per ANSI E1.31-2018 Section 6.2.7.
    let address = UniverseId::DISCOVERY.to_ipv4_multicast_addr().as_socket_ipv4();

    recv_socket
        .join_multicast_v4(address.unwrap().ip(), &Ipv4Addr::new(0, 0, 0, 0))
        .unwrap();

    let mut recv_buf = [0; DISCOVERY_PACKET_LENGTH_EXPECTED];

    // Register the universes, note be = BigEndian which is used as network byte order is BigEndian.
    source
        .register_universes(&[
            UniverseId::from_be_bytes(UNIVERSES[0..2].try_into().unwrap()).expect("in range"),
            UniverseId::from_be_bytes(UNIVERSES[2..4].try_into().unwrap()).expect("in range"),
            UniverseId::from_be_bytes(UNIVERSES[4..6].try_into().unwrap()).expect("in range"),
        ])
        .unwrap();

    // The source is expected to eventually send a universe discovery packet.

    // Receive the packet and compare its content to the expected.
    recv_socket.read(&mut recv_buf).unwrap();

    assert_eq!(
        recv_buf[..],
        discovery_packet[..],
        "Discovery packet sent by source doesn't match expected format"
    );
}

/// Similar to test_data_packet_transmit_format, creates a SacnSender and then a receiver socket. The sender then sends
/// a synchronisation packet and the receive socket receives the packet and checks that the format of the packet is as expected.
///
/// The use of a UDP socket also shows that the protocol uses UDP at the transport layer.
#[test]
#[ignore]
fn test_sync_packet_transmit_seq_numbers() {
    let cid: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let universe = UniverseId::new(1).expect("in range");

    // Sequence number of initial synchronisation packet is expected to be 0.
    let sequence_num: u8 = 0;

    // Root Layer
    let mut sync_packet = Vec::new();

    // Preamble Size
    sync_packet.extend("\x00\x10".bytes());

    // Post-amble Size
    sync_packet.extend("\x00\x00".bytes());

    // ACN Packet Identifier
    sync_packet.extend("\x41\x53\x43\x2d\x45\x31\x2e\x31\x37\x00\x00\x00".bytes());

    // Flags and Length (0x70, 33)
    sync_packet.push(0b01110000);
    sync_packet.push(0b00100001);

    // Vector, VECTOR_ROOT_E131_EXTENDED as per ANSI E1.31-2018 Section 4.2 Table 4-2.
    sync_packet.extend("\x00\x00\x00\x08".bytes());

    // CID
    sync_packet.extend(&cid);

    // E1.31 Framing Layer
    // Flags and Length (0x70, 11)
    sync_packet.push(0b01110000);
    sync_packet.push(0b00001011);

    // Vector, VECTOR_E131_EXTENDED_SYNCHRONISATION as per ANSI E1.31-2018 Appendix A.
    sync_packet.extend("\x00\x00\x00\x01".bytes());

    // Sequence Number
    sync_packet.push(sequence_num);

    // Synchronisation Address, 1
    sync_packet.push(0);
    sync_packet.push(1);

    // Reserve bytes as 0 as per ANSI E1.31-2018 Section 6.3.4.
    sync_packet.push(0);
    sync_packet.push(0);

    let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT + 1);
    let mut source = SacnSource::with_cid_ip("Source", Uuid::from_slice(&cid).unwrap(), ip).unwrap();

    source.set_multicast_loop_v4(true).unwrap();

    // Create a standard udp receive socket to receive the packet sent by the source.
    let mut recv_socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();

    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);

    recv_socket.bind(&addr.into()).unwrap();

    recv_socket
        .join_multicast_v4(&Ipv4Addr::new(239, 255, 0, 1), &Ipv4Addr::new(0, 0, 0, 0))
        .unwrap();

    let mut recv_buf = [0; E131_SYNC_PACKET_LENGTH];

    // Send the synchronisation packet.
    source.register_universes(&[universe]).unwrap();
    source.send_sync_packet(universe, None).unwrap();

    // Receive the packet and compare its content to the expected.
    recv_socket.read(&mut recv_buf).unwrap();

    assert_eq!(
        recv_buf[..],
        sync_packet[..],
        "Sync packet sent by source doesn't match expected format"
    );
}

/// Creates a source and a receiver socket. The source then sends data packets meant for different universes and the receiver checks
/// that the sequence numbers are incremented by 1 for each packet and are incremented independently for each universe.SockAddr
/// 
/// This shows the source complies with ANSI E1.31-2018 Section 6.2.5 "E1.31 Data Packet: Sequence Number". 
/// 
#[test]
#[rustfmt::skip]
#[ignore]
fn test_track_data_packet_seq_numbers() {
    // Packet parameters
    let cid: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let options: u8 = 0; // Checks that the options field is transmitted as 0's.
    let priority = Priority::new(150).expect("in range");
    let source_name = "SourceName".to_string() +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0";
    let mut dmx_data: Vec<u8> = Vec::new();
    dmx_data.push(0); // Start code
    dmx_data.extend(iter::repeat(100).take(255));

    // The parameters above are set to arbitrary values as they aren't the focus of the test

    // The expected starting sequence number of data packets from the source.
    let start_seq_num: usize = 0;

    // The number of data packets to send per universe.
    let data_packets_to_send: usize = 300;

    // The universes that the data packets are sent on.
    let universes = slice_to_universes(&[1, 3, 5, 7, 9]).expect("in range");

    // Create a source.
    let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), ACN_SDT_MULTICAST_PORT + 1);
    let mut source = SacnSource::with_cid_ip(&source_name.clone(), Uuid::from_slice(&cid).unwrap(), ip).unwrap();
    source.set_multicast_loop_v4(true).unwrap();
    source.register_universes(&universes).unwrap();

    // Don't want universe discovery packets to be sent which might interfer with checking data packets.
    source.set_is_sending_discovery(false);

    // Create receiver socket.
    let mut recv_socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);
    recv_socket.bind(&addr.into()).unwrap();

    // Join the multicast groups for each of the universes.
    for u in universes.iter() {
        let address =  u.to_ipv4_multicast_addr().as_socket_ipv4();

        recv_socket
            .join_multicast_v4(address.unwrap().ip(), &Ipv4Addr::new(0, 0, 0, 0))
            .unwrap();
    }

    for s in start_seq_num .. start_seq_num + data_packets_to_send {
        let expected_seq_num: u8 = (s % 256).try_into().unwrap();
        for u in universes.iter() {
            let expected_packet = generate_data_packet_raw(cid, *u, source_name.clone(), priority, expected_seq_num, options, dmx_data.clone());
            source.send(&[*u], &dmx_data, Some(priority), None, None).unwrap();

            let mut recv_buf = [0; 1024];
            let amt = recv_socket.read(&mut recv_buf).unwrap();

            assert_eq!(&recv_buf[0..amt], &expected_packet[..]);
        }
    }
}

/// Creates a source and a receiver socket. The source then sends data packets meant for different universes and the receiver checks
/// that the sequence numbers are incremented by 1 for each packet and are incremented independently for each universe.SockAddr
/// 
/// This shows the source complies with ANSI E1.31-2018 Section 6.2.5 "E1.31 Data Packet: Sequence Number". 
/// 
#[test]
#[rustfmt::skip]
#[ignore]
fn test_track_sync_packet_seq_numbers() {
    // Source CID and name, set to arbitrary values as not the focus of the test.
    let cid: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let source_name = "SourceName".to_string() +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0";

    // The expected starting sequence number of sync packets from the source.
    let start_seq_num: usize = 0;

    // The number of sync packets to send per universe. Chosen to be high enough that a sequence number wrap around due to the maximum possible value in a u8 is required. 
    // This checks that the sequence numbers wrap around correctly.
    let sync_packets_to_send: usize = 300;

    // The universes that the sync packets are sent on.
    let sync_addresses = slice_to_universes(&[1, 3, 5, 7, 9]).expect("in range");

    // Create a source.
    let ip: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), ACN_SDT_MULTICAST_PORT + 1);
    let mut source = SacnSource::with_cid_ip(&source_name.clone(), Uuid::from_slice(&cid).unwrap(), ip).unwrap();
    source.set_multicast_loop_v4(true).unwrap();

    // Register the synchronisation addresses.
    source.register_universes(&sync_addresses).unwrap();

    // Don't want universe discovery packets to be sent which might interfer with checking sync packets.
    source.set_is_sending_discovery(false);

    // Create receiver socket.
    let mut recv_socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);
    recv_socket.bind(&addr.into()).unwrap();

    // Join the multicast groups for each of the synchronisation addresses.
    for u in sync_addresses.iter() {
        let address = u.to_ipv4_multicast_addr().as_socket_ipv4();

        recv_socket
            .join_multicast_v4(address.unwrap().ip(), &Ipv4Addr::new(0, 0, 0, 0))
            .unwrap();
    }

    for s in start_seq_num .. start_seq_num + sync_packets_to_send {
        let expected_seq_num: u8 = (s % 256).try_into().unwrap();
        for a in sync_addresses.iter() {
            let expected_packet = generate_sync_packet_raw(cid, *a, expected_seq_num);
            source.send_sync_packet(*a, None).unwrap();

            let mut recv_buf = [0; 1024];
            let amt  = recv_socket.read(&mut recv_buf).unwrap();

            assert_eq!(&recv_buf[0..amt], expected_packet);
        }
    }
}

/// Creates 5 receiver sockets each listening to a different multicast address for a specific synchronisation address.
/// Then creates a source which sends synchronisation packets meant for different synchronisation addresses.
/// The receiver sockets check that they only receive synchronisation packets meant for their synchronisation address / multicast address.
/// 
/// This shows that synchronisation packets are only sent to the multicast address which corresponds to the synchronisation address as per
/// ANSI E1.31-2018 Section 6.3.3.1.
/// 
#[test]
#[rustfmt::skip]
#[ignore]
/// Linux only because of the mechanism used for creating the recv sockets so that they only receive from a single multicast address.
/// This is unrelated to the actual library and is just the way the test is written.
#[cfg(target_os = "linux")]
fn test_sync_packet_multicast_address() {
    // Source CID and name, set to arbitrary values as not the focus of the test.
    let cid: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let source_name = "SourceName".to_string() +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0\0\0\0\0\0\0" +
                        "\0\0\0\0";

    // The expected starting sequence number of sync packets from the source.
    let start_seq_num: usize = 0;

    // The number of sync packets to send per sync_address. Chosen arbitrarily to be high enough that if there was going to be a mix up in the addressing there would be a
    // sufficient chance of it being seen.
    let sync_packets_to_send: usize = 250;

    // The universes that the sync packets are sent on.
    // Chosen to contain adjacent universes and a separate universe to check that this doesn't effect the address sending.
    let sync_addresses = slice_to_universes(&[1, 2, 63999]).expect("in range");

    // Create a source.
    let ip: SocketAddr = SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT + 1);
    let mut source = SacnSource::with_cid_ip(&source_name.clone(), Uuid::from_slice(&cid).unwrap(), ip).unwrap();
    source.set_multicast_loop_v4(true).unwrap();

    // Register the synchronisation addresses.
    source.register_universes(&sync_addresses).unwrap();

    // Don't want universe discovery packets to be sent which might interfer with checking sync packets.
    source.set_is_sending_discovery(false);

    // Create receiver sockets.
    let mut recv_sockets: Vec<Socket> = Vec::new();

    let mut i = 0;
    for sync_addr in sync_addresses.iter() {
        recv_sockets.push(Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap());

        // Join only the multicast address corresponding to the synchronisation address.
        let multicast_addr =  sync_addr.to_ipv4_multicast_addr();
        recv_sockets[i].bind(&multicast_addr).unwrap();
        recv_sockets[i]
            .join_multicast_v4(multicast_addr.as_socket_ipv4().unwrap().ip(), &TEST_NETWORK_INTERFACE_IPV4[i].parse().unwrap())
            .unwrap();

        i += 1;
    }

    for s in start_seq_num .. start_seq_num + sync_packets_to_send {
        let expected_seq_num: u8 = (s % 256).try_into().unwrap();

        let mut i = 0;
        for sync_addr in sync_addresses.iter() {
            let expected_packet = generate_sync_packet_raw(cid, *sync_addr, expected_seq_num);
            source.send_sync_packet(*sync_addr, None).unwrap();

            let mut recv_buf = [0; 1024];

            // Receive only from the corresponding socket for that sync address.
            // This means that the sync address must have been sent to the correct multicast address.
            // If it was also sent to other addresses then this will be caught the next time the other sockets
            // receive as they will receive the wrong packet.
            let amt = recv_sockets[i].read(&mut recv_buf).unwrap();

            assert_eq!(&recv_buf[0..amt], &expected_packet[..]);

            i += 1;
        }
    }
}

#[test]
#[ignore]
fn test_register_terminate_universe() {
    let mut src = SacnSource::with_cid_ip(
        "Test name",
        Uuid::new_v4(),
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
    )
    .unwrap();

    let universe = UniverseId::new(1).expect("in range");

    src.register_universe(universe).unwrap();

    assert_eq!(src.universes().unwrap(), vec!(1), "Universe not registered correctly");

    src.terminate_stream(universe, 0).unwrap();

    assert!(src.universes().unwrap().is_empty(), "Universe not registered correctly");
}

#[test]
#[ignore]
fn test_terminate_universe_no_register() {
    let mut src = SacnSource::with_cid_ip(
        "Test name",
        Uuid::new_v4(),
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
    )
    .unwrap();

    let universe = UniverseId::new(1).expect("in range");

    match src.terminate_stream(universe, 0) {
        Err(e) => match e {
            SourceError::UniverseNotRegistered(_) => {
                assert!(true, "Expected error returned");
            }
            _ => {
                assert!(false, "Unexpected error returned");
            }
        },
        _ => {
            assert!(false, "Src terminated stream that wasn't registered!");
        }
    }
}

#[test]
#[ignore]
fn test_send_empty() {
    let universe = UniverseId::new(1).expect("in range");

    let mut src = SacnSource::with_cid_ip(
        "Test name",
        Uuid::new_v4(),
        SocketAddr::new(IpAddr::V4(TEST_NETWORK_INTERFACE_IPV4[0].parse().unwrap()), ACN_SDT_MULTICAST_PORT),
    )
    .unwrap();

    src.register_universe(universe).unwrap();

    match src.send(&[universe], &[], None, None, None) {
        Err(e) => match e {
            SourceError::Io(x) => match x.kind() {
                std::io::ErrorKind::InvalidInput => {
                    assert!(true, "Unexpected error returned");
                }
                _ => {
                    assert!(false, "Unexpected error returned");
                }
            },
            _ => {
                assert!(false, "Unexpected error returned");
            }
        },
        _ => {
            assert!(false, "Empty data accepted to send incorrectly");
        }
    }
}
