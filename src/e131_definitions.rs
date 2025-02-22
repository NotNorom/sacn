use core::time::Duration;

/// The maximum number of universes per page in a universe discovery packet.
pub const DISCOVERY_UNI_PER_PAGE: usize = 512;

/// Value of the highest byte of the IPV4 multicast address as specified in section 9.3.1 of ANSI E1.31-2018.
pub const E131_MULTICAST_IPV4_HIGHEST_BYTE: u8 = 239;

/// Value of the second highest byte of the IPV4 multicast address as specified in section 9.3.1 of ANSI E1.31-2018.
pub const E131_MULTICAST_IPV4_SECOND_BYTE: u8 = 255;

/// The interval between universe discovery packets (adverts) as defined by ANSI E1.31-2018 Appendix A.
pub const E131_UNIVERSE_DISCOVERY_INTERVAL: Duration = Duration::from_secs(10);

/// The exclusive lower bound on the different between the received and expected sequence numbers within which a
/// packet will be discarded. Outside of the range specified by (E131_SEQ_DIFF_DISCARD_LOWER_BOUND, E131_SEQ_DIFF_DISCARD_UPPER_BOUND]
/// the packet won't be discarded.
///
/// Having a range allows receivers to catch up if packets are lost.
/// Value as specified in ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
pub const E131_SEQ_DIFF_DISCARD_LOWER_BOUND: isize = -20;

/// The inclusive upper bound on the different between the received and expected sequence numbers within which a
/// packet will be discarded. Outside of the range specified by (E131_SEQ_DIFF_DISCARD_LOWER_BOUND, E131_SEQ_DIFF_DISCARD_UPPER_BOUND]
/// the packet won't be discarded.
///
/// Having a range allows receivers to catch up if packets are lost.
/// Value as specified in ANSI E1.31-2018 Section 6.7.2 Sequence Numbering.
pub const E131_SEQ_DIFF_DISCARD_UPPER_BOUND: isize = 0;

/// The bit mask used to get the preview-data option within the packet option field as per
/// ANSI E1.31-2018 Section 6.2.6
pub const E131_PREVIEW_DATA_OPTION_BIT_MASK: u8 = 0b1000_0000;

/// The bit mask used to get the stream-termination option within the packet option field as per
/// ANSI E1.31-2018 Section 6.2.6
pub const E131_STREAM_TERMINATION_OPTION_BIT_MASK: u8 = 0b0100_0000;

/// The bit mask used to get the force-synchronisation option within the packet option field as per
/// ANSI E1.31-2018 Section 6.2.6
pub const E131_FORCE_SYNCHRONISATION_OPTION_BIT_MASK: u8 = 0b0010_0000;

/// The minimum allowed length of the discovery layer of an ANSI E1.31-2018 universe discovery packet.
/// As per ANSI E1.31-2018 Section 8 Table 8-9.
pub const E131_UNIVERSE_DISCOVERY_LAYER_MIN_LENGTH: usize = 8;

/// The maximum allowed length of the discovery layer of an ANSI E1.31-2018 universe discovery packet.
/// As per ANSI E1.31-2018 Section 8 Table 8-9.
pub const E131_UNIVERSE_DISCOVERY_LAYER_MAX_LENGTH: usize = 1032;

/// The expected value of the root layer length field for a synchronisation packet.
/// 33 bytes as per ANSI E1.31-2018 Section 4.2 Table 4-2.
pub const E131_UNIVERSE_SYNC_PACKET_ROOT_LENGTH: usize = 33;

/// The expected value of the framing layer length field for a synchronisation packet.
/// 11 bytes as per ANSI E1.31-2018 Section 4.2 Table 4-2.
pub const E131_UNIVERSE_SYNC_PACKET_FRAMING_LAYER_LENGTH: usize = 11;

/// The minimum expected value of the framing layer length field for a discovery packet.
/// 84 bytes as per ANSI E1.31-2018 Section 4.3 Table 4-3.
pub const E131_UNIVERSE_DISCOVERY_FRAMING_LAYER_MIN_LENGTH: usize = 82;

/// The number of stream termination packets sent when a source terminates a stream.
/// Set to 3 as per section 6.2.6 , Stream_Terminated: Bit 6 of ANSI E1.31-2018.
pub const E131_TERMINATE_STREAM_PACKET_COUNT: usize = 3;

/// The length of the pdu flags and length field in bytes.
pub const E131_PDU_LENGTH_FLAGS_LENGTH: usize = 2;

/// The pdu flags expected for an ANSI E1.31-2018 packet as per ANSI E1.31-2018 Section 4 Table 4-1, 4-2, 4-3.
pub const E131_PDU_FLAGS: u8 = 0x70;

/// The length in bytes of the root layer vector field as per ANSI E1.31-2018 Section 4 Table 4-1, 4-2, 4-3.
pub const E131_ROOT_LAYER_VECTOR_LENGTH: usize = 4;

/// The length in bytes of the E1.31 framing layer vector field as per ANSI E1.31-2018 Section 4 Table 4-1, 4-2, 4-3.
pub const E131_FRAMING_LAYER_VECTOR_LENGTH: usize = 4;

/// The length in bytes of the priority field within an ANSI E1.31-2018 data packet as defined in ANSI E1.31-2018 Section 4, Table 4-1.
pub const E131_PRIORITY_FIELD_LENGTH: usize = 1;

/// The length in bytes of the sequence number field within an ANSI E1.31-2018 packet as defined in ANSI E1.31-2018 Section 4, Table 4-1, 4-2.
pub const E131_SEQ_NUM_FIELD_LENGTH: usize = 1;

/// The length in bytes of the options field within an ANSI E1.31-2018 data packet as defined in ANSI E1.31-2018 Section 4, Table 4-1.
pub const E131_OPTIONS_FIELD_LENGTH: usize = 1;

/// The length in bytes of a universe field within an ANSI E1.31-2018 packet as defined in ANSI E1.31-2018 Section 4, Table 4-1, 4-3.
pub const E131_UNIVERSE_FIELD_LENGTH: usize = 2;

/// The length in bytes of the Vector field within the DMP layer of an ANSI E1.31-2018 data packet as per ANSI E1.31-2018
/// Section 4, Table 4-1.
pub const E131_DATA_PACKET_DMP_LAYER_VECTOR_FIELD_LENGTH: usize = 1;

/// The length in bytes of the "Address Type and Data Type" field within an ANSI E1.31-2018 data packet DMP layer as per
/// ANSI E1.31-2018 Section 4, Table 4-1.
pub const E131_DATA_PACKET_DMP_LAYER_ADDRESS_DATA_FIELD_LENGTH: usize = 1;

/// The length in bytes of the "First Property Address" field within an ANSI E1.31-2018 data packet DMP layer as per
/// ANSI E1.31-2018 Section 4, Table 4-1.
pub const E131_DATA_PACKET_DMP_LAYER_FIRST_PROPERTY_ADDRESS_FIELD_LENGTH: usize = 2;

/// The length in bytes of the "Address Increment" field within an ANSI E1.31-2018 data packet DMP layer as per
/// ANSI E1.31-2018 Section 4, Table 4-1.
pub const E131_DATA_PACKET_DMP_LAYER_ADDRESS_INCREMENT_FIELD_LENGTH: usize = 2;

/// The length in bytes of the "Property value count" field within an ANSI E1.31-2018 data packet DMP layer as per
/// ANSI E1.31-2018 Section 4, Table 4-1.
pub const E131_DATA_PACKET_DMP_LAYER_PROPERTY_VALUE_COUNT_FIELD_LENGTH: usize = 2;

/// The length in bytes of the Vector field in the Universe Discovery Layer of an ANSI E1.31-2018 Universe Discovery Packet.
/// 4 bytes as per ANSI E1.31-2018 Section 4, Table 4-3.
pub const E131_DISCOVERY_LAYER_VECTOR_FIELD_LENGTH: usize = 4;

/// The length in bytes of the Page field in the Universe Discovery Layer of an ANSI E1.31-2018 Universe Discovery Packet.
/// 1 bytes as per ANSI E1.31-2018 Section 4, Table 4-3.
pub const E131_DISCOVERY_LAYER_PAGE_FIELD_LENGTH: usize = 1;

/// The length in bytes of the Last Page field in the Universe Discovery Layer of an ANSI E1.31-2018 Universe Discovery Packet.
/// 1 bytes as per ANSI E1.31-2018 Section 4, Table 4-3.
pub const E131_DISCOVERY_LAYER_LAST_PAGE_FIELD_LENGTH: usize = 1;

/// The value of the "Address Type and Data Type" field within an ANSI E1.31-2018 data packet DMP layer as per ANSI E1.31-2018
/// Section 4, Table 4-1.
pub const E131_DMP_LAYER_ADDRESS_DATA_FIELD: u8 = 0xa1;

/// The value of the "First Property Address" field within an ANSI E1.31-2018 data packet DMP layer as per ANSI E1.31-2018
/// Section 4, Table 4-1.
pub const E131_DATA_PACKET_DMP_LAYER_FIRST_PROPERTY_FIELD: u16 = 0x0000;

/// The value of the "Address Increment" field within an ANSI E1.31-2018 data packet DMP layer as per ANSI E1.31-2018
/// Section 4, Table 4-1.
pub const E131_DATA_PACKET_DMP_LAYER_ADDRESS_INCREMENT: u16 = 0x0001;

/// The size of the ACN root layer preamble, must be 0x0010 bytes as per ANSI E1.31-2018 Section 5.1.
/// Often treated as a usize for comparison or use with arrays however stored as u16 as this represents its field size
/// within a packet and converting u16 -> usize is always safe as len(usize) is always greater than len(u16), usize -> u16 is unsafe.
pub const E131_PREAMBLE_SIZE: u16 = 0x0010;

/// The size of the ACN root layer postamble, must be 0x0 bytes as per ANSI E1.31-2018 Section 5.2.
pub const E131_POSTAMBLE_SIZE: u16 = 0x0;

/// The E131 ACN packet identifier field value. Must be 0x41 0x53 0x43 0x2d 0x45 0x31 0x2e 0x31 0x37 0x00 0x00 0x00 as per
/// ANSI E1.31-2018 Section 5.3.
pub const E131_ACN_PACKET_IDENTIFIER: [u8; 12] = [0x41, 0x53, 0x43, 0x2d, 0x45, 0x31, 0x2e, 0x31, 0x37, 0x00, 0x00, 0x00];

/// The E131 CID field length in bytes as per ANSI E1.31-2018 Section 4 Table 4-1, 4-2, 4-3.
pub const E131_CID_FIELD_LENGTH: usize = 16;

// The exclusive end index of the CID field. Calculated based on previous values defined in ANSI E1.31-2018 Section 4 Table 4-1, 4-2, 4-3.
pub const E131_CID_END_INDEX: usize = E131_PDU_LENGTH_FLAGS_LENGTH + E131_ROOT_LAYER_VECTOR_LENGTH + E131_CID_FIELD_LENGTH;

/// The length of the Source Name field in bytes in an ANSI E1.31-2018 packet as per ANSI E1.31-2018 Section 4, Table 4-1, 4-2, 4-3.
pub const E131_SOURCE_NAME_FIELD_LENGTH: usize = 64;

/// Sync packet length 49 bytes as per ANSI E1.31-2018 Section 4.2 Table 4-2.
pub const E131_SYNC_PACKET_LENGTH: usize = 49;

/// The length of the Synchronisation Address field in bytes in an ANSI E1.31-2018 packet as per ANSI E1.31-2018 Section 4, Table 4-1, 4-2, 4-3.
pub const E131_SYNC_ADDR_FIELD_LENGTH: usize = 2;

/// The length in bytes of the sequence number field within the framing layer of an E1.31 synchronisation packet.
/// AS per ANSI E1.31-2018 Section 4, Table 4-2.
pub const E131_SYNC_FRAMING_LAYER_SEQ_NUM_FIELD_LENGTH: usize = 1;

/// The length in bytes of the reserved field within the framing layer of an E1.31 synchronisation packet.
/// AS per ANSI E1.31-2018 Section 4, Table 4-2.
pub const E131_SYNC_FRAMING_LAYER_RESERVE_FIELD_LENGTH: usize = 2;

// The length in bytes of the reserve field in the universe discovery framing layer of an ANSI E1.31-2018 Universe Discovery Packet.
// Length as per ANSI E1.31-2018 Section 4, Table 4-3.
pub const E131_DISCOVERY_FRAMING_LAYER_RESERVE_FIELD_LENGTH: usize = 4;

/// The initial/starting sequence number used.
pub const STARTING_SEQUENCE_NUMBER: u8 = 0;

/// The vector field value used to identify the ACN packet as an ANSI E1.31 data packet.
/// This is used at the ACN packet layer not the E1.31 layer.
/// Value as defined in ANSI E1.31-2018 Appendix A: Defined Parameters (Normative).
pub const VECTOR_ROOT_E131_DATA: u32 = 0x0000_0004;

/// The vector field value used to identify the packet as an ANSI E1.31 universe discovery or synchronisation packet.
/// This is used at the ACN packet layer not the E1.31 layer.
/// Value as defined in ANSI E1.31-2018 Appendix A: Defined Parameters (Normative).
pub const VECTOR_ROOT_E131_EXTENDED: u32 = 0x0000_0008;

/// The E1.31 packet vector field value used to identify the E1.31 packet as a synchronisation packet.
/// This is used at the E1.31 layer and shouldn't be confused with the VECTOR values used for the ACN layer (i.e. VECTOR_ROOT_E131_DATA and VECTOR_ROOT_E131_EXTENDED).
/// Value as defined in ANSI E1.31-2018 Appendix A: Defined Parameters (Normative).
pub const VECTOR_E131_EXTENDED_SYNCHRONIZATION: u32 = 0x0000_0001;

/// The E1.31 packet vector field value used to identify the E1.31 packet as a universe discovery packet.
/// This is used at the E1.31 layer and shouldn't be confused with the VECTOR values used for the ACN layer (i.e. VECTOR_ROOT_E131_DATA and VECTOR_ROOT_E131_EXTENDED).
/// This VECTOR value is shared by E1.31 data packets, distinguished by the value of the ACN ROOT_VECTOR.
/// Value as defined in ANSI E1.31-2018 Appendix A: Defined Parameters (Normative).
pub const VECTOR_E131_EXTENDED_DISCOVERY: u32 = 0x0000_0002;

/// The E1.31 packet vector field value used to identify the E1.31 packet as a data packet.
/// This is used at the E1.31 layer and shouldn't be confused with the VECTOR values used for the ACN layer (i.e. VECTOR_ROOT_E131_DATA and VECTOR_ROOT_E131_EXTENDED).
/// This VECTOR value is shared by E1.31 universe discovery packets, distinguished by the value of the ACN ROOT_VECTOR.
/// Value as defined in ANSI E1.31-2018 Appendix A: Defined Parameters (Normative).
pub const VECTOR_E131_DATA_PACKET: u32 = 0x0000_0002;

/// Used at the DMP layer in E1.31 data packets to identify the packet as a set property message.
/// Not to be confused with the other VECTOR values used at the E1.31, ACN etc. layers.
/// Value as defined in ANSI E1.31-2018 Appendix A: Defined Parameters (Normative).
pub const VECTOR_DMP_SET_PROPERTY: u8 = 0x02;

/// Used at the universe discovery packet universe discovery layer to identify the packet as a universe discovery list of universes.
/// Not to be confused with the other VECTOR values used at the E1.31, ACN, DMP, etc. layers.
/// Value as defined in ANSI E1.31-2018 Appendix A: Defined Parameters (Normative).
pub const VECTOR_UNIVERSE_DISCOVERY_UNIVERSE_LIST: u32 = 0x0000_0001;

/// The port number used for the ACN family of protocols and therefore the sACN protocol.
/// As defined in ANSI E1.31-2018 Appendix A: Defined Parameters (Normative)
pub const ACN_SDT_MULTICAST_PORT: u16 = 5568;

/// The payload capacity for a sacn packet, for DMX data this would translate to 512 frames + a startcode byte.
pub const UNIVERSE_CHANNEL_CAPACITY: usize = 513;

/// The synchronisation universe/address of packets which do not require synchronisation as specified in section 6.2.4.1 of ANSI E1.31-2018.
pub const NO_SYNC_UNIVERSE: u16 = 0;

/// The timeout before data loss is assumed for an E131 source, as defined in Appendix A of ANSI E1.31-2018.
pub const E131_NETWORK_DATA_LOSS_TIMEOUT: Duration = Duration::from_millis(2500);

/// The timeout before a discovered source is assumed to be lost as defined in section 12.2 of ANSI E1.31-2018.
pub const UNIVERSE_DISCOVERY_SOURCE_TIMEOUT: Duration = E131_NETWORK_DATA_LOSS_TIMEOUT;

/// The maximum size a packet can have, specified in secion 6.1
/// 
/// The potentially biggest packet is a universe discovery packet with 
/// all 512 slots being used. 
pub const MAXIMUM_PACKET_SIZE: usize = 1144;
