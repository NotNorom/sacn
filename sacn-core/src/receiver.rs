use uuid::Uuid;

use crate::{
    dmx_data::DMXData,
    packet::{DataPacketFramingLayer, SynchronizationPacketFramingLayer, UniverseDiscoveryPacketFramingLayer},
    protocol::Transmit,
    time::Timestamp,
    universe_id::UniverseId,
};

pub trait Receiver {
    type Error;

    fn handle_data_packet(&mut self, when: Timestamp, cid: Uuid, frame: DataPacketFramingLayer) -> Result<(), Self::Error>;

    fn handle_sync_packet(&mut self, when: Timestamp, cid: Uuid, frame: SynchronizationPacketFramingLayer) -> Result<(), Self::Error>;

    fn handle_discovery_packet(
        &mut self,
        when: Timestamp,
        cid: Uuid,
        frame: UniverseDiscoveryPacketFramingLayer,
    ) -> Result<(), Self::Error>;

    fn poll_dmx_values(&mut self) -> Option<DMXData>;

    fn poll_transmit(&mut self) -> Option<Transmit>;

    fn handle_timeout(&mut self, now: Timestamp) -> Result<(), Self::Error>;

    fn clear_sources(&mut self);

    fn clear_waiting_data(&mut self, universe: &[UniverseId]);

    fn clear_all_waiting_data(&mut self);

    fn listen_on_universe(&mut self, universe: UniverseId);

    fn listen_on_universes(&mut self, universes: &[UniverseId]) {
        for universe in universes {
            self.listen_on_universe(*universe);
        }
    }

    fn stop_listening_on_universe(&mut self, universe: UniverseId);

    fn stop_listening_on_universes(&mut self, universes: &[UniverseId]) {
        for universe in universes {
            self.stop_listening_on_universe(*universe);
        }
    }

    fn is_listening_on_universe(&self, universe: UniverseId) -> bool;
}
