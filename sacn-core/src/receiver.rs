use uuid::Uuid;

use crate::{
    dmx_data::DMXData,
    packet::{DataPacketFramingLayer, SynchronizationPacketFramingLayer, UniverseDiscoveryPacketFramingLayer},
    protocol::Transmit,
    time::Timestamp,
    universe::UniverseId,
};

pub trait Receiver {
    type Error;

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
