use core::net::SocketAddr;

use crate::{priority::Priority, universe::UniverseId};

/// A [Source] is s as type that can send sacn data
trait Source {
    type Error;

    fn send_data(
        &mut self,
        universes: &[UniverseId],
        data: &[u8],
        priority: Option<Priority>,
        dst_ip: Option<SocketAddr>,
        synchronisation_addr: Option<UniverseId>,
    ) -> Result<(), Self::Error>;
}

/// A [SynchronizedSource] is a type that can sends sacn data in the background, syncing it
trait SynchronizedSource {
    type Error;

    fn register_universe(&mut self, universes: UniverseId) -> Result<(), Self::Error>;
    fn register_universes(&mut self, universes: &[UniverseId]) -> Result<(), Self::Error> {
        for universe in universes {
            self.register_universe(*universe)?;
        }
        Ok(())
    }

    fn deregister_universe(&mut self, universes: UniverseId) -> Result<(), Self::Error>;
    fn deregister_universes(&mut self, universes: &[UniverseId]) -> Result<(), Self::Error> {
        for universe in universes {
            self.deregister_universe(*universe)?;
        }
        Ok(())
    }

    fn send_sync_packet(&mut self, universe: UniverseId, dst_ip: Option<SocketAddr>) -> Result<(), Self::Error>;

    fn terminate_stream(&mut self, universe: UniverseId, start_code: u8) -> Result<(), Self::Error>;
}
