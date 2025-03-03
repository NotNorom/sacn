use core::net::SocketAddr;

use crate::{priority::Priority, universe::Universe};

/// A [Source] is s as type that can send sacn data
trait Source {
    type Error;

    fn send_data(
        &mut self,
        universes: &[Universe],
        data: &[u8],
        priority: Option<Priority>,
        dst_ip: Option<SocketAddr>,
        synchronisation_addr: Option<Universe>,
    ) -> Result<(), Self::Error>;
}

/// A [SynchronizedSource] is a type that can sends sacn data in the background, syncing it
trait SynchronizedSource {
    type Error;

    fn register_universe(&mut self, universes: Universe) -> Result<(), Self::Error>;
    fn register_universes(&mut self, universes: &[Universe]) -> Result<(), Self::Error> {
        for universe in universes {
            self.register_universe(*universe)?;
        }
        Ok(())
    }

    fn deregister_universe(&mut self, universes: Universe) -> Result<(), Self::Error>;
    fn deregister_universes(&mut self, universes: &[Universe]) -> Result<(), Self::Error> {
        for universe in universes {
            self.deregister_universe(*universe)?;
        }
        Ok(())
    }

    fn send_sync_packet(&mut self, universe: Universe, dst_ip: Option<SocketAddr>) -> Result<(), Self::Error>;

    fn terminate_stream(&mut self, universe: Universe, start_code: u8) -> Result<(), Self::Error>;
}
