use crate::universe::Universe;

pub trait Receiver {
    type Error;

    fn clear_sources(&mut self);

    fn clear_waiting_data(&mut self, universe: Universe);

    fn clear_all_waiting_data(&mut self);

    fn listen_on_universe(&mut self, universe: Universe);

    fn listen_on_universes(&mut self, universes: &[Universe]) {
        for universe in universes {
            self.listen_on_universe(*universe);
        }
    }

    fn stop_listening_on_universe(&mut self, universe: Universe);

    fn stop_listening_on_universes(&mut self, universes: &[Universe]) {
        for universe in universes {
            self.stop_listening_on_universe(*universe);
        }
    }

    fn is_listening_on_universe(&self, universe: Universe) -> bool;
}
