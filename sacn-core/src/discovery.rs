//! This module deals with types relevant to universe discovery

extern crate alloc;
use alloc::boxed::Box;

use heapless::Vec;

use crate::{e131_definitions::DISCOVERY_UNI_PER_PAGE, source_name::SourceName, time::Timestamp, universe_id::UniverseId};

/// Represents an sACN source/sender on the network that has been discovered by this sACN receiver by receiving universe discovery packets.
#[derive(Clone, Debug)]
pub struct DiscoveredSacnSource<const PAGE_CAPACITY: usize = { u8::MAX as usize }> {
    /// The name of the source, no protocol guarantee this will be unique but if it isn't then universe discovery may not work correctly.
    pub name: SourceName,

    /// The time at which the discovered source was last updated / a discovery packet was received by the source.
    pub last_updated: Timestamp,

    /// The pages that have been sent so far by this source when enumerating the universes it is currently sending on.
    pub pages: Box<Vec<UniversePage, PAGE_CAPACITY>>,

    // pub universes: CompactUniverseList,
    /// The last page that will be sent by this source.
    pub last_page: u8,
}

impl DiscoveredSacnSource {
    /// Returns true if all the pages sent by this DiscoveredSacnSource have been received.
    ///
    /// This is based on each page containing a last-page value which indicates the number of the last page expected.
    pub fn has_all_pages(&mut self) -> bool {
        // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/sorting.html (31/12/2019)
        self.pages.sort_by(|a, b| a.page.cmp(&b.page));
        for i in 0..=self.last_page {
            if self.pages[i as usize].page != i {
                return false;
            }
        }

        true
    }

    /// Returns all the universes being send by this SacnSource as discovered through the universe discovery mechanism.
    ///
    /// Intentionally abstracts over the underlying concept of pages as this is purely an E1.31 Universe Discovery concept and is otherwise transparent.
    pub fn get_all_universes(&self) -> Vec<UniverseId, { u8::MAX as usize * DISCOVERY_UNI_PER_PAGE as usize }> {
        let mut uni = Vec::new();
        for p in &*self.pages {
            uni.extend_from_slice(&p.universes).unwrap();
        }
        uni
    }

    /// Removes the given universe from the list of universes being sent by this discovered source.
    pub fn terminate_universe(&mut self, universe: UniverseId) {
        for p in &mut *self.pages {
            p.universes.retain(|x| *x != universe);
        }
    }
}

/// Universe discovery packets are broken down into pages to allow sending a large list of universes, each page contains a list of universes and
/// which page it is. The receiver then puts the pages together to get the complete list of universes that the discovered source is sending on.
///
/// The concept of pages is intentionally hidden from the end-user of the library as they are a way of fragmenting large discovery
/// universe lists so that they can work over the network and don't play any part out-side of the protocol.
#[derive(Eq, Ord, PartialEq, PartialOrd, Clone, Debug)]
pub struct UniversePage {
    /// The page number of this page.
    pub page: u8,

    /// The universes that the source is transmitting that are on this page, this may or may-not be a complete list of all universes being sent
    /// depending on if there are more pages.
    pub universes: Vec<UniverseId, DISCOVERY_UNI_PER_PAGE>,
}
