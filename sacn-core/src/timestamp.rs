use core::time::Duration;

#[cfg(not(feature = "std"))]
use fugit::Instant;

#[cfg(feature = "std")]
extern crate std;

#[derive(Debug, Clone, Copy)]
pub struct Timestamp {
    /// The duration in seconds = NOM / DENOM * ticks
    ///
    /// So e.g. 1 / 1000 means 1000 ticks = 1 second
    // inner: Instant<u64, { Self::NOM }, { Self::DENOM }>,
    #[cfg(feature = "std")]
    inner: std::time::Instant,
}

impl Timestamp {
    #[cfg(not(feature = "std"))]
    const NOM: u32 = 1;
    #[cfg(not(feature = "std"))]
    const DENOM: u32 = 1;

    pub fn now() -> Self {
        // let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        // let secs = now.as_secs();
        // std::println!("{secs:0b}");
        // let milli_secs = now.subsec_millis();

        // let ticks = secs * 1000 + milli_secs as u64;

        // let inner = Instant::<u64, { Self::NOM }, { Self::DENOM }>::from_ticks(ticks);

        let inner = std::time::Instant::now();
        Self { inner }
    }

    pub fn elapsed(&self) -> Duration {
        // let now = Self::now();
        // let duration = now.inner.checked_duration_since(self.inner).expect("eh whatever");
        // let ticks = duration.ticks();
        // std::println!("{ticks} seconds have passed...");
        // Duration::from_millis(ticks);
        self.inner.elapsed()
    }
}
