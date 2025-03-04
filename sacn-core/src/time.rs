use core::ops::{Add, Div, Mul, Sub};

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
        self.inner.elapsed().into()
    }

    pub fn duration_since(&self, earlier: Self) -> Duration {
        self.inner.duration_since(earlier.inner).into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Duration {
    #[cfg(feature = "std")]
    inner: core::time::Duration,
}

#[cfg(feature = "std")]
impl From<Duration> for core::time::Duration {
    fn from(duration: Duration) -> core::time::Duration {
        duration.inner
    }
}

#[cfg(feature = "std")]
impl From<core::time::Duration> for Duration {
    fn from(inner: core::time::Duration) -> Self {
        Self { inner }
    }
}

impl Add for Duration {
    type Output = Duration;

    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(rhs).expect("overflow when multiplying duration by scalar")
    }
}

impl Sub for Duration {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(rhs).expect("overflow when multiplying duration by scalar")
    }
}

impl Mul<u32> for Duration {
    type Output = Duration;

    fn mul(self, rhs: u32) -> Self::Output {
        self.checked_mul(rhs).expect("overflow when multiplying duration by scalar")
    }
}

impl Mul<Duration> for u32 {
    type Output = Duration;

    fn mul(self, rhs: Duration) -> Self::Output {
        rhs.mul(self)
    }
}

impl Div<u32> for Duration {
    type Output = Duration;

    fn div(self, rhs: u32) -> Self::Output {
        self.checked_div(rhs).expect("overflow when multiplying duration by scalar")
    }
}

impl Div<Duration> for u32 {
    type Output = Duration;

    fn div(self, rhs: Duration) -> Self::Output {
        rhs.div(self)
    }
}

impl Duration {
    #[cfg(feature = "std")]
    pub const fn new_std(secs: u64, nanos: u32) -> Self {
        let inner = core::time::Duration::new(secs, nanos);
        Self { inner }
    }

    pub const fn from_secs(secs: u64) -> Self {
        let inner = core::time::Duration::from_secs(secs);
        Self { inner }
    }

    pub const fn from_millis(millis: u64) -> Self {
        let inner = core::time::Duration::from_millis(millis);
        Self { inner }
    }

    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.inner.checked_add(rhs.inner) {
            Some(inner) => Some(Self { inner }),
            None => None,
        }
    }

    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.inner.checked_sub(rhs.inner) {
            Some(inner) => Some(Self { inner }),
            None => None,
        }
    }

    pub const fn checked_mul(self, rhs: u32) -> Option<Self> {
        match self.inner.checked_mul(rhs) {
            Some(inner) => Some(Self { inner }),
            None => None,
        }
    }

    pub const fn checked_div(self, rhs: u32) -> Option<Self> {
        match self.inner.checked_div(rhs) {
            Some(inner) => Some(Self { inner }),
            None => None,
        }
    }

    pub fn inner(self) -> core::time::Duration {
        self.inner
    }

    pub const fn as_millis(&self) -> u128 {
        self.inner.as_millis()
    }
}

pub fn sleep(dur: Duration) {
    #[cfg(feature = "std")]
    std::thread::sleep(dur.inner)
}
