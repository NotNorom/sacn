//! This module deals with time types

use core::ops::{Add, Div, Mul, Sub};

#[cfg(not(feature = "std"))]
use fugit::Instant;

#[cfg(feature = "std")]
extern crate std;

/// Represents in instant in time.
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

    /// Returns a [Timestamp] corresponding to "now"
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

    /// Returns the amount of time elapsed since this [Timestamp].
    pub fn elapsed(&self) -> Duration {
        // let now = Self::now();
        // let duration = now.inner.checked_duration_since(self.inner).expect("eh whatever");
        // let ticks = duration.ticks();
        // std::println!("{ticks} seconds have passed...");
        // Duration::from_millis(ticks);
        self.inner.elapsed().into()
    }
    /// Returns the amount of time elapsed from another instant to this one, or zero duration if that instant is later than this one.
    pub fn duration_since(&self, earlier: Self) -> Duration {
        self.inner.duration_since(earlier.inner).into()
    }
}

/// A [Duration] type to represent a span of time, typically used for system timeouts.
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
    /// Creates a new [Duration] from the specified number of whole seconds and additional nanoseconds.
    /// If the number of nanoseconds is greater than 1 billion (the number of nanoseconds in a second), then it will carry over into the seconds provided.
    #[cfg(feature = "std")]
    pub const fn new_std(secs: u64, nanos: u32) -> Self {
        let inner = core::time::Duration::new(secs, nanos);
        Self { inner }
    }

    /// Creates a new [Duration] from the specified number of whole seconds.
    pub const fn from_secs(secs: u64) -> Self {
        let inner = core::time::Duration::from_secs(secs);
        Self { inner }
    }

    /// Creates a new [Duration] from the specified number of milliseconds.
    pub const fn from_millis(millis: u64) -> Self {
        let inner = core::time::Duration::from_millis(millis);
        Self { inner }
    }

    /// Checked [Duration] addition. Computes `self + other`, returning [None] if overflow occurred.
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.inner.checked_add(rhs.inner) {
            Some(inner) => Some(Self { inner }),
            None => None,
        }
    }

    /// Checked [Duration] subtraction. Computes `self - other`, returning [None] if the result would be negative or if overflow occurred.
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.inner.checked_sub(rhs.inner) {
            Some(inner) => Some(Self { inner }),
            None => None,
        }
    }

    /// Checked [Duration] multiplication. Computes `self * other`, returning [None] if overflow occurred.
    pub const fn checked_mul(self, rhs: u32) -> Option<Self> {
        match self.inner.checked_mul(rhs) {
            Some(inner) => Some(Self { inner }),
            None => None,
        }
    }

    /// Checked [Duration] division. Computes `self / other`, returning [None] if `other == 0``.
    pub const fn checked_div(self, rhs: u32) -> Option<Self> {
        match self.inner.checked_div(rhs) {
            Some(inner) => Some(Self { inner }),
            None => None,
        }
    }

    /// Return inner duration type
    #[cfg(feature = "std")]
    pub fn inner(self) -> core::time::Duration {
        self.inner
    }

    /// Returns the total number of whole milliseconds contained by this [Duration]
    pub const fn as_millis(&self) -> u128 {
        self.inner.as_millis()
    }
}

/// Puts the current thread to sleep for at least the specified amount of time.
pub fn sleep(dur: Duration) {
    #[cfg(feature = "std")]
    std::thread::sleep(dur.inner);
}
