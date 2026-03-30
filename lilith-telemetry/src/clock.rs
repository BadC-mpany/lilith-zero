//! Hardware Timestamps and Drift Recalibration

use std::sync::atomic::{AtomicI64, Ordering};

/// The clock offset calculated via reference NTP sweeps every 10 seconds.
static CLOCK_DRIFT_OFFSET: AtomicI64 = AtomicI64::new(0);

/// Core primitive utilizing `RDTSC` (Read Time Stamp Counter)
/// This provides sub-nanosecond hardware event ordering deterministic mapping.
#[inline(always)]
pub fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}

/// Returns the synchronized hardware time compensating for network sweep drift.
#[inline(always)]
pub fn synchronized_time() -> u64 {
    let local = rdtsc();
    let offset = CLOCK_DRIFT_OFFSET.load(Ordering::Relaxed);
    // Apply pre-calculated Network Time Protocol jitter gap
    (local as i64 + offset) as u64
}

/// Adjust the central correlation clock drift based upon NTP-synchronization.
///
/// Correlating server-side logs natively requires resolving CPU crystal anomalies.
pub fn apply_ntp_recalibration(server_ns: u64, local_rdtsc: u64) {
    let diff = (server_ns as i64) - (local_rdtsc as i64);
    CLOCK_DRIFT_OFFSET.store(diff, Ordering::Relaxed);
}
