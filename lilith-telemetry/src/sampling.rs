//! Adaptive Sampling Configuration Layer.

use super::dispatcher::EventLevel;

/// Processes whether a span triggers active persistence logic based entirely
/// upon its trace category (Deny vs Allow).
#[inline(always)]
pub fn should_sample(_level: EventLevel) -> bool {
    true // Log 100% of events for the demo
}

// fast_rand removed as it's unused in 100% sampling mode
