//! Time utilities.
//!
//! This module provides the `now()` function for recording timestamps
//! in a consistent format across the project.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
