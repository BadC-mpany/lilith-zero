// Copyright 2026 BadCompany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Type-System enforcement for Taint Tracking.
//!
//! This module defines wrapper types to strictly separate "Tainted" data
//! (potentially malicious or sensitive) from "Clean" data (verified by policy).

use serde::{Deserialize, Serialize};

/// Metadata regarding the taint of an object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintMetadata {
    pub tags: Vec<String>,
}

/// A wrapper around data that bears taint information.
/// It cannot be accessed directly as T without sanitization.
#[derive(Debug, Clone)]
pub struct Tainted<T> {
    inner: T,
    metadata: TaintMetadata,
}

/// A wrapper around data that has been verified to be safe for a specific sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Clean<T> {
    inner: T,
}

impl<T> Tainted<T> {
    pub fn new(inner: T, tags: Vec<String>) -> Self {
        Self {
            inner,
            metadata: TaintMetadata { tags },
        }
    }

    pub fn metadata(&self) -> &TaintMetadata {
        &self.metadata
    }

    /// Dangerous! Only use if you are implementing a Sanitizer.
    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T> Clean<T> {
    /// Create a Clean wrapper. This should ONLY be called by the Policy Engine.
    pub fn new_unchecked(inner: T) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> std::ops::Deref for Clean<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
