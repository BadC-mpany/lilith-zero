// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use serde::{Deserialize, Serialize};

/// Metadata carried alongside a tainted value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintMetadata {
    /// Taint tags active on this value (e.g. `"ACCESS_PRIVATE"`, `"UNTRUSTED_SOURCE"`).
    pub tags: Vec<String>,
}

/// A value of type `T` annotated with taint metadata.
///
/// Forces explicit acknowledgement that the inner value originated from an untrusted source.
/// Callers must call [`Tainted::into_inner_unchecked`] to unwrap, which is a visible, auditable
/// operation that signals intentional trust-boundary crossing.
#[derive(Debug, Clone)]
pub struct Tainted<T> {
    inner: T,
    metadata: TaintMetadata,
}

/// A value of type `T` that has been marked as clean (safe for trust-boundary crossing).
///
/// Created only via [`Clean::new_unchecked`]; the name signals that the caller is responsible
/// for ensuring the value is safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Clean<T> {
    inner: T,
}

impl<T> Tainted<T> {
    /// Wrap `inner` in a `Tainted` value with the given taint `tags`.
    pub fn new(inner: T, tags: Vec<String>) -> Self {
        Self {
            inner,
            metadata: TaintMetadata { tags },
        }
    }

    /// Borrow the taint metadata without consuming the wrapper.
    pub fn metadata(&self) -> &TaintMetadata {
        &self.metadata
    }

    /// Consume the wrapper and return the raw inner value, crossing the trust boundary.
    ///
    /// The `_unchecked` suffix signals that the caller is explicitly asserting the value
    /// is safe to use in a trusted context; this is an auditable escape hatch.
    pub fn into_inner_unchecked(self) -> T {
        self.inner
    }

    /// Borrow the inner value without consuming the wrapper.
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T> Clean<T> {
    /// Wrap `inner` in a `Clean` marker without performing any sanitisation.
    ///
    /// # Safety (logical)
    /// The caller asserts that `inner` is safe to cross the trust boundary.
    pub fn new_unchecked(inner: T) -> Self {
        Self { inner }
    }

    /// Consume the wrapper and return the raw inner value.
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
