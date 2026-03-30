// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use serde::{Deserialize, Serialize};

/// A string that originates from an untrusted source and has not yet been sanitised.
///
/// The type system prevents accidental use of tainted strings as safe values;
/// callers must either sanitise via [`TaintedString::sanitize_unchecked`] or
/// extract the raw value via [`TaintedString::into_inner`] after explicit review.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintedString(String);

/// A string that has passed through a sanitisation step.
///
/// Created only via [`TaintedString::sanitize_unchecked`]; the name of that constructor
/// signals that the caller is responsible for ensuring the value is safe.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SafeString(String);

impl TaintedString {
    /// Wrap a raw string in a [`TaintedString`] to mark it as untrusted.
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Consume the tainted string and produce a [`SafeString`] without performing
    /// any sanitisation.
    ///
    /// # Safety (logical)
    /// The caller asserts that the string is safe to use in a trusted context.
    /// This is an escape hatch — prefer policy evaluation over direct calls.
    pub fn sanitize_unchecked(self) -> SafeString {
        SafeString(self.0)
    }

    /// Consume the tainted string and return the raw inner value.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl SafeString {
    /// Borrow the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the safe string and return the inner value.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for SafeString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
