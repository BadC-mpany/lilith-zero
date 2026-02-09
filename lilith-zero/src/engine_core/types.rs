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

//! Security Types.
//!
//! Strongly typed string wrappers to prevent accidental taint leakage.

use serde::{Deserialize, Serialize};

/// A string that has NOT been validated by the Policy Engine.
/// It cannot be dereferenced to &str immediately.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintedString(String);

/// A string that has been blessed by the Policy Engine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SafeString(String);

impl TaintedString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Explicitly mark as safe (requires Audit or Policy check)
    pub fn sanitize_unchecked(self) -> SafeString {
        SafeString(self.0)
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl SafeString {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for SafeString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
