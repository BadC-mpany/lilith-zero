// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and


use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintedString(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SafeString(String);

impl TaintedString {
    pub fn new(s: String) -> Self {
        // Description: Executes the new logic.
        Self(s)
    }

    pub fn sanitize_unchecked(self) -> SafeString {
        // Description: Executes the sanitize_unchecked logic.
        SafeString(self.0)
    }

    pub fn into_inner(self) -> String {
        // Description: Executes the into_inner logic.
        self.0
    }
}

impl SafeString {
    pub fn as_str(&self) -> &str {
        // Description: Executes the as_str logic.
        &self.0
    }

    pub fn into_inner(self) -> String {
        // Description: Executes the into_inner logic.
        self.0
    }
}

impl AsRef<str> for SafeString {
    fn as_ref(&self) -> &str {
        // Description: Executes the as_ref logic.
        &self.0
    }
}
