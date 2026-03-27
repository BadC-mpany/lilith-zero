// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintMetadata {
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Tainted<T> {
    inner: T,
    metadata: TaintMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Clean<T> {
    inner: T,
}

impl<T> Tainted<T> {
    pub fn new(inner: T, tags: Vec<String>) -> Self {
        // Description: Executes the new logic.
        Self {
            inner,
            metadata: TaintMetadata { tags },
        }
    }

    pub fn metadata(&self) -> &TaintMetadata {
        // Description: Executes the metadata logic.
        &self.metadata
    }

    pub fn into_inner(self) -> T {
        // Description: Executes the into_inner logic.
        self.inner
    }

    pub fn inner(&self) -> &T {
        // Description: Executes the inner logic.
        &self.inner
    }
}

impl<T> Clean<T> {
    pub fn new_unchecked(inner: T) -> Self {
        // Description: Executes the new_unchecked logic.
        Self { inner }
    }

    pub fn into_inner(self) -> T {
        // Description: Executes the into_inner logic.
        self.inner
    }
}

impl<T> std::ops::Deref for Clean<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // Description: Executes the deref logic.
        &self.inner
    }
}
