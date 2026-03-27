// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine_core::constants::spotlight;
use rand::distr::Alphanumeric;
use rand::Rng;

pub struct SecurityEngine;

impl SecurityEngine {
    pub fn spotlight(content: &str) -> String {
        // Description: Executes the spotlight logic.
        let id: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(spotlight::RANDOM_ID_LENGTH)
            .map(char::from)
            .collect();

        format!(
            "{}{}{}\n{}\n{}{}{}",
            spotlight::DATA_START_PREFIX,
            id,
            spotlight::DELIMITER_SUFFIX,
            content,
            spotlight::DATA_END_PREFIX,
            id,
            spotlight::DELIMITER_SUFFIX
        )
    }
}
