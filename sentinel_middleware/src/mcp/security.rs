use rand::{distributions::Alphanumeric, Rng};

use crate::constants::spotlight;

pub struct SecurityEngine;

impl SecurityEngine {
    /// Applies 'Spotlighting' to the tool output.
    /// Wraps the content in randomized delimiters to prevent Prompt Injection.
    /// This makes it explicit to the LLM where the tool output starts and ends,
    /// preventing "instruction injection" attacks where the tool output mimics user instructions.
    pub fn spotlight(content: &str) -> String {
        let id: String = rand::thread_rng()
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
