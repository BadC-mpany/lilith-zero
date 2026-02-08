use crate::core::constants::spotlight;
use rand::distr::Alphanumeric;
use rand::{Rng, RngExt};

pub struct SecurityEngine;

impl SecurityEngine {
    /// Applies 'Spotlighting' to the tool output.
    /// Wraps the content in randomized delimiters to prevent Prompt Injection.
    pub fn spotlight(content: &str) -> String {
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
