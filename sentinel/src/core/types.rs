
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
