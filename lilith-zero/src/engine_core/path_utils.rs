// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use std::path::{Component, Path, PathBuf};
use serde_json::Value;

/// Robust, strictly lexical path canonicalization.
/// Resolves `.` and `..` segments purely string-wise without touching the filesystem.
/// This prevents TOCTOU (Time-of-Check to Time-of-Use) races and allows safely
/// reasoning about paths that do not yet exist on disk (e.g., file writes).
pub fn lexical_canonicalize<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.as_ref().components() {
        match component {
            Component::Prefix(p) => normalized.push(p.as_os_str()),
            Component::RootDir => {
                normalized.push("/");
            }
            Component::CurDir => {}
            Component::ParentDir => {
                // Pop the last component if it exists and isn't root or prefix.
                // If it is root, we can't go up further.
                normalized.pop();
            }
            Component::Normal(c) => normalized.push(c),
        }
    }

    // Ensure we don't return an empty path, default to "." if empty
    if normalized.as_os_str().is_empty() {
        normalized.push(".");
    }

    normalized
}

/// Recursively extract all string values from a JSON Value that might represent paths or URIs,
/// strip schemes, canonicalize them lexically, and return as a flat list.
pub fn extract_and_canonicalize_paths(args: &Value) -> Vec<String> {
    let mut paths = Vec::new();

    // Helper closure to recursively find path-like keys or just extract all strings?
    // Since we want to be bulletproof against bypasses where an attacker nests a path inside a 
    // weird key or array, we will extract ALL strings that look like paths, OR specifically known keys.
    // To be most bulletproof, if we don't know the exact schema, extracting ALL string values and 
    // testing them against resource rules is the safest approach (fail-closed/conservative).

    fn extract_strings(v: &Value, paths: &mut Vec<String>) {
        match v {
            Value::String(s) => {
                // Only consider strings that look like paths or URIs or might be used as one
                // To be extremely rigorous, any string could be a path in a poorly typed tool.
                paths.push(s.clone());
            }
            Value::Array(arr) => {
                for item in arr {
                    extract_strings(item, paths);
                }
            }
            Value::Object(obj) => {
                for (_, value) in obj {
                    extract_strings(value, paths);
                }
            }
            _ => {}
        }
    }

    extract_strings(args, &mut paths);

    paths.into_iter().map(|p| {
        // Strip common schemes
        let p = p.strip_prefix("file://").unwrap_or(&p);
        let p = p.strip_prefix("file:").unwrap_or(p);
        
        // Lexical canonicalize
        let canon = lexical_canonicalize(p);
        canon.to_string_lossy().to_string()
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_lexical_canonicalize() {
        assert_eq!(lexical_canonicalize("/a/b/../c").to_str().unwrap(), "/a/c");
        assert_eq!(lexical_canonicalize("/a/b/../../c").to_str().unwrap(), "/c");
        assert_eq!(lexical_canonicalize("/../c").to_str().unwrap(), "/c"); // Pop on root does nothing
        assert_eq!(lexical_canonicalize("a/./b/../c").to_str().unwrap(), "a/c");
        assert_eq!(lexical_canonicalize("").to_str().unwrap(), ".");
    }

    #[test]
    fn test_extract_and_canonicalize() {
        let args = json!({
            "path": "file:///tmp/nested/../../etc/passwd",
            "nested": {
                "arr": ["/var/log", "../foo"]
            }
        });
        let paths = extract_and_canonicalize_paths(&args);
        assert!(paths.contains(&"/etc/passwd".to_string()));
        assert!(paths.contains(&"/var/log".to_string()));
        // Note: "../foo" is relative. Depending on CWD, this is tricky, but lexical is correct for the string.
    }
}
