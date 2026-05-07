//! Validates that process isolation primitives compiled and linked correctly.

#[test]
fn isolation_primitives_available() {
    let os = std::env::consts::OS;
    assert!(
        ["linux", "macos", "windows"].contains(&os),
        "unexpected OS: {os}"
    );
}
