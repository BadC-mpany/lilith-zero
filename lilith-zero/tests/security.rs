use lilith_zero::engine_core::crypto::CryptoSigner;

#[test]
fn test_session_id_integrity() {
    let signer = CryptoSigner::try_new().unwrap();
    let valid_id = signer.generate_session_id().unwrap();

    assert!(signer.validate_session_id(&valid_id));

    // Tamper with the UUID part
    let parts: Vec<&str> = valid_id.split('.').collect();
    let tampered = format!("{}.{}.{}", parts[0], "YWJj", parts[2]); // Replace UUID b64 with "abc"
    assert!(!signer.validate_session_id(&tampered));

    // Tamper with signature
    let tampered_sig = format!("{}.{}.{}", parts[0], parts[1], "bad_sig");
    assert!(!signer.validate_session_id(&tampered_sig));
}
