# Red Teaming & Verification

Lilith Zero includes a comprehensive suite of **Red Team** tests to verify that your policies are actually enforcing security.

## The Red Team Suite

Located in `sdk/tests/red_team/`, this Python test suite simulates a compromised agent attempting the **Lethal Trifecta**.

### Running attacks against your Policy

You can run these tests against your specific `policy.yaml` to see if it holds up.

```bash
# Install the SDK with test dependencies
uv pip install -e "sdk[test]"

# Run the attack suite
pytest sdk/tests/red_team/test_attacks.py
```

## Attack Vectors Tested

The suite attempts the following exploits:

1.  **File Read**: Attempts to read `/etc/passwd` (Linux) or `C:\Windows\win.ini`.
2.  **File Write**: Attempts to overwrite `policy.yaml` or creating persistence.
3.  **Network Connect**: Attempts `curl`, `wget`, or Python `requests` to external IPs.
4.  **env leakage**: Attempts to print environment variables (`printenv`).
5.  **Fork Bomb**: Attempts to crash the host via resource exhaustion (mitigated by Job Objects).

## Interpretation of Results

-   **PASS**: The attack failed (was blocked by Lilith Zero). This is Good.
-   **FAIL**: The attack succeeded. Your policy is too permissive!

!!! tip "Continuous Verification"
    We recommend adding this Red Team step to your CI/CD pipeline. Every time you update `policy.yaml`, run the attacks to ensure no regressions.
