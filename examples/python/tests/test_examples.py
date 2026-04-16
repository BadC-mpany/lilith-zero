"""
End-to-end integration tests for all Python SDK reference examples.

Each test spins up a real lilith-zero binary + an example MCP server and
exercises the full policy enforcement pipeline.  Tests are skipped
automatically when the binary is not available.

Run:
    export LILITH_ZERO_BINARY_PATH=/path/to/lilith-zero
    python -m pytest examples/python/tests -v
"""

import asyncio
import sys

import pytest
import pytest_asyncio  # noqa: F401 — required for @pytest.mark.asyncio fixture


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def upstream(server_path: str) -> str:
    return f"{sys.executable} -u {server_path}"


# ---------------------------------------------------------------------------
# minimal/ — static allow/deny
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_minimal_session_id_set(binary_path, minimal_policy, minimal_server):
    """Lilith assigns a non-empty HMAC session ID on connect."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(minimal_server), policy=minimal_policy) as lilith:
        assert lilith.session_id
        assert lilith.session_id.startswith("1.")


@pytest.mark.asyncio
async def test_minimal_tool_discovery(binary_path, minimal_policy, minimal_server):
    """list_tools returns the expected tool names."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(minimal_server), policy=minimal_policy) as lilith:
        tools = await lilith.list_tools()
        names = {t["name"] for t in tools}
        assert {"search_web", "get_time", "query_database"} == names


@pytest.mark.asyncio
async def test_minimal_allowed_tool_succeeds(binary_path, minimal_policy, minimal_server):
    """Allowed tools return a non-empty text result."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(minimal_server), policy=minimal_policy) as lilith:
        result = await lilith.call_tool("search_web", {"query": "test"})
        text = result["content"][0]["text"]
        assert text
        assert "test" in text.lower()


@pytest.mark.asyncio
async def test_minimal_denied_tool_raises(binary_path, minimal_policy, minimal_server):
    """Statically denied tool raises PolicyViolationError."""
    from lilith_zero import Lilith, PolicyViolationError

    async with Lilith(upstream=upstream(minimal_server), policy=minimal_policy) as lilith:
        with pytest.raises(PolicyViolationError):
            await lilith.call_tool("query_database", {"sql": "SELECT 1"})


@pytest.mark.asyncio
async def test_minimal_sequential_calls(binary_path, minimal_policy, minimal_server):
    """Multiple sequential allowed calls within one session all succeed."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(minimal_server), policy=minimal_policy) as lilith:
        r1 = await lilith.call_tool("search_web", {"query": "foo"})
        r2 = await lilith.call_tool("get_time", {})
        assert r1["content"][0]["text"]
        assert r2["content"][0]["text"]


# ---------------------------------------------------------------------------
# advanced/ — taint tracking, resource ACL, spans, audit logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_advanced_taint_source_allowed(binary_path, advanced_policy, advanced_server):
    """read_report succeeds and returns content."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        result = await lilith.call_tool("read_report", {"path": "test.txt"})
        assert result["content"][0]["text"]


@pytest.mark.asyncio
async def test_advanced_taint_sink_blocked(binary_path, advanced_policy, advanced_server):
    """post_to_slack is blocked after read_report taints the session."""
    from lilith_zero import Lilith, PolicyViolationError

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        await lilith.call_tool("read_report", {"path": "test.txt"})
        with pytest.raises(PolicyViolationError) as exc_info:
            await lilith.call_tool("post_to_slack", {"text": "hello"})
        assert "redact" in str(exc_info.value).lower() or "confidential" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_advanced_taint_custom_error_message(binary_path, advanced_policy, advanced_server):
    """The PolicyViolationError carries the custom message from policy.yaml."""
    from lilith_zero import Lilith, PolicyViolationError

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        await lilith.call_tool("read_report", {"path": "test.txt"})
        with pytest.raises(PolicyViolationError) as exc_info:
            await lilith.call_tool("post_to_slack", {"text": "hello"})
        assert "Cannot post confidential" in str(exc_info.value)


@pytest.mark.asyncio
async def test_advanced_taint_cleaner_re_allows_sink(binary_path, advanced_policy, advanced_server):
    """redact() removes the taint; post_to_slack succeeds afterwards."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        await lilith.call_tool("read_report", {"path": "test.txt"})
        await lilith.call_tool("redact", {"text": "INTERNAL revenue"})
        result = await lilith.call_tool("post_to_slack", {"text": "summary ready"})
        assert result["content"][0]["text"]


@pytest.mark.asyncio
async def test_advanced_neutral_tool_unaffected_by_taint(binary_path, advanced_policy, advanced_server):
    """summarize() is allowed regardless of CONFIDENTIAL taint."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        await lilith.call_tool("read_report", {"path": "test.txt"})
        result = await lilith.call_tool("summarize", {"text": "Revenue is $42M."})
        assert result["content"][0]["text"]


@pytest.mark.asyncio
async def test_advanced_conditional_block(binary_path, advanced_policy, advanced_server):
    """archive() is blocked without confirmed=true."""
    from lilith_zero import Lilith, PolicyViolationError

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        with pytest.raises(PolicyViolationError) as exc_info:
            await lilith.call_tool("archive", {"path": "q3.txt"})
        assert "confirmed" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_advanced_conditional_exception(binary_path, advanced_policy, advanced_server):
    """archive() is allowed when confirmed=true is passed."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        result = await lilith.call_tool("archive", {"path": "q3.txt", "confirmed": True})
        assert result["content"][0]["text"]


@pytest.mark.asyncio
async def test_advanced_resource_public_allowed(binary_path, advanced_policy, advanced_server):
    """Public resource reads succeed without adding taint."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        result = await lilith.read_resource("reports://public/q3_press_release.txt")
        text = result["contents"][0]["text"]
        assert text
        # After reading a public resource, post_to_slack must still be allowed.
        post_result = await lilith.call_tool("post_to_slack", {"text": "press release"})
        assert post_result["content"][0]["text"]


@pytest.mark.asyncio
async def test_advanced_resource_confidential_taints(binary_path, advanced_policy, advanced_server):
    """Reading a confidential resource re-taints the session, blocking the sink."""
    from lilith_zero import Lilith, PolicyViolationError

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        # Clean state — post is allowed.
        await lilith.call_tool("post_to_slack", {"text": "initial"})
        # Read confidential resource — injects taint.
        await lilith.read_resource("reports://confidential/q3_full_financials.txt")
        # Now sink must be blocked.
        with pytest.raises(PolicyViolationError):
            await lilith.call_tool("post_to_slack", {"text": "after confidential read"})


@pytest.mark.asyncio
async def test_advanced_spans(binary_path, advanced_policy, advanced_server):
    """Span context manager works and does not affect tool call outcomes."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        async with lilith.span("test-span"):
            result = await lilith.call_tool("summarize", {"text": "hello world"})
            assert result["content"][0]["text"]


@pytest.mark.asyncio
async def test_advanced_audit_logs_populated(binary_path, advanced_policy, advanced_server):
    """Audit log captures at least one SessionStart and one Decision event."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        await lilith.call_tool("read_report", {"path": "test.txt"})
        logs = await lilith.drain_audit_logs()

    assert len(logs) >= 2
    event_types = {e["event_type"] for e in logs}
    assert "SessionStart" in event_types
    assert "Decision" in event_types


@pytest.mark.asyncio
async def test_advanced_audit_deny_logged(binary_path, advanced_policy, advanced_server):
    """Denied calls appear in the audit log with decision=DENY."""
    from lilith_zero import Lilith, PolicyViolationError

    async with Lilith(upstream=upstream(advanced_server), policy=advanced_policy) as lilith:
        await lilith.call_tool("read_report", {"path": "test.txt"})
        with pytest.raises(PolicyViolationError):
            await lilith.call_tool("post_to_slack", {"text": "bad"})
        logs = await lilith.drain_audit_logs()

    deny_logs = [
        e for e in logs
        if e.get("details", {}).get("decision") == "DENY"
    ]
    assert deny_logs, "Expected at least one DENY entry in audit log"


# ---------------------------------------------------------------------------
# fastmcp/ — calculator, static deny, resource ACL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_calculator_allowed_tools(binary_path, calculator_policy, calculator_server):
    """add, multiply, sqrt all succeed."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(calculator_server), policy=calculator_policy) as lilith:
        r_add = await lilith.call_tool("add", {"a": 7, "b": 3})
        r_mul = await lilith.call_tool("multiply", {"a": 6, "b": 7})
        r_sqrt = await lilith.call_tool("sqrt", {"x": 144.0})

        assert r_add["content"][0]["text"].strip() == "10"
        assert r_mul["content"][0]["text"].strip() == "42"
        assert r_sqrt["content"][0]["text"].strip() == "12.0"


@pytest.mark.asyncio
async def test_calculator_static_deny(binary_path, calculator_policy, calculator_server):
    """divide is statically denied."""
    from lilith_zero import Lilith, PolicyViolationError

    async with Lilith(upstream=upstream(calculator_server), policy=calculator_policy) as lilith:
        with pytest.raises(PolicyViolationError):
            await lilith.call_tool("divide", {"a": 10, "b": 2})


@pytest.mark.asyncio
async def test_calculator_resource_acl(binary_path, calculator_policy, calculator_server):
    """constants://* resources are readable."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(calculator_server), policy=calculator_policy) as lilith:
        pi = await lilith.read_resource("constants://pi")
        assert "3.14" in pi["contents"][0]["text"]

        e_val = await lilith.read_resource("constants://e")
        assert "2.71" in e_val["contents"][0]["text"]


@pytest.mark.asyncio
async def test_calculator_tool_discovery(binary_path, calculator_policy, calculator_server):
    """list_tools and list_resources both return expected entries."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(calculator_server), policy=calculator_policy) as lilith:
        tools = {t["name"] for t in await lilith.list_tools()}
        resources = {r["uri"] for r in await lilith.list_resources()}

        assert {"add", "multiply", "divide", "sqrt"} == tools
        assert "constants://pi" in resources


# ---------------------------------------------------------------------------
# langchain/ — agentic loop, taint exfiltration guard, static deny
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agentic_safe_tool_always_allowed(binary_path, agentic_policy, agentic_server):
    """calculator is allowed before and after database access."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(agentic_server), policy=agentic_policy) as lilith:
        r1 = await lilith.call_tool("calculator", {"expression": "6 * 7"})
        assert r1["content"][0]["text"].strip() == "42"

        await lilith.call_tool("database", {"query": "users"})

        r2 = await lilith.call_tool("calculator", {"expression": "2 ** 8"})
        assert r2["content"][0]["text"].strip() == "256"


@pytest.mark.asyncio
async def test_agentic_exfiltration_blocked(binary_path, agentic_policy, agentic_server):
    """web_search is blocked once database access adds SENSITIVE_CONTEXT taint."""
    from lilith_zero import Lilith, PolicyViolationError

    async with Lilith(upstream=upstream(agentic_server), policy=agentic_policy) as lilith:
        # Pre-taint: database access
        await lilith.call_tool("database", {"query": "customer list"})
        # Exfiltration attempt must be blocked
        with pytest.raises(PolicyViolationError) as exc_info:
            await lilith.call_tool("web_search", {"query": "revenue data"})
        assert "exfiltration" in str(exc_info.value).lower() or "database" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_agentic_delete_statically_denied(binary_path, agentic_policy, agentic_server):
    """delete_record is permanently denied by static_rules."""
    from lilith_zero import Lilith, PolicyViolationError

    async with Lilith(upstream=upstream(agentic_server), policy=agentic_policy) as lilith:
        with pytest.raises(PolicyViolationError):
            await lilith.call_tool("delete_record", {"record_id": "42"})


@pytest.mark.asyncio
async def test_agentic_web_search_allowed_before_db(binary_path, agentic_policy, agentic_server):
    """web_search is allowed when no SENSITIVE_CONTEXT taint is active."""
    from lilith_zero import Lilith

    async with Lilith(upstream=upstream(agentic_server), policy=agentic_policy) as lilith:
        result = await lilith.call_tool("web_search", {"query": "public news"})
        assert result["content"][0]["text"]


@pytest.mark.asyncio
async def test_agentic_audit_captures_multi_turn(binary_path, agentic_policy, agentic_server):
    """Audit log covers all turns including the blocked exfiltration attempt."""
    from lilith_zero import Lilith, PolicyViolationError

    async with Lilith(upstream=upstream(agentic_server), policy=agentic_policy) as lilith:
        await lilith.call_tool("calculator", {"expression": "1+1"})
        await lilith.call_tool("database", {"query": "orders"})
        with pytest.raises(PolicyViolationError):
            await lilith.call_tool("web_search", {"query": "orders data"})
        with pytest.raises(PolicyViolationError):
            await lilith.call_tool("delete_record", {"record_id": "1"})
        logs = await lilith.drain_audit_logs()

    decisions = [e.get("details", {}).get("decision") for e in logs if "decision" in e.get("details", {})]
    assert "ALLOW" in decisions
    assert "ALLOW_WITH_SIDE_EFFECTS" in decisions
    assert "DENY" in decisions
