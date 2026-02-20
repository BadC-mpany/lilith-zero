import asyncio
from typing import Any, Generator
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

from lilith_zero.client import Lilith
from lilith_zero.exceptions import (
    LilithConfigError,
    LilithConnectionError,
    LilithProcessError,
    PolicyViolationError,
)

# --- Fixtures ---


@pytest.fixture
def mock_subprocess() -> AsyncMock:
    """Provides a fully mocked asyncio subprocess."""
    process = AsyncMock()
    process.stdin = MagicMock()  # write() is not a coroutine
    process.stdin.drain = AsyncMock()
    process.stdout = AsyncMock()
    process.stderr = AsyncMock()
    process.terminate = MagicMock()
    process.kill = MagicMock()
    process.returncode = None
    return process


@pytest.fixture
def mock_env(mock_subprocess: AsyncMock) -> Generator[MagicMock, None, None]:
    """Sets up common mocks for Lilith environment."""
    with (
        patch(
            "asyncio.create_subprocess_exec", return_value=mock_subprocess
        ) as mock_exec,
        patch("lilith_zero.client._find_binary", return_value="/bin/lilith"),
        patch("os.path.exists", return_value=True),
    ):
        yield mock_exec


# --- Configuration Tests ---


@pytest.mark.asyncio
async def test_config_validation() -> None:
    """Verify strictly required configuration parameters."""
    with pytest.raises(LilithConfigError, match="Upstream command is required"):
        Lilith(upstream="")

    with patch(
        "lilith_zero.client._find_binary",
        side_effect=LilithConfigError("Binary not found"),
    ):
        with pytest.raises(LilithConfigError, match="Binary not found"):
            Lilith(upstream="echo tools")


# --- Lifecycle & Connection Tests ---


@pytest.mark.asyncio
async def test_lifecycle_success(
    mock_subprocess: AsyncMock, mock_env: MagicMock
) -> None:
    """Verify successful connection setup, handshake, and teardown."""
    # Mock Handshake Logic
    with (
        patch.object(Lilith, "_send_request", new_callable=AsyncMock) as mock_req,
        patch.object(
            Lilith, "_send_notification", new_callable=AsyncMock
        ) as mock_notify,
    ):
        # 1. Stderr provides session ID
        # 1. Stderr provides session ID
        mock_subprocess.stderr.readline.side_effect = [
            b"LILITH_ZERO_SESSION_ID=valid-sess-id\n",
            b"",
        ]
        # 2. Stdout active
        mock_subprocess.stdout.readline.side_effect = [
            b""
        ]  # EOF immediately for unit test

        async with Lilith("python server.py") as client:
            assert client.session_id == "valid-sess-id"
            mock_req.assert_any_call("initialize", ANY)
            mock_notify.assert_called_with("notifications/initialized", {})

        mock_subprocess.terminate.assert_called()


@pytest.mark.asyncio
async def test_connection_failure_immediate_exit(
    mock_subprocess: AsyncMock, mock_env: MagicMock
) -> None:
    """Verify LilithProcessError/ConnectionError when process exits immediately."""
    # Process exits with error code before session ID is captured
    mock_subprocess.returncode = 1

    # Mock stderr to return error message
    mock_subprocess.stderr.read.return_value = b"Process failed to start"
    mock_subprocess.stderr.readline.side_effect = [b""]

    with pytest.raises(
        (LilithConnectionError, LilithProcessError),
        match=r"Lilith process exited early",
    ):
        async with Lilith("echo"):
            pass


@pytest.mark.asyncio
async def test_connection_failure_timeout(
    mock_subprocess: AsyncMock, mock_env: MagicMock
) -> None:
    async def mock_wait_for_timeout(coro: Any, timeout: float | None = None) -> Any:
        if hasattr(coro, "close"):
            coro.close()
        raise asyncio.TimeoutError()

    # Mock wait_for to raise TimeoutError
    with patch("asyncio.wait_for", side_effect=mock_wait_for_timeout):
        # Stderr provides ID (so we pass the first check)
        mock_subprocess.stderr.readline.side_effect = [
            b"LILITH_ZERO_SESSION_ID=sess\n",
            b"",
        ]

        with pytest.raises(LilithConnectionError, match="Handshake timeout"):
            async with Lilith("echo"):
                pass


# --- Protocol & Policy Tests ---


@pytest.mark.asyncio
async def test_tool_call_dispatch(
    mock_subprocess: AsyncMock, mock_env: MagicMock
) -> None:
    """Verify correct dispatch of JSON-RPC responses."""
    client = Lilith("echo")
    client._session_id = "sess"  # Bypass connect

    response = {
        "jsonrpc": "2.0",
        "id": "fixed-id",
        "result": {"content": [{"text": "success"}]},
    }

    with patch("uuid.uuid4", return_value="fixed-id"):
        future: asyncio.Future[Any] = asyncio.Future()
        client._pending_requests["fixed-id"] = future

        client._dispatch_response(response)

        result = await future
        assert result == {"content": [{"text": "success"}]}


@pytest.mark.asyncio
async def test_policy_violation_parsing(
    mock_subprocess: AsyncMock, mock_env: MagicMock
) -> None:
    """Verify mapping of protocol errors to PolicyViolationError."""
    client = Lilith("echo")
    future: asyncio.Future[Any] = asyncio.Future()
    client._pending_requests["1"] = future

    error_response = {
        "jsonrpc": "2.0",
        "id": "1",
        "error": {
            "code": -32000,
            "message": "Policy Violation: Blocked by rule",
            "data": {"reason": "lethal trifecta"},
        },
    }

    client._dispatch_response(error_response)

    with pytest.raises(PolicyViolationError) as exc:
        await future

    assert "Blocked by rule" in str(exc.value)
    assert exc.value.policy_details["reason"] == "lethal trifecta"


@pytest.mark.asyncio
async def test_large_payload_handling(
    mock_subprocess: AsyncMock, mock_env: MagicMock
) -> None:
    """Verify SDK can serialize and dispatch large payloads."""
    client = Lilith("echo")
    client._session_id = "sess"

    # 5MB Payload
    huge_str = "A" * (5 * 1024 * 1024)
    asyncio.Future()

    # Mock send_request to ensure it actually tries to write to stdin
    # We can't use the real _send_request unless we mock stdin.write
    mock_subprocess.stdin.write = MagicMock()
    mock_subprocess.stdin.drain = AsyncMock()

    # We need to use the real _send_request logic for this test?
    # Or just verify `call_tool` doesn't choke?
    # `call_tool` calls `_send_request`.
    # Let's mock `_send_request` to verify it receives the huge string.

    with patch.object(Lilith, "_send_request", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = {"content": [{"text": "ok"}]}

        await client.call_tool("heavy_tool", {"data": huge_str})

        # Verify it was passed to send_request
        args, _ = mock_send.call_args
        # call_tool(name, args) calls _send_request(
        #     "tools/call", {"name": name, "arguments": args}
        # )
        assert args[0] == "tools/call"

        params = args[1]
        assert params["name"] == "heavy_tool"
        assert len(params["arguments"]["data"]) == 5 * 1024 * 1024


@pytest.mark.asyncio
async def test_concurrent_requests(
    mock_subprocess: AsyncMock, mock_env: MagicMock
) -> None:
    """Verify handling of multiple concurrent requests."""
    client = Lilith("echo")
    # Bypass connect to manipulate state directly
    client._session_id = "sess"
    client._process = mock_subprocess

    async def mock_send(method: str, params: dict[str, Any]) -> dict[str, Any]:
        # Simulate network delay to allow overlap
        await asyncio.sleep(0.01)
        # params structure is {'name': 'echo', 'arguments': {'i': ...}}
        val = params["arguments"]["i"]
        return {"content": [{"text": f"echo {val}"}]}

    with patch.object(client, "_send_request", side_effect=mock_send) as mock_req:
        tasks = []
        for i in range(50):
            tasks.append(client.call_tool("echo", {"i": i}))

        results = await asyncio.gather(*tasks)

        assert len(results) == 50
        assert len(mock_req.call_args_list) == 50
        # Verify order independence / data integrity
        texts = [r["content"][0]["text"] for r in results]
        assert set(texts) == {f"echo {i}" for i in range(50)}


@pytest.mark.asyncio
async def test_runtime_health_check(
    mock_subprocess: AsyncMock, mock_env: MagicMock
) -> None:
    """Verify detection of process death during runtime."""
    client = Lilith("echo")
    client._session_id = "sess"
    client._process = mock_subprocess

    # 1. Process is alive -> Success
    mock_subprocess.returncode = None
    with patch.object(client, "_send_request", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = {"tools": []}
        await client.list_tools()

    # 2. Process dies -> Failure
    mock_subprocess.returncode = -9  # Killed

    # We do NOT mock _send_request here, so it runs the real logic which checks
    # returncode
    # The SDK itself does NOT parse/strip them (that's user's job or verifying they
    # exist).
    # This test verifies that if middleware sends them, SDK passes them through
    # correctly.
    with pytest.raises(LilithConnectionError, match=r"Lilith process is not running"):
        await client.list_tools()


@pytest.mark.asyncio
async def test_spotlighting_delimiters(
    mock_subprocess: AsyncMock, mock_env: MagicMock
) -> None:
    """Verify detection and handling of spotlighting delimiters."""
    client = Lilith("echo")
    client._session_id = "sess"

    # Mock response containing spotlight delimiters
    # The SDK itself does NOT parse/strip them (that's user's job or verifying they
    # exist).
    # This test verifies that if middleware sends them, SDK passes them through
    # correctly.

    response_text = (
        "<<<LILITH_ZERO_DATA_START:123>>>secret<<<LILITH_ZERO_DATA_END:123>>>"
    )

    with patch.object(client, "_send_request", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = {"content": [{"text": response_text}]}

        result = await client.call_tool("read_secret", {})
        text = result["content"][0]["text"]

        assert "<<<LILITH_ZERO_DATA_START" in text
        assert "secret" in text
