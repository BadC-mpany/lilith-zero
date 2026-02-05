
import asyncio
import unittest
import sys
import os
from unittest.mock import MagicMock, patch, AsyncMock

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_sdk import Sentinel, SentinelError, SentinelConfigError

class TestSentinelHermetic(unittest.IsolatedAsyncioTestCase):
    """
    Hermetic Unit Tests for Sentinel Client.
    These tests do NOT require the Rust binary or an upstream process.
    They verify internal logic, state management, and error handling.
    """

    def test_init_config_errors(self):
        """Test configuration validation in __init__."""
        # Missing upstream
        with self.assertRaisesRegex(SentinelConfigError, "Upstream command is required"):
            Sentinel(upstream="")
            
        with self.assertRaisesRegex(SentinelConfigError, "Upstream command is required"):
            Sentinel(upstream=None)

    @patch("sentinel_sdk.sentinel_sdk.client.os.path.exists")
    @patch("sentinel_sdk.sentinel_sdk.client._find_binary")
    def test_binary_path_resolution(self, mock_find, mock_exists):
        """Test binary path resolution logic."""
        # Case 1: Binary provided and exists
        mock_exists.return_value = True
        s = Sentinel(upstream="python tool.py", binary="/custom/sentinel")
        
        expected = os.path.abspath("/custom/sentinel")
        self.assertEqual(os.path.normcase(s._binary_path), os.path.normcase(expected))
        
        # Case 2: Auto-discovery (mocked)
        mock_find.return_value = "/found/sentinel"
        s = Sentinel(upstream="python tool.py")
        expected_found = os.path.abspath("/found/sentinel")
        self.assertEqual(os.path.normcase(s._binary_path), os.path.normcase(expected_found))

    @patch("sentinel_sdk.sentinel_sdk.client.os.path.exists")
    @patch("asyncio.create_subprocess_exec")
    async def test_connect_spawn_error(self, mock_exec, mock_exists):
        """Test failure to spawn subprocess."""
        mock_exists.return_value = True
        mock_exec.side_effect = OSError("Exec format error")
        
        s = Sentinel(upstream="python tool.py", binary="/bin/sentinel")
        
        with self.assertRaisesRegex(Exception, "Failed to spawn Sentinel"):
           await s._connect()

    def test_build_command(self):
        """Test command line construction."""
        with patch("sentinel_sdk.sentinel_sdk.client.os.path.exists", return_value=True):
            s = Sentinel(upstream="python tool.py --flag", binary="/bin/sentinel", policy="/etc/policy.yaml")
            
            cmd = s._build_command()
            expected_bin = os.path.abspath("/bin/sentinel")
            expected_policy = os.path.abspath("/etc/policy.yaml")
            
            self.assertEqual(os.path.normcase(cmd[0]), os.path.normcase(expected_bin))
            self.assertIn("--policy", cmd)
            # Find the policy path in args and verify it matches normalized expectation
            policy_arg = next(arg for arg in cmd if arg.endswith("policy.yaml"))
            self.assertEqual(os.path.normcase(policy_arg), os.path.normcase(expected_policy))
            
            self.assertIn("--upstream-cmd", cmd)
            self.assertIn("python", cmd)
            
            self.assertIn("--", cmd)
            self.assertIn("tool.py", cmd)
            self.assertIn("--flag", cmd)

if __name__ == "__main__":
    unittest.main()
