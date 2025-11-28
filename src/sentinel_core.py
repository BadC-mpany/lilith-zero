import json
import hashlib
from typing import Dict, Any


class CryptoUtils:
    """
    Core cryptographic utilities shared between Interceptor and MCP Verifier.
    Ensures that both sides speak the exact same mathematical language regarding
    parameter binding.
    """

    @staticmethod
    def canonicalize(data: Dict[str, Any]) -> bytes:
        """
        RFC 8785 (JCS) style Canonicalization.
        CRITICAL: This ensures that {"a": 1, "b": 2} results in the EXACT same
        byte sequence as {"b": 2, "a": 1} for signing purposes.
        """
        if data is None:
            return b"{}"

        # 1. sort_keys=True: Enforce lexicographical ordering of keys
        # 2. separators=(',', ':'): Remove ALL whitespace (no spaces after commas/colons)
        # 3. ensure_ascii=False: Handle UTF-8 characters correctly without escaping
        return json.dumps(
            data,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False
        ).encode('utf-8')

    @staticmethod
    def hash_params(data: Dict[str, Any]) -> str:
        """
        Creates the 'p_hash' (Parameter Anchor).
        This hash binds the specific tool arguments to the cryptographic signature.
        """
        canonical_bytes = CryptoUtils.canonicalize(data)
        return hashlib.sha256(canonical_bytes).hexdigest()
