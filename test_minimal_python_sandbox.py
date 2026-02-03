import asyncio
import os
import sys
import logging

sys.path.append(os.path.abspath("sentinel_sdk/src"))
from sentinel_sdk import Sentinel

async def test():
    logging.basicConfig(level=logging.DEBUG)
    print("Testing minimal python sandbox...")
    # Use system python to avoid venv complexities for a moment
    async with Sentinel(
        upstream_cmd=sys.executable,
        upstream_args=["-c", "print('SANDBOX_OK')"],
        binary_path=os.path.abspath("sentinel/target/debug/sentinel.exe"),
        skip_handshake=True
    ) as sentinel:
        await asyncio.sleep(5)
        output = "\n".join(sentinel.stdout_lines + sentinel.stderr_lines)
        print(f"Output:\n{output}")
        if "SANDBOX_OK" in output:
            print("SUCCESS")
        else:
            print("FAILED")

if __name__ == "__main__":
    asyncio.run(test())
