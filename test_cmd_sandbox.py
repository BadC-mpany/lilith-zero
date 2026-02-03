import asyncio
import os
import sys

sys.path.append(os.path.abspath("sentinel_sdk/src"))
from sentinel_sdk import Sentinel

async def test():
    print("Testing minimal CMD sandbox...")
    async with Sentinel(
        upstream_cmd="cmd.exe",
        upstream_args=["/c", "echo SANDBOX_OK"],
        binary_path=os.path.abspath("sentinel/target/debug/sentinel.exe"),
        skip_handshake=True
    ) as sentinel:
        await asyncio.sleep(3)
        output = "\n".join(sentinel.stdout_lines + sentinel.stderr_lines)
        print(f"Output:\n{output}")
        if "SANDBOX_OK" in output:
            print("SUCCESS")
        else:
            print("FAILED")

if __name__ == "__main__":
    asyncio.run(test())
