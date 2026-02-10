# Quickstart: Hello World

Let's build a secure "Hello World" agent using Lilith Zero. We will create a simple Python script that uses `curl` to fetch a webpage, and we will protect it with a policy.

## 1. Create the Agent

Create a file named `agent.py`:

```python
import subprocess
import sys

# This is an "unsafe" agent that tries to access the internet
def main():
    print("Agent: I am going to try and fetch google.com...")
    try:
        result = subprocess.run(
            ["curl", "-I", "https://www.google.com"], 
            capture_output=True, 
            text=True
        )
        print(f"Agent: Success! Output:\n{result.stdout}")
    except FileNotFoundError:
        print("Agent: Failed to run curl.")

if __name__ == "__main__":
    main()
```

## 2. Define the Policy

Create a file named `policies.yaml` that **allows** `python` but **blocks** network access by default.

```yaml
version: "1.0"
policies:
  - name: "Allow Python Agent"
    command: "python"
    args: [".*"]
    isolation:
      network: false  # <--- BLOCK THE INTERNET
      filesystem: "readonly"
```

## 3. Run with Lilith Zero

Now, run the agent wrapped in the middleware:

```bash
lilith-zero --policy policies.yaml -- python agent.py
```

### Expected Output

You should see the agent start, but the `curl` command inside it will fail (or hang/timeout depending on how `curl` handles network errors) because Lilith Zero blocked the network access at the process level.

If you check the audit log, you'll see the violation.

## 4. Allow Access

Edit `policies.yaml` to allow network:

```yaml
    isolation:
      network: true # <--- ALLOW THE INTERNET
```

Run it again, and it should succeed!

## Next Steps

-   Learn how to [Write granular policies](../guides/writing-policies.md).
-   Explore the [Architecture](../concepts/architecture.md).
