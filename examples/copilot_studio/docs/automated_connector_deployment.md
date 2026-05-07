# Automated Custom Connector Deployment

This guide explains how to use the `deploy_connectors.py` script to automate the deployment of multiple tools as standalone Microsoft Power Platform Custom Connectors.

## Overview

When building complex agentic integrations in Copilot Studio, it is common to have a "master" API definition containing dozens of tools. Manually creating a Custom Connector for each tool is time-consuming and error-prone. 

The `deploy_connectors.py` script automates this by:
1.  **Splitting** a master OpenAPI v2 file into individual JSON files (one per operation).
2.  **Initializing** the required Power Platform "NoAuth" scaffolding.
3.  **Deploying** each tool as a standalone Custom Connector to a target environment.

## Prerequisites

- **Power Platform CLI (pac)** installed and authenticated (`pac auth login`).
- **Python 3.x** installed.
- A master OpenAPI v2 file (e.g., `enterprise-integrations.json`).

## How to Use

### 1. Configure the Target Environment
Open `deploy_connectors.py` and ensure the `environment_id` matches your target Power Platform environment (e.g., your Default Directory or a Developer Environment).

```python
# Target Environment: Default Directory
environment_id = "98e2f7d2-c1d3-4410-b87f-2396f157975f"
```

### 2. Run the Script
Execute the script from the terminal:

```bash
python3 examples/copilot_studio/deploy_connectors.py
```

### 3. Review the Results
The script will output a summary table. Tools will be marked as:
- **Created**: Successfully deployed for the first time.
- **Already Present**: The connector logical name already exists in the environment (skipped to avoid conflicts).
- **Failed**: An error occurred (e.g., connection glitch, malformed JSON).

## Operation Details

### Splitting Logic
The script iterates through every path and method in the master JSON. It generates a valid OpenAPI v2 file for each, preserving the `host`, `basePath`, and `schemes`. The `info.title` is set to the operation's `summary`.

### Scaffolding
The tool uses `pac connector init --connection-template "NoAuth"` to generate an `apiProperties.json` file. This ensures the connectors are created with the "No Authentication" type, which is ideal for middleware-protected tools where authentication is handled at the gateway layer (e.g., Lilith Zero).

### Deployment
Deployment is handled via `pac connector create`. The script includes a retry mechanism for transient "Failed to connect to Dataverse" errors, which can occasionally occur during batch operations.

## Post-Deployment: Initializing Connections

After the connectors are deployed, you must perform a one-time "initialization" in the Copilot Studio UI:

1.  Open **Copilot Studio** and navigate to your bot.
2.  Go to **Tools** -> **Add Tool**.
3.  Search for your connector (e.g., "Send Email").
4.  Click **Create Connection**. Since it is a `NoAuth` connector, this is a single-click process.
5.  The tool is now available for the agent's planner.

## Maintenance

If you add new tools to the `enterprise-integrations.json` file, simply run the script again. It will skip existing connectors and only deploy the new additions.
