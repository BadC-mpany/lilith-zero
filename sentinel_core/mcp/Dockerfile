# Dockerfile for Sentinel MCP Server

FROM python:3.10-alpine

# Set working directory
WORKDIR /app

# Copy specific requirements file first
COPY requirements.txt .

# Install dependencies for the MCP server
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project code into the container
COPY . .

# Install all local packages in editable mode
RUN pip install -e sentinel_core -e sentinel_agent -e sentinel_sdk

# Set PYTHONPATH to include the src directories of all packages for explicit module resolution
ENV PYTHONPATH="/app/sentinel_core/interceptor/python/src:/app/sentinel_core/mcp/src:/app/sentinel_core/shared/python/src:/app/sentinel_agent/src:/app/sentinel_sdk/src"

# Expose the port the service runs on
EXPOSE 9000

# Command to run the MCP service using its new path
CMD ["uvicorn", "sentinel_core.mcp.src.mcp_server:app", "--host", "0.0.0.0", "--port", "9000"]
