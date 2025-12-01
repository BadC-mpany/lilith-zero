# Dockerfile for Sentinel Interceptor Service

FROM python:3.10-alpine

# Set working directory
WORKDIR /app

# Copy all project code into the container FIRST
COPY . .

# Install dependencies for the interceptor (use the specific requirements file)
RUN pip install --no-cache-dir -r sentinel_core/interceptor/python/requirements.txt

# Set PYTHONPATH to include all necessary src directories
# We use PYTHONPATH instead of package installation because the structure doesn't support editable installs
ENV PYTHONPATH="/app/sentinel_core/interceptor/python/src:/app/sentinel_core/mcp/src:/app/sentinel_core/shared/python/src:/app/sentinel_agent/src:/app/sentinel_sdk/src"

# Expose the port the service runs on
EXPOSE 8000

# Command to run the Interceptor service
# Use module path that matches PYTHONPATH structure
CMD ["uvicorn", "interceptor_service:app", "--host", "0.0.0.0", "--port", "8000"]
