# Tool Classifier Integration Guide

## Quick Overview
The tool classifier is a Python function that uses an LLM to classify tools into security classes. This guide shows how to integrate it into your web app.

---

## Option 1: Direct Python Import (Same Machine)

### Setup
```bash
# Install dependencies
pip install openai pyyaml python-dotenv

# Set environment variables in .env
OPENROUTER_API_KEY=sk-or-your-key
OPENROUTER_MODEL=gpt-4o-mini
```

### Usage in Your Code
```python
import sys
sys.path.append('/path/to/sentinel')  # Add sentinel to path

from rule_maker.classifier import classify_tool_with_llm

# Classify a tool
result = classify_tool_with_llm(
    tool_name="send_email",
    tool_description="Sends an email to a recipient"
)

print(result["classes"])    # ["CONSEQUENTIAL_WRITE"]
print(result["reasoning"])  # "Sends data externally..."
```

---

## Option 2: REST API (Remote/Different Machine)

### 1. Start the Classifier API

Create `classifier_api.py` in the sentinel repo:

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from rule_maker.classifier import classify_tool_with_llm
import uvicorn

app = FastAPI()

class ToolClassifyRequest(BaseModel):
    tool_name: str
    tool_description: str
    max_examples_per_class: int = 2

class ToolClassifyResponse(BaseModel):
    classes: list[str]
    reasoning: str

@app.post("/classify", response_model=ToolClassifyResponse)
async def classify_tool(req: ToolClassifyRequest):
    try:
        result = classify_tool_with_llm(
            tool_name=req.tool_name,
            tool_description=req.tool_description,
            max_examples_per_class=req.max_examples_per_class
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
```

Run it:
```bash
cd /path/to/sentinel
python classifier_api.py
```

### 2. Call from Your Web App

**JavaScript/TypeScript:**
```javascript
async function classifyTool(toolName, description) {
  const response = await fetch('http://localhost:8001/classify', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      tool_name: toolName,
      tool_description: description,
      max_examples_per_class: 2
    })
  });
  
  const result = await response.json();
  return result;  // {classes: [...], reasoning: "..."}
}
```

**Python:**
```python
import requests

def classify_tool(tool_name, description):
    response = requests.post('http://localhost:8001/classify', json={
        'tool_name': tool_name,
        'tool_description': description,
        'max_examples_per_class': 2
    })
    return response.json()

result = classify_tool("send_sms", "Sends text messages")
print(result['classes'])
```

**cURL:**
```bash
curl -X POST http://localhost:8001/classify \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "send_email", "tool_description": "Sends emails"}'
```

---

## Response Format

```json
{
  "classes": ["CONSEQUENTIAL_WRITE"],
  "reasoning": "This tool sends data to an external email service, making it a potential data exfiltration vector."
}
```

**Possible Classes:**
- `SAFE_READ` - Public data retrieval
- `SENSITIVE_READ` - Private/confidential data access
- `SAFE_WRITE` - Local-only storage
- `CONSEQUENTIAL_WRITE` - External data transmission
- `UNSAFE_EXECUTE` - Code/command execution
- `HUMAN_VERIFY` - Destructive operations
- `SANITIZER` - PII removal

---

## Production Deployment

### Using Docker

Create `Dockerfile` in sentinel repo:
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install fastapi uvicorn openai pyyaml python-dotenv

ENV OPENROUTER_API_KEY=""
ENV OPENROUTER_MODEL="gpt-4o-mini"

CMD ["python", "classifier_api.py"]
```

Run:
```bash
docker build -t classifier-api .
docker run -p 8001:8001 -e OPENROUTER_API_KEY=sk-or-... classifier-api
```

### Environment Variables

Required:
- `OPENROUTER_API_KEY` - Your OpenRouter API key

Optional:
- `OPENROUTER_MODEL` - Model to use (default: `gpt-4o-mini`)

---

## Testing

```bash
# Health check
curl http://localhost:8001/health

# Classify a tool
curl -X POST http://localhost:8001/classify \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "test_tool",
    "tool_description": "Does something"
  }'
```

---

## Notes

- Classifier automatically loads from `.env` in sentinel repo
- Each classification takes ~1-2 seconds (LLM API call)
- Consider caching results for identical descriptions
- Rate limit to avoid API cost spikes
- Free models (Gemini) less reliable than `gpt-4o-mini`

