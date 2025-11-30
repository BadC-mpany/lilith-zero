# Quick Start Guide - Tool Classification & Import

## 🎯 What This Does

Automatically classifies tools into security classes (SENSITIVE_READ, CONSEQUENTIAL_WRITE, etc.) using AI, making it easy to:
1. Import tools from MCP stores
2. Add new custom tools
3. Scale your security rules

---

## ⚡ Quick Examples

**Prerequisites**: Add to your `.env` file:
```
OPENROUTER_API_KEY=sk-or-your-key-here
OPENROUTER_MODEL=gpt-4o-mini  # Recommended for reliability
```

**Note**: Free models may have reliability issues. Use `gpt-4o-mini` or `anthropic/claude-3-haiku` for best results.

### Example 1: Classify a Single Tool

```bash
# Classify (API key loaded from .env automatically)
python rule_maker/classifier.py "send_text" "Sends SMS to phone number"
```

Output:
```
Classification Result:
  Classes: CONSEQUENTIAL_WRITE
  Reasoning: Sends data to external SMS service (exfiltration risk)
```

### Example 2: Test the Classifier

```bash
# Just run it - uses .env automatically
python rule_maker/test_classifier.py
```

Tests 5 different tools to verify everything works.

### Example 3: Import MCP Tools

```bash
# Dry run (preview only)
python rule_maker/import_mcp_tools.py example_mcp_tools.json --dry-run

# Actually import
python rule_maker/import_mcp_tools.py example_mcp_tools.json
```

This will:
1. Read 6 example tools from JSON
2. Classify each using AI
3. Add to `tool_registry.yaml`

---

## 📋 MCP File Format

Your MCP tools file should look like this:

```json
{
  "tools": [
    {
      "name": "tool_name",
      "description": "What it does",
      "inputSchema": {
        "type": "object",
        "properties": {
          "arg": {"type": "string", "description": "..."}
        },
        "required": ["arg"]
      }
    }
  ]
}
```

See `example_mcp_tools.json` for a complete example.

---

## 🌐 Web Integration

### Backend (FastAPI)

```python
from fastapi import FastAPI
from rule_maker.classifier import classify_tool_with_llm
import os

app = FastAPI()

@app.post("/classify-tool")
async def classify(tool_name: str, description: str):
    result = classify_tool_with_llm(
        tool_name=tool_name,
        tool_description=description,
        api_key=os.getenv("OPENROUTER_API_KEY")
    )
    return {
        "classes": result["classes"],
        "reasoning": result["reasoning"]
    }
```

### Frontend (React)

```javascript
async function classifyTool(name, description) {
  const res = await fetch('/classify-tool', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      tool_name: name,
      description: description
    })
  });
  const data = await res.json();
  
  // Show user: data.classes and data.reasoning
  console.log(`Tool "${name}" classified as: ${data.classes.join(', ')}`);
  return data;
}
```

---

## 🛠️ Common Tasks

### Get Tools from MCP Store

1. Visit MCP store (e.g., https://mcp.so)
2. Export tools as JSON
3. Save to `my_tools.json`
4. Run: `python rule_maker/import_mcp_tools.py my_tools.json`

### Add Custom Tool Manually

Edit `rule_maker/tool_registry.yaml`:

```yaml
tools:
  my_new_tool:
    description: "What my tool does"
    classes: [SAFE_READ]  # Change as needed
    auto_classified: false
    args:
      my_arg:
        type: string
        description: "Argument description"
        required: true
```

### Review Auto-Classified Tools

After importing, review tools marked `auto_classified: true` in `tool_registry.yaml` and adjust if needed.

---

## 💡 Tips

1. **Start small**: Test with `example_mcp_tools.json` first
2. **Use dry-run**: Always `--dry-run` before actual import
3. **Review classifications**: AI is good but not perfect
4. **Better descriptions = better classification**: Detailed tool descriptions lead to more accurate classification

---

## 🐛 Troubleshooting

**"OPENROUTER_API_KEY not set in .env file"**

Add to your `.env` file in the project root:
```
OPENROUTER_API_KEY=sk-or-your-key-here
OPENROUTER_MODEL=gpt-4o-mini
```

**Import seems slow**
- Normal - each tool needs one LLM call (~1-2 seconds each)
- For 100 tools, expect ~2-3 minutes

**Classification wrong**
- Review and manually edit in `tool_registry.yaml`
- Try with more examples: `--max-examples 3`

---

For detailed documentation, see `README.md`

