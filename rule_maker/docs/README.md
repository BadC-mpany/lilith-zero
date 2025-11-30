# Rule Maker - Tool Classification & Import System

This directory contains utilities for classifying tools into security classes and importing tools from MCP (Model Context Protocol) stores.

## 📁 Directory Structure

- `taint_classes.json` - Security class definitions with classification rules
- `tool_registry.yaml` - Registered tools with their security classifications
- `rule_templates.yaml` - Pre-built rule templates for common attack patterns
- `classifier.py` - LLM-based tool classification system
- `import_mcp_tools.py` - Bulk import tools from MCP format
- `example_mcp_tools.json` - Example MCP tools file format

---

## 🔍 Tool Classification System

### Overview

The classifier uses an LLM judge to automatically classify tools into security classes based on their name and description. It leverages:
- Security class definitions from `taint_classes.json`
- Example tools from existing `tool_registry.yaml` entries
- Few-shot learning with configurable examples per class

### Security Classes

1. **SAFE_READ** - Public, non-sensitive data retrieval
2. **SENSITIVE_READ** - Private data, secrets, confidential info (Taint Source)
3. **SAFE_WRITE** - Local-only, ephemeral storage
4. **CONSEQUENTIAL_WRITE** - External sinks, persistent state changes (Taint Sink)
5. **UNSAFE_EXECUTE** - Arbitrary code/command execution
6. **HUMAN_VERIFY** - Destructive, irreversible, high-value actions
7. **SANITIZER** - PII/secret removal (Taint Cleaner)

---

## 🚀 Usage

**Setup**: Add to your `.env` file:
```
OPENROUTER_API_KEY=sk-or-your-key-here
OPENROUTER_MODEL=gpt-4o-mini  # Recommended: gpt-4o-mini, openai/gpt-4o-mini, anthropic/claude-3-haiku
```

**Note**: Free models (like `google/gemini-2.0-flash-exp:free`) may have reliability issues with JSON output. For production, use `gpt-4o-mini` or better.

### 1. Classify a Single Tool

```bash
# Classify a tool (uses .env automatically)
python rule_maker/classifier.py "send_sms" "Sends SMS to a phone number"
```

Output:
```
Classifying tool: send_sms
Description: Sends SMS to a phone number

Classification Result:
  Classes: CONSEQUENTIAL_WRITE
  Reasoning: This tool sends data to an external service (SMS gateway), making it a data exfiltration risk.
```

### 2. Use in Python Code

```python
from rule_maker.classifier import classify_tool_with_llm

# Get detailed classification
result = classify_tool_with_llm(
    tool_name="send_email",
    tool_description="Sends an email to a recipient",
    max_examples_per_class=2,  # Show 2 examples per class
    api_key="your-api-key"
)

print(result["classes"])    # ['CONSEQUENTIAL_WRITE']
print(result["reasoning"])  # "Sends data externally..."

# Or get just the classes
from rule_maker.classifier import classify_tool

classes = classify_tool(
    "read_config",
    "Reads application configuration file",
    api_key="your-api-key"
)
# classes = ['SENSITIVE_READ']
```

### 3. Web Integration

For web apps, use the classifier function with user-provided tools:

```python
# Backend API endpoint example
@app.post("/classify-tool")
def classify_tool_endpoint(tool_name: str, tool_description: str):
    try:
        result = classify_tool_with_llm(
            tool_name=tool_name,
            tool_description=tool_description,
            api_key=os.getenv("OPENROUTER_API_KEY")
        )
        return {
            "success": True,
            "classes": result["classes"],
            "reasoning": result["reasoning"]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
```

Frontend can then display classification for user review before saving.

---

## 📥 Importing MCP Tools

### MCP Format

Tools should be in MCP (Model Context Protocol) JSON format:

```json
{
  "tools": [
    {
      "name": "tool_name",
      "description": "What the tool does",
      "inputSchema": {
        "type": "object",
        "properties": {
          "arg_name": {
            "type": "string",
            "description": "Argument description"
          }
        },
        "required": ["arg_name"]
      }
    }
  ]
}
```

### Getting MCP Tools

**Option 1: From MCP Store**
1. Browse tools at https://mcp.so or your MCP provider
2. Export tools as JSON (use MCP client or API)
3. Save to a `.json` file

**Option 2: From MCP Server**
```bash
# If you have an MCP server running
curl http://localhost:3000/tools > my_tools.json
```

**Option 3: Manual Creation**
Use the format in `example_mcp_tools.json`

### Import Tools

```bash
# Dry run - see what would be added (uses .env for API key)
python rule_maker/import_mcp_tools.py my_tools.json --dry-run

# Actually import
python rule_maker/import_mcp_tools.py my_tools.json

# Custom options
python rule_maker/import_mcp_tools.py my_tools.json --model gpt-4 --max-examples 3 --registry custom_registry.yaml
```

### Import Process

For each tool in the MCP file:
1. ✅ Check if tool already exists in registry (skip if yes)
2. 🔍 Classify tool using LLM judge
3. 🔄 Convert MCP `inputSchema` to our YAML args format
4. ➕ Add to `tool_registry.yaml` with `auto_classified: true`

### Example Import Session

```
================================================================================
MCP TOOLS IMPORT & CLASSIFICATION
================================================================================

📁 MCP File: example_mcp_tools.json
📋 Registry: rule_maker/tool_registry.yaml
🤖 Model: gpt-4o-mini
📚 Max examples per class: 2

Loading tools from example_mcp_tools.json...
Found 6 tools in MCP file

🔍 [1/6] Classifying: get_weather
   Description: Fetches current weather information for a given location...
   ✅ Classes: SAFE_READ
   💭 Reasoning: Accesses public weather API data...

🔍 [2/6] Classifying: send_email
   Description: Sends an email message to a specified recipient...
   ✅ Classes: CONSEQUENTIAL_WRITE
   💭 Reasoning: Sends data to external email service...

... [3-6 processed] ...

================================================================================
IMPORT SUMMARY
================================================================================
✅ Added: 6
⏭️  Skipped (already exists): 0
❌ Errors: 0
📊 Total processed: 6
================================================================================

✅ Successfully updated rule_maker/tool_registry.yaml
   Added 6 new tools
```

---

## 🔧 Configuration

### Classifier Settings

- **max_examples_per_class**: Number of example tools to show (default: 2)
  - Higher = more context, slower, more expensive
  - Lower = faster, cheaper, less context
  - Recommended: 2-3 for most cases

- **model**: LLM model to use
  - `gpt-4o-mini` - Fast, cheap, good quality (default)
  - `gpt-4o` - Best quality, slower, more expensive
  - `gpt-4` - High quality, expensive
  - Compatible with OpenRouter or other OpenAI-compatible APIs

- **temperature**: Controls randomness (default: 0.1)
  - Low (0.0-0.2) = Consistent, deterministic
  - High (0.7-1.0) = Creative, varied

### Using Custom API Providers

```python
# OpenRouter example
result = classify_tool_with_llm(
    tool_name="my_tool",
    tool_description="Does something",
    api_key="sk-or-...",
    base_url="https://openrouter.ai/api/v1",
    model="anthropic/claude-3-sonnet"
)
```

---

## 📊 Tool Registry Format

Tools in `tool_registry.yaml`:

```yaml
tools:
  tool_name:
    description: "What the tool does"
    classes: [CLASS1, CLASS2]  # Can have multiple
    auto_classified: true      # Set by import script
    args:
      arg_name:
        type: string|int|bool|float
        description: "Argument description"
        required: true|false
```

---

## 🛠️ Troubleshooting

### "OPENROUTER_API_KEY not set in .env file"

Add to your `.env` file in the project root:
```
OPENROUTER_API_KEY=sk-or-your-key-here
OPENROUTER_MODEL=gpt-4o-mini
```

**Note**: OpenRouter API keys start with `sk-or-`. The classifier auto-detects these and uses OpenRouter's API endpoint.

### "Invalid class name" error
The LLM returned a class not in `taint_classes.json`. This is rare but can happen.
- Try with a different model (e.g., gpt-4 instead of gpt-4o-mini)
- Reduce temperature to 0.0 for more consistent output

### Classification seems wrong
- Increase `max_examples_per_class` to provide more context
- Use a more powerful model (gpt-4)
- Review and manually correct in `tool_registry.yaml`
- Tools marked `auto_classified: true` can be reviewed and changed

### Import script slow
- Reduce `max_examples_per_class`
- Use faster model (gpt-4o-mini)
- Each tool requires one LLM API call (cannot be parallelized for consistent classification)

---

## 🔐 Security Considerations

1. **Review auto-classified tools** - Always review tools marked `auto_classified: true`
2. **Conservative classification** - Classifier errs on the side of caution (e.g., assumes files may be sensitive)
3. **Multi-class tools** - Tools can belong to multiple classes (e.g., read + execute)
4. **Manual override** - You can always manually edit classifications in `tool_registry.yaml`

---

## 📝 Best Practices

1. **Start with example tools** - Manually classify 2-3 tools per class before importing bulk
2. **Use dry-run first** - Always `--dry-run` to preview before importing
3. **Review classifications** - Check auto-classified tools, especially for sensitive operations
4. **Update descriptions** - Clear, detailed tool descriptions lead to better classification
5. **Keep examples updated** - Periodically review and update example tools in registry

---

## 🚢 Production Deployment

For web apps using the classifier:

1. **API Key Management**: Store in environment variables or secrets manager
2. **Rate Limiting**: Implement rate limits on classification endpoint
3. **Caching**: Cache classification results for identical tool descriptions
4. **Fallback**: Have manual classification option if LLM fails
5. **Audit**: Log all classifications for review and improvement
6. **Cost**: Monitor API costs, consider using cheaper models for MVP

---

## 🔗 Integration Examples

### FastAPI Backend
```python
from fastapi import FastAPI
from rule_maker.classifier import classify_tool_with_llm

app = FastAPI()

@app.post("/api/classify-tool")
async def classify(tool_name: str, description: str):
    result = classify_tool_with_llm(
        tool_name, description,
        api_key=os.getenv("OPENROUTER_API_KEY")
    )
    return result
```

### React Frontend
```javascript
async function classifyTool(toolName, description) {
  const response = await fetch('/api/classify-tool', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({tool_name: toolName, description})
  });
  const result = await response.json();
  // Display result.classes and result.reasoning to user
  return result;
}
```

---

For more information, see:
- `../docs/blueprint.md` - System architecture
- `../policies.yaml` - Example policy configurations
- `rule_templates.yaml` - Pre-built rule patterns

