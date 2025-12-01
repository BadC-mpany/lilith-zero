"""
Tool Class Classifier - Uses LLM to classify tools into security classes
"""

import json
import yaml
import os
from typing import List, Dict, Any, Optional
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


def load_class_definitions(classes_path: str = "rule_maker/taint_classes.json") -> List[Dict[str, Any]]:
    """Load class definitions from taint_classes.json"""
    with open(classes_path, 'r') as f:
        return json.load(f)


def load_existing_tools(registry_path: str = "rule_maker/tool_registry.yaml") -> Dict[str, Any]:
    """Load existing tool registry"""
    if not os.path.exists(registry_path):
        return {"tools": {}}

    with open(registry_path, 'r') as f:
        config = yaml.safe_load(f)
    return config if config else {"tools": {}}


def extract_examples_per_class(
    existing_tools: Dict[str, Any],
    max_examples_per_class: int = 2
) -> Dict[str, List[Dict[str, str]]]:
    """
    Extract example tools for each class from existing registry.

    Returns:
        Dict mapping class_name -> list of {name, description} examples
    """
    class_examples: Dict[str, List[Dict[str, str]]] = {}

    tools = existing_tools.get("tools", {})
    for tool_name, tool_config in tools.items():
        tool_classes = tool_config.get("classes", [])
        description = tool_config.get("description", "")

        for class_name in tool_classes:
            if class_name not in class_examples:
                class_examples[class_name] = []

            # Add example if we haven't reached max
            if len(class_examples[class_name]) < max_examples_per_class:
                class_examples[class_name].append({
                    "name": tool_name,
                    "description": description
                })

    return class_examples


def build_classification_prompt(
    tool_name: str,
    tool_description: str,
    class_definitions: List[Dict[str, Any]],
    class_examples: Dict[str, List[Dict[str, str]]]
) -> str:
    """Build prompt for LLM judge to classify tool"""

    prompt = f"""You are a security expert classifier for AI agent tools. Your task is to classify a tool into one or more security classes based on its functionality.

## Tool to Classify:
**Name:** {tool_name}
**Description:** {tool_description}

## Available Security Classes:

"""

    for class_def in class_definitions:
        class_name = class_def["className"]
        rule = class_def["classificationRule"]
        desc = class_def["description"]

        prompt += f"### {class_name}\n"
        prompt += f"**Rule:** {rule}\n"
        prompt += f"**Description:** {desc}\n"

        # Add examples if available
        if class_name in class_examples and class_examples[class_name]:
            prompt += f"**Examples from existing tools:**\n"
            for ex in class_examples[class_name]:
                prompt += f"  - `{ex['name']}`: {ex['description']}\n"

        prompt += "\n"

    prompt += """## Classification Instructions:

1. **Analyze the tool's purpose and risk profile** based on its name and description
2. **A tool can belong to MULTIPLE classes** if it performs multiple types of operations
3. **Be conservative**: If unsure whether a tool accesses sensitive data, classify as SENSITIVE_READ
4. **Consider data flow**: Does it read data? Write data? Execute code? Modify state?
5. **Output ONLY valid JSON** in this exact format:

```json
{
  "classes": ["CLASS_NAME_1", "CLASS_NAME_2"],
  "reasoning": "Brief explanation of why these classes were chosen"
}
```

**IMPORTANT:** 
- Return ONLY the JSON object, no additional text
- Use exact class names from the list above
- Include at least one class
- Provide clear reasoning

Classify the tool now:"""

    return prompt


def classify_tool_with_llm(
    tool_name: str,
    tool_description: str,
    max_examples_per_class: int = 2,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    base_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Classify a tool using LLM judge.

    Args:
        tool_name: Name of the tool
        tool_description: Description of what the tool does
        max_examples_per_class: Maximum number of example tools to include per class
        api_key: OpenAI API key (or compatible API)
        model: Model to use for classification
        base_url: Optional base URL for API (e.g., for OpenRouter)

    Returns:
        Dict with:
            - classes: List[str] - Security classes
            - reasoning: str - Why these classes were chosen
            - confidence: str - LLM's confidence level

    Usage for web integration:
        1. Get tool_name and tool_description from user input or MCP
        2. Call this function with API credentials
        3. Return the classification to frontend
        4. User can review/modify before saving

    Example:
        result = classify_tool_with_llm(
            tool_name="send_email",
            tool_description="Sends an email to a recipient",
            api_key=os.getenv("OPENROUTER_API_KEY")
        )
        # result = {
        #   "classes": ["CONSEQUENTIAL_WRITE"],
        #   "reasoning": "...",
        #   "confidence": "high"
        # }
    """
    # Load class definitions and examples
    class_definitions = load_class_definitions()
    existing_tools = load_existing_tools()
    class_examples = extract_examples_per_class(existing_tools, max_examples_per_class)

    # Build prompt
    prompt = build_classification_prompt(
        tool_name, tool_description, class_definitions, class_examples
    )

    # Get API key and model from environment if not provided
    if api_key is None:
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError(
                "No API key provided. Set OPENROUTER_API_KEY in .env file or pass api_key parameter."
            )

    if model is None:
        model = os.getenv("OPENROUTER_MODEL", "gpt-4o-mini")

    # Initialize OpenAI client (or compatible)
    client_kwargs = {"api_key": api_key}

    # Auto-detect OpenRouter API keys and set base URL
    if base_url:
        client_kwargs["base_url"] = base_url
    elif api_key.startswith("sk-or-"):
        # OpenRouter API key detected - use OpenRouter base URL
        client_kwargs["base_url"] = "https://openrouter.ai/api/v1"

    client = OpenAI(**client_kwargs)

    # Call LLM (some models don't support response_format, so we handle both)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a security classification expert. Return only valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,  # Low temperature for consistency
            response_format={"type": "json_object"}  # Ensure JSON output
        )
    except Exception as e:
        # Some models don't support response_format, try without it
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a security classification expert. Return only valid JSON in this exact format: {\"classes\": [\"CLASS1\"], \"reasoning\": \"explanation\"}"
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1
        )

    # Parse response
    result_text = response.choices[0].message.content.strip()

    # Try to extract JSON if wrapped in markdown code blocks
    if result_text.startswith("```"):
        # Remove markdown code blocks
        lines = result_text.split('\n')
        result_text = '\n'.join(lines[1:-1]) if len(lines) > 2 else result_text
        result_text = result_text.replace("```json", "").replace("```", "").strip()

    try:
        result = json.loads(result_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned invalid JSON. Response: {result_text[:200]}...") from e

    # Validate result
    if "classes" not in result:
        raise ValueError("LLM response missing 'classes' field")

    if not isinstance(result["classes"], list):
        raise ValueError("'classes' must be a list")

    # Validate class names
    valid_classes = {c["className"] for c in class_definitions}
    for cls in result["classes"]:
        if cls not in valid_classes:
            raise ValueError(f"Invalid class name: {cls}")

    return result


def classify_tool(
    tool_name: str,
    tool_description: str,
    max_examples_per_class: int = 2,
    api_key: Optional[str] = None,
    model: str = "gpt-4o-mini"
) -> List[str]:
    """
    Simple wrapper that returns only the class list.

    Args:
        tool_name: Name of the tool
        tool_description: Description of what the tool does
        max_examples_per_class: Maximum examples to show per class
        api_key: OpenAI API key
        model: Model to use

    Returns:
        List of security class names

    Example:
        classes = classify_tool("send_sms", "Sends SMS to a phone number")
        # classes = ["CONSEQUENTIAL_WRITE"]
    """
    result = classify_tool_with_llm(
        tool_name=tool_name,
        tool_description=tool_description,
        max_examples_per_class=max_examples_per_class,
        api_key=api_key,
        model=model
    )
    return result["classes"]


if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) < 3:
        print("Usage: python classifier.py <tool_name> <tool_description>")
        print("\nExample:")
        print('  python classifier.py "send_email" "Sends an email to a recipient"')
        sys.exit(1)

    tool_name = sys.argv[1]
    tool_description = sys.argv[2]

    print(f"\nClassifying tool: {tool_name}")
    print(f"Description: {tool_description}\n")

    # API key will be loaded from .env automatically
    result = classify_tool_with_llm(tool_name, tool_description)

    print("Classification Result:")
    print(f"  Classes: {', '.join(result['classes'])}")
    print(f"  Reasoning: {result['reasoning']}")
