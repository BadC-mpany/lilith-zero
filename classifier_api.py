"""
Classifier API Server
Exposes the tool classifier as a REST API for remote access.

Usage:
    python classifier_api.py

Then call from anywhere:
    curl -X POST http://localhost:8001/classify \
      -H "Content-Type: application/json" \
      -d '{"tool_name": "send_email", "tool_description": "Sends emails"}'
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from rule_maker.classifier import classify_tool_with_llm
from typing import List
import uvicorn
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Sentinel Tool Classifier API",
    description="Classifies tools into security classes using LLM",
    version="1.0.0"
)


class ToolClassifyRequest(BaseModel):
    tool_name: str
    tool_description: str
    max_examples_per_class: int = 2

    class Config:
        json_schema_extra = {
            "example": {
                "tool_name": "send_email",
                "tool_description": "Sends an email message to a recipient",
                "max_examples_per_class": 2
            }
        }


class ToolClassifyResponse(BaseModel):
    classes: List[str]
    reasoning: str

    class Config:
        json_schema_extra = {
            "example": {
                "classes": ["CONSEQUENTIAL_WRITE"],
                "reasoning": "This tool sends data to an external email service."
            }
        }


@app.post("/classify", response_model=ToolClassifyResponse)
async def classify_tool(req: ToolClassifyRequest):
    """
    Classify a tool into security classes.

    Returns:
        - classes: List of security class names
        - reasoning: Explanation of classification
    """
    try:
        logger.info(f"Classifying tool: {req.tool_name}")

        result = classify_tool_with_llm(
            tool_name=req.tool_name,
            tool_description=req.tool_description,
            max_examples_per_class=req.max_examples_per_class
        )

        logger.info(f"Classification complete: {result['classes']}")
        return result

    except Exception as e:
        logger.error(f"Classification error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok", "service": "classifier-api"}


@app.get("/classes")
async def list_classes():
    """
    List all available security classes.
    """
    return {
        "classes": [
            {
                "name": "SAFE_READ",
                "description": "Public, non-sensitive data retrieval"
            },
            {
                "name": "SENSITIVE_READ",
                "description": "Private data, secrets, confidential info"
            },
            {
                "name": "SAFE_WRITE",
                "description": "Local-only, ephemeral storage"
            },
            {
                "name": "CONSEQUENTIAL_WRITE",
                "description": "External sinks, persistent state changes"
            },
            {
                "name": "UNSAFE_EXECUTE",
                "description": "Arbitrary code/command execution"
            },
            {
                "name": "HUMAN_VERIFY",
                "description": "Destructive, irreversible operations"
            },
            {
                "name": "SANITIZER",
                "description": "PII/secret removal"
            }
        ]
    }


if __name__ == "__main__":
    logger.info("Starting Classifier API on http://0.0.0.0:8001")
    logger.info("API docs available at http://localhost:8001/docs")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        log_level="info"
    )
