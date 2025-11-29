# src/config.py

import os
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Sentinel Configuration
SENTINEL_API_KEY = os.getenv("SENTINEL_API_KEY", "sk_live_demo_123")
SENTINEL_URL = os.getenv("SENTINEL_URL", "http://localhost:8000")

# LLM Provider Configuration (OpenRouter)
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemini-pro")

# Pre-flight check to ensure the necessary API key is set
if not OPENROUTER_API_KEY:
    raise ValueError("CRITICAL ERROR: OPENROUTER_API_KEY is not set in the environment or .env file.")
