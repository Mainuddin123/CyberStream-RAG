
import os
from pathlib import Path

from dotenv import load_dotenv
from langsmith import Client

# ------------------------------------------
# Project configuration
# ------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=True)

# ------------------------------------------
# Load environment variables
# ------------------------------------------

api_key = os.getenv("LANGSMITH_API_KEY")
tracing = os.getenv("LANGSMITH_TRACING", "false").lower()
project = os.getenv("LANGSMITH_PROJECT", "CyberStream-RAG")

# ------------------------------------------
# Validate configuration
# ------------------------------------------

if not api_key:
    raise ValueError("LANGSMITH_API_KEY is missing from .env")

if tracing != "true":
    raise ValueError("Set LANGSMITH_TRACING=true in .env")

# ------------------------------------------
# Initialize LangSmith client
# ------------------------------------------

client = Client(api_key=api_key)

print("LangSmith client initialized.")
print("Tracing enabled:", tracing)
print("Project:", project)

# ------------------------------------------
# Verify authentication
# ------------------------------------------

try:
    projects = list(client.list_projects(limit=5))

    print("\nLangSmith authentication successful.")
    print("Accessible projects:", len(projects))

    for item in projects:
        print("-", item.name)

except Exception as error:
    print("\nLangSmith authentication failed.")
    print("Error:", error)
