# config.py
import os
from dotenv import load_dotenv

load_dotenv()

# Gemini API Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL_NAME = "gemini-2.5-pro-preview-03-25" # Or your specific preview model

# Paths
WORKSPACE_DIR = "workspace"
DATA_DIR = "data"
VULNERABILITY_CHECKLIST_FILE = os.path.join(DATA_DIR, "checklist.json")

# Git
GIT_COMMAND = "git" # Path to git executable if not in PATH

# Other settings
DEFAULT_SOLIDITY_VERSION = "0.8.20" # Example, can be detected from project

# Create directories if they don't exist
os.makedirs(WORKSPACE_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)