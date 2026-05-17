import os
from dotenv import load_dotenv

load_dotenv()

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
DEEPSEEK_API_BASE = os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com")

CHROMA_DB_PATH = os.getenv("CHROMA_DB_PATH", "./knowledge_base/chroma_db")

FIREWALL_API_URL = os.getenv("FIREWALL_API_URL", "http://localhost:8001")
EDR_API_URL = os.getenv("EDR_API_URL", "http://localhost:8002")
LOG_API_URL = os.getenv("LOG_API_URL", "http://localhost:8003")

API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")