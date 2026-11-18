"""CERBERUS configuration loaded from environment / .env."""
import os

from dotenv import load_dotenv

load_dotenv()

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
# Comma-separated list of webhook URLs that receive alert JSON pushes.
WEBHOOK_URLS = [u.strip() for u in os.getenv("WEBHOOK_URLS", "").split(",") if u.strip()]

MQTT_BROKER_HOST = os.getenv("MQTT_BROKER_HOST", "localhost")
MQTT_BROKER_PORT = int(os.getenv("MQTT_BROKER_PORT", "1883"))

FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))

DB_PATH = os.getenv("DB_PATH", "cerberus.db")

DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
