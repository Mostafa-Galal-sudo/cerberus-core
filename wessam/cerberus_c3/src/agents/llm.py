"""OpenAI-compatible clients for Groq (defense agent) and DeepSeek (attack agent).
Keys come from the environment / .env — never hard-code them.
Model names change often: override with GROQ_MODEL / DEEPSEEK_MODEL and check the providers' docs.
"""
from __future__ import annotations

import os

PROVIDERS = {
    "groq": {"base_url": "https://api.groq.com/openai/v1", "key_env": "GROQ_API_KEY",
             "model_env": "GROQ_MODEL", "default_model": "llama-3.3-70b-versatile"},
    "deepseek": {"base_url": "https://api.deepseek.com", "key_env": "DEEPSEEK_API_KEY",
                 "model_env": "DEEPSEEK_MODEL", "default_model": "deepseek-chat"},
}


def load_dotenv_if_present(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def has_key(provider: str) -> bool:
    load_dotenv_if_present()
    return bool(os.environ.get(PROVIDERS[provider]["key_env"]))


def make_client(provider: str):
    """Returns (client, model)."""
    from openai import OpenAI
    load_dotenv_if_present()
    p = PROVIDERS[provider]
    client = OpenAI(api_key=os.environ[p["key_env"]], base_url=p["base_url"], timeout=60)
    return client, os.environ.get(p["model_env"], p["default_model"])
