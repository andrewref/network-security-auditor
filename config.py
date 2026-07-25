"""
Config, environment loading and the single shared LLM client.

Everything in this project talks to the LLM through OpenRouter, which is
OpenAI-API-compatible. That means we just point `ChatOpenAI` at
OpenRouter's base_url instead of using a Groq/OpenAI-specific client.

Swap OPENROUTER_MODEL in your .env for any model listed at
https://openrouter.ai/models, just make sure it's a model that supports
tool/function calling, since report_agent and risk_agent rely on
llm.bind_tools(...).
"""

import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
if not OPENROUTER_API_KEY:
    raise RuntimeError(
        "OPENROUTER_API_KEY is not set. Copy .env.example to .env and fill it in."
    )

OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct")

# LangSmith tracing is optional, only enabled if a key is provided.
if os.getenv("LANGSMITH_API_KEY"):
    os.environ["LANGCHAIN_TRACING_V2"] = os.getenv("LANGCHAIN_TRACING_V2", "true")
    os.environ["LANGCHAIN_PROJECT"] = os.getenv("LANGCHAIN_PROJECT", "network-security-auditor")
    os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"

llm = ChatOpenAI(
    model=OPENROUTER_MODEL,
    temperature=0,
    api_key=OPENROUTER_API_KEY,
    base_url="https://openrouter.ai/api/v1",
)
