"""TRACE — Transactional Risk Analysis & Compliance Engine."""

import os
from typing import Optional
from openai import OpenAI

__version__ = "1.0.0"
__author__ = "Amit Kumar Koshta"


def create_openai_client(api_key: Optional[str] = None, base_url: Optional[str] = None) -> OpenAI:
    """Create a configured OpenAI-compatible client for AML investigation workflows."""
    resolved_key = api_key or os.getenv("OPENAI_API_KEY")
    resolved_url = base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    return OpenAI(api_key=resolved_key, base_url=resolved_url)
