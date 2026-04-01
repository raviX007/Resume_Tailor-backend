"""Central LLM client — OpenAI primary, Gemini fallback.

All calls are async. Thread-safe singleton via asyncio.Lock.
Langfuse tracing: if langfuse is installed, all OpenAI calls are auto-traced.
Retry via tenacity for transient failures.
"""

import asyncio
import json

import httpx
import openai as openai_errors
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

_LANGFUSE_TRACING = False
try:
    from langfuse.openai import AsyncOpenAI
    _LANGFUSE_TRACING = True
except ImportError:
    from openai import AsyncOpenAI

from app.config import load_settings
from app.core.constants import MAX_OPENAI_FAILURES
from app.core.logger import logger

# Transient errors worth retrying
_RETRYABLE = (httpx.TimeoutException, httpx.ConnectError, openai_errors.APITimeoutError)


class LLMClient:
    """OpenAI primary, Gemini fallback."""

    def __init__(self):
        settings = load_settings()
        self.openai_client = AsyncOpenAI(api_key=settings.openai_api_key) if settings.openai_api_key else None
        self.gemini_available = bool(settings.google_ai_api_key)
        self._gemini_api_key = settings.google_ai_api_key
        self._gemini_model = settings.gemini_model
        self.openai_failures = 0
        self.model = settings.llm_model

    async def call(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.3,
        max_tokens: int = 1000,
        name: str | None = None,
    ) -> str | None:
        """Make an LLM call. Returns response text or None."""
        if self.openai_client and self.openai_failures < MAX_OPENAI_FAILURES:
            try:
                result = await self._call_openai(
                    prompt, system_prompt, temperature, max_tokens, name=name
                )
                self.openai_failures = 0
                return result
            except (openai_errors.APIError, httpx.HTTPError, ValueError) as e:
                self.openai_failures += 1
                logger.warning(f"OpenAI failed ({self.openai_failures}x): {e}")

        if self.gemini_available:
            try:
                result = await self._call_gemini(prompt, system_prompt)
                # Gemini succeeded — reset OpenAI counter so it retries next call
                self.openai_failures = 0
                return result
            except (httpx.HTTPError, ValueError, RuntimeError) as e:
                logger.warning(f"Gemini fallback also failed: {e}")

        logger.error("All LLM providers failed.")
        return None

    async def call_json(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.2,
        max_tokens: int = 1500,
        name: str | None = None,
    ) -> dict | None:
        """Make an LLM call that returns structured JSON."""
        if self.openai_client and self.openai_failures < MAX_OPENAI_FAILURES:
            try:
                result = await self._call_openai_json(
                    prompt, system_prompt, temperature, max_tokens, name=name
                )
                self.openai_failures = 0
                return result
            except (openai_errors.APIError, httpx.HTTPError, ValueError) as e:
                self.openai_failures += 1
                logger.warning(f"OpenAI JSON failed ({self.openai_failures}x): {e}")

        if self.gemini_available:
            try:
                text = await self._call_gemini(prompt, system_prompt)
                if text:
                    parsed = json.loads(text)
                    # Gemini succeeded — reset OpenAI counter
                    self.openai_failures = 0
                    return parsed
            except json.JSONDecodeError as e:
                logger.warning(f"Gemini returned invalid JSON: {e}")
            except (httpx.HTTPError, ValueError, RuntimeError) as e:
                logger.warning(f"Gemini JSON fallback failed: {e}")

        logger.error("All LLM providers failed for JSON call.")
        return None

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(min=1, max=5),
        retry=retry_if_exception_type(_RETRYABLE),
    )
    async def _call_openai(
        self,
        prompt: str,
        system_prompt: str,
        temperature: float,
        max_tokens: int,
        name: str | None = None,
    ) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = dict(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if _LANGFUSE_TRACING and name:
            kwargs["name"] = name

        response = await self.openai_client.chat.completions.create(**kwargs)

        if not response.choices:
            raise ValueError("LLM returned no choices")

        return response.choices[0].message.content

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(min=1, max=5),
        retry=retry_if_exception_type(_RETRYABLE),
    )
    async def _call_openai_json(
        self,
        prompt: str,
        system_prompt: str,
        temperature: float,
        max_tokens: int,
        name: str | None = None,
    ) -> dict | None:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = dict(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        if _LANGFUSE_TRACING and name:
            kwargs["name"] = name

        response = await self.openai_client.chat.completions.create(**kwargs)

        if not response.choices:
            raise ValueError("LLM returned no choices")

        content = response.choices[0].message.content
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"LLM returned invalid JSON: {e}\nContent: {content[:200]}")
            return None

    async def _call_gemini(self, prompt: str, system_prompt: str) -> str:
        """Fallback to Google Gemini free tier."""
        import google.generativeai as genai

        genai.configure(api_key=self._gemini_api_key)
        model = genai.GenerativeModel(self._gemini_model)

        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        response = await model.generate_content_async(full_prompt)
        return response.text


_client: LLMClient | None = None
_lock = asyncio.Lock()


async def get_llm_client() -> LLMClient:
    """Get or create the singleton LLM client (thread-safe)."""
    global _client
    if _client is None:
        async with _lock:
            if _client is None:
                _client = LLMClient()
    return _client
