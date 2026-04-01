"""Langfuse prompt management + tracing client.

Fetches versioned prompts from Langfuse at runtime. Falls back gracefully
if Langfuse is not configured or unavailable. Thread-safe init via lock.

Exports:
- observe: decorator for tracing functions (no-op if langfuse not installed)
- flush: flush pending traces at end of request

Env vars: LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST
"""

import threading

from app.config import load_settings
from app.core.logger import logger

# Export observe decorator (no-op fallback if langfuse not installed)
try:
    from langfuse import observe
except ImportError:
    def observe(*args, **kwargs):
        """No-op decorator when langfuse is not installed."""
        def decorator(func):
            return func
        if args and callable(args[0]):
            return args[0]
        return decorator

# Lazy singleton with thread-safe init
_client = None
_initialized = False
_lock = threading.Lock()


def _get_client():
    """Get or create the Langfuse client singleton. Returns None if not configured."""
    global _client, _initialized

    if _initialized:
        return _client

    with _lock:
        if _initialized:
            return _client

        _initialized = True
        settings = load_settings()

        if not settings.langfuse_public_key or not settings.langfuse_secret_key:
            logger.info("Langfuse: no keys configured — prompts unavailable")
            return None

        try:
            from langfuse import Langfuse

            _client = Langfuse(
                public_key=settings.langfuse_public_key,
                secret_key=settings.langfuse_secret_key,
                host=settings.langfuse_host,
            )
            logger.info("Langfuse: client initialized")
            return _client
        except Exception as e:
            logger.warning(f"Langfuse: failed to initialize client: {e}")
            return None


def get_prompt_messages(
    prompt_name: str,
    variables: dict,
) -> tuple[str, str, dict] | None:
    """Fetch a chat prompt from Langfuse, compile with variables.

    Returns:
        (system_content, user_content, config_dict) or None if unavailable.
    """
    client = _get_client()
    if not client:
        return None

    try:
        prompt = client.get_prompt(prompt_name, type="chat", cache_ttl_seconds=300)
        messages = prompt.compile(**variables)
        config = prompt.config or {}

        system_content = ""
        user_content = ""
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "system":
                system_content = content
            elif role == "user":
                user_content = content

        logger.debug(f"Langfuse: fetched prompt '{prompt_name}' (v{prompt.version})")
        return system_content, user_content, config

    except (ValueError, KeyError, TypeError, RuntimeError) as e:
        logger.warning(f"Langfuse: failed to fetch prompt '{prompt_name}': {e}")
        return None


def flush():
    """Flush pending Langfuse traces."""
    client = _get_client()
    if client:
        try:
            client.flush()
            logger.debug("Langfuse: traces flushed")
        except Exception as e:
            logger.warning(f"Langfuse: flush failed: {e}")
