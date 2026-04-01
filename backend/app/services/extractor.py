"""Step 1: LLM parses JD to extract structured keywords.

Fetches prompt from Langfuse ("resume-tailor-extract") at runtime.
Prompt managed in Langfuse — edit via Langfuse UI, push via scripts/push_prompts.py.
"""

import hashlib

from app.core.langfuse_client import get_prompt_messages, observe
from app.core.llm import get_llm_client
from app.core.constants import JD_TRUNCATE_LENGTH
from app.core.logger import logger
from app.models import ExtractedKeywords

# In-memory cache: SHA-256(jd_text + job_title) → ExtractedKeywords
# Same JD re-submitted (e.g. during refine) skips the LLM call.
_extraction_cache: dict[str, ExtractedKeywords] = {}
_MAX_CACHE = 50


def _jd_hash(jd_text: str, job_title: str) -> str:
    return hashlib.sha256(f"{jd_text}|{job_title}".encode()).hexdigest()


@observe(name="resume-tailor-extract")
async def extract_keywords(jd_text: str, job_title: str = "") -> ExtractedKeywords | None:
    """Extract structured keywords from a job description via LLM.

    Fetches prompt from Langfuse ("resume-tailor-extract").
    Results are cached by content hash — same JD skips the LLM call.
    Returns ExtractedKeywords or None if LLM call fails.
    """
    content_hash = _jd_hash(jd_text, job_title)
    if content_hash in _extraction_cache:
        logger.info(f"JD extraction cache HIT (hash={content_hash[:8]}...)")
        return _extraction_cache[content_hash]

    truncated_jd = jd_text[:JD_TRUNCATE_LENGTH]

    template_vars = {
        "jd_text": truncated_jd,
        "job_title": job_title,
    }

    default_config = {"temperature": 0.1, "max_tokens": 1000}

    langfuse_result = get_prompt_messages("resume-tailor-extract", template_vars)
    if langfuse_result:
        system_prompt, user_prompt, config = langfuse_result
        config = config or default_config
    else:
        from app.core.fallback_prompts import FALLBACK_PROMPTS
        fb = FALLBACK_PROMPTS["resume-tailor-extract"]
        system_prompt = fb["system"]
        user_prompt = fb["user"].format(**template_vars)
        config = fb["config"]
        logger.warning("Langfuse unavailable — using embedded fallback for resume-tailor-extract")

    llm = await get_llm_client()
    result = await llm.call_json(
        prompt=user_prompt,
        system_prompt=system_prompt,
        temperature=config.get("temperature", 0.1),
        max_tokens=config.get("max_tokens", 1000),
        name="jd-keyword-extraction",
    )

    if not result:
        logger.warning("JD keyword extraction returned no result")
        return None

    try:
        extracted = ExtractedKeywords(**result)
        # Cache the result
        if len(_extraction_cache) >= _MAX_CACHE:
            oldest_key = next(iter(_extraction_cache))
            del _extraction_cache[oldest_key]
        _extraction_cache[content_hash] = extracted
        return extracted
    except (KeyError, TypeError, ValueError) as e:
        logger.warning(f"Failed to parse extraction result: {e}")
        return None
