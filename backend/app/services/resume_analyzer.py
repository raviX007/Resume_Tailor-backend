"""Step 0: Analyze an uploaded .tex resume using LLM.

When a user uploads their own .tex resume (without our markers), this service:
1. Sends the .tex to GPT-4o-mini to identify sections and insert comment markers
2. Extracts the user's actual skills organized by category
3. Returns marked .tex + dynamic skills dict for the existing pipeline

Fetches prompt from Langfuse ("resume-tailor-analyze") at runtime.
Prompt managed in Langfuse — edit via Langfuse UI, push via scripts/push_prompts.py.

This is the ONLY step that modifies the uploaded content. All other steps
operate on the marked .tex using the same marker-based parsing as before.
"""

import hashlib

from app.core.llm import get_llm_client
from app.core.langfuse_client import get_prompt_messages, observe
from app.core.constants import TEX_TRUNCATE_LENGTH
from app.core.logger import logger
from app.models import ResumeAnalysis

# In-memory cache: SHA-256(tex_content) → ResumeAnalysis
# Avoids re-calling the LLM when the same resume is submitted again (e.g. different JD).
_analysis_cache: dict[str, ResumeAnalysis] = {}
_MAX_CACHE = 20


def _tex_hash(tex: str) -> str:
    return hashlib.sha256(tex.encode()).hexdigest()


@observe(name="resume-tailor-analyze")
async def analyze_uploaded_resume(tex_content: str) -> ResumeAnalysis | None:
    """Analyze an uploaded .tex file: insert markers and extract skills.

    Fetches prompt from Langfuse ("resume-tailor-analyze").
    Results are cached by content hash — same resume skips the LLM call.

    Args:
        tex_content: Raw content of the uploaded .tex file.

    Returns:
        ResumeAnalysis with marked_tex, skills dict, and sections_found.
        None if the LLM call fails.
    """
    content_hash = _tex_hash(tex_content)
    if content_hash in _analysis_cache:
        logger.info(f"Resume analysis cache HIT (hash={content_hash[:8]}...)")
        return _analysis_cache[content_hash]

    truncated = tex_content[:TEX_TRUNCATE_LENGTH]

    template_vars = {"tex_content": truncated}
    default_config = {"temperature": 0.1, "max_tokens": 8000}

    langfuse_result = get_prompt_messages("resume-tailor-analyze", template_vars)
    if langfuse_result:
        system_prompt, user_prompt, config = langfuse_result
        config = config or default_config
    else:
        from app.core.fallback_prompts import FALLBACK_PROMPTS
        fb = FALLBACK_PROMPTS["resume-tailor-analyze"]
        system_prompt = fb["system"]
        user_prompt = fb["user"].format(**template_vars)
        config = fb["config"]
        logger.warning("Langfuse unavailable — using embedded fallback for resume-tailor-analyze")

    llm = await get_llm_client()
    result = await llm.call_json(
        prompt=user_prompt,
        system_prompt=system_prompt,
        temperature=config.get("temperature", 0.1),
        max_tokens=config.get("max_tokens", 8000),
        name="resume-analysis",
    )

    if not result:
        logger.warning("Resume analysis returned no result")
        return None

    try:
        analysis = ResumeAnalysis(**result)
        logger.info(
            f"Resume analyzed: sections={analysis.sections_found}, "
            f"skill_cats={list(analysis.skills.keys())}, "
            f"name='{analysis.person_name}'"
        )
        # Cache the result
        if len(_analysis_cache) >= _MAX_CACHE:
            oldest_key = next(iter(_analysis_cache))
            del _analysis_cache[oldest_key]
        _analysis_cache[content_hash] = analysis

        return analysis
    except (KeyError, TypeError, ValueError) as e:
        logger.warning(f"Failed to parse resume analysis: {e}")
        return None
