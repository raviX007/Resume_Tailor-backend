"""Step 2: LLM-powered matching of JD keywords against resume skills.

Fetches prompt from Langfuse ("resume-tailor-match") at runtime.
Prompt managed in Langfuse — edit via Langfuse UI, push via scripts/push_prompts.py.
"""

from app.core.langfuse_client import get_prompt_messages, observe
from app.core.llm import get_llm_client
from app.core.logger import logger
from app.models import ExtractedKeywords, MatchResult


@observe(name="resume-tailor-match")
async def match_keywords(
    extracted: ExtractedKeywords,
    master_skills: dict,
    skills_on_resume: dict[str, list[str]] | None = None,
    user_instructions: str = "",
) -> MatchResult | None:
    """Match JD keywords against resume skills using LLM.

    The LLM understands semantic equivalence (e.g., "React" = "React.js",
    "container orchestration" ≈ "Kubernetes") without needing an alias table.

    Args:
        extracted: Keywords extracted from JD by LLM (Step 1)
        master_skills: All candidate skills by category (from Step 0)
        skills_on_resume: Skills currently on the resume (from parser),
            used to determine injectable skills
        user_instructions: Optional user instructions for tailoring emphasis
            (e.g. "add Docker to skills", "emphasize AI experience")

    Returns:
        MatchResult or None if LLM call fails.
    """
    # Build flat JD keywords by category
    jd_keywords = {
        "languages": extracted.languages,
        "backend": extracted.backend,
        "frontend": extracted.frontend,
        "ai_llm": extracted.ai_llm,
        "databases": extracted.databases,
        "devops": extracted.devops,
        "domains": extracted.domains,
    }

    # Build template variables
    template_vars = {
        "jd_keywords": _format_skills_dict(jd_keywords),
        "resume_skills": _format_skills_dict(master_skills),
        "skills_on_resume": _format_skills_dict(skills_on_resume) if skills_on_resume else "Same as resume_skills",
        "user_instructions": user_instructions if user_instructions else "No special instructions.",
    }

    default_config = {"temperature": 0.1, "max_tokens": 2000, "response_format": "json"}

    langfuse_result = get_prompt_messages("resume-tailor-match", template_vars)
    if langfuse_result:
        system_prompt, user_prompt, config = langfuse_result
        config = config or default_config
    else:
        from app.core.fallback_prompts import FALLBACK_PROMPTS
        fb = FALLBACK_PROMPTS["resume-tailor-match"]
        system_prompt = fb["system"]
        user_prompt = fb["user"].format(**template_vars)
        config = fb["config"]
        logger.warning("Langfuse unavailable — using embedded fallback for resume-tailor-match")

    llm = await get_llm_client()
    result = await llm.call_json(
        prompt=user_prompt,
        system_prompt=system_prompt,
        temperature=config.get("temperature", 0.1),
        max_tokens=config.get("max_tokens", 2000),
        name="resume-tailor-match",
    )

    if not result:
        logger.warning("LLM matching returned no result")
        return None

    # Parse LLM response into MatchResult
    matched = result.get("matched", {})
    missing = result.get("missing_from_resume", {})
    injectable = result.get("injectable", {})

    total_jd = sum(len(v) for v in jd_keywords.values())
    total_matched = sum(len(v) for v in matched.values())
    match_score = int((total_matched / max(total_jd, 1)) * 100)
    match_score = max(0, min(100, match_score))

    # Determine dominant category
    category_scores = {cat: len(matched.get(cat, [])) for cat in jd_keywords}
    dominant_category = max(category_scores, key=category_scores.get) if category_scores else "languages"

    logger.info(
        f"Match: {total_matched}/{total_jd} keywords ({match_score}%), "
        f"dominant={dominant_category}, "
        f"injectable={sum(len(v) for v in injectable.values())}"
    )

    return MatchResult(
        matched=matched,
        missing_from_resume=missing,
        injectable=injectable,
        total_jd_keywords=total_jd,
        total_matched=total_matched,
        match_score=match_score,
        dominant_category=dominant_category,
    )


def _format_skills_dict(skills: dict) -> str:
    """Format a skills dict into a readable string for the LLM."""
    lines = []
    for cat, items in skills.items():
        if items:
            lines.append(f"  {cat}: {', '.join(items)}")
    return "\n".join(lines) if lines else "  (none)"
