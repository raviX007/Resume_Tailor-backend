"""Step 3: Compute reorder plan based on match results.

Determines how to rearrange resume sections to best match the JD.
Pure Python — no LLM needed.
"""

from app.models import ExtractedKeywords, MatchResult, ReorderPlan, ResumeSections
from app.core.logger import logger


# Map dominant category to summary opening role title
CATEGORY_ROLE_MAP = {
    "ai_llm": "AI/LLM Engineer",
    "backend": "Backend Developer",
    "frontend": "Frontend Developer",
    "languages": "Software Developer",
    "databases": "Software Developer",
    "devops": "DevOps Engineer",
    "domains": "Software Developer",
}


def compute_reorder_plan(
    extracted: ExtractedKeywords,
    match: MatchResult,
    sections: ResumeSections,
) -> ReorderPlan:
    """Determine how to reorder resume sections based on JD relevance.

    Args:
        extracted: Keywords extracted from the JD.
        match: Match result against skills.
        sections: Pre-parsed resume sections from parser.

    Rules:
    1. Skills categories: order by number of JD matches (descending)
    2. Projects: order by keyword overlap with JD
    3. Summary first line: mirror the JD role title + top matched skills
    4. Experience emphasis: which keywords to highlight per entry
    """
    # 1. Skills category order: sort by match count descending, keep all cats
    all_categories = list(sections.get("skills", {}).keys())
    category_counts = {cat: len(match.matched.get(cat, [])) for cat in all_categories}
    skills_order = sorted(all_categories, key=lambda c: category_counts.get(c, 0), reverse=True)

    # 2. Project order: score each project by keyword overlap
    all_matched_keywords = set()
    for kws in match.matched.values():
        all_matched_keywords.update(kw.lower() for kw in kws)

    project_scores = {}
    for project_name, project_content in sections.get("projects", {}).items():
        content_lower = project_content.lower()
        score = sum(1 for kw in all_matched_keywords if kw in content_lower)
        project_scores[project_name] = score

    project_order = sorted(
        project_scores.keys(),
        key=lambda p: project_scores[p],
        reverse=True,
    )

    # 3. Summary first line: use JD role_title or infer from dominant category
    if extracted.role_title:
        role_title = extracted.role_title
    else:
        role_title = CATEGORY_ROLE_MAP.get(match.dominant_category, "Software Developer")

    # Build the top matched skills for the summary
    top_skills = []
    for cat in skills_order[:3]:
        top_skills.extend(match.matched.get(cat, [])[:2])
    top_skills = top_skills[:4]

    if top_skills:
        skills_mention = ", ".join(top_skills[:3])
        summary_first_line = (
            f"{role_title} with hands-on expertise in {skills_mention}."
        )
    else:
        summary_first_line = f"{role_title}."

    # 4. Experience emphasis: for each experience entry, find matched keywords
    experience_emphasis = {}
    for exp_name, exp_content in sections.get("experience", {}).items():
        content_lower = exp_content.lower()
        relevant = [
            kw for kw in all_matched_keywords
            if kw in content_lower
        ]
        experience_emphasis[exp_name] = relevant[:5]

    logger.info(
        f"Reorder plan: skills={skills_order}, "
        f"projects={project_order}, "
        f"role='{role_title}'"
    )

    return ReorderPlan(
        skills_category_order=skills_order,
        project_order=project_order,
        summary_first_line=summary_first_line,
        experience_emphasis=experience_emphasis,
    )
