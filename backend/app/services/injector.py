"""Step 4: Inject matched keywords and reorder sections in the LaTeX file.

Applies the reorder plan to the base .tex file:
1. Reorder skills categories
2. Inject missing-but-owned keywords into skills
3. Reorder projects
4. Update summary first line

Returns the modified .tex content and a unified diff.
"""

import difflib

from app.models import ReorderPlan, MatchResult, ResumeSections
from app.latex.writer import replace_between_markers, rebuild_skills_section, rebuild_projects_section, escape_latex
from app.core.logger import logger


def inject_into_latex(
    plan: ReorderPlan,
    match: MatchResult,
    tex_content: str,
    sections: ResumeSections,
) -> tuple[str, str]:
    """Apply reorder plan and keyword injection to the .tex file.

    Args:
        plan: Reorder plan from Step 3.
        match: Match result from Step 2.
        tex_content: The marked .tex content (from analyzer or pre-marked file).
        sections: Pre-parsed resume sections from parser.

    Returns: (modified_tex_content, unified_diff_string)
    """
    original_tex = tex_content
    modified_tex = original_tex

    # 1. Reorder and inject skills
    skills_dict = sections.get("skills", {})
    if skills_dict:
        new_skills = rebuild_skills_section(
            skills_dict=skills_dict,
            category_order=plan.skills_category_order,
            injectable=match.injectable,
        )
        modified_tex = replace_between_markers(
            modified_tex, "% SKILLS_START", "% SKILLS_END", new_skills
        )

    # 2. Reorder projects
    projects_dict = sections.get("projects", {})
    if projects_dict and plan.project_order:
        new_projects = rebuild_projects_section(
            projects_dict=projects_dict,
            project_order=plan.project_order,
        )
        modified_tex = replace_between_markers(
            modified_tex, "% PROJECTS_START", "% PROJECTS_END", new_projects
        )

    # 3. Update summary first line
    if plan.summary_first_line:
        old_summary = sections.get("summary", "")
        if old_summary:
            # Replace just the first sentence (up to the first period + space)
            lines = old_summary.split(". ")
            if len(lines) > 1:
                # Keep everything after the first two sentences, prepend new summary
                remaining = ". ".join(lines[2:]) if len(lines) > 2 else ""
                new_summary = escape_latex(plan.summary_first_line)
                if remaining:
                    new_summary += " " + remaining
            else:
                new_summary = escape_latex(plan.summary_first_line)

            modified_tex = replace_between_markers(
                modified_tex, "% SUMMARY_START", "% SUMMARY_END", new_summary
            )

    # Generate unified diff
    diff = difflib.unified_diff(
        original_tex.splitlines(keepends=True),
        modified_tex.splitlines(keepends=True),
        fromfile="resume_base.tex",
        tofile="resume_tailored.tex",
    )
    tex_diff = "".join(diff)

    changes = tex_diff.count("\n+") + tex_diff.count("\n-")
    logger.info(f"Injection complete: ~{changes} lines changed")

    return modified_tex, tex_diff
