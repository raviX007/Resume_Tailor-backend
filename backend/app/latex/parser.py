"""Parse a .tex resume using comment markers.

Markers (inserted deterministically by insert_section_markers):
  % SUMMARY_START / % SUMMARY_END
  % SKILLS_START / % SKILLS_END  (with % SKILL_CAT:name sub-markers)
  % EXPERIENCE_START / % EXPERIENCE_END  (with % EXP:name sub-markers)
  % PROJECTS_START / % PROJECTS_END  (with % PROJECT:name sub-markers)
"""

import re

from app.models import ResumeSections
from app.core.logger import logger

# ── Section title → marker type mapping ────────────────────────────────────
_TITLE_TO_MARKER: dict[str, str] = {
    "summary": "SUMMARY",
    "professional summary": "SUMMARY",
    "technical skills": "SKILLS",
    "skills": "SKILLS",
    "core competencies": "SKILLS",
    "experience": "EXPERIENCE",
    "work experience": "EXPERIENCE",
    "professional experience": "EXPERIENCE",
    "projects": "PROJECTS",
    "personal projects": "PROJECTS",
    "selected projects": "PROJECTS",
}


def _slugify_name(text: str) -> str:
    """Turn 'ReAct AI Agent' → 'react_ai_agent'."""
    # Take the part before | (for entries like "Role | Company")
    text = text.split("|")[0].strip()
    text = re.sub(r"[^a-zA-Z0-9 ]", "", text)
    return re.sub(r"\s+", "_", text.strip()).lower()


def _normalize_skill_cat(label: str) -> str:
    """Normalize skill category label: 'AI / LLM' → 'ai_llm', 'DevOps & Tools' → 'devops'."""
    label_lower = label.lower().strip()
    known = {
        "languages": "languages",
        "backend": "backend",
        "frontend": "frontend",
        "ai / llm": "ai_llm",
        "ai/llm": "ai_llm",
        "ai_llm": "ai_llm",
        "ai / ml": "ai_llm",
        "databases": "databases",
        "devops & tools": "devops",
        "devops": "devops",
        "tools": "devops",
        "devops & cloud": "devops",
        "soft skills": "soft_skills",
        "domains": "domains",
    }
    return known.get(label_lower, _slugify_name(label_lower))


def insert_section_markers(tex: str) -> str:
    """Add comment markers to a .tex resume deterministically.

    Preserves ALL original LaTeX content — only inserts comment lines.
    This replaces the LLM-based marker insertion which could mangle formatting.
    """
    section_re = re.compile(r"\\section\{([^}]+)\}")
    matches = list(section_re.finditer(tex))
    if not matches:
        logger.warning("No \\section commands found — cannot insert markers")
        return tex

    end_doc = tex.find(r"\end{document}")
    if end_doc == -1:
        end_doc = len(tex)

    # Collect (content_start, content_end, marker_type) for each relevant section.
    sections = []
    for i, m in enumerate(matches):
        title = m.group(1).strip().lower()
        marker_type = _TITLE_TO_MARKER.get(title)
        if not marker_type:
            continue

        # Content starts on the line after the \section{} line
        newline_after = tex.find("\n", m.end())
        content_start = (newline_after + 1) if newline_after != -1 else m.end()

        # Content ends where the next \section starts (or \end{document})
        content_end = matches[i + 1].start() if i + 1 < len(matches) else end_doc

        sections.append((content_start, content_end, marker_type))

    # Insert markers in REVERSE order so offsets stay valid
    result = tex
    for content_start, content_end, marker_type in reversed(sections):
        raw_content = result[content_start:content_end]
        marked = _mark_content(raw_content, marker_type)
        result = result[:content_start] + marked + result[content_end:]

    found = [s[2] for s in sections]
    logger.info(f"Deterministic markers inserted for: {found}")
    return result


def _mark_content(content: str, marker_type: str) -> str:
    """Wrap a section's content with START/END markers and add sub-markers."""
    # Preserve trailing whitespace structure — strip only for processing
    trailing = "\n\n" if content.endswith("\n\n") else "\n" if content.endswith("\n") else ""
    body = content.rstrip()

    if marker_type == "SUMMARY":
        # Simple wrap — skip leading blank lines
        body = body.strip()
        return f"% SUMMARY_START\n{body}\n% SUMMARY_END\n{trailing}"

    elif marker_type == "SKILLS":
        lines = body.split("\n")
        out = ["% SKILLS_START"]
        for line in lines:
            m = re.match(r"\s*\\skillline\{([^}]+)\}", line)
            if m:
                cat_key = _normalize_skill_cat(m.group(1))
                out.append(f"% SKILL_CAT:{cat_key}")
            if line.strip():
                out.append(line)
        out.append("% SKILLS_END")
        return "\n".join(out) + "\n" + trailing

    elif marker_type == "EXPERIENCE":
        # Split into blocks at \experienceentry or common bold patterns
        lines = body.split("\n")
        out = ["% EXPERIENCE_START"]
        for line in lines:
            # Match \experienceentry{Title | Company}
            m = re.match(r"\s*\\experienceentry\{([^}]+)", line)
            if m:
                entry_key = _slugify_name(m.group(1))
                out.append(f"% EXP:{entry_key}")
            out.append(line)
        out.append("% EXPERIENCE_END")
        return "\n".join(out) + "\n" + trailing

    elif marker_type == "PROJECTS":
        lines = body.split("\n")
        out = ["% PROJECTS_START"]
        for line in lines:
            m = re.match(r"\s*\\projectentry\{([^}]+)", line)
            if m:
                entry_key = _slugify_name(m.group(1))
                out.append(f"% PROJECT:{entry_key}")
            out.append(line)
        out.append("% PROJECTS_END")
        return "\n".join(out) + "\n" + trailing

    return content


def extract_between_markers(tex: str, start_marker: str, end_marker: str) -> str:
    """Extract content between two comment markers (exclusive of markers)."""
    pattern = re.compile(
        rf"^{re.escape(start_marker)}\s*$\n(.*?)^{re.escape(end_marker)}\s*$",
        re.DOTALL | re.MULTILINE,
    )
    m = pattern.search(tex)
    if m:
        return m.group(1)
    logger.warning(f"Markers not found: {start_marker} ... {end_marker}")
    return ""


def _parse_sub_blocks(content: str, prefix: str) -> dict[str, str]:
    """Parse content into named blocks using sub-markers like % SKILL_CAT:name."""
    blocks = {}
    current_name = None
    current_lines = []

    for line in content.split("\n"):
        match = re.match(rf"^% {re.escape(prefix)}:(\S+)", line)
        if match:
            if current_name is not None:
                blocks[current_name] = "\n".join(current_lines)
            current_name = match.group(1)
            current_lines = []
        elif current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        blocks[current_name] = "\n".join(current_lines)

    return blocks


def parse_resume_sections(tex: str) -> ResumeSections:
    """Parse a .tex file into named sections.

    Args:
        tex: The LaTeX content to parse (with comment markers).

    Returns:
        {
            "summary": "AI/LLM Engineer and Full-Stack Developer...",
            "skills": {"languages": "\\skillline{...}", "backend": "...", ...},
            "experience": {"company": "\\experienceentry{...}", ...},
            "projects": {"project_name": "\\projectentry{...}", ...},
        }
    """
    sections: ResumeSections = {
        "summary": "",
        "skills": {},
        "experience": {},
        "projects": {},
    }

    sections["summary"] = extract_between_markers(tex, "% SUMMARY_START", "% SUMMARY_END").strip()

    skills_content = extract_between_markers(tex, "% SKILLS_START", "% SKILLS_END")
    sections["skills"] = _parse_sub_blocks(skills_content, "SKILL_CAT")

    exp_content = extract_between_markers(tex, "% EXPERIENCE_START", "% EXPERIENCE_END")
    sections["experience"] = _parse_sub_blocks(exp_content, "EXP")

    projects_content = extract_between_markers(tex, "% PROJECTS_START", "% PROJECTS_END")
    sections["projects"] = _parse_sub_blocks(projects_content, "PROJECT")

    logger.debug(
        f"Parsed: {len(sections['skills'])} skill cats, "
        f"{len(sections['projects'])} projects, "
        f"{len(sections['experience'])} experience entries"
    )

    return sections


def get_skills_on_resume(sections: ResumeSections) -> dict[str, list[str]]:
    """Extract the list of skill keywords currently on the resume per category.

    Parses the \\skillline{Category}{skill1, skill2, ...} lines.
    """
    skills_on_resume = {}
    for cat, content in sections.get("skills", {}).items():
        # Match the skills inside \skillline{...}{THESE SKILLS}
        m = re.search(r"\\skillline\{[^}]*\}\{([^}]*)\}", content)
        if m:
            raw = m.group(1)
            skills_on_resume[cat] = [s.strip() for s in raw.split(",") if s.strip()]
        else:
            skills_on_resume[cat] = []
    return skills_on_resume
