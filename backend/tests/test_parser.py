"""Comprehensive tests for app.latex.parser module."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app.latex.parser import (
    _parse_sub_blocks,
    extract_between_markers,
    get_skills_on_resume,
    parse_resume_sections,
)

# ---------------------------------------------------------------------------
# Realistic .tex fixture
# ---------------------------------------------------------------------------

SAMPLE_TEX = r"""
\documentclass[letterpaper,11pt]{article}
\usepackage{geometry}
\begin{document}

\name{Jane Doe}
\email{jane@example.com}

% SUMMARY_START
AI/LLM Engineer and Full-Stack Developer with 4+ years of experience
building scalable web applications and integrating large-language-model
pipelines into production systems.
% SUMMARY_END

\section{Technical Skills}
% SKILLS_START
% SKILL_CAT:languages
\skillline{Languages}{Python, JavaScript, TypeScript, Go}
% SKILL_CAT:backend
\skillline{Backend}{Django, FastAPI, Flask, Node.js}
% SKILL_CAT:frontend
\skillline{Frontend}{React, Next.js, Tailwind CSS}
% SKILL_CAT:devops
\skillline{DevOps}{Docker, Kubernetes, GitHub Actions, Terraform}
% SKILLS_END

\section{Projects}
% PROJECTS_START
% PROJECT:resume_tailor
\projectentry{Resume Tailor}{Python, FastAPI, React}
{An AI-powered tool that tailors resumes to specific job descriptions.}

% PROJECT:job_tracker
\projectentry{Job Tracker}{Django, PostgreSQL, Celery}
{A full-stack application for tracking job applications and interviews.}
% PROJECTS_END

\section{Experience}
% EXPERIENCE_START
% EXP:zelthy
\experienceentry{Zelthy}{Software Engineer}{Jan 2022 -- Present}
{Built microservices platform handling 10k RPM with 99.9\% uptime.}

% EXP:acme
\experienceentry{Acme Corp}{Junior Developer}{Jun 2020 -- Dec 2021}
{Developed internal tooling and REST APIs for the data science team.}
% EXPERIENCE_END

\end{document}
""".lstrip()

# ---------------------------------------------------------------------------
# Partial .tex -- missing PROJECTS and EXPERIENCE sections entirely
# ---------------------------------------------------------------------------

PARTIAL_TEX = r"""
\begin{document}
% SUMMARY_START
Backend developer with distributed-systems expertise.
% SUMMARY_END

% SKILLS_START
% SKILL_CAT:languages
\skillline{Languages}{Rust, Python}
% SKILLS_END
\end{document}
""".lstrip()


# ===================================================================
# Tests for extract_between_markers
# ===================================================================


class TestExtractBetweenMarkers:
    """Tests for the extract_between_markers helper."""

    def test_found_returns_content_between_markers(self):
        """Content between existing markers is returned verbatim."""
        result = extract_between_markers(SAMPLE_TEX, "% SUMMARY_START", "% SUMMARY_END")
        assert "AI/LLM Engineer" in result
        assert "production systems." in result

    def test_found_excludes_markers_themselves(self):
        """The marker lines themselves must not appear in the output."""
        result = extract_between_markers(SAMPLE_TEX, "% SUMMARY_START", "% SUMMARY_END")
        assert "% SUMMARY_START" not in result
        assert "% SUMMARY_END" not in result

    def test_not_found_returns_empty_string(self):
        """Missing markers yield an empty string."""
        result = extract_between_markers(SAMPLE_TEX, "% NONEXISTENT_START", "% NONEXISTENT_END")
        assert result == ""

    def test_mismatched_markers_returns_empty(self):
        """A valid start with an invalid end should return empty."""
        result = extract_between_markers(SAMPLE_TEX, "% SUMMARY_START", "% BOGUS_END")
        assert result == ""

    def test_multiple_matches_returns_first(self):
        """When duplicated marker pairs exist, only the first match is used."""
        tex_with_dups = (
            "% BLOCK_START\nfirst block\n% BLOCK_END\n"
            "some filler\n"
            "% BLOCK_START\nsecond block\n% BLOCK_END\n"
        )
        result = extract_between_markers(tex_with_dups, "% BLOCK_START", "% BLOCK_END")
        assert "first block" in result
        assert "second block" not in result

    def test_multiline_content_preserved(self):
        """Content spanning multiple lines is captured intact."""
        result = extract_between_markers(SAMPLE_TEX, "% SKILLS_START", "% SKILLS_END")
        lines = result.strip().splitlines()
        # Should contain all SKILL_CAT sub-markers and \skillline entries
        assert len(lines) >= 8

    def test_empty_content_between_markers(self):
        """Markers with nothing between them return an empty/whitespace string."""
        tex = "% START\n% END\n"
        result = extract_between_markers(tex, "% START", "% END")
        assert result.strip() == ""

    def test_markers_with_trailing_whitespace(self):
        """Markers followed by trailing spaces still match (regex \\s*)."""
        tex = "% START   \ncontent here\n% END   \n"
        result = extract_between_markers(tex, "% START", "% END")
        assert "content here" in result


# ===================================================================
# Tests for _parse_sub_blocks
# ===================================================================


class TestParseSubBlocks:
    """Tests for the _parse_sub_blocks internal helper."""

    def test_single_block(self):
        """A single sub-marker produces one named block."""
        content = "% PREFIX:alpha\nline one\nline two\n"
        blocks = _parse_sub_blocks(content, "PREFIX")
        assert "alpha" in blocks
        assert "line one" in blocks["alpha"]
        assert "line two" in blocks["alpha"]

    def test_multiple_blocks(self):
        """Multiple sub-markers split content into separate named blocks."""
        content = (
            "% CAT:first\nA\nB\n"
            "% CAT:second\nC\nD\n"
            "% CAT:third\nE\n"
        )
        blocks = _parse_sub_blocks(content, "CAT")
        assert len(blocks) == 3
        assert "A" in blocks["first"]
        assert "C" in blocks["second"]
        assert "E" in blocks["third"]

    def test_empty_content(self):
        """Empty content string produces an empty dict."""
        blocks = _parse_sub_blocks("", "ANYTHING")
        assert blocks == {}

    def test_no_matching_prefix(self):
        """Content with no matching prefix returns empty dict."""
        content = "% OTHER:alpha\nsome data\n"
        blocks = _parse_sub_blocks(content, "NOMATCH")
        assert blocks == {}

    def test_lines_before_first_marker_ignored(self):
        """Lines appearing before the first sub-marker are discarded."""
        content = "orphan line\n% TAG:first\nkept line\n"
        blocks = _parse_sub_blocks(content, "TAG")
        assert "first" in blocks
        assert "orphan line" not in blocks.get("first", "")
        assert "kept line" in blocks["first"]

    def test_block_content_preserves_empty_lines(self):
        """Empty lines within a block are preserved in the output."""
        content = "% BLK:a\nline1\n\nline3\n"
        blocks = _parse_sub_blocks(content, "BLK")
        lines = blocks["a"].split("\n")
        assert "" in lines  # The empty line is retained

    def test_sub_marker_name_is_exact(self):
        """Only the non-whitespace token after the colon is the block name."""
        content = "% X:my_block_123\ndata\n"
        blocks = _parse_sub_blocks(content, "X")
        assert "my_block_123" in blocks

    def test_real_skills_content(self):
        """Parse actual SKILL_CAT blocks extracted from the sample .tex."""
        skills_raw = extract_between_markers(SAMPLE_TEX, "% SKILLS_START", "% SKILLS_END")
        blocks = _parse_sub_blocks(skills_raw, "SKILL_CAT")
        assert set(blocks.keys()) == {"languages", "backend", "frontend", "devops"}
        assert r"\skillline" in blocks["languages"]


# ===================================================================
# Tests for parse_resume_sections
# ===================================================================


class TestParseResumeSections:
    """Tests for the top-level parse_resume_sections function."""

    def test_full_tex_has_all_keys(self):
        """A complete .tex produces summary, skills, experience, projects."""
        sections = parse_resume_sections(SAMPLE_TEX)
        assert set(sections.keys()) == {"summary", "skills", "experience", "projects"}

    def test_summary_is_plain_text(self):
        """Summary should be a stripped string, not a dict."""
        sections = parse_resume_sections(SAMPLE_TEX)
        assert isinstance(sections["summary"], str)
        assert sections["summary"].startswith("AI/LLM Engineer")

    def test_skills_parsed_into_categories(self):
        """Skills section must be a dict keyed by category name."""
        sections = parse_resume_sections(SAMPLE_TEX)
        assert isinstance(sections["skills"], dict)
        assert "languages" in sections["skills"]
        assert "backend" in sections["skills"]
        assert "frontend" in sections["skills"]
        assert "devops" in sections["skills"]

    def test_experience_parsed_into_entries(self):
        """Experience section must be a dict keyed by company/entry name."""
        sections = parse_resume_sections(SAMPLE_TEX)
        assert isinstance(sections["experience"], dict)
        assert "zelthy" in sections["experience"]
        assert "acme" in sections["experience"]

    def test_projects_parsed_into_entries(self):
        """Projects section must be a dict keyed by project name."""
        sections = parse_resume_sections(SAMPLE_TEX)
        assert isinstance(sections["projects"], dict)
        assert "resume_tailor" in sections["projects"]
        assert "job_tracker" in sections["projects"]

    def test_experience_content_contains_latex(self):
        """Each experience block should contain the experienceentry command."""
        sections = parse_resume_sections(SAMPLE_TEX)
        assert r"\experienceentry" in sections["experience"]["zelthy"]

    def test_projects_content_contains_latex(self):
        """Each project block should contain the projectentry command."""
        sections = parse_resume_sections(SAMPLE_TEX)
        assert r"\projectentry" in sections["projects"]["resume_tailor"]

    def test_partial_tex_missing_sections(self):
        """A .tex missing PROJECTS and EXPERIENCE yields empty dicts for those."""
        sections = parse_resume_sections(PARTIAL_TEX)
        assert sections["summary"] == "Backend developer with distributed-systems expertise."
        assert isinstance(sections["skills"], dict)
        assert len(sections["skills"]) == 1
        assert sections["experience"] == {}
        assert sections["projects"] == {}

    def test_empty_tex_gives_empty_everything(self):
        """An empty string produces empty summary and empty sub-dicts."""
        sections = parse_resume_sections("")
        assert sections["summary"] == ""
        assert sections["skills"] == {}
        assert sections["experience"] == {}
        assert sections["projects"] == {}


# ===================================================================
# Tests for get_skills_on_resume
# ===================================================================


class TestGetSkillsOnResume:
    """Tests for extracting skill keyword lists from parsed sections."""

    @pytest.fixture()
    def full_sections(self):
        """Pre-parsed sections from the full sample .tex."""
        return parse_resume_sections(SAMPLE_TEX)

    def test_normal_skills_extraction(self, full_sections):
        """Skills are split on commas and stripped of whitespace."""
        skills = get_skills_on_resume(full_sections)
        assert "languages" in skills
        assert skills["languages"] == ["Python", "JavaScript", "TypeScript", "Go"]

    def test_all_categories_present(self, full_sections):
        """Every SKILL_CAT category appears as a key in the result."""
        skills = get_skills_on_resume(full_sections)
        assert set(skills.keys()) == {"languages", "backend", "frontend", "devops"}

    def test_backend_skills(self, full_sections):
        """Verify backend category has the expected frameworks."""
        skills = get_skills_on_resume(full_sections)
        assert skills["backend"] == ["Django", "FastAPI", "Flask", "Node.js"]

    def test_frontend_skills(self, full_sections):
        """Verify frontend category has the expected libraries."""
        skills = get_skills_on_resume(full_sections)
        assert skills["frontend"] == ["React", "Next.js", "Tailwind CSS"]

    def test_empty_categories_return_empty_list(self):
        """A category whose content has no \\skillline match yields []."""
        sections = {
            "skills": {
                "misc": "% just a comment, no skillline here\n",
            }
        }
        skills = get_skills_on_resume(sections)
        assert skills["misc"] == []

    def test_no_skillline_match_at_all(self):
        """Content without any \\skillline command yields empty list."""
        sections = {
            "skills": {
                "tools": "Some plain text without the expected pattern.",
            }
        }
        skills = get_skills_on_resume(sections)
        assert skills["tools"] == []

    def test_no_skills_section_returns_empty_dict(self):
        """Sections dict lacking a 'skills' key returns {}."""
        skills = get_skills_on_resume({})
        assert skills == {}

    def test_empty_skills_dict_returns_empty(self):
        """An empty skills dict produces an empty result."""
        skills = get_skills_on_resume({"skills": {}})
        assert skills == {}

    def test_skillline_with_single_skill(self):
        """A skillline containing exactly one skill (no comma) is handled."""
        sections = {
            "skills": {
                "niche": r"\skillline{Niche}{Cobol}",
            }
        }
        skills = get_skills_on_resume(sections)
        assert skills["niche"] == ["Cobol"]

    def test_skillline_with_extra_whitespace(self):
        """Extra spaces around commas are stripped cleanly."""
        sections = {
            "skills": {
                "langs": r"\skillline{Languages}{  Python ,  Rust  ,Go  }",
            }
        }
        skills = get_skills_on_resume(sections)
        assert skills["langs"] == ["Python", "Rust", "Go"]

    def test_skillline_empty_braces(self):
        """A skillline with empty braces yields an empty list."""
        sections = {
            "skills": {
                "empty": r"\skillline{Empty}{}",
            }
        }
        skills = get_skills_on_resume(sections)
        assert skills["empty"] == []
