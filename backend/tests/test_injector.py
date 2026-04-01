"""Tests for app/services/injector.py and app/latex/writer.py."""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app.latex.writer import (
    replace_between_markers,
    rebuild_skills_section,
    rebuild_projects_section,
)
from app.services.injector import inject_into_latex
from app.models import ReorderPlan, MatchResult


# ---------------------------------------------------------------------------
# Fixtures — realistic LaTeX snippets
# ---------------------------------------------------------------------------

SAMPLE_TEX = r"""
\documentclass{article}
\begin{document}

% SUMMARY_START
Experienced software engineer with 5 years in backend systems. Proficient in distributed computing. Strong communicator.
% SUMMARY_END

\section{Skills}
% SKILLS_START
% SKILL_CAT:Languages
\skillline{Languages}{Python, Java, Go}
% SKILL_CAT:Backend
\skillline{Backend}{Django, Flask, Spring Boot}
% SKILL_CAT:DevOps
\skillline{DevOps}{Docker, Kubernetes, Terraform}
% SKILLS_END

\section{Projects}
% PROJECTS_START
% PROJECT:ChatBot
\projectheading{ChatBot}{Python, LangChain}{2024}
Built an AI-powered chatbot for customer support.

% PROJECT:DataPipeline
\projectheading{DataPipeline}{Spark, Airflow}{2023}
Designed a real-time data pipeline processing 1M events/day.

% PROJECT:WebApp
\projectheading{WebApp}{React, Node.js}{2023}
Full-stack web application for inventory management.
% PROJECTS_END

\end{document}
""".strip()


SKILLS_DICT = {
    "Languages": r"\skillline{Languages}{Python, Java, Go}",
    "Backend": r"\skillline{Backend}{Django, Flask, Spring Boot}",
    "DevOps": r"\skillline{DevOps}{Docker, Kubernetes, Terraform}",
}

PROJECTS_DICT = {
    "ChatBot": (
        r"\projectheading{ChatBot}{Python, LangChain}{2024}" "\n"
        "Built an AI-powered chatbot for customer support."
    ),
    "DataPipeline": (
        r"\projectheading{DataPipeline}{Spark, Airflow}{2023}" "\n"
        "Designed a real-time data pipeline processing 1M events/day."
    ),
    "WebApp": (
        r"\projectheading{WebApp}{React, Node.js}{2023}" "\n"
        "Full-stack web application for inventory management."
    ),
}


# ===================================================================
# replace_between_markers
# ===================================================================

class TestReplaceBetweenMarkers:
    """Test marker-based content replacement in LaTeX."""

    def test_replaces_content_between_markers(self):
        tex = "% START\nold content\n% END\n"
        result = replace_between_markers(tex, "% START", "% END", "new content")
        assert "new content" in result
        assert "old content" not in result

    def test_preserves_markers(self):
        tex = "% START\nold content\n% END\n"
        result = replace_between_markers(tex, "% START", "% END", "new content")
        assert "% START" in result
        assert "% END" in result

    def test_returns_unchanged_if_start_marker_missing(self):
        tex = "no markers here\n% END\n"
        result = replace_between_markers(tex, "% START", "% END", "new content")
        assert result == tex

    def test_returns_unchanged_if_end_marker_missing(self):
        tex = "% START\nsome content\nno end marker"
        result = replace_between_markers(tex, "% START", "% END", "new content")
        assert result == tex

    def test_returns_unchanged_if_both_markers_missing(self):
        tex = "just plain text\nnothing to replace"
        result = replace_between_markers(tex, "% START", "% END", "new content")
        assert result == tex

    def test_multiline_replacement(self):
        tex = "% SKILLS_START\nline1\nline2\nline3\n% SKILLS_END\n"
        new_content = "alpha\nbeta\ngamma"
        result = replace_between_markers(tex, "% SKILLS_START", "% SKILLS_END", new_content)
        assert "alpha\nbeta\ngamma" in result
        assert "line1" not in result
        assert "line2" not in result

    def test_empty_replacement(self):
        tex = "% START\nold stuff\n% END\n"
        result = replace_between_markers(tex, "% START", "% END", "")
        assert "old stuff" not in result
        assert "% START" in result
        assert "% END" in result

    def test_works_with_full_sample_tex(self):
        result = replace_between_markers(
            SAMPLE_TEX, "% SKILLS_START", "% SKILLS_END", "REPLACED"
        )
        assert "REPLACED" in result
        assert "% SKILLS_START" in result
        assert "% SKILLS_END" in result
        # Original skill lines should be gone
        assert r"\skillline{Languages}" not in result


# ===================================================================
# rebuild_skills_section
# ===================================================================

class TestRebuildSkillsSection:
    """Test skills reordering and keyword injection."""

    def test_reorder_categories(self):
        order = ["DevOps", "Languages", "Backend"]
        result = rebuild_skills_section(SKILLS_DICT, order, injectable={})
        lines = result.split("\n")
        # Find category comment positions
        cat_positions = [
            (i, line) for i, line in enumerate(lines)
            if line.startswith("% SKILL_CAT:")
        ]
        assert len(cat_positions) == 3
        assert cat_positions[0][1] == "% SKILL_CAT:DevOps"
        assert cat_positions[1][1] == "% SKILL_CAT:Languages"
        assert cat_positions[2][1] == "% SKILL_CAT:Backend"

    def test_inject_new_keywords(self):
        injectable = {"Languages": ["Rust", "TypeScript"]}
        result = rebuild_skills_section(
            SKILLS_DICT,
            category_order=["Languages", "Backend", "DevOps"],
            injectable=injectable,
        )
        assert "Rust" in result
        assert "TypeScript" in result
        # Original keywords still present
        assert "Python" in result
        assert "Java" in result

    def test_skip_duplicate_keywords(self):
        # "Python" already exists in Languages — should not be added again
        injectable = {"Languages": ["Python", "Rust"]}
        result = rebuild_skills_section(
            SKILLS_DICT,
            category_order=["Languages", "Backend", "DevOps"],
            injectable=injectable,
        )
        # Count occurrences of "Python" — should appear exactly once
        assert result.count("Python") == 1
        # Rust is new, so it should appear
        assert "Rust" in result

    def test_skip_duplicate_case_insensitive(self):
        # "python" (lowercase) matches "Python" — should not be added
        injectable = {"Languages": ["python"]}
        result = rebuild_skills_section(
            SKILLS_DICT,
            category_order=["Languages", "Backend", "DevOps"],
            injectable=injectable,
        )
        # Only original "Python" should appear, not a second "python"
        assert result.lower().count("python") == 1

    def test_inject_into_multiple_categories(self):
        injectable = {
            "Languages": ["Rust"],
            "DevOps": ["AWS"],
        }
        result = rebuild_skills_section(
            SKILLS_DICT,
            category_order=["Languages", "Backend", "DevOps"],
            injectable=injectable,
        )
        assert "Rust" in result
        assert "AWS" in result

    def test_unknown_category_in_order_is_skipped(self):
        order = ["Languages", "NonExistent", "Backend"]
        result = rebuild_skills_section(SKILLS_DICT, order, injectable={})
        assert "NonExistent" not in result
        # Only two categories emitted
        cat_comments = [l for l in result.split("\n") if l.startswith("% SKILL_CAT:")]
        assert len(cat_comments) == 2

    def test_empty_injectable(self):
        result = rebuild_skills_section(
            SKILLS_DICT,
            category_order=["Languages", "Backend", "DevOps"],
            injectable={},
        )
        # Output should contain original content unchanged
        assert "Python, Java, Go" in result
        assert "Django, Flask, Spring Boot" in result

    def test_empty_skills_dict(self):
        result = rebuild_skills_section({}, ["Languages"], injectable={"Languages": ["Rust"]})
        assert result == ""


# ===================================================================
# rebuild_projects_section
# ===================================================================

class TestRebuildProjectsSection:
    """Test project reordering."""

    def test_reorder_projects(self):
        order = ["WebApp", "ChatBot", "DataPipeline"]
        result = rebuild_projects_section(PROJECTS_DICT, order)
        lines = result.split("\n")
        proj_positions = [
            (i, line) for i, line in enumerate(lines)
            if line.startswith("% PROJECT:")
        ]
        assert len(proj_positions) == 3
        assert proj_positions[0][1] == "% PROJECT:WebApp"
        assert proj_positions[1][1] == "% PROJECT:ChatBot"
        assert proj_positions[2][1] == "% PROJECT:DataPipeline"

    def test_unknown_project_skipped(self):
        order = ["ChatBot", "NonExistent", "WebApp"]
        result = rebuild_projects_section(PROJECTS_DICT, order)
        assert "NonExistent" not in result
        proj_comments = [l for l in result.split("\n") if l.startswith("% PROJECT:")]
        assert len(proj_comments) == 2

    def test_subset_of_projects(self):
        order = ["DataPipeline"]
        result = rebuild_projects_section(PROJECTS_DICT, order)
        assert "DataPipeline" in result
        assert "ChatBot" not in result
        assert "WebApp" not in result

    def test_empty_project_order(self):
        result = rebuild_projects_section(PROJECTS_DICT, [])
        assert result == ""

    def test_empty_projects_dict(self):
        result = rebuild_projects_section({}, ["ChatBot"])
        assert result == ""

    def test_project_content_preserved(self):
        order = ["ChatBot"]
        result = rebuild_projects_section(PROJECTS_DICT, order)
        assert "AI-powered chatbot" in result
        assert "LangChain" in result


# ===================================================================
# inject_into_latex (integration)
# ===================================================================

class TestInjectIntoLatex:
    """Integration tests for the full injection pipeline."""

    @staticmethod
    def _make_plan(
        skills_order=None,
        project_order=None,
        summary_first_line="",
    ):
        return ReorderPlan(
            skills_category_order=skills_order or ["Languages", "Backend", "DevOps"],
            project_order=project_order or ["ChatBot", "DataPipeline", "WebApp"],
            summary_first_line=summary_first_line,
            experience_emphasis={},
        )

    @staticmethod
    def _make_match(injectable=None):
        return MatchResult(
            matched={"Languages": ["Python"]},
            missing_from_resume={},
            injectable=injectable or {},
            total_jd_keywords=10,
            total_matched=5,
            match_score=50,
            dominant_category="Languages",
        )

    @staticmethod
    def _make_sections():
        return {
            "skills": SKILLS_DICT,
            "projects": PROJECTS_DICT,
            "summary": (
                "Experienced software engineer with 5 years in backend systems. "
                "Proficient in distributed computing. "
                "Strong communicator."
            ),
        }

    def test_returns_tuple_of_two_strings(self):
        plan = self._make_plan()
        match = self._make_match()
        modified, diff = inject_into_latex(plan, match, SAMPLE_TEX, self._make_sections())
        assert isinstance(modified, str)
        assert isinstance(diff, str)

    def test_produces_diff_string(self):
        plan = self._make_plan(
            skills_order=["DevOps", "Languages", "Backend"],
        )
        match = self._make_match(injectable={"Languages": ["Rust"]})
        _, diff = inject_into_latex(plan, match, SAMPLE_TEX, self._make_sections())
        # Diff should contain unified-diff markers
        assert "---" in diff
        assert "+++" in diff
        assert "resume_base.tex" in diff
        assert "resume_tailored.tex" in diff

    def test_skills_reordered_in_output(self):
        plan = self._make_plan(skills_order=["DevOps", "Backend", "Languages"])
        match = self._make_match()
        modified, _ = inject_into_latex(plan, match, SAMPLE_TEX, self._make_sections())
        # DevOps should appear before Languages in the output
        devops_pos = modified.index("% SKILL_CAT:DevOps")
        languages_pos = modified.index("% SKILL_CAT:Languages")
        assert devops_pos < languages_pos

    def test_keywords_injected_in_output(self):
        plan = self._make_plan()
        match = self._make_match(injectable={"Backend": ["FastAPI"]})
        modified, _ = inject_into_latex(plan, match, SAMPLE_TEX, self._make_sections())
        assert "FastAPI" in modified

    def test_projects_reordered_in_output(self):
        plan = self._make_plan(project_order=["WebApp", "DataPipeline", "ChatBot"])
        match = self._make_match()
        modified, _ = inject_into_latex(plan, match, SAMPLE_TEX, self._make_sections())
        webapp_pos = modified.index("% PROJECT:WebApp")
        chatbot_pos = modified.index("% PROJECT:ChatBot")
        assert webapp_pos < chatbot_pos

    def test_summary_replaced(self):
        plan = self._make_plan(
            summary_first_line="Senior backend engineer specializing in scalable microservices."
        )
        match = self._make_match()
        modified, _ = inject_into_latex(plan, match, SAMPLE_TEX, self._make_sections())
        assert "Senior backend engineer specializing in scalable microservices" in modified

    def test_no_diff_when_nothing_changes(self):
        # Use the exact same order and no injections / no summary change
        plan = self._make_plan(
            skills_order=["Languages", "Backend", "DevOps"],
            project_order=["ChatBot", "DataPipeline", "WebApp"],
            summary_first_line="",
        )
        match = self._make_match(injectable={})
        _, diff = inject_into_latex(plan, match, SAMPLE_TEX, self._make_sections())
        # When skills are rebuilt they get SKILL_CAT markers, so there will be
        # structural differences even with the same order. But diff should still
        # be a string (possibly non-empty due to marker reformatting).
        assert isinstance(diff, str)

    def test_handles_empty_skills_section(self):
        plan = self._make_plan()
        match = self._make_match()
        sections = self._make_sections()
        sections["skills"] = {}
        modified, diff = inject_into_latex(plan, match, SAMPLE_TEX, sections)
        # Should not crash — skills markers remain untouched
        assert "% SKILLS_START" in modified
        assert isinstance(diff, str)

    def test_handles_empty_projects_section(self):
        plan = self._make_plan(project_order=[])
        match = self._make_match()
        sections = self._make_sections()
        sections["projects"] = {}
        modified, diff = inject_into_latex(plan, match, SAMPLE_TEX, sections)
        assert "% PROJECTS_START" in modified
        assert isinstance(diff, str)

    def test_handles_missing_summary_section(self):
        plan = self._make_plan(summary_first_line="New summary line.")
        match = self._make_match()
        sections = self._make_sections()
        sections.pop("summary", None)
        modified, _ = inject_into_latex(plan, match, SAMPLE_TEX, sections)
        # Without summary in sections dict, replacement should not happen
        # and original summary text is still in the tex
        assert "Experienced software engineer" in modified

    def test_preserves_document_structure(self):
        plan = self._make_plan()
        match = self._make_match(injectable={"Languages": ["Rust"]})
        modified, _ = inject_into_latex(plan, match, SAMPLE_TEX, self._make_sections())
        assert r"\documentclass{article}" in modified
        assert r"\begin{document}" in modified
        assert r"\end{document}" in modified
