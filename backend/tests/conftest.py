"""Shared fixtures for resume-tailor backend tests."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app.main import app
from app.routes import tailor as tailor_route


@pytest.fixture(autouse=True)
def _disable_rate_limiter():
    """Disable slowapi rate limiting for all tests."""
    app.state.limiter.enabled = False
    tailor_route.limiter.enabled = False
    yield
    app.state.limiter.enabled = True
    tailor_route.limiter.enabled = True


@pytest.fixture(autouse=True)
def _clear_llm_caches():
    """Clear in-memory LLM caches between tests to prevent interference."""
    from app.services.resume_analyzer import _analysis_cache
    from app.services.extractor import _extraction_cache
    _analysis_cache.clear()
    _extraction_cache.clear()
    yield
    _analysis_cache.clear()
    _extraction_cache.clear()


from app.models import (
    ExtractedKeywords,
    MatchResult,
    ReorderPlan,
    ResumeAnalysis,
)


# ---------------------------------------------------------------------------
# Sample .tex content for endpoint + integration tests
# ---------------------------------------------------------------------------

SAMPLE_TEX = r"""
\documentclass[letterpaper,11pt]{article}
\begin{document}

\name{Jane Doe}
\email{jane@example.com}

% SUMMARY_START
AI/LLM Engineer with 4+ years of experience.
% SUMMARY_END

\section{Technical Skills}
% SKILLS_START
% SKILL_CAT:languages
\skillline{Languages}{Python, JavaScript, TypeScript}
% SKILL_CAT:backend
\skillline{Backend}{Django, FastAPI, Flask}
% SKILLS_END

\section{Projects}
% PROJECTS_START
% PROJECT:resume_tailor
\projectentry{Resume Tailor}{Python, FastAPI}
{An AI-powered resume tailoring tool.}
% PROJECTS_END

\end{document}
""".strip()


SAMPLE_JD = (
    "We are looking for a Senior Backend Engineer with experience in Python, "
    "Django, FastAPI, PostgreSQL, Docker, and Kubernetes. "
    "You will build scalable microservices and collaborate with cross-functional teams."
)


# ---------------------------------------------------------------------------
# Model fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_analysis():
    """A realistic ResumeAnalysis from Step 0."""
    return ResumeAnalysis(
        marked_tex=SAMPLE_TEX,
        skills={
            "languages": ["Python", "JavaScript", "TypeScript"],
            "backend": ["Django", "FastAPI", "Flask"],
        },
        sections_found=["summary", "skills", "projects"],
        person_name="Jane Doe",
    )


@pytest.fixture()
def sample_extracted():
    """A realistic ExtractedKeywords from Step 1."""
    return ExtractedKeywords(
        languages=["Python"],
        backend=["Django", "FastAPI"],
        frontend=[],
        ai_llm=[],
        databases=["PostgreSQL"],
        devops=["Docker", "Kubernetes"],
        soft_skills=[],
        domains=[],
        role_title="Senior Backend Engineer",
        experience_level="senior",
    )


@pytest.fixture()
def sample_match():
    """A realistic MatchResult from Step 2."""
    return MatchResult(
        matched={"backend": ["Django", "FastAPI"], "languages": ["Python"]},
        missing_from_resume={"devops": ["Docker", "Kubernetes"]},
        injectable={"databases": ["PostgreSQL"]},
        total_jd_keywords=6,
        total_matched=3,
        match_score=50,
        dominant_category="backend",
    )


@pytest.fixture()
def sample_reorder_plan():
    """A realistic ReorderPlan from Step 3."""
    return ReorderPlan(
        skills_category_order=["backend", "languages"],
        project_order=["resume_tailor"],
        summary_first_line="Senior Backend Engineer with hands-on expertise in Django, FastAPI, Python.",
        experience_emphasis={},
    )
