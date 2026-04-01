"""Tests for the /api/tailor endpoint.

All LLM-dependent services are mocked — these test request validation,
error handling, and response shape without making real API calls.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from io import BytesIO
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models import ResumeAnalysis, ExtractedKeywords, MatchResult, ReorderPlan
from tests.conftest import SAMPLE_TEX, SAMPLE_JD


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tex_upload(content: str = SAMPLE_TEX, filename: str = "resume.tex") -> dict:
    """Build the multipart file dict for httpx."""
    return {"resume_file": (filename, BytesIO(content.encode()), "application/x-tex")}


def _form_data(jd_text: str = SAMPLE_JD, **extra) -> dict:
    """Build form data dict for the endpoint."""
    data = {"jd_text": jd_text}
    data.update(extra)
    return data


# ---------------------------------------------------------------------------
# Mock return values
# ---------------------------------------------------------------------------

MOCK_ANALYSIS = ResumeAnalysis(
    marked_tex=SAMPLE_TEX,
    skills={"languages": ["Python"], "backend": ["Django", "FastAPI"]},
    sections_found=["summary", "skills", "projects"],
    person_name="Jane Doe",
)

MOCK_EXTRACTED = ExtractedKeywords(
    languages=["Python"],
    backend=["Django", "FastAPI"],
    devops=["Docker"],
    role_title="Backend Engineer",
)

MOCK_MATCH = MatchResult(
    matched={"backend": ["Django", "FastAPI"], "languages": ["Python"]},
    missing_from_resume={"devops": ["Docker"]},
    injectable={},
    total_jd_keywords=4,
    total_matched=3,
    match_score=75,
    dominant_category="backend",
)

MOCK_PLAN = ReorderPlan(
    skills_category_order=["backend", "languages"],
    project_order=["resume_tailor"],
    summary_first_line="Backend Engineer with hands-on expertise in Django, FastAPI, Python.",
    experience_emphasis={},
)


def _patch_all():
    """Return a dict of patches for all external dependencies."""
    return {
        "analyze": patch(
            "app.routes.tailor.analyze_uploaded_resume",
            new_callable=AsyncMock,
            return_value=MOCK_ANALYSIS,
        ),
        "extract": patch(
            "app.routes.tailor.extract_keywords",
            new_callable=AsyncMock,
            return_value=MOCK_EXTRACTED,
        ),
        "match": patch(
            "app.routes.tailor.match_keywords",
            new_callable=AsyncMock,
            return_value=MOCK_MATCH,
        ),
        "reorder": patch(
            "app.routes.tailor.compute_reorder_plan",
            return_value=MOCK_PLAN,
        ),
        "inject": patch(
            "app.routes.tailor.inject_into_latex",
            return_value=(SAMPLE_TEX, "--- diff ---"),
        ),
        "compile": patch(
            "app.routes.tailor.compile_pdf",
            return_value=("Jane_Doe_Backend_abc123.pdf", b"%PDF-fake"),
        ),
        "flush": patch("app.routes.tailor.flush"),
    }


# ---------------------------------------------------------------------------
# Tests — Validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestEndpointValidation:
    """Request validation tests — no mocks needed for most of these."""

    async def test_missing_file_returns_422(self):
        """No resume_file attached → 422."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/tailor", data=_form_data())
        assert resp.status_code == 422

    async def test_non_tex_file_returns_400(self):
        """A .pdf upload → 400."""
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(),
                    files=_tex_upload(filename="resume.pdf"),
                )
        assert resp.status_code == 400
        assert "tex" in resp.json()["detail"].lower()

    async def test_empty_jd_returns_422(self):
        """JD shorter than min_length → 422."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/tailor",
                data=_form_data(jd_text="too short"),
                files=_tex_upload(),
            )
        assert resp.status_code == 422

    async def test_tiny_tex_returns_400(self):
        """A .tex file with almost no content → 400."""
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(),
                    files=_tex_upload(content="hi"),
                )
        assert resp.status_code == 400
        assert "small" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Tests — Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestEndpointHappyPath:
    """Full pipeline with all services mocked."""

    async def test_successful_tailor_returns_200(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(job_title="Backend Engineer", company_name="Acme"),
                    files=_tex_upload(),
                )
        assert resp.status_code == 200

    async def test_response_contains_expected_fields(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        body = resp.json()
        assert "extracted" in body
        assert "match" in body
        assert "reorder_plan" in body
        assert "pdf_url" in body
        assert "tex_diff" in body
        assert "processing_time_ms" in body

    async def test_match_score_in_response(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        body = resp.json()
        assert body["match"]["match_score"] == 75

    async def test_pdf_url_in_response(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        body = resp.json()
        assert body["pdf_url"].endswith(".pdf")


# ---------------------------------------------------------------------------
# Tests — Service failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestEndpointServiceFailures:
    """When individual pipeline steps fail, the endpoint should return 500."""

    async def test_analysis_failure_returns_500(self):
        patches = _patch_all()
        with patch(
            "app.routes.tailor.analyze_uploaded_resume",
            new_callable=AsyncMock,
            return_value=None,
        ), patches["extract"], patches["match"], patches["reorder"], \
             patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        assert resp.status_code == 500
        assert "analysis" in resp.json()["detail"].lower()

    async def test_extraction_failure_returns_500(self):
        patches = _patch_all()
        with patches["analyze"], patch(
            "app.routes.tailor.extract_keywords",
            new_callable=AsyncMock,
            return_value=None,
        ), patches["match"], patches["reorder"], patches["inject"], \
             patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        assert resp.status_code == 500
        assert "extraction" in resp.json()["detail"].lower()

    async def test_match_failure_returns_500(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patch(
            "app.routes.tailor.match_keywords",
            new_callable=AsyncMock,
            return_value=None,
        ), patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        assert resp.status_code == 500
        assert "matching" in resp.json()["detail"].lower()

    async def test_compile_failure_still_returns_200(self):
        """PDF compilation failure is non-fatal — endpoint returns data without PDF."""
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patch(
                 "app.routes.tailor.compile_pdf",
                 side_effect=RuntimeError("pdflatex not found"),
             ), patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        assert resp.status_code == 200
        body = resp.json()
        assert body["pdf_url"] == ""
        assert body["pdf_b64"] == ""

    async def test_injection_failure_returns_500(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patch(
                 "app.routes.tailor.inject_into_latex",
                 side_effect=ValueError("Bad LaTeX"),
             ), patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        assert resp.status_code == 500
        assert "latex" in resp.json()["detail"].lower()
