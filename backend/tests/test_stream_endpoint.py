"""Tests for the /api/tailor-stream SSE endpoint.

Reuses mock patterns from test_endpoint.py. Verifies that:
- Validation errors return normal HTTP responses (not SSE)
- Happy path emits progress + complete events
- Service failures emit error events
- PDF compile failure is non-fatal (emits complete)
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from io import BytesIO
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models import ResumeAnalysis, ExtractedKeywords, MatchResult, ReorderPlan
from tests.conftest import SAMPLE_TEX, SAMPLE_JD


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tex_upload(content: str = SAMPLE_TEX, filename: str = "resume.tex") -> dict:
    return {"resume_file": (filename, BytesIO(content.encode()), "application/x-tex")}


def _form_data(jd_text: str = SAMPLE_JD, **extra) -> dict:
    data = {"jd_text": jd_text}
    data.update(extra)
    return data


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


def _parse_sse_events(raw_text: str) -> list[dict]:
    """Parse SSE event text into a list of {event, data} dicts."""
    events = []
    for block in raw_text.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        event_type = None
        data_str = ""
        for line in block.split("\n"):
            if line.startswith("event: "):
                event_type = line[7:].strip()
            elif line.startswith("data: "):
                data_str += line[6:]
        if event_type and data_str:
            events.append({"event": event_type, "data": json.loads(data_str)})
    return events


# ---------------------------------------------------------------------------
# Tests — Validation (normal HTTP errors, not SSE)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestStreamValidation:
    """Validation errors should return normal HTTP responses, not SSE streams."""

    async def test_missing_file_returns_422(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/tailor-stream", data=_form_data())
        assert resp.status_code == 422

    async def test_non_tex_file_returns_400(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(filename="resume.pdf"),
                )
        assert resp.status_code == 400
        assert "tex" in resp.json()["detail"].lower()

    async def test_empty_jd_returns_422(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/tailor-stream",
                data=_form_data(jd_text="too short"),
                files=_tex_upload(),
            )
        assert resp.status_code == 422

    async def test_tiny_tex_returns_400(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(content="hi"),
                )
        assert resp.status_code == 400
        assert "small" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Tests — Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestStreamHappyPath:

    async def test_stream_returns_200_event_stream(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")

    async def test_stream_emits_progress_events(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        events = _parse_sse_events(resp.text)
        progress_events = [e for e in events if e["event"] == "progress"]
        assert len(progress_events) == 6
        steps = [e["data"]["step"] for e in progress_events]
        assert steps == [0, 1, 2, 3, 4, 5]

    async def test_stream_emits_complete_event(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        events = _parse_sse_events(resp.text)
        complete_events = [e for e in events if e["event"] == "complete"]
        assert len(complete_events) == 1
        data = complete_events[0]["data"]
        assert "extracted" in data
        assert "match" in data
        assert "reorder_plan" in data
        assert data["match"]["match_score"] == 75

    async def test_stream_complete_has_pdf(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        events = _parse_sse_events(resp.text)
        data = [e for e in events if e["event"] == "complete"][0]["data"]
        assert data["pdf_url"].endswith(".pdf")
        assert len(data["pdf_b64"]) > 0

    async def test_progress_labels_are_meaningful(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        events = _parse_sse_events(resp.text)
        labels = [e["data"]["label"] for e in events if e["event"] == "progress"]
        assert "Analyzing resume..." in labels
        assert "Compiling PDF..." in labels


# ---------------------------------------------------------------------------
# Tests — Error handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestStreamErrors:

    async def test_analysis_failure_emits_error_event(self):
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
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        assert resp.status_code == 200  # Stream opened successfully
        events = _parse_sse_events(resp.text)
        error_events = [e for e in events if e["event"] == "error"]
        assert len(error_events) == 1
        assert "analysis" in error_events[0]["data"]["detail"].lower()
        assert error_events[0]["data"]["step"] == 0

    async def test_extraction_failure_emits_error_event(self):
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
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        events = _parse_sse_events(resp.text)
        error_events = [e for e in events if e["event"] == "error"]
        assert len(error_events) == 1
        assert "extraction" in error_events[0]["data"]["detail"].lower()
        assert error_events[0]["data"]["step"] == 1

    async def test_match_failure_emits_error_event(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patch(
            "app.routes.tailor.match_keywords",
            new_callable=AsyncMock,
            return_value=None,
        ), patches["reorder"], patches["inject"], patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        events = _parse_sse_events(resp.text)
        error_events = [e for e in events if e["event"] == "error"]
        assert len(error_events) == 1
        assert "matching" in error_events[0]["data"]["detail"].lower()
        assert error_events[0]["data"]["step"] == 2

    async def test_compile_failure_still_emits_complete(self):
        """PDF compilation failure is non-fatal — complete event still sent."""
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patches["inject"], patch(
                 "app.routes.tailor.compile_pdf",
                 side_effect=RuntimeError("pdflatex not found"),
             ), patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        events = _parse_sse_events(resp.text)
        error_events = [e for e in events if e["event"] == "error"]
        assert len(error_events) == 0  # No error — just no PDF
        complete_events = [e for e in events if e["event"] == "complete"]
        assert len(complete_events) == 1
        assert complete_events[0]["data"]["pdf_url"] == ""
        assert complete_events[0]["data"]["pdf_b64"] == ""

    async def test_injection_failure_emits_error_event(self):
        patches = _patch_all()
        with patches["analyze"], patches["extract"], patches["match"], \
             patches["reorder"], patch(
                 "app.routes.tailor.inject_into_latex",
                 side_effect=ValueError("Bad LaTeX"),
             ), patches["compile"], patches["flush"]:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/tailor-stream",
                    data=_form_data(),
                    files=_tex_upload(),
                )
        events = _parse_sse_events(resp.text)
        error_events = [e for e in events if e["event"] == "error"]
        assert len(error_events) == 1
        assert "latex" in error_events[0]["data"]["detail"].lower()
        assert error_events[0]["data"]["step"] == 4
