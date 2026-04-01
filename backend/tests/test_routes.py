"""Route tests for the Resume Tailor API.

Covers:
- Health endpoint (GET /api/health)
- Tailor endpoint validation (POST /api/tailor) — fast, no LLM/network
- CORS headers and middleware behavior

All validation tests hit guards before any pipeline/LLM calls, so they
run quickly and require no mocks.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.core.constants import MAX_UPLOAD_SIZE, MIN_TEX_SIZE


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def client():
    """Async httpx test client wired to the FastAPI app via ASGI transport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A valid JD that exceeds the 50-char minimum.
VALID_JD = (
    "We are looking for a Senior Backend Engineer with deep experience in "
    "Python, Django, FastAPI, PostgreSQL, Docker, and Kubernetes. "
    "You will design and build scalable microservices."
)

# A valid .tex body that exceeds MIN_TEX_SIZE (100 chars).
VALID_TEX_BODY = (
    r"\documentclass[letterpaper,11pt]{article}" "\n"
    r"\begin{document}" "\n"
    r"\section{Experience}" "\n"
    "Software Engineer at Acme Corp. Built distributed systems in Python.\n"
    r"\end{document}" "\n"
)

assert len(VALID_JD) >= 50
assert len(VALID_TEX_BODY) >= MIN_TEX_SIZE


def _tex_file(
    content=VALID_TEX_BODY,
    filename="resume.tex",
    content_type="application/x-tex",
):
    """Build the ``files`` dict for an httpx multipart upload."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return {"resume_file": (filename, content, content_type)}


def _form(jd_text=VALID_JD, **extra):
    """Build the ``data`` dict for the /api/tailor form fields."""
    payload = {"jd_text": jd_text}
    payload.update(extra)
    return payload


# ============================================================================
# 1. Health endpoint
# ============================================================================


@pytest.mark.asyncio
class TestHealthEndpoint:
    """GET /api/health — basic liveness/readiness checks."""

    async def test_health_returns_200(self, client):
        response = await client.get("/api/health")
        assert response.status_code == 200

    async def test_health_response_fields(self, client):
        response = await client.get("/api/health")
        body = response.json()
        assert body["status"] == "ok"
        assert body["service"] == "resume-tailor"
        assert "version" in body
        assert "uptime_seconds" in body
        assert isinstance(body["uptime_seconds"], (int, float))


# ============================================================================
# 2. Tailor endpoint — input validation
# ============================================================================


@pytest.mark.asyncio
class TestTailorValidation:
    """POST /api/tailor validation guards.

    Every test triggers a rejection *before* the LLM pipeline runs,
    so no mocks or network access are needed and execution is fast.
    """

    async def test_missing_resume_file_returns_422(self, client):
        """Omitting resume_file entirely must yield 422."""
        response = await client.post("/api/tailor", data=_form())
        assert response.status_code == 422

    async def test_missing_jd_text_returns_422(self, client):
        """Omitting jd_text (required Form field) must yield 422."""
        response = await client.post("/api/tailor", files=_tex_file())
        assert response.status_code == 422

    async def test_jd_text_too_short_returns_422(self, client):
        """JD text shorter than 50 characters must be rejected (422)."""
        short_jd = "This JD is way too short."
        assert len(short_jd) < 50

        response = await client.post(
            "/api/tailor",
            data=_form(jd_text=short_jd),
            files=_tex_file(),
        )
        assert response.status_code == 422

    async def test_wrong_file_extension_returns_400(self, client):
        """Uploading a .pdf instead of .tex must be rejected with 400."""
        response = await client.post(
            "/api/tailor",
            data=_form(),
            files=_tex_file(filename="resume.pdf"),
        )
        assert response.status_code == 400
        assert "tex" in response.json()["detail"].lower()

    async def test_invalid_content_type_returns_400(self, client):
        """An image/png content type on a .tex file must be rejected with 400."""
        response = await client.post(
            "/api/tailor",
            data=_form(),
            files=_tex_file(content_type="image/png"),
        )
        assert response.status_code == 400
        detail = response.json()["detail"].lower()
        assert "file type" in detail or "tex" in detail

    async def test_file_too_large_returns_413(self, client):
        """A file exceeding MAX_UPLOAD_SIZE (2 MB) must be rejected with 413."""
        oversized = b"%" + b"x" * (MAX_UPLOAD_SIZE + 1)
        response = await client.post(
            "/api/tailor",
            data=_form(),
            files=_tex_file(content=oversized),
        )
        assert response.status_code == 413
        assert "large" in response.json()["detail"].lower()

    async def test_non_utf8_file_returns_400(self, client):
        """A .tex file with invalid UTF-8 bytes must be rejected with 400."""
        bad_bytes = b"\xc3\x28" * 100  # invalid UTF-8, > MIN_TEX_SIZE bytes
        response = await client.post(
            "/api/tailor",
            data=_form(),
            files=_tex_file(content=bad_bytes),
        )
        assert response.status_code == 400
        detail = response.json()["detail"].lower()
        assert "utf-8" in detail or "utf" in detail

    async def test_file_too_small_returns_400(self, client):
        """A .tex file under MIN_TEX_SIZE chars must be rejected."""
        tiny_tex = r"\documentclass{article}" + "\n"
        assert 0 < len(tiny_tex) < MIN_TEX_SIZE

        response = await client.post(
            "/api/tailor",
            data=_form(),
            files=_tex_file(content=tiny_tex),
        )
        assert response.status_code == 400
        assert "small" in response.json()["detail"].lower()


# ============================================================================
# 3. CORS headers
# ============================================================================


@pytest.mark.asyncio
class TestCORSHeaders:
    """Verify CORS middleware behaviour on preflight and normal responses."""

    async def test_options_preflight_returns_cors_headers(self, client):
        """OPTIONS preflight from allowed origin must include CORS headers."""
        response = await client.options(
            "/api/tailor",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers
        assert response.headers["access-control-allow-origin"] == "http://localhost:3000"

    async def test_response_includes_expected_headers(self, client):
        """Normal GET should include Content-Type and X-Request-ID."""
        response = await client.get(
            "/api/health",
            headers={"Origin": "http://localhost:3000"},
        )
        assert response.status_code == 200
        assert "content-type" in response.headers
        assert "application/json" in response.headers["content-type"]

        # X-Request-ID from RequestIdMiddleware (8-char hex)
        assert "x-request-id" in response.headers
        rid = response.headers["x-request-id"]
        assert len(rid) == 8
        assert rid.isalnum()
