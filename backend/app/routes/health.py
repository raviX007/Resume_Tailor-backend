"""Health check + auth verify endpoints."""

import time

from fastapi import APIRouter, Request

from app.config import load_settings

router = APIRouter(tags=["System"])

_start_time = time.monotonic()


@router.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "resume-tailor",
        "version": "1.0.0",
        "uptime_seconds": round(time.monotonic() - _start_time),
    }


@router.post("/api/auth/verify")
async def verify_auth(request: Request):
    """Check if provided credentials are valid.

    Reads X-Auth-Username and X-Auth-Password headers.
    Returns {"valid": bool, "auth_enabled": bool}.
    """
    settings = load_settings()
    if not settings.auth_username:
        return {"valid": True, "auth_enabled": False}

    req_user = request.headers.get("x-auth-username", "")
    req_pass = request.headers.get("x-auth-password", "")
    valid = req_user == settings.auth_username and req_pass == settings.auth_password
    return {"valid": valid, "auth_enabled": True}
