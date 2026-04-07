"""
app/routes/auth.py

Handles authentication: verify (login) and register (sign up).

Verify checks two sources in order:
  1. The env-var admin account (existing behaviour via load_settings).
  2. Registered users stored in the PostgreSQL `users` table (bcrypt hashes).

Requires:
  - asyncpg   (`pip install asyncpg`)
  - bcrypt     (`pip install bcrypt`)
  - DATABASE_URL in your .env  (e.g. postgresql://user:pass@host/dbname)

The `users` table is expected to exist with this schema (already confirmed):
  id            SERIAL PRIMARY KEY,
  username      VARCHAR(100) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMP DEFAULT NOW()
"""

import os

import asyncpg
import bcrypt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator

from app.config import load_settings

router = APIRouter()

# ---------------------------------------------------------------------------
# DB helper
# ---------------------------------------------------------------------------

async def _get_conn() -> asyncpg.Connection:
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise HTTPException(status_code=500, detail="DATABASE_URL is not configured")
    return await asyncpg.connect(db_url)


# ---------------------------------------------------------------------------
# /api/auth/verify  — backward-compatible drop-in replacement
# ---------------------------------------------------------------------------

@router.post("/api/auth/verify")
async def verify_auth(request: Request):
    """Check if provided credentials are valid.

    Reads X-Auth-Username and X-Auth-Password headers.
    Returns {"valid": bool, "auth_enabled": bool}.
    """
    settings = load_settings()
    req_user = request.headers.get("x-auth-username", "")
    req_pass = request.headers.get("x-auth-password", "")

    env_admin_set = bool(settings.auth_username)

    # 1. Env-var admin account (plain-text, existing behaviour)
    if env_admin_set:
        if req_user == settings.auth_username and req_pass == settings.auth_password:
            return {"valid": True, "auth_enabled": True}

    # 2. Registered users in PostgreSQL (bcrypt)
    try:
        conn = await _get_conn()
        try:
            row = await conn.fetchrow(
                "SELECT password_hash FROM users WHERE username = $1", req_user
            )
        finally:
            await conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}") from exc

    if row:
        # bcrypt is blocking — run in threadpool to avoid blocking the event loop
        import asyncio
        loop = asyncio.get_running_loop()
        valid = await loop.run_in_executor(
            None,
            bcrypt.checkpw,
            req_pass.encode(),
            row["password_hash"].encode(),
        )
        if valid:
            return {"valid": True, "auth_enabled": True}

    # Auth is "enabled" if either an env admin or any DB user exists
    if not env_admin_set:
        try:
            conn = await _get_conn()
            try:
                count = await conn.fetchval("SELECT COUNT(*) FROM users")
            finally:
                await conn.close()
            if count == 0:
                return {"valid": True, "auth_enabled": False}
        except Exception:
            pass

    return {"valid": False, "auth_enabled": True}


# ---------------------------------------------------------------------------
# /api/auth/register
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(v) > 50:
            raise ValueError("Username must be 50 characters or fewer")
        if not v.replace("_", "").replace("-", "").replace(".", "").replace("@", "").isalnum():
            raise ValueError("Username may only contain letters, numbers, -, _, ., @")
        return v

    @field_validator("password")
    @classmethod
    def password_valid(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


@router.post("/api/auth/register", status_code=201)
async def register(body: RegisterRequest):
    settings = load_settings()

    # Prevent claiming the env-var admin username
    if settings.auth_username and body.username == settings.auth_username:
        raise HTTPException(status_code=409, detail="Username already taken")

    # Hash password in threadpool (bcrypt is CPU-bound)
    import asyncio
    loop = asyncio.get_running_loop()
    hashed: bytes = await loop.run_in_executor(
        None,
        lambda: bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()),
    )

    try:
        conn = await _get_conn()
        try:
            await conn.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES ($1, $2)
                """,
                body.username,
                hashed.decode(),
            )
        finally:
            await conn.close()
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="Username already taken")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}") from exc

    return {"registered": True, "username": body.username}