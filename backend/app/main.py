"""Resume Tailor API — generates JD-tailored PDF resumes.

Run: uvicorn app.main:app --reload --port 8001
Docs: http://localhost:8001/docs
"""

import traceback
from pathlib import Path

from fastapi import FastAPI, Request
from starlette.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from app.config import load_settings  # noqa: E402
from app.core.constants import RATE_LIMIT_PER_MINUTE  # noqa: E402
from app.core.logger import logger  # noqa: E402
from app.middleware import RequestIdMiddleware, PasswordGateMiddleware, request_id_var  # noqa: E402
from app.routes import tailor, health  # noqa: E402

settings = load_settings()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Resume Tailor API",
    version="1.0.0",
    description="Generates JD-tailored PDF resumes using LLM extraction + LaTeX compilation.",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ALLOWED_ORIGINS = settings.allowed_origins.split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID", "X-Auth-Username", "X-Auth-Password"],
    expose_headers=["X-Request-ID"],
)

# Auth middleware (runs after CORS, before route handlers)
# app.add_middleware(
#     PasswordGateMiddleware,
#     username=settings.auth_username,
#     password=settings.auth_password,
# )

# Request ID middleware (innermost — runs closest to route handlers)
app.add_middleware(RequestIdMiddleware)


# ── Global exception handlers ────────────────────────────────────────


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    rid = request_id_var.get("-")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "request_id": rid},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    rid = request_id_var.get("-")
    logger.error(f"Unhandled exception [{rid}]: {exc}\n{traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": rid},
    )


output_dir = Path(__file__).resolve().parent.parent / "output"
output_dir.mkdir(exist_ok=True)
app.mount("/output", StaticFiles(directory=str(output_dir)), name="output")

app.include_router(health.router)
app.include_router(tailor.router)
