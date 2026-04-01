"""Middleware — request ID + optional password gate.

Uses pure ASGI middleware (not BaseHTTPMiddleware) to avoid buffering
StreamingResponse, which is needed for the SSE endpoint.
"""

import json
import uuid
from contextvars import ContextVar

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIdMiddleware:
    """Attach an 8-char request ID to every request/response cycle."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        rid = uuid.uuid4().hex[:8]
        request_id_var.set(rid)
        scope.setdefault("state", {})["request_id"] = rid

        async def send_with_rid(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.append("X-Request-ID", rid)
            await send(message)

        await self.app(scope, receive, send_with_rid)


class PasswordGateMiddleware:
    """Block /api/tailor* requests that lack valid credentials.

    If username is empty, auth is disabled and all requests pass through.
    Health check and /api/auth/* endpoints are always unprotected.
    """

    def __init__(self, app: ASGIApp, username: str, password: str) -> None:
        self.app = app
        self.username = username
        self.password = password

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.username:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/api/tailor"):
            await self.app(scope, receive, send)
            return

        # Extract auth headers
        headers_list = scope.get("headers", [])
        headers = {k: v for k, v in headers_list}
        req_user = headers.get(b"x-auth-username", b"").decode()
        req_pass = headers.get(b"x-auth-password", b"").decode()

        if req_user != self.username or req_pass != self.password:
            body = json.dumps({"detail": "Invalid credentials"}).encode()
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(body)).encode()],
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)
