"""Tests for request ID middleware and global exception handlers."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client():
    return TestClient(app)


class TestRequestIdMiddleware:
    """Tests for X-Request-ID generation and propagation."""

    def test_health_response_has_request_id_header(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert "X-Request-ID" in resp.headers
        assert len(resp.headers["X-Request-ID"]) == 8

    def test_each_request_gets_unique_id(self, client):
        r1 = client.get("/api/health")
        r2 = client.get("/api/health")
        assert r1.headers["X-Request-ID"] != r2.headers["X-Request-ID"]

    def test_error_response_includes_request_id_in_body(self, client):
        """404 error should include request_id in the JSON body."""
        resp = client.get("/api/nonexistent")
        assert resp.status_code == 404
        body = resp.json()
        assert "request_id" in body
        assert len(body["request_id"]) == 8

    def test_request_id_matches_header_and_body(self, client):
        """For error responses, header and body request_id should match."""
        resp = client.get("/api/nonexistent")
        assert resp.headers["X-Request-ID"] == resp.json()["request_id"]
