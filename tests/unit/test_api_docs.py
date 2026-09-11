"""OpenAPI / Swagger UI for local flow testing."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.constants.api import DOCS_PATH, OPENAPI_PATH, PREDICTIONS_PATH, REDOC_PATH
from app.core.config import Settings
from app.main import SentinelApp

WEBHOOK_TOKEN = "unit-test-webhook-token"


def _client() -> TestClient:
    return TestClient(SentinelApp.create(Settings(webhook_token=WEBHOOK_TOKEN)))


def test_root_redirects_to_docs() -> None:
    with _client() as client:
        response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == DOCS_PATH


def test_swagger_and_redoc_are_enabled() -> None:
    with _client() as client:
        docs = client.get(DOCS_PATH)
        redoc = client.get(REDOC_PATH)
        spec = client.get(OPENAPI_PATH)
    assert docs.status_code == 200
    assert "swagger" in docs.text.lower()
    assert redoc.status_code == 200
    assert spec.status_code == 200
    body = spec.json()
    assert PREDICTIONS_PATH in body["paths"]
    assert "/health/live" in body["paths"]
    examples = body["paths"][PREDICTIONS_PATH]["post"]["requestBody"]["content"][
        "application/json"
    ]["examples"]
    assert "benign" in examples
    assert "dga" in examples
