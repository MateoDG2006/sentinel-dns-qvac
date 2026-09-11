"""FastAPI dependency injection for settings, auth, and collaborators."""

from __future__ import annotations

from typing import Annotated, cast

from fastapi import Header, HTTPException, Request, status

from app.constants.api import WEBHOOK_TOKEN_HEADER
from app.core.config import Settings
from app.core.security import WebhookToken
from app.observability.health import HealthProbe
from app.observability.metrics import SentinelMetrics
from app.services.prediction import PredictionService


class ApiDependencies:
    """Resolve collaborators from app state and authenticate the webhook."""

    @staticmethod
    def settings(request: Request) -> Settings:
        return cast(Settings, request.app.state.settings)

    @staticmethod
    def prediction_service(request: Request) -> PredictionService:
        return cast(PredictionService, request.app.state.prediction_service)

    @staticmethod
    def metrics(request: Request) -> SentinelMetrics:
        return cast(SentinelMetrics, request.app.state.metrics)

    @staticmethod
    def health(request: Request) -> HealthProbe:
        return cast(HealthProbe, request.app.state.health)

    @staticmethod
    def require_webhook_token(
        request: Request,
        x_sentinel_token: Annotated[str | None, Header(alias=WEBHOOK_TOKEN_HEADER)] = None,
    ) -> None:
        settings = ApiDependencies.settings(request)
        if x_sentinel_token is None or x_sentinel_token == "":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
            )
        try:
            expected = settings.resolved_webhook_token()
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
            ) from None
        if not WebhookToken.matches(provided=x_sentinel_token, expected=expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
            )
