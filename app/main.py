from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from app.api.routes.health import HealthApi
from app.api.routes.metrics import MetricsApi
from app.api.routes.predictions import PredictionsApi
from app.constants.api import DOCS_PATH, OPENAPI_PATH, REDOC_PATH
from app.core.config import Settings
from app.core.lifecycle import AppLifecycle
from app.core.logging import JsonLogging
from app.observability.health import HealthProbe
from app.observability.metrics import SentinelMetrics
from app.services.prediction import PredictionService


class SentinelApp:
    """FastAPI composition root. Domain logic stays in services."""

    @staticmethod
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings: Settings = app.state.settings
        JsonLogging.configure(settings)
        async with AppLifecycle.run(app, settings):
            yield

    @staticmethod
    def create(settings: Settings | None = None) -> FastAPI:
        resolved = settings if settings is not None else Settings.get()
        application = FastAPI(
            title="Sentinel-DNS",
            version="0.1.0",
            description=(
                "Webhook local y health para probar el mismo `PredictionService` "
                "que consume Kafka.\n\n"
                "1. En `POST /api/v1/predictions` usa el header `X-Sentinel-Token`.\n"
                "2. Elige un ejemplo (benigno o DGA) y cambia `event_id` si reenvías.\n"
                "3. En perfil hackathon `synthetic` debe ser `true`.\n"
                "4. Kafka no se dispara desde esta UI; es el consumer del stream."
            ),
            lifespan=SentinelApp.lifespan,
            docs_url=DOCS_PATH,
            redoc_url=REDOC_PATH,
            openapi_url=OPENAPI_PATH,
            swagger_ui_parameters={"persistAuthorization": True, "tryItOutEnabled": True},
            openapi_tags=[
                {"name": "health", "description": "Liveness, readiness y estado degradado."},
                {"name": "predictions", "description": "Webhook 1..100 eventos sintéticos."},
                {"name": "metrics", "description": "Prometheus sin labels de identidad."},
            ],
        )
        application.state.settings = resolved
        application.state.metrics = SentinelMetrics()
        application.state.health = HealthProbe(resolved)
        application.state.prediction_service = PredictionService(settings=resolved)
        application.add_api_route(
            "/",
            SentinelApp.redirect_to_docs,
            methods=["GET"],
            include_in_schema=False,
        )
        application.include_router(HealthApi.router)
        application.include_router(MetricsApi.router)
        application.include_router(PredictionsApi.router)
        return application

    @staticmethod
    def redirect_to_docs() -> RedirectResponse:
        return RedirectResponse(url=DOCS_PATH, status_code=307)

    @staticmethod
    def run() -> None:
        import uvicorn

        settings = Settings.get()
        uvicorn.run(
            "app.main:app",
            host=settings.app_host,
            port=settings.app_port,
            factory=False,
        )


app = SentinelApp.create()
