from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes.health import HealthApi
from app.api.routes.metrics import MetricsApi
from app.api.routes.predictions import PredictionsApi
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
            lifespan=SentinelApp.lifespan,
            docs_url=None,
            redoc_url=None,
        )
        application.state.settings = resolved
        application.state.metrics = SentinelMetrics()
        application.state.health = HealthProbe(resolved)
        application.state.prediction_service = PredictionService(settings=resolved)
        application.include_router(HealthApi.router)
        application.include_router(MetricsApi.router)
        application.include_router(PredictionsApi.router)
        return application

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
