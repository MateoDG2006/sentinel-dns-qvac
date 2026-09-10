from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes.health import router as health_router
from app.api.routes.metrics import router as metrics_router
from app.api.routes.predictions import router as predictions_router
from app.core.config import Settings
from app.core.lifecycle import lifespan_context
from app.core.logging import configure_logging


class SentinelApp:
    """FastAPI composition root. Domain logic stays in services."""

    @staticmethod
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings = Settings.get()
        configure_logging(settings)
        async with lifespan_context(app, settings):
            yield

    @staticmethod
    def create(settings: Settings | None = None) -> FastAPI:
        _ = settings or Settings.get()
        application = FastAPI(
            title="Sentinel-DNS",
            version="0.1.0",
            lifespan=SentinelApp.lifespan,
            docs_url=None,
            redoc_url=None,
        )
        application.include_router(health_router)
        application.include_router(metrics_router)
        application.include_router(predictions_router)
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
