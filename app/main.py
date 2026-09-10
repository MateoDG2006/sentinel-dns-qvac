from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes.health import router as health_router
from app.api.routes.metrics import router as metrics_router
from app.api.routes.predictions import router as predictions_router
from app.core.config import Settings, get_settings
from app.core.lifecycle import lifespan_context
from app.core.logging import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings)
    async with lifespan_context(app, settings):
        yield


def create_app(settings: Settings | None = None) -> FastAPI:
    _ = settings or get_settings()
    application = FastAPI(
        title="Sentinel-DNS",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )
    application.include_router(health_router)
    application.include_router(metrics_router)
    application.include_router(predictions_router)
    return application


app = create_app()


def run() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.app_host,
        port=settings.app_port,
        factory=False,
    )
