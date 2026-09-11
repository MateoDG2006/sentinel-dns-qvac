"""Local QVAC fidelity lab. Delegates detection to PredictionService."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from app.api.dependencies import ApiDependencies
from app.constants.api import LAB_CATALOG_PATH, LAB_EVALUATE_PATH, LAB_PATH
from app.domain.errors import KafkaBackpressureError
from app.services.lab_fidelity import (
    LabCatalogItem,
    LabEvaluateRequest,
    LabEvaluateResponse,
    LabFidelityService,
)
from app.services.prediction import PredictionService

LAB_PAGE = Path(__file__).resolve().parent.parent / "static" / "lab.html"


class LabApi:
    """Interactive synthetic evaluation for the hybrid detector."""

    router = APIRouter(tags=["lab"])
    _service = LabFidelityService()

    @staticmethod
    def page() -> FileResponse:
        if not LAB_PAGE.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="lab ui missing")
        return FileResponse(LAB_PAGE, media_type="text/html; charset=utf-8")

    @staticmethod
    def catalog() -> list[LabCatalogItem]:
        return LabApi._service.catalog()

    @staticmethod
    async def evaluate(
        payload: LabEvaluateRequest,
        service: Annotated[PredictionService, Depends(ApiDependencies.prediction_service)],
        _: Annotated[None, Depends(ApiDependencies.require_webhook_token)],
    ) -> LabEvaluateResponse:
        try:
            return await LabApi._service.evaluate(payload, service)
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        except KafkaBackpressureError as exc:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="internal queue exceeded backpressure limit",
            ) from exc


LabApi.router.add_api_route(
    LAB_PATH,
    LabApi.page,
    methods=["GET"],
    include_in_schema=False,
)
LabApi.router.add_api_route(
    LAB_CATALOG_PATH,
    LabApi.catalog,
    methods=["GET"],
    summary="Escenarios sintéticos disponibles (simulador C1)",
    response_model=list[LabCatalogItem],
)
LabApi.router.add_api_route(
    LAB_EVALUATE_PATH,
    LabApi.evaluate,
    methods=["POST"],
    summary="Evaluar un lote sintético contra heurísticas + QVAC",
    response_model=LabEvaluateResponse,
)
