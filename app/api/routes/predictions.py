"""Webhook HTTP surface. Validates the contract and delegates to PredictionService."""

from __future__ import annotations

import logging
import time
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import ApiDependencies
from app.constants.api import PREDICTIONS_PATH, WEBHOOK_RETRY_AFTER_SECONDS
from app.domain.enums import DetectorRuntime, EventSource, PredictionMode
from app.domain.errors import KafkaBackpressureError
from app.domain.schemas import PredictionReceipt, PredictionRequest, PredictionResult
from app.observability.metrics import SentinelMetrics
from app.services.prediction import PredictionService


class PredictionsApi:
    """POST /api/v1/predictions — 202 without waiting for Wazuh."""

    router = APIRouter()
    _logger = logging.getLogger("app.api.predictions")

    @staticmethod
    async def create_predictions(
        payload: PredictionRequest,
        service: Annotated[PredictionService, Depends(ApiDependencies.prediction_service)],
        metrics: Annotated[SentinelMetrics, Depends(ApiDependencies.metrics)],
        _: Annotated[None, Depends(ApiDependencies.require_webhook_token)],
    ) -> PredictionReceipt:
        started = time.perf_counter()
        try:
            results = await service.process_batch(
                list(payload.events),
                source=EventSource.WEBHOOK,
            )
        except KafkaBackpressureError as exc:
            metrics.increment_events(
                source=EventSource.WEBHOOK.value,
                status="backpressure",
                amount=len(payload.events),
            )
            PredictionsApi._logger.info(
                "predictions_backpressure",
                extra={
                    "event": "predictions_backpressure",
                    "source": EventSource.WEBHOOK.value,
                    "queue_depth": service.queue.depth,
                    "accepted": 0,
                    "rejected": len(payload.events),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="internal queue exceeded backpressure limit",
                headers={"Retry-After": str(WEBHOOK_RETRY_AFTER_SECONDS)},
            ) from exc
        metrics.observe_processing(time.perf_counter() - started)
        PredictionsApi._record_success(metrics, results)
        correlation_id = payload.correlation_id or uuid4()
        receipt = PredictionReceipt(
            correlation_id=correlation_id,
            accepted=len(results),
            rejected=0,
            result_ids=[item.prediction.prediction_id for item in results],
            mode=PredictionsApi._receipt_mode(results),
        )
        PredictionsApi._logger.info(
            "predictions_accepted",
            extra={
                "event": "predictions_accepted",
                "correlation_id": str(receipt.correlation_id),
                "accepted": receipt.accepted,
                "rejected": receipt.rejected,
                "source": EventSource.WEBHOOK.value,
                "mode": receipt.mode.value,
                "result_count": len(receipt.result_ids),
            },
        )
        return receipt

    @staticmethod
    def _record_success(metrics: SentinelMetrics, results: list[PredictionResult]) -> None:
        metrics.increment_events(
            source=EventSource.WEBHOOK.value,
            status="accepted",
            amount=len(results),
        )
        for item in results:
            runtime = (
                DetectorRuntime.HEURISTIC_FALLBACK.value
                if item.mode is PredictionMode.HEURISTIC_FALLBACK
                else DetectorRuntime.QVAC_LOCAL.value
            )
            metrics.increment_prediction(
                threat_type=item.prediction.threat_type.value,
                severity=item.prediction.severity.value,
                runtime=runtime,
            )

    @staticmethod
    def _receipt_mode(results: list[PredictionResult]) -> PredictionMode:
        modes = {item.mode for item in results}
        if len(modes) == 1:
            return next(iter(modes))
        return PredictionMode.HYBRID


PredictionsApi.router.add_api_route(
    PREDICTIONS_PATH,
    PredictionsApi.create_predictions,
    methods=["POST"],
    status_code=status.HTTP_202_ACCEPTED,
    response_model=PredictionReceipt,
)
