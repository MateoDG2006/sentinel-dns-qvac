"""Webhook HTTP surface. Validates the contract and delegates to PredictionService."""

from __future__ import annotations

import logging
import time
from typing import Annotated, Any, ClassVar
from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException, status

from app.api.dependencies import ApiDependencies
from app.constants.api import PREDICTIONS_PATH, WEBHOOK_RETRY_AFTER_SECONDS
from app.domain.enums import DetectorRuntime, EventSource, PredictionMode
from app.domain.errors import KafkaBackpressureError
from app.domain.schemas import PredictionReceipt, PredictionRequest, PredictionResult
from app.observability.metrics import SentinelMetrics
from app.services.prediction import PredictionService


class WebhookDocsExamples:
    """Static Try-it-out payloads for /docs. Not production traffic."""

    _STAMP: ClassVar[str] = "2026-09-10T12:00:00+00:00"

    @staticmethod
    def _event(*, event_id: str, qname: str, rcode: str = "NOERROR") -> dict[str, Any]:
        return {
            "event_id": event_id,
            "event_ts": WebhookDocsExamples._STAMP,
            "observed_at": WebhookDocsExamples._STAMP,
            "site_id": "pop-1",
            "zone_id": "zone-a",
            "resolver_id": "resolver-1",
            "client_hash": "client-hash-1",
            "qname": qname,
            "qtype": "A",
            "rcode": rcode,
            "latency_ms": 25.0,
            "response_bytes": 128,
            "timed_out": False,
            "synthetic": True,
        }

    @staticmethod
    def openapi_examples() -> dict[str, dict[str, Any]]:
        return {
            "benign": {
                "summary": "Consulta benigna",
                "description": "www.example.com → threat none, mode heuristic_fallback.",
                "value": {
                    "events": [
                        WebhookDocsExamples._event(
                            event_id="11111111-1111-1111-1111-111111111111",
                            qname="www.example.com",
                        )
                    ]
                },
            },
            "dga": {
                "summary": "DGA sintético (NXDOMAIN)",
                "description": "Label larga de alta entropía. Cambia event_id si reenvías.",
                "value": {
                    "events": [
                        WebhookDocsExamples._event(
                            event_id="22222222-2222-2222-2222-222222222222",
                            qname="xkqpwzlmntabvdfg.test",
                            rcode="NXDOMAIN",
                        )
                    ]
                },
            },
            "typosquatting": {
                "summary": "Typosquatting contra marca de brands.yaml",
                "value": {
                    "events": [
                        WebhookDocsExamples._event(
                            event_id="33333333-3333-3333-3333-333333333333",
                            qname="acmebannk.test",
                        )
                    ]
                },
            },
        }


class PredictionsApi:
    """POST /api/v1/predictions — 202 without waiting for Wazuh."""

    router = APIRouter(tags=["predictions"])
    _logger = logging.getLogger("app.api.predictions")

    @staticmethod
    async def create_predictions(
        payload: Annotated[
            PredictionRequest,
            Body(openapi_examples=WebhookDocsExamples.openapi_examples()),
        ],
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
    summary="Aceptar 1..100 eventos DNS sintéticos",
    responses={
        401: {"description": "Token ausente o inválido"},
        422: {"description": "Esquema inválido o synthetic=false"},
        429: {"description": "Cola interna llena; Retry-After"},
    },
)
