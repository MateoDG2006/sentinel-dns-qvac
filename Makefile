# Sentinel-DNS — comandos para la infra que existe hoy.
#
# Disponible: Kafka local (C1) + API/consumer/QVAC en el host (A2–A5).
# Todavía no está en Compose: ClickHouse, Grafana, Prometheus, Wazuh (C3/C4, B).
# El CLI del simulador (simulator/main.py) aún no publica a Kafka.
#
# Windows (PowerShell): GNU Make usa cmd.exe; las recetas evitan bash.
# Linux/macOS: recetas POSIX.

.DEFAULT_GOAL := help

COMPOSE := docker compose
UV := uv
KAFKA_HOST_BOOTSTRAP := localhost:29092
API_HOST := 127.0.0.1
API_PORT := 8000

.PHONY: help env sync kafka up down logs ps wait-kafka topics \
	bootstrap qvac-smoke api dev check test fmt

help:
	$(info Infra actual: Kafka Compose + API en el host)
	$(info)
	$(info   make env          Copia .env.example a .env si no existe)
	$(info   make sync         uv sync + npm install (@qvac/sdk local))
	$(info   make up           Levanta Kafka y crea topics)
	$(info   make wait-kafka   Espera healthcheck de sentinel-kafka)
	$(info   make topics       Lista topics congelados)
	$(info   make logs         Logs de Kafka)
	$(info   make down         Para el stack Compose)
	$(info   make bootstrap    Descarga el GGUF a data/qvac (red; usa node_modules/@qvac/sdk))
	$(info   make qvac-smoke   Comprueba cache local, no descarga)
	$(info   make api          Uvicorn en $(API_HOST):$(API_PORT) contra Kafka del host)
	$(info   make dev          env + sync + up)
	$(info   make check        ruff + mypy + pytest unit)
	$(info   make test         pytest tests/unit)
	$(info)
	$(info Lab QVAC: http://$(API_HOST):$(API_PORT)/lab)
	$(info Docs: http://$(API_HOST):$(API_PORT)/docs)
	$(info Kafka host: $(KAFKA_HOST_BOOTSTRAP))
	@:

ifeq ($(OS),Windows_NT)
env:
	powershell -NoProfile -Command "if (-not (Test-Path -LiteralPath '.env')) { Copy-Item .env.example .env; Write-Host 'Creado .env. Rellena SENTINEL_WEBHOOK_TOKEN.' } else { Write-Host '.env ya existe' }"
else
ifeq ($(wildcard .env),)
env:
	cp .env.example .env
	@echo Creado .env. Rellena SENTINEL_WEBHOOK_TOKEN.
else
env:
	@echo .env ya existe
endif
endif

sync:
	$(UV) sync
	npm install

up:
	$(COMPOSE) up -d
	@$(MAKE) wait-kafka

kafka: up

ifeq ($(OS),Windows_NT)
wait-kafka:
	@echo Esperando Kafka healthy...
	powershell -NoProfile -Command "$$n=0; do { $$s = docker inspect -f '{{.State.Health.Status}}' sentinel-kafka 2>$$null; if ($$s -eq 'healthy') { Write-Host 'Kafka listo.'; exit 0 }; $$n++; if ($$n -ge 36) { Write-Host 'timeout esperando sentinel-kafka'; exit 1 }; Start-Sleep -Seconds 2 } while ($$true)"
else
wait-kafka:
	@echo Esperando Kafka healthy...
	@n=0; \
	until [ "$$(docker inspect -f '{{.State.Health.Status}}' sentinel-kafka 2>/dev/null)" = "healthy" ]; do \
		n=$$((n+1)); \
		if [ $$n -gt 36 ]; then echo timeout esperando sentinel-kafka; exit 1; fi; \
		sleep 2; \
	done
	@echo Kafka listo.
endif

topics:
	docker exec sentinel-kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list

logs:
	$(COMPOSE) logs -f kafka

ps:
	$(COMPOSE) ps -a

down:
	$(COMPOSE) down

bootstrap:
	$(UV) run python scripts/bootstrap_models.py

qvac-smoke:
	$(UV) run python scripts/bootstrap_models.py --smoke


ifeq ($(OS),Windows_NT)
api: env
	@echo API en http://$(API_HOST):$(API_PORT)/docs Kafka=$(KAFKA_HOST_BOOTSTRAP)
	powershell -NoProfile -Command "$$env:SENTINEL_KAFKA__BOOTSTRAP_SERVERS='$(KAFKA_HOST_BOOTSTRAP)'; uv run uvicorn app.main:app --host $(API_HOST) --port $(API_PORT)"
else
api: env
	@echo API en http://$(API_HOST):$(API_PORT)/docs Kafka=$(KAFKA_HOST_BOOTSTRAP)
	SENTINEL_KAFKA__BOOTSTRAP_SERVERS=$(KAFKA_HOST_BOOTSTRAP) \
		$(UV) run uvicorn app.main:app --host $(API_HOST) --port $(API_PORT)
endif

dev: env sync up
	$(info)
	$(info Stack listo. Siguiente:)
	$(info   1. Rellena SENTINEL_WEBHOOK_TOKEN en .env)
	$(info   2. make bootstrap   (si data/qvac ya tiene el GGUF: make qvac-smoke))
	$(info   3. make api)
	$(info   4. http://$(API_HOST):$(API_PORT)/lab)
	@:

check:
	$(UV) run ruff check .
	$(UV) run ruff format --check .
	$(UV) run mypy app simulator
	$(UV) run pytest tests/unit

test:
	$(UV) run pytest tests/unit

fmt:
	$(UV) run ruff check --fix .
	$(UV) run ruff format .
