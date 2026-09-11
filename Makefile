# Sentinel-DNS — comandos locales.

# make up    perfil core (Kafka, ClickHouse, Grafana, Prometheus, API)
# make full  perfil full (core + Wazuh manager + simulador mixed_demo)
# make api   API en el host contra Kafka/ClickHouse publicados en loopback

.DEFAULT_GOAL := help

COMPOSE := docker compose
UV := uv
KAFKA_HOST_BOOTSTRAP := localhost:29092
CLICKHOUSE_HOST := localhost
API_HOST := 127.0.0.1
API_PORT := 8000

.PHONY: help env sync kafka up full wazuh down logs ps wait-kafka topics \
	bootstrap qvac-smoke api dev check test fmt smoke validate-k8s \
	ensure-wazuh-dir

help:
	$(info   make env            Copia .env.example a .env si no existe)
	$(info   make sync           uv sync + npm install (@qvac/sdk local))
	$(info   make up             Perfil core: Kafka, ClickHouse, Grafana, Prometheus, API)
	$(info   make full           Perfil full: core + Wazuh manager + simulador)
	$(info   make wazuh          Levanta wazuh-manager, exporta el cert TLS y hace ingest de prueba)
	$(info   make wait-kafka     Espera healthcheck de sentinel-kafka)
	$(info   make topics         Lista topics congelados)
	$(info   make down           Para el stack Compose)
	$(info   make bootstrap      Descarga el GGUF a data/qvac (requiere red))
	$(info   make qvac-smoke     Comprueba cache local, no descarga)
	$(info   make api            Uvicorn en el host contra loopback)
	$(info   make smoke          scripts/smoke_test.py)
	$(info   make validate-k8s   Kustomize + kubeconform + policy)
	$(info   make check          ruff + mypy + pytest unit)
	$(info)
	$(info Lab: http://$(API_HOST):$(API_PORT)/lab)
	$(info Grafana: http://127.0.0.1:3000)
	@:

ifeq ($(OS),Windows_NT)
env:
	powershell -NoProfile -Command "if (-not (Test-Path -LiteralPath '.env')) { Copy-Item .env.example .env; Write-Host 'Creado .env. Rellena SENTINEL_WEBHOOK_TOKEN y credenciales Wazuh.' } else { Write-Host '.env ya existe' }"
else
ifeq ($(wildcard .env),)
env:
	cp .env.example .env
	@echo Creado .env. Rellena SENTINEL_WEBHOOK_TOKEN y credenciales Wazuh.
else
env:
	@echo .env ya existe
endif
endif

sync:
	$(UV) sync
	npm install

ifeq ($(OS),Windows_NT)
ensure-wazuh-dir:
	powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path 'data/wazuh' | Out-Null"
else
ensure-wazuh-dir:
	mkdir -p data/wazuh
endif

up: env
	@$(MAKE) ensure-wazuh-dir
	$(COMPOSE) --profile core up -d --build
	@$(MAKE) wait-kafka

full: env
	@$(MAKE) ensure-wazuh-dir
	$(COMPOSE) --profile full up -d --build
	@$(MAKE) wait-kafka

wazuh: env
	@$(MAKE) ensure-wazuh-dir
	$(COMPOSE) --profile security up -d
	$(UV) run python scripts/bootstrap_wazuh.py

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
	$(COMPOSE) --profile core logs -f

ps:
	$(COMPOSE) --profile full ps -a

down:
	$(COMPOSE) --profile full down

bootstrap:
	$(UV) run python scripts/bootstrap_models.py

qvac-smoke:
	$(UV) run python scripts/bootstrap_models.py --smoke

smoke:
	$(UV) run python scripts/smoke_test.py

validate-k8s:
	$(UV) run python scripts/validate_manifests.py

ifeq ($(OS),Windows_NT)
api: env
	@echo API en http://$(API_HOST):$(API_PORT)/docs Kafka=$(KAFKA_HOST_BOOTSTRAP) ClickHouse=$(CLICKHOUSE_HOST)
	powershell -NoProfile -Command "$$env:SENTINEL_KAFKA__BOOTSTRAP_SERVERS='$(KAFKA_HOST_BOOTSTRAP)'; $$env:SENTINEL_CLICKHOUSE__HOST='$(CLICKHOUSE_HOST)'; $$env:SENTINEL_WAZUH__BASE_URL='https://localhost:55000'; uv run uvicorn app.main:app --host $(API_HOST) --port $(API_PORT)"
else
api: env
	@echo API en http://$(API_HOST):$(API_PORT)/docs Kafka=$(KAFKA_HOST_BOOTSTRAP) ClickHouse=$(CLICKHOUSE_HOST)
	SENTINEL_KAFKA__BOOTSTRAP_SERVERS=$(KAFKA_HOST_BOOTSTRAP) \
		SENTINEL_CLICKHOUSE__HOST=$(CLICKHOUSE_HOST) \
		SENTINEL_WAZUH__BASE_URL=https://localhost:55000 \
		$(UV) run uvicorn app.main:app --host $(API_HOST) --port $(API_PORT)
endif

dev: env sync up
	$(info)
	$(info Stack core listo. Siguiente:)
	$(info   1. Rellena SENTINEL_WEBHOOK_TOKEN en .env)
	$(info   2. make bootstrap   (si data/qvac ya tiene el GGUF: make qvac-smoke))
	$(info   3. make api   o deja sentinel-api del compose)
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
