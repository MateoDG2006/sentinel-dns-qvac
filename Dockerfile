FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv build-essential curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages uv

WORKDIR /app
COPY . .

RUN npm ci --omit=dev
RUN uv sync --frozen

ENV QVAC_SDK_DIR=/app/node_modules/@qvac/sdk
ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]