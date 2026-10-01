FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    POETRY_NO_INTERACTION=1

RUN pip install --no-cache-dir poetry

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main


FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Копируем только реально нужные для рантайма зависимости, без самого poetry
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

COPY . .
RUN pip install --no-deps --no-cache-dir .

RUN mkdir -p /root/.cache/mac-vendor-lookup && \
    python -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()"

ENTRYPOINT ["netscan"]
