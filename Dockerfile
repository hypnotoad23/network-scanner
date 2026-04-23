FROM python:3.12-slim AS builder

RUN pip install --no-cache-dir poetry

WORKDIR /app

COPY pyproject.toml poetry.lock ./

RUN poetry config virtualenvs.create false \
	&& poetry install --no-interaction --no-ansi --no-root

FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . .

RUN pip install .

RUN apt-get update && apt-get install -y tcpdump && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /root/.cache/mac-vendor-lookup && \
	python -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()"

ENTRYPOINT ["netscan"]
