# ---------------------------------------------------------------------------
# Crucible backend
#
# Built once, shipped inside the offline bundle. The running container never
# installs anything and never resolves a hostname outside the deployment.
# ---------------------------------------------------------------------------

FROM python:3.11-slim AS builder

WORKDIR /build

# Build dependencies for lxml and psycopg. Present in the builder only, so the
# runtime image stays small and has less to audit.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libxml2-dev libxslt1-dev libpq-dev \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY crucible ./crucible

RUN pip install --no-cache-dir --prefix=/install ".[ai]"


FROM python:3.11-slim AS runtime

# Probe tooling for Crucible lives in its own image, not here. This container
# audits configurations; it does not scan networks.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libxml2 libxslt1.1 libpq5 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --uid 10001 crucible

COPY --from=builder /install /usr/local
COPY --chown=crucible:crucible crucible /app/crucible
COPY --chown=crucible:crucible ../rules /app/rules
COPY --chown=crucible:crucible ../schemas /app/schemas

WORKDIR /app
USER crucible

# Offline by construction. A library that lazily fetches a model on first use is
# the most likely accidental egress in the whole system, so it is closed here as
# well as in the compose environment.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CRUCIBLE_OFFLINE=1 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_DATASETS_OFFLINE=1

EXPOSE 8000

CMD ["uvicorn", "crucible.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
