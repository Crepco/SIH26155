# Deployment

Air-gapped has to mean an installer that works with the cable unplugged, not an aspiration.

| File | Purpose |
|------|---------|
| `docker-compose.yml` | The full stack for development and for an on-premises deployment |
| `.env.example` | Every setting, documented. No secrets, ever |
| `OFFLINE-BUNDLE.md` | How the offline installation bundle is built and verified |

## Services

| Service | What it is | Notes |
|---------|-----------|-------|
| `api` | FastAPI backend | The only service exposed outside the compose network |
| `worker` | Celery worker | Bulk audits of 200 configs are embarrassingly parallel |
| `db` | PostgreSQL | IR documents are JSONB and query well |
| `redis` | Broker and result backend | — |
| `ollama` | Local model runtime | Bound to the compose network. Models pre-pulled into the image |
| `neo4j` | Fleet graph | Optional. NetworkX fallback for a laptop-only deployment |
| `frontend` | Next.js | Assets bundled. No CDN reference in the build output |

## The rule that governs this directory

**No service may reach a host outside the deployment.** Not for models, not for updates, not for
telemetry, not for fonts. This is checked in CI by running the full audit pipeline with no route
to anything but loopback, and it is stated in the report footer at runtime so an auditor can see
the posture a report was generated under.

## First run

Setup instructions land with Phase 1, and they will be written so that someone outside the team
can follow them cold — that is a stated submission requirement, and it is also the only way to
find out whether they are real.
