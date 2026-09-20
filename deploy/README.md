# Deployment

Air-gapped has to mean an installer that works with the cable unplugged, not an aspiration.

| File | Purpose |
|------|---------|
| `OFFLINE-BUNDLE.md` | How the offline installation bundle is built and verified |
| `docker-compose.yml` | The planned multi-user stack. **Not needed by the current build** |
| `.env.example` | Every setting, documented. No secrets, ever |

## What actually runs today

One Python process. No database, no broker, no container, no message queue.

```bash
pip install -r backend/requirements.txt
cd backend && uvicorn crucible.api.main:app --host 127.0.0.1 --port 8000
```

That serves the API and the audit console, and the CLI (`crucible audit`, `verify`, `show`,
`drift`, `rules`) runs against the same code with no server at all. Seven runtime dependencies,
all of them pure-Python or wheel-shipping. State lives in `$CRUCIBLE_HOME` — the publisher key,
the adapter-pack trust store and installed packs — and defaults to `~/.crucible`.

Docker is needed for exactly one optional feature: the Crucible verification sandbox, which boots
a container twin of a device to demonstrate a finding. Everything else runs without it. With no
Docker daemon the run records `no Docker daemon: findings stay ASSERTED` and the audit completes
normally — a finding that could not be demonstrated stays a finding, and never becomes a pass.

For setup, follow the [top-level README](../README.md). The offline path is
[OFFLINE-BUNDLE.md](OFFLINE-BUNDLE.md).

## The compose stack

`docker-compose.yml` is the multi-user deployment: it becomes necessary when several auditors
share one installation, when bulk audits want more than one machine's cores, or when the fleet
graph outgrows memory. None of that is true of the current build, and running it today buys
nothing.

| Service | What it is | Status |
|---------|-----------|--------|
| `api` | The FastAPI backend and the console | The one thing that exists today |
| `worker` | Celery worker for bulk audits | Planned. A 60-device audit runs in-process in seconds |
| `db` | PostgreSQL. IR documents are JSONB and query well | Planned. Reports are files today |
| `redis` | Broker and result backend | Planned, with the worker |
| `ollama` | Local model runtime, loopback-bound | Optional, and off by default (ADR 0003) |
| `neo4j` | Fleet graph | Optional. The in-process graph is the default and needs no server |

There is no frontend service: the console is plain HTML, CSS and JavaScript served by the API
itself, with no build step and no bundler (ADR 0007).

## The rule that governs this directory

**No service may reach a host outside the deployment.** Not for models, not for updates, not for
telemetry, not for fonts. `scripts/check-airgap.sh` enforces this in CI over the dependency tree,
every shipped browser asset and the model layer; `scripts/verify-offline-bundle.sh` enforces it
over an actual installation. The posture a report was generated under is stated in the report
footer, so an auditor can see it rather than take it on trust.

The local model is the sharpest edge here. When Ollama is enabled it is refused any address that
is not loopback — not as configuration, but in the code that constructs the client.
