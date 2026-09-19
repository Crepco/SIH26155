# ADR 0007 — The console and the training GUI are plain HTML, not Next.js

**Status:** Accepted · 20 Sep 2026 · Track D · Amends [docs/13](../13-tech-stack.md)

## Context

The stack document named Next.js for the dashboard, the training GUI and the fleet view, on the
grounds that the training GUI is the surface judges physically touch and has to feel finished.
The audit console shipped in Phase 1 as plain HTML, CSS and JavaScript served by the API, and the
Next.js scaffold beside it was never built. It had no lockfile, so the CI job that tried to build
it failed on every push.

The scaffold's cost is the air-gap claim itself. `npm ci` pulls roughly three hundred packages
over the network, and a bundler's output is something whose offline behaviour has to be
*asserted*. A page with no bundler and no third-party code is one whose offline behaviour can be
*checked*: `backend/tests/test_console.py` scans every shipped asset for anything that would make
a browser reach off the host.

## Decision

The audit console, the training GUI (Tier 3) and the fleet view are one plain HTML/CSS/JS
application in `frontend/public/`, served by the API at `/`. The Next.js scaffold is removed, and
so is its CI job. It is replaced by a job that runs the console's self-containment tests.

## Consequences

**Good.**

- There is nothing to install or build, and nothing to vendor into the offline bundle for the UI.
- The no-external-asset property is tested on every push instead of being claimed.
- One origin, one process, one set of assets. The training GUI talks to the same API as the
  audit console, so there is no CORS surface and no second server to secure.

**Bad, and accepted.**

- No component library and no type checking on the view layer. State is handled by hand.
- If the training GUI outgrows this, the right move is a small, vendored, lockfile-pinned build
  committed with its output. It should not be a framework that fetches at install time.
