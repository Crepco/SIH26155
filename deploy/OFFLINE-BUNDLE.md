# The offline installation bundle

The deliverable that makes the air-gap claim true rather than aspirational.

**Definition of done: a machine that has never had internet access can install Crucible from this
bundle and complete a full audit, including a Crucible verification run.**

## What goes in

| Component | Why it must be bundled |
|-----------|------------------------|
| Container images (api, worker, db, redis, ollama, frontend, neo4j) | A `docker pull` on the target host is a network call |
| Quantised model weights, baked into the ollama image | A runtime model pull is the most likely accidental egress in the whole system |
| Sentence-transformer embedding weights | Same, and easy to miss because the library fetches lazily on first use |
| Python wheels for every dependency | Installation must run with no package index configured |
| Frontend build output | Fonts and icons included. No CDN reference anywhere |
| VyOS image and the probe image | Crucible boots twins offline or it does not boot them |
| Rule set (CIS + imported STIG) | An air-gapped deployment cannot fetch a benchmark |
| IR, rule and adapter schemas | Validation is not optional, so the contracts ship |
| Installation script and this document | Someone outside the team has to follow it cold |

## How it is built

By a script, never assembled by hand. Hand-assembly is how a bundle ends up working on the
machine that built it and nowhere else.

    scripts/build-offline-bundle.sh

produces a single archive plus a manifest of SHA-256 digests. The manifest is what makes the
bundle verifiable on arrival, which matters when the delivery mechanism is physically carrying
media into a secure facility.

## How it is verified

The build is not trusted; it is tested. The verification job:

1. Starts a container with **no network namespace route** except loopback.
2. Installs from the bundle with no package index and no registry configured.
3. Runs a full audit over a corpus device: ingest, parse, evaluate, report, sign.
4. Runs one Crucible verification: boot the twin, demonstrate, remediate, re-test, regression.
5. Asserts that no DNS resolution and no outbound connection was attempted at any point.

Any attempt to resolve or connect fails the job. This runs in CI from Phase 1, not as a manual
check in September, because the failure we are guarding against is a dependency quietly fetching
something on first use — and that is exactly the failure that shows up for the first time in
front of an audience.

## Delivery

One archive, one manifest, one signature. The install script verifies the manifest against the
signature before extracting anything, using a public key delivered separately.
