# Scripts

Operator and developer tasks. Invoked through the [Makefile](../Makefile), not directly, so that
there is one place to look for how to do a thing.

**Status: Phase 0. Specified here, implemented alongside the code they support.**

| Script | Invoked by | What it does |
|--------|-----------|--------------|
| `check-airgap.sh` | `make airgap-check` | Fails if a cloud inference SDK appears in any dependency manifest, or if an external asset host is referenced in source. Mirrors the CI job so the failure happens locally first |
| `corpus-status.sh` | `make corpus` | Counts configurations and labels per vendor in `corpus/`, and reports progress against the Phase 0 target of 60 collected and 20 labelled |
| `misconfigure.sh` | By hand, after `make lab-up` | Introduces the documented weaknesses into the lab devices so the corpus contains devices worth auditing |
| `export-lab-configs.sh` | By hand | Pulls running configurations and `show version` output from the lab into `corpus/raw/`, as bundles rather than bare config files |
| `build-offline-bundle.sh` | `make bundle` | Produces the offline installation archive and its SHA-256 manifest. See [deploy/OFFLINE-BUNDLE.md](../deploy/OFFLINE-BUNDLE.md) |
| `verify-bundle.sh` | CI, and by hand before shipping | Installs the bundle in a container with no route off the host and runs a full audit. Any resolution attempt fails |

## Rules for anything in this directory

1. **POSIX sh or bash, no other runtime.** A script that needs Python to bootstrap the Python
   environment is a bad morning waiting to happen.
2. **Idempotent.** Running twice does the same thing as running once.
3. **No network.** Same rule as everything else in this repository, and these scripts are the ones
   most tempted to break it.
4. **Fail loudly.** `set -euo pipefail` at the top, a real exit code, and a message that says what
   to do next.
