# The offline installation bundle

The deliverable that makes the air-gap claim true rather than aspirational.

**Definition of done: a machine that has never had internet access can install Crucible from this
bundle and complete a full audit.** That is tested, not asserted — see *How it is verified*.

## What goes in

| Component | Why it must be bundled |
|-----------|------------------------|
| Python wheels for every dependency | Installation must run with no package index configured |
| The product, taken from `git archive` | Source, rules, schemas, the console, the labs |
| Corpus label files | The validation harness reads them, and the suite runs from the bundle |
| The Crucible twin image, via `docker save` | A `docker pull` on the target host is a network call |
| `INSTALL.md` and a manifest | Someone outside the team has to follow it cold |

The console needs nothing else: it is plain HTML, CSS and JavaScript with no build step, no
bundler and no font or icon fetched from anywhere (ADR 0007).

Model weights are the one thing not in the bundle. The default proposer is deterministic and
needs none (ADR 0003), so an installation is complete and fully functional without them; a
deployment that wants the local Qwen2.5-Coder-7B installs Ollama and loads the weights alongside.
Folding the 4.7 GB blob into the archive is mechanical and not yet done.

## How it is built

By a script, never assembled by hand. Hand-assembly is how a bundle ends up working on the
machine that built it and nowhere else.

```bash
scripts/build-offline-bundle.sh          # writes dist/
```

Building needs a network, to download the wheels. Installing must not.

The contents come from `git archive HEAD`, not from a copy of the working tree. This is not
fastidiousness: a plain `cp -r` picked up a local virtualenv on the first run, which took the
bundle from 17M to 74M and buried files deep enough that extraction silently truncated them on
Windows.

A measured build, on a laptop:

| | |
|---|---|
| Archive | 17 MB, built in ~41s |
| Wheels | 24, for 7 direct runtime dependencies |
| Files | 227, each with a SHA-256 in `MANIFEST.sha256` |
| Integrity | A digest of the manifest, and a `.sha256` beside the archive |

The archive's digest is recorded under its bare filename, so `sha256sum -c` works from wherever
the media is mounted rather than only from the directory that built it.

## How it is verified

The build is not trusted; it is tested.

```bash
scripts/verify-offline-bundle.sh dist/crucible-0.1.0-offline-YYYYMMDD.tar.gz
```

1. Checks the archive digest, then the manifest against the extracted contents.
2. Installs into a fresh virtualenv with `--no-index`, so any package not in the bundle fails
   here rather than on the customer's machine.
3. Runs the suite, a full audit and a ledger verification out of the installed copy, with every
   proxy variable pointed at the discard port.

A clean run:

```
  ok    archive digest matches
  ok    manifest verifies (227 files)
  ok    installed from vendored wheels with no package index
  ok    the suite passes from the installed bundle (227 passed)
  ok    a full audit ran and wrote a ledger
  ok    the ledger verifies INTACT
```

What this does *not* do is sever the interface — that needs a container with no route but
loopback, which is how the CI job runs it. What it does catch is the common failure: something
that is not actually in the bundle, so installation reaches out for it.

Poisoning the proxy variables is the part that has already paid for itself. It failed on first
use, and the cause was not the bundle: the Ollama proposer validated that its URL was loopback
but called `urlopen`, whose default opener reads `http_proxy` from the environment. On a host
with a corporate proxy configured, every prompt — customer configuration lines included — would
have gone to that proxy. The transport now bypasses proxies explicitly, and a test fails if the
proxy is ever consulted.

## Delivery

One archive, one manifest, one digest. Where the delivery mechanism is physically carrying media
into a secure facility, the manifest is what makes the bundle verifiable on arrival.

Signing the manifest with the same Ed25519 machinery the ledger and adapter packs already use —
so the install script can refuse an archive that was altered in transit — is the obvious next
step and is not built yet.
