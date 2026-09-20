# ADR 0008 — The twin is a purpose-built container, not VyOS

**Status:** Accepted · 20 Sep 2026 · Track F · Supersedes [ADR 0005](0005-single-emulation-target.md)

## Context

[ADR 0005](0005-single-emulation-target.md) chose VyOS in containerlab as the single emulation
target: one renderer from the IR, one image, no vendor licensing. The reasoning still holds, and
this record keeps all of it. What did not survive contact with the build is the *image*.

VyOS publishes no official container image. Getting one means downloading a rolling ISO of around
half a gigabyte and converting it, or building from source; containerlab then has to be installed
as well, which on Windows means a Linux VM underneath it. That is a long dependency chain for a
component whose job is to answer four questions: is Telnet listening, what does SSH negotiate,
does SNMP answer `public`, and can the untrusted segment reach the management plane at all.

## Decision

The twin is a small Alpine container built from a Dockerfile in this repository
(`labs/crucible/twin/`), and the harness drives `docker` directly rather than containerlab.

What the twin models is unchanged: the **security properties** of the audited device, rendered
from the IR. Telnet, SSH with its offered algorithms, plaintext HTTP, SNMP communities, and a
management filter. It is not a router, it does not forward packets, and it does not pretend to be
any vendor's operating system.

Remediation is applied to it as the VyOS-style command subset the rules already carry in their
`vyos` block, interpreted by `crucible/sandbox/apply.py`. That is the same intent as the Cisco or
FortiOS spelling of the fix — which is what the IR is for — and a command the interpreter does
not understand is reported as not applied rather than silently skipped.

## Consequences

**Good.**

- The image is a few tens of megabytes and builds from an Alpine base in about five seconds. A
  twin boots in roughly two seconds, and `crucible verify --device X --finding Y` finishes in
  about twelve, against the fifteen the plan asked for.
- One dependency: a Docker daemon. No containerlab, no ISO, no VM on Linux hosts.
- The whole twin is one readable Dockerfile and one 150-line entrypoint, so "what exactly did you
  boot?" is a question an evaluator can answer themselves. With a vendor image it is not.
- Probes are standard-library Python, so the sandbox image needs no tooling beyond Python, and
  the *response bytes* are the proof artefact rather than some tool's summary of them.

**Bad, and accepted.**

- The twin is even further from a real Palo Alto than a VyOS instance would be. The answer is
  unchanged from ADR 0005: we are not verifying feature parity, we are verifying security
  properties, and a property the twin cannot model leaves its finding ASSERTED and says so.
- Applying the VyOS spelling of a fix does not prove the Cisco spelling is free of typos. Nothing
  that boots a single twin could, and the report does not claim otherwise.
- Routing, ACL evaluation on transit traffic and control-plane behaviour are out of reach. The
  fleet graph reasons about those statically instead, and marks what it inferred.

**If this becomes the wrong trade.** The harness talks to a twin through `boot`, `reconfigure`
and `probe`. A VyOS or vendor-image backend implementing those three would slot in beside this
one; nothing above the harness knows what is underneath.
