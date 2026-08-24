# Labs

containerlab topologies. Two purposes, deliberately kept apart.

| Directory | Purpose | Lifetime |
|-----------|---------|----------|
| [`corpus/`](corpus/) | Generate real multi-vendor configurations for the corpus | Long-lived, run by hand |
| [`crucible/`](crucible/) | Twin topologies booted by the verification sandbox | Ephemeral, seconds, torn down automatically |

## corpus/ — where the config corpus comes from

Arista cEOS, Nokia SR Linux, FRR, SONiC and VyOS all run as containers on one laptop. Boot them,
configure them badly on purpose, and export the configurations. This is how we get sixty real
files across eight vendors without owning any hardware.

Configure them *badly on purpose* is not a joke: a corpus of correctly hardened devices proves
nothing about a tool whose job is finding misconfiguration. Each topology has a matching
misconfiguration script that introduces known, documented weaknesses — which also makes those
files useful for ground-truth labelling.

## crucible/ — twin topologies

Generated, not hand-written. The sandbox renders IR to a VyOS configuration and emits a topology
around it: the twin, an untrusted segment to probe from, and nothing else.

Hard constraints, stated here because they are the ones an NTRO evaluator will ask about:

- **Isolated bridge. No egress.** The twin cannot reach the host network, the internet, or any
  production device.
- **Ephemeral.** Torn down after every run, including on failure.
- **No production credentials.** Rendering strips credential material; the twin gets generated
  values, because the point is to test reachability and protocol posture, not to reproduce
  secrets.

## Requirements

containerlab and Docker. Both are in the offline bundle. Images are pre-pulled — a lab that needs
to fetch an image is a lab that does not run on the demo machine with the cable out.
