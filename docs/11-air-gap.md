# 11 — Air-gap constraints

**Owner: Track F. Enforced from day one, not added at the end.**

The customer is NCIIPC. A network device configuration is a complete blueprint of an
organisation defences. Uploading that file to a commercial LLM API hosted in another jurisdiction
is not a policy preference to be weighed — it is a hard disqualifier. Any solution that depends
on an internet-connected model is undeployable for the customer who wrote this problem statement.

So air-gap is not a feature. It is the operating environment.

## What offline actually has to mean

| Claim | Operational test |
|-------|------------------|
| No inference leaves the host | Ollama refused any address but loopback, in the transport itself — an empty `ProxyHandler`, so a proxy configured in the environment cannot capture a prompt |
| No model is reached by accident | The model is opt-in (`CRUCIBLE_OLLAMA=1`). One merely listening on loopback is not adopted |
| No retrieval weights to leak | There are none. Tier 2's default retrieval is in-process TF-IDF, not an embedding model |
| No package fetch at install time | Wheels vendored; installation runs with no index configured |
| No frontend asset fetch | Fonts, icons and styles bundled. No CDN reference anywhere in the build output |
| No telemetry, no update check | Disabled at the dependency level, verified in CI |
| No DNS at runtime | The service starts and completes a full audit with resolution unavailable |

The last row is the honest test and the one we rehearse: not *did we avoid calling an API*, but
*does the whole thing work with the cable out*.

## Enforcement, not intention

Three mechanisms, because a rule nobody checks is a rule that decays:

1. **Dependency review.** A cloud LLM SDK in the dependency tree is a defect regardless of whether
   any code path calls it. CI fails on the presence of the package, not on its use.
2. **Egress test in CI.** The full audit pipeline runs in a container with no network namespace
   route to anything but loopback. If a code path tries to resolve or connect, the test fails.
3. **Runtime assertion.** The service logs, at startup, the outbound policy it is running under,
   and that line is printed in the report footer. An auditor can see the posture the report was
   generated with.

## The offline installation bundle

"Air-gapped" has to mean an installer that works with the cable unplugged, not an aspiration.
The bundle contains the product, a wheel for every dependency, the rule set, the IR and rule
schemas, the corpus labels and the Crucible twin image. 17 MB, 227 files, each with a SHA-256 in
a manifest.

It is produced by a build step, not assembled by hand, and the definition of done is that a
machine which has never had internet access can install and run a complete audit from it — which
`scripts/verify-offline-bundle.sh` tests by installing with no package index and every proxy
variable pointed at the discard port, then running the suite, a full audit and a ledger check
from the installed copy.

Model weights are the one thing not yet folded in. A deployment that wants the local model
installs Ollama and loads the weights alongside the bundle; the audit pipeline is unaffected
without them, because the deterministic proposer is the default.

## The demo consequence

During the demo we **disconnect the machine from the network, visibly**, and keep auditing.
Fifteen teams will have shown an API wrapper before we present. We pull the plug and the tool
still works.

That moment is worth more than any slide, and it is only available to a team that took this
constraint seriously in week one rather than week four.

## What this rules out, permanently

- No cloud LLM API. Not OpenAI, not Anthropic, not Gemini. *We can swap it later* is not an
  architecture.
- No hosted vector database.
- No CDN-delivered fonts or scripts in the frontend.
- No error reporting or analytics service.
- No dependency that phones home on import.

Every one of these is easy to accept in August and impossible to retrofit in September.
