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
| No inference leaves the host | Ollama bound to loopback, model pre-pulled into the bundle, no registry configured |
| No embeddings leave the host | sentence-transformers weights vendored in the bundle, `HF_HUB_OFFLINE` set |
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
The bundle contains: container images, the quantised model, embedding weights, Python wheels,
frontend build output, the rule set, the IR and rule schemas, and the VyOS image for Crucible.

It is produced by a build step, not assembled by hand, and the definition of done is that a
machine which has never had internet access can install and run a complete audit from it.

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
