# Frontend

Two things live here. Only one of them ships today.

| Path | What it is | Status |
|------|-----------|--------|
| [`public/`](public/) | **The audit console.** Plain HTML, CSS and JavaScript, served by the API at `/`. | **Ships now** |
| `package.json`, `next.config.mjs`, `tsconfig.json`, `Dockerfile` | Next.js scaffold for the Phase 2 training GUI | Not yet built |

## Running it

```bash
cd backend
uvicorn crucible.api.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. There is no install step and no build step, because there is nothing
to install or build.

## Why plain HTML and not the Next.js app the stack document specifies

The stack document ([docs/13](../docs/13-tech-stack.md)) names Next.js, and that remains the right
answer for the training GUI, which is a genuinely stateful editing surface. It is the wrong answer
for the audit console, for one reason:

**`npm ci` pulls roughly three hundred packages over the network.** The single claim this project
cannot afford to weaken is that it runs with the cable out. A page with no bundler, no lockfile and
no third-party code is a page whose offline behaviour can be *checked* rather than asserted — and
[`backend/tests/test_console.py`](../backend/tests/test_console.py) checks it, on every push, by
scanning every asset for anything that would make a browser reach off the deployment.

The cost is real and worth naming: no component library, no type checking on the view layer, and
state handled by hand. At this size that is a good trade. If the training GUI outgrows it, the
scaffold is still here.

## Design

The console is the living version of the signed PDF the tool produces — a cool-paper instrument
sheet, not a dark dashboard with a neon accent. Every product in this category looks like the
latter; the deliverable here is a *document*, so the console reads like one, and it projects
legibly in a bright room.

The typography is deliberately inverted. Monospace carries all chrome, labels, numbers and
navigation, because the entire interface is quoting machine text and should look like it. A book
serif is reserved for the sentences a human wrote — the rationale under a finding — and nothing
else. There is no sans-serif on the page. Both faces come from system stacks, because the air gap
rules out web fonts, and that constraint shaped the result rather than damaging it.

### The signature element

Everything on the page is quiet so that one thing can be loud: the **evidence gutter**. Expanding
a finding shows the device's own configuration, at its real line numbers, with the offending line
marked. A reader can open the file and check.

```
running-config.txt                          mgmt.telnet_enabled · tier 0
   99   logging synchronous
  100  line vty 0 4
  101   exec-timeout 30 0
> 102   transport input telnet ssh  ◄
  103  line vty 5 15
```

That is the argument of the whole project rendered as an interface component: the finding is not
an opinion, and here is the line.

## What the console will not do

- **It never computes a verdict.** It renders what the backend decided, so the screen and the
  signed PDF cannot disagree. A dashboard that recalculated anything would eventually drift, and
  then neither artefact could be trusted.
- **It never hides coverage.** The percentage of lines read is on screen before the findings are,
  and the uninterpreted lines are one click away, verbatim.
- **It never collapses three states into two.** `DEMONSTRATED`, `ASSERTED` and `UNKNOWN` get three
  distinct treatments, each underlined in its own colour. Grey is not green.
