"""Tier 2 - propose a mapping for a line nobody recognised. Never a verdict.

Two proposers, one contract:

* :class:`LexicalProposer` - the offline default. Ranks IR fields by TF-IDF
  similarity (words plus character trigrams) between the line, its block
  context and the vocabulary built from vendors we already parse. It needs no
  model and no download, and it is deterministic.
* :class:`OllamaProposer` - a local model on loopback. It is shown the top
  lexical candidates as precedent and asked only to *choose one and point at
  the value token*. It never writes a pattern: the extraction rule is built by
  :func:`build_mapping` from the model's choice, so a model cannot smuggle an
  arbitrary regex into a pack. If Ollama is absent or answers badly, the
  lexical proposal is used and the proposal says so.

Either way the output is a :class:`~crucible.adapters.pack.Mapping`: a
candidate *parser*, applied deterministically. The policy engine still issues
every verdict (ADR 0004). A proposal below the configured confidence goes to a
human at Tier 3 rather than into a report.
"""

from __future__ import annotations

import json
import math
import os
import re
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlparse

from crucible.adapters.pack import Mapping, customer_data_in
from crucible.adapters.transforms import TransformError, apply_transform
from crucible.training.vocabulary import VOCABULARY, FieldSpec

__all__ = [
    "LexicalProposer",
    "OllamaProposer",
    "Proposal",
    "Proposer",
    "build_mapping",
    "default_proposer",
]

# -- tokens and features ------------------------------------------------------

_WORD = re.compile(r"[a-z][a-z0-9+-]*")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_IPV6 = re.compile(r"^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?$")
_NUMBER = re.compile(r"^\d+$")
_FQDN = re.compile(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){2,}$")

_BOOL_PAIRS: tuple[tuple[str, str], ...] = (
    ("enable", "disable"),
    ("enabled", "disabled"),
    ("yes", "no"),
    ("true", "false"),
    ("on", "off"),
)
_BOOL_WORDS = {w: pair for pair in _BOOL_PAIRS for w in pair}
_NEGATIONS = frozenset({"no", "undo", "delete", "disable", "deactivate"})
_COMMUNITY_MODIFIERS = frozenset(
    {"read", "write", "ro", "rw", "cipher", "simple", "read-only", "read-write", "add", "set"}
)


def _split_compound(word: str, known: frozenset[str]) -> list[str]:
    """``loghost`` -> ``log``, ``host`` when both halves are known words.

    Vendors glue words together freely. Splitting against the vocabulary's own
    word list is generic and learns nothing about any particular vendor.
    """
    if len(word) < 6 or word in known:
        return []
    for cut in range(3, len(word) - 2):
        head, tail = word[:cut], word[cut:]
        if head in known and tail in known:
            return [head, tail]
    return []


def _words(text: str, known: frozenset[str] = frozenset()) -> list[str]:
    cleaned = re.sub(r"[=/\"'{};:,()\[\]]", " ", text.lower())
    words: list[str] = []
    for token in _WORD.findall(cleaned):
        words.append(token)
        parts = [part for part in token.split("-") if len(part) > 1] if "-" in token else [token]
        if "-" in token:
            words.extend(parts)
        if known:
            for part in parts:
                words.extend(_split_compound(part, known))
    return words


def _features(words: Sequence[str], weight: float = 1.0) -> dict[str, float]:
    feats: dict[str, float] = defaultdict(float)
    for word in words:
        feats[f"w:{word}"] += weight
        padded = f"#{word}#"
        for i in range(len(padded) - 2):
            feats[f"t:{padded[i : i + 3]}"] += 0.25 * weight
    return feats


def _accumulate(target: dict[str, float], extra: dict[str, float]) -> None:
    for key, value in extra.items():
        target[key] = target.get(key, 0.0) + value


# -- the proposal -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Proposal:
    """A candidate extraction rule for one line, with how sure we are."""

    ir_path: str
    mapping: Mapping
    confidence: float
    rationale: str
    source: str
    #: The captured value as the transform will record it, for the GUI preview.
    preview: Any = None
    alternatives: tuple[tuple[str, float], ...] = field(default=())

    def to_dict(self) -> dict[str, Any]:
        return {
            "ir_path": self.ir_path,
            "mapping": self.mapping.to_dict(),
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
            "source": self.source,
            "preview": self.preview,
            "alternatives": [{"ir_path": p, "score": round(s, 3)} for p, s in self.alternatives],
        }


class Proposer(Protocol):
    name: str

    def propose(self, text: str, context: Sequence[str] = ()) -> Proposal | None: ...


# -- building the extraction rule ------------------------------------------------

#: Keys whose value is a credential. Never captured, never kept literal.
_SECRET_KEYS = frozenset(
    {"password", "passwd", "secret", "key", "psk", "pre-shared-key", "auth-key", "priv-key"}
)
#: Keys whose value is organisation data (names, addresses). Generalised in any
#: emitted pattern even when not captured, so a pack never carries it.
_DATA_KEYS = frozenset(
    {
        "name",
        "user",
        "username",
        "community",
        "address",
        "remote",
        "host",
        "server",
        "comment",
        "src-address",
        "dst-address",
        "interface",
        "default-name",
    }
)
#: Command verbs and selector syntax: grammar, never a value.
_VERBS = frozenset({"set", "add", "remove", "edit", "find", "print", "delete", "config", "next"})
_ENABLE_KEYS = ("disabled", "disable", "enabled", "enable", "status", "state", "shutdown")


@dataclass(frozen=True, slots=True)
class _Tok:
    raw: str
    key: str | None = None
    val: str | None = None

    @property
    def word(self) -> str:
        return (
            (self.val if self.key is not None and self.val is not None else self.raw)
            .strip("\"';")
            .lower()
        )

    @property
    def content(self) -> str:
        return (self.val if self.key is not None and self.val is not None else self.raw).strip(
            "\"';"
        )


def _tokenise(text: str) -> list[_Tok]:
    tokens: list[_Tok] = []
    for raw in text.split():
        if "=" in raw and not raw.startswith("="):
            key, _, val = raw.partition("=")
            tokens.append(_Tok(raw, key, val))
        else:
            tokens.append(_Tok(raw))
    return tokens


def _lit(text: str) -> str:
    """re.escape, minus the hyphen escapes that make patterns unreadable."""
    return re.escape(text).replace(r"\-", "-")


def _is_variable(token: str) -> bool:
    """Tokens that are data, not grammar: generalised in any pattern we emit."""
    core = token.strip("\"';,")
    return bool(
        _IPV4.match(core)
        or _IPV6.match(core)
        or _NUMBER.match(core)
        or _FQDN.match(core)
        or token.startswith(("$", '"', "'"))
        or (any(c.isdigit() for c in core) and len(core) > 1)
        or customer_data_in(_lit(core))
    )


def _value_group(kind: str, token: str) -> str:
    core = token.strip("\"';")
    if kind == "int":
        return r"(?P<value>\d+)"
    if _IPV4.match(core) or _IPV6.match(core):
        return r"(?P<value>[0-9A-Fa-f:./]+)"
    return r"(?P<value>[^\s;]+)"


def _render(tokens: Sequence[_Tok], index: int | None, group: str) -> str:
    parts: list[str] = []
    for i, tok in enumerate(tokens):
        if tok.key is not None:
            key = tok.key.lower()
            if i == index:
                parts.append(_lit(tok.key) + "=" + group)
            elif key in _SECRET_KEYS or key in _DATA_KEYS or _is_variable(tok.val or ""):
                parts.append(_lit(tok.key) + r"=\S+")
            else:
                parts.append(_lit(tok.raw))
        elif i == index:
            parts.append(group)
        elif _is_variable(tok.raw):
            parts.append(r"\S+")
        else:
            parts.append(_lit(tok.raw))
    return "^" + r"\s+".join(parts) + "$"


def _within_for(context: Sequence[str]) -> str | None:
    if not context:
        return None
    words = [w for w in context[-1].split() if not _is_variable(w)][:2]
    if not words:
        return None
    return "^" + r"\s+".join(_lit(w) for w in words) + r"\b"


def _secret_position(tokens: Sequence[_Tok], index: int) -> bool:
    """True when the token at ``index`` is, or directly follows, a credential."""
    tok = tokens[index]
    if tok.key is not None and tok.key.lower() in _SECRET_KEYS:
        return True
    previous = tokens[index - 1].word if index > 0 else ""
    return previous in _SECRET_KEYS or previous.endswith(("password", "secret", "cipher"))


def _hinted(tokens: Sequence[_Tok], hint: str | None) -> int | None:
    if hint is None:
        return None
    for i, tok in enumerate(tokens):
        if hint in (tok.raw.strip("\"';"), tok.content):
            return i
    return None


def _choose_bool(tokens: Sequence[_Tok]) -> tuple[str, int | None, str]:
    words = [t.word for t in tokens]
    if words[0] in _NEGATIONS and len(tokens) > 1:
        return "negated_presence", None, ""
    for i, tok in enumerate(tokens):
        if tok.key is not None and tok.key.lower() in _ENABLE_KEYS and tok.word in _BOOL_WORDS:
            pair = "|".join(_BOOL_WORDS[tok.word])
            inverted = tok.key.lower().startswith(("disable", "shutdown"))
            return ("invert_yes_no" if inverted else "to_bool"), i, f"(?P<value>{pair})"
    positional = [
        i for i, w in enumerate(words) if i > 0 and w in _BOOL_WORDS and tokens[i].key is None
    ]
    if positional:
        i = positional[-1]
        pair = "|".join(_BOOL_WORDS[words[i]])
        inverted = any(w.startswith("disable") for w in words[:i])
        return ("invert_yes_no" if inverted else "to_bool"), i, f"(?P<value>{pair})"
    return "presence", None, ""


def _choose_int(tokens: Sequence[_Tok], hint: str | None) -> tuple[str, int | None, str] | None:
    index = _hinted(tokens, hint)
    if index is None:
        numeric = [i for i, tok in enumerate(tokens) if i > 0 and _NUMBER.match(tok.content)]
        index = numeric[0] if numeric else None
    if index is None or _secret_position(tokens, index):
        return None
    return "to_int", index, r"(?P<value>\d+)"


def _community_index(tokens: Sequence[_Tok]) -> int | None:
    words = [t.word for t in tokens]
    for i, tok in enumerate(tokens):
        if tok.key is not None and tok.key.lower() in ("name", "community"):
            return i
        if i > 0 and "community" in words[i - 1] and words[i] not in _COMMUNITY_MODIFIERS:
            return i
        if (
            i > 1
            and "community" in words[i - 2]
            and words[i - 1] in _COMMUNITY_MODIFIERS
            and words[i] not in _COMMUNITY_MODIFIERS
        ):
            return i
    return None


def _choose_data(
    spec: FieldSpec, tokens: Sequence[_Tok], hint: str | None
) -> tuple[str, int | None, str] | None:
    kind = spec.kind
    if spec.path == "snmp.communities":
        transform = "collect_redacted"
    else:
        transform = "collect" if kind == "list" else "identity"

    index = _hinted(tokens, hint)
    if index is None and spec.path == "snmp.communities":
        index = _community_index(tokens)
    if index is None:
        for i, tok in enumerate(tokens):
            value = tok.content
            if i > 0 and (_IPV4.match(value) or _IPV6.match(value) or _FQDN.match(value)):
                index = i
                break
    if index is None and kind != "list":
        named = [
            i for i, tok in enumerate(tokens) if tok.key is not None and tok.key.lower() == "name"
        ]
        positional = [
            i
            for i, tok in enumerate(tokens)
            if i > 0
            and tok.key is None
            and tok.word not in _VERBS
            and any(c.isalnum() for c in tok.raw)
        ]
        if named:
            index = named[0]
        elif positional:
            index = positional[-1]
    if index is None or index == 0 or _secret_position(tokens, index):
        return None
    return transform, index, _value_group(kind, tokens[index].content)


def build_mapping(
    spec: FieldSpec,
    text: str,
    context: Sequence[str] = (),
    *,
    confidence: float,
    value_hint: str | None = None,
) -> tuple[Mapping, Any] | None:
    """Turn "this line sets ``spec.path``" into a deterministic extraction rule.

    Returns the mapping and the value it extracts from ``text``, or ``None``
    when the line has no token of the right shape for the field. Shared by
    both proposers, so a model's choice goes through exactly the same checks.
    Credentials are never captured, and organisation data (names, addresses)
    is generalised out of every emitted pattern.
    """
    stripped = text.strip().rstrip(";").strip()
    tokens = _tokenise(stripped)
    if not tokens:
        return None

    chosen: tuple[str, int | None, str] | None
    if spec.kind == "bool":
        chosen = _choose_bool(tokens)
    elif spec.kind == "int":
        chosen = _choose_int(tokens, value_hint)
    else:
        chosen = _choose_data(spec, tokens, value_hint)
    if chosen is None:
        return None

    transform, index, group = chosen
    mapping = Mapping(
        ir_path=spec.path,
        match=_render(tokens, index, group),
        transform=transform,
        tier_learned=2,
        confidence=round(max(0.0, min(confidence, 0.99)), 4),
        samples=1,
        within=_within_for(context),
    )
    try:
        mapping.validate(0)
    except Exception:
        return None
    match = mapping.regex.search(stripped)
    if match is None:
        return None
    raw = match.group("value") if "value" in mapping.regex.groupindex else None
    try:
        outcome = apply_transform(transform, raw, None)
    except TransformError:
        return None
    return mapping, outcome.value


# -- the lexical proposer -------------------------------------------------------


#: Below this cosine similarity there is no proposal at all.
MIN_SIMILARITY = 0.12
#: Below this confidence a proposal is not shown; the line is simply unknown.
MIN_CONFIDENCE = 0.2


class LexicalProposer:
    """Offline, deterministic, no model. The default."""

    name = "lexical"

    def __init__(self, vocabulary: Sequence[FieldSpec] = VOCABULARY) -> None:
        self.vocabulary = tuple(vocabulary)
        self._known = frozenset(
            word
            for spec in self.vocabulary
            for text in (*spec.keywords, *spec.examples)
            for word in _words(text)
            if len(word) >= 3
        )
        documents: list[dict[str, float]] = []
        for spec in self.vocabulary:
            doc: dict[str, float] = defaultdict(float)
            for word, weight in spec.keywords.items():
                _accumulate(doc, _features(_words(word), weight))
            for example in spec.examples:
                _accumulate(doc, _features(_words(example), 0.5))
            documents.append(doc)
        df: Counter[str] = Counter()
        for doc in documents:
            df.update(doc.keys())
        n = len(documents)
        self._idf = {f: math.log((n + 1) / (count + 1)) + 1.0 for f, count in df.items()}
        self._docs = [self._weigh(doc) for doc in documents]

    def _weigh(self, feats: dict[str, float]) -> dict[str, float]:
        vector = {f: v * self._idf.get(f, 0.0) for f, v in feats.items() if f in self._idf}
        norm = math.sqrt(sum(v * v for v in vector.values())) or 1.0
        return {f: v / norm for f, v in vector.items()}

    def rank(self, text: str, context: Sequence[str] = ()) -> list[tuple[FieldSpec, float]]:
        feats = _features(_words(text, self._known))
        for header in context[-2:]:
            _accumulate(feats, _features(_words(header, self._known), 0.35))
        query = self._weigh(feats)
        scored = [
            (spec, sum(query.get(f, 0.0) * w for f, w in doc.items()))
            for spec, doc in zip(self.vocabulary, self._docs, strict=True)
        ]
        return sorted(scored, key=lambda item: item[1], reverse=True)

    def _evidence(
        self,
        spec: FieldSpec,
        text: str,
        ranked: list[tuple[FieldSpec, float]],
        position: int,
    ) -> float:
        """How much *our own* evidence supports mapping this line to ``spec``.

        Similarity carries most of the weight; a clear margin over the next
        field adds the rest. Falling back to a lower-ranked field because the
        top one had no token of the right shape costs confidence, because it
        is weaker evidence.

        This is the only thing in the system that may set a confidence. A
        model's opinion of its own answer cannot, which is what
        :meth:`OllamaProposer.propose` uses it for.
        """
        if not ranked or position >= len(ranked):
            return 0.0
        top_score = ranked[0][1]
        score = ranked[position][1]
        runner_up = ranked[position + 1][1] if position + 1 < len(ranked) else 0.0
        margin = (score - runner_up) / score if score else 0.0
        confidence = (0.15 + 0.7 * min(score / 0.6, 1.0) + 0.15 * margin) * (
            1.0 if position == 0 else 0.75 * score / top_score if top_score else 0.0
        )
        line_words = set(_words(text, self._known))
        if not any(w in line_words for w, weight in spec.keywords.items() if weight >= 1.0):
            # Similar only through context or character overlap: no word the
            # field is actually known by appears on the line. Weak evidence,
            # so it is sent to a human rather than applied.
            confidence *= 0.5
        return confidence

    def evidence_for(
        self, spec: FieldSpec, text: str, ranked: list[tuple[FieldSpec, float]]
    ) -> float:
        """The evidence score for a field chosen by someone else - a model.

        Zero when the field is not among the ranked candidates at all: nothing
        we can measure supports it, so nothing may be auto-applied from it.
        """
        for position, (candidate, _score) in enumerate(ranked):
            if candidate.path == spec.path:
                return self._evidence(spec, text, ranked, position)
        return 0.0

    def propose(self, text: str, context: Sequence[str] = ()) -> Proposal | None:
        ranked = self.rank(text, context)
        if not ranked or ranked[0][1] < MIN_SIMILARITY:
            # Nothing in the vocabulary resembles this line. Proposing the
            # least-bad field would only teach an administrator to click
            # "accept" without reading.
            return None
        for position, (spec, _score) in enumerate(ranked[:4]):
            if position > 1:
                break
            confidence = self._evidence(spec, text, ranked, position)
            if confidence < MIN_CONFIDENCE:
                continue
            built = build_mapping(spec, text, context, confidence=confidence)
            if built is None:
                continue
            mapping, preview = built
            words = sorted(
                {w for w in _words(text, self._known) if w in spec.keywords},
                key=lambda w: -spec.keywords[w],
            )
            rationale = (
                f"similar to {spec.description.lower()}"
                + (f"; keywords: {', '.join(words)}" if words else "")
                + (f"; inside '{context[-1]}'" if context else "")
            )
            return Proposal(
                ir_path=spec.path,
                mapping=mapping,
                confidence=mapping.confidence or 0.0,
                rationale=rationale,
                source=self.name,
                preview=preview,
                alternatives=tuple((s.path, sc) for s, sc in ranked[:5] if s.path != spec.path)[:3],
            )
        return None


# -- the local-model proposer ----------------------------------------------------

_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"

_PROMPT = """You map one line of a network device configuration to a field of a \
vendor-neutral security model. You do NOT judge compliance.

Line: {line}
Enclosing blocks: {context}

Candidate fields (choose one, or "none"):
{candidates}

Reply with JSON only:
{{"ir_path": "<one candidate path or none>", "value_token": "<the exact token from the \
line that carries the value, or null if the line's presence is the value>", \
"confidence": <0.0 to 1.0>}}"""


class OllamaProposer:
    """A local model on loopback, chosen among lexical candidates. Optional."""

    def __init__(
        self,
        url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_OLLAMA_MODEL,
        *,
        fallback: LexicalProposer | None = None,
        timeout: float = 30.0,
    ) -> None:
        host = urlparse(url).hostname or ""
        if host not in _LOOPBACK:
            # The air-gap guarantee is enforced here, not documented here.
            raise ValueError(f"Ollama must be on loopback; refusing {url!r}")
        self.url = url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.fallback = fallback or LexicalProposer()
        self.name = f"ollama:{model}"
        # A loopback URL is not enough on its own. urlopen's default opener
        # reads http_proxy from the environment, so on a host with a corporate
        # proxy configured - exactly the kind of host that also has an air gap -
        # every prompt, customer configuration lines included, would be sent to
        # that proxy instead of to the daemon two ports away. An empty
        # ProxyHandler is what makes "loopback" true of the transport and not
        # only of the string.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 - loopback enforced in __init__
            self.url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self._opener.open(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
        if not isinstance(body, dict):
            raise ValueError("unexpected response shape")
        return body

    def available(self) -> bool:
        try:
            with self._opener.open(self.url + "/api/tags", timeout=1.5) as response:
                tags = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError, urllib.error.URLError):
            return False
        names = {m.get("name") for m in tags.get("models", []) if isinstance(m, dict)}
        return self.model in names

    def propose(self, text: str, context: Sequence[str] = ()) -> Proposal | None:
        # The full ranking scores the evidence; only the top few are shown to
        # the model. Scoring against the truncated list would read a margin
        # over nothing for the last candidate and inflate its confidence.
        full_ranking = self.fallback.rank(text, context)
        ranked = full_ranking[:6]
        lexical = self.fallback.propose(text, context)
        candidates = "\n".join(f"- {spec.path}: {spec.description}" for spec, _ in ranked)
        prompt = _PROMPT.format(
            line=text.strip(),
            context=" > ".join(context) or "(top level)",
            candidates=candidates,
        )
        try:
            reply = self._post(
                "/api/generate",
                {
                    "model": self.model,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0},
                },
            )
            answer = json.loads(str(reply.get("response", "")))
            chosen = str(answer.get("ir_path", "none"))
            token = answer.get("value_token")
            model_confidence = float(answer.get("confidence", 0.0))
        except (OSError, ValueError, TypeError, urllib.error.URLError):
            return _relabel(lexical, "lexical (ollama unavailable)")

        spec = next((s for s, _ in ranked if s.path == chosen), None)
        if spec is None:
            return _relabel(lexical, "lexical (model declined)")
        hint = str(token) if token not in (None, "", "null") and str(token) in text else None
        # The model chooses the field. It does NOT get to say how sure we are.
        #
        # A self-reported confidence is not calibrated: measured against the
        # held-out vendors, a 3B model returned 0.95 for nearly every answer,
        # including eight lines that carry no fact at all, and a 7B called
        # Huawei's `stelnet server enable` - which is SSH - telnet_enabled at
        # 0.95. Passed straight through, both sail past the auto-accept gate
        # and a wrong mapping gets signed into a pack.
        #
        # So the model's number may only ever *lower* the confidence our own
        # evidence supports, never raise it. A model that is unsure is heard;
        # a model that is confidently wrong is capped at what we can measure,
        # and the disagreement goes to a human at Tier 3 where it belongs.
        evidence = self.fallback.evidence_for(spec, text, full_ranking)
        confidence = min(evidence, max(model_confidence, 0.0), 0.95)
        built = build_mapping(spec, text, context, confidence=confidence, value_hint=hint)
        if built is None:
            return _relabel(lexical, "lexical (model choice had no usable value)")
        mapping, preview = built
        return Proposal(
            ir_path=spec.path,
            mapping=mapping,
            confidence=mapping.confidence or 0.0,
            rationale=f"model chose {spec.path} among {len(ranked)} lexical candidates",
            source=self.name,
            preview=preview,
            alternatives=tuple((s.path, sc) for s, sc in ranked if s.path != spec.path)[:3],
        )


def _relabel(proposal: Proposal | None, source: str) -> Proposal | None:
    if proposal is None:
        return None
    return Proposal(
        ir_path=proposal.ir_path,
        mapping=proposal.mapping,
        confidence=proposal.confidence,
        rationale=proposal.rationale,
        source=source,
        preview=proposal.preview,
        alternatives=proposal.alternatives,
    )


def default_proposer(
    url: str | None = None, model: str | None = None, *, enabled: bool | None = None
) -> Proposer:
    """The lexical proposer, unless a model is explicitly asked for.

    Opting in is deliberate: pass ``enabled=True`` (the CLI's ``--ollama``) or
    set ``CRUCIBLE_OLLAMA=1``.

    It would be friendlier to notice a model already listening on loopback and
    use it. That is exactly what this refuses to do. An audit has to give the
    same answer twice, and picking up a daemon that happens to be running would
    mean two machines auditing the same configuration disagree because somebody
    installed Ollama for an unrelated reason. It also made the test suite
    non-hermetic: the same suite took seconds or minutes, and exercised
    different code, depending on what was listening.

    Off by default is what the README promises, so off by default is what this
    does.
    """
    lexical = LexicalProposer()
    if enabled is None:
        enabled = os.environ.get("CRUCIBLE_OLLAMA", "").strip().lower() in {"1", "true", "yes"}
    if not enabled:
        return lexical
    try:
        candidate = OllamaProposer(
            url or DEFAULT_OLLAMA_URL, model or DEFAULT_OLLAMA_MODEL, fallback=lexical
        )
    except ValueError:
        return lexical
    return candidate if candidate.available() else lexical
