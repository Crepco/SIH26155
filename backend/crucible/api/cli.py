"""Command line interface.

    crucible audit corpus/ --out reports/
    crucible verify reports/ledger.jsonl                     the ledger is unaltered
    crucible verify --device core-sw-01/ --finding CIS-NET-1.1.1   prove it on a twin
    crucible rules --framework CIS
    crucible show corpus/core-sw-01/

    crucible propose unknown-device/            Tier 2 proposals for what was not understood
    crucible train unknown-device/ --pack-id huawei-vrp --vendor huawei --install
    crucible pack list | show | export | import | remove | verify
    crucible trust list | add publisher.pub | remove KEYID | key
    crucible tier2-eval tests/fixtures/devices/routeros-branch-01
    crucible stig-import U_Cisco_NDM_STIG.zip --bindings rules/stig/bindings/cisco.yaml
    crucible validate --labels corpus/labels/fixtures --devices tests/fixtures/devices
    crucible drift march/core-sw-01.audit.json september/core-sw-01.audit.json

Exit codes are meaningful, because this is a tool that belongs in a pipeline:

===  ===========================================================
 0   ran, and nothing critical or high failed
 1   ran, and at least one critical or high finding failed
 2   could not run - bad input, unloadable rules, broken ledger
===  ===========================================================

That distinction matters. A CI job that treats "the auditor crashed" the same
as "the auditor found a problem" will eventually treat a crash as a clean bill
of health, which is the silent-pass failure wearing a different hat.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from crucible import __version__
from crucible.common.errors import CrucibleError
from crucible.common.types import Severity, Verdict

if TYPE_CHECKING:
    from crucible.api.home import Home
    from crucible.training.proposer import Proposer
    from crucible.training.session import TrainingSession

__all__ = ["main"]

#: The bundled rule set, found relative to the package so `crucible audit x`
#: works from any directory, not only from the repository root.
DEFAULT_RULES = str(Path(__file__).resolve().parents[3] / "rules" / "cis")

# --------------------------------------------------------------------------
# Presentation helpers. Deliberately plain: this runs on an air-gapped console
# that may not have a colour terminal, so nothing depends on escape codes.
# --------------------------------------------------------------------------

_VERDICT_MARK = {
    Verdict.FAIL: "FAIL",
    Verdict.UNKNOWN: "UNKN",
    Verdict.PASS: "PASS",
    Verdict.NOT_APPLICABLE: "N/A ",
}


def _bar(percent: int, width: int = 24) -> str:
    filled = round(width * percent / 100)
    return "#" * filled + "." * (width - filled)


def _cmd_audit(args: argparse.Namespace) -> int:
    from crucible.api.runner import run_audit

    formats = tuple(f.strip() for f in args.format.split(",") if f.strip())
    packs = [] if args.no_packs else _home(args).packs()

    job = run_audit(
        args.target,
        rules_path=args.rules,
        output_dir=args.out,
        framework=args.framework,
        formats=formats,
        sign=not args.no_sign,
        workdir=args.out,
        packs=packs,
        hold_out=args.hold_out or [],
        verify=args.verify,
    )

    if args.json:
        print(json.dumps(job.to_dict(), indent=2, sort_keys=True))
        return _exit_code(job)

    print()
    print(f"  CRUCIBLE {__version__}   rules: {job.ruleset_size} (digest {job.rule_set_digest})")
    print(
        f"  {len(job.results)} device(s)   fleet score {job.fleet_score}%   "
        f"mean coverage {job.mean_coverage}%"
    )
    print()

    for result in job.results:
        report = result.report
        device = report.device
        counts = report.evaluation.counts()

        print(f"  {device.get('hostname') or report.device_id}")
        serial = device.get("serial")
        serial_text = f"  serial {serial}" if serial else "  serial: not supplied"
        print(
            f"    {device.get('vendor', 'unknown')} {device.get('os') or ''} "
            f"{device.get('version') or ''}{serial_text}"
        )
        print(
            f"    score  [{_bar(report.score)}] {report.score}%  "
            f"-> {report.projected_score()}% after remediation"
        )
        print(
            f"    checks fail {counts['fail']}  unknown {counts['unknown']}  pass {counts['pass']}"
        )

        coverage = report.coverage
        total = coverage["total_lines"]
        percent = round(100.0 * coverage["parsed_lines"] / total, 1) if total else 0
        print(
            f"    parsed {coverage['parsed_lines']:,}/{total:,} lines ({percent}%)"
            f"  {coverage['unparsed_lines']} uninterpreted"
        )

        if report.adapter_packs:
            print(
                "    NOTE: no built-in parser - read by adapter pack "
                f"{', '.join(report.adapter_packs)}"
            )
        elif not report.parser_applied:
            print("    NOTE: vendor not recognised - no parser applied, all controls UNKNOWN")

        shown = 0
        for finding in report.findings:
            if args.all or finding.severity.verifiable:
                cite = finding.evidence[0].cite() if finding.evidence else "no line to cite"
                print(
                    f"      {_VERDICT_MARK[finding.verdict]} {finding.severity.value:8} "
                    f"{finding.rule_id:14} {finding.title[:44]:<46} {cite}"
                )
                shown += 1
        remaining = len(report.findings) - shown
        if remaining > 0:
            print(f"      ... {remaining} more of lower severity (use --all)")

        for kind, path in sorted(result.artefacts.items()):
            print(f"    {kind:9} {path}")
        print()

    if job.failures:
        print(f"  {len(job.failures)} device(s) could not be audited:")
        for failure in job.failures:
            print(f"    {failure['device_id']:24} {failure['error']}")
        print()

    for run in job.sandbox:
        if run.verifications or run.error:
            print("  CRUCIBLE   findings proved against a disposable twin")
            print(run.text())

    if job.fleet is not None and job.fleet.correlations:
        fleet = job.fleet
        counts = fleet.counts()
        print("  FLEET   what no single device's audit can see")
        print(f"    {fleet.headline()}")
        print(
            f"    critical {counts['critical']}  high {counts['high']}  "
            f"medium {counts['medium']}  across {fleet.paths} attack paths"
        )
        print()
        print("    fixes, ranked by paths severed:")
        for index, fix in enumerate(fleet.fixes[:6], start=1):
            print(f"      {index}. [{fix.paths_severed:>2} paths] {fix.action}")
        if len(fleet.fixes) > 6:
            print(f"      ... {len(fleet.fixes) - 6} more")
        print()
        if not args.all:
            print("    (--all lists every cross-device finding)")
        else:
            for correlation in fleet.correlations:
                print(f"      {correlation.severity.upper():8} {correlation.id}")
                print(f"               {correlation.title}")
                for route in correlation.paths[:3]:
                    print(f"                 {' -> '.join(route.hops)}")
        print()

    if job.ledger_path:
        print(f"  ledger  {job.ledger_path}")
        print()

    return _exit_code(job)


def _cmd_prove(args: argparse.Namespace) -> int:
    """Boot a twin and demonstrate a finding against it.

    Exit 0 when every requested finding was demonstrated and closed by the
    printed fix, 1 when something was demonstrated and not closed, 2 when the
    sandbox could not run at all - the same distinction the audit makes
    between "found a problem" and "could not look".
    """
    from crucible.ingest.bundle import load
    from crucible.pipeline import build_ir
    from crucible.policy.engine import evaluate_device
    from crucible.policy.ruleset import load_rules
    from crucible.sandbox import verify_device

    ruleset = load_rules(args.rules)
    packs = [] if args.no_packs else _home(args).packs()
    code = 0
    for bundle in load(args.device):
        parsed = build_ir(bundle, packs=packs, hold_out=args.hold_out or [])
        evaluation = evaluate_device(parsed.ir, ruleset)
        run = verify_device(
            parsed.ir, bundle.device_id, evaluation.findings, ruleset, only=args.finding
        )
        if args.json:
            print(json.dumps(run.to_dict(), indent=2))
        else:
            print()
            print(run.text())
            if run.not_modelled:
                print("    the twin cannot model, so these stay ASSERTED:")
                for path, reason in sorted(run.not_modelled.items()):
                    print(f"      {path:28} {reason}")
                print()
        if not run.available:
            print(f"crucible: {run.error}", file=sys.stderr)
            return 2
        if any(v.demonstrated and not v.closed for v in run.verifications):
            code = max(code, 1)
    return code


def _exit_code(job: object) -> int:
    """Non-zero when something that matters failed."""
    results = getattr(job, "results", [])
    failures = getattr(job, "failures", [])
    if failures and not results:
        # Nothing could be audited at all: that is "could not run", not a
        # clean bill of health.
        return 2
    for result in results:
        for finding in result.report.findings:
            if finding.verdict is Verdict.FAIL and finding.severity in (
                Severity.CRITICAL,
                Severity.HIGH,
            ):
                return 1
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    if args.device:
        return _cmd_prove(args)
    if not args.ledger:
        print("crucible: give a ledger to check, or --device to prove a finding", file=sys.stderr)
        return 2

    from crucible.ledger.chain import Ledger
    from crucible.ledger.signing import VerifyingKey

    ledger = Ledger.open(args.ledger)
    if not len(ledger):
        print(f"  ledger {args.ledger} is empty")
        return 2

    key = None
    key_path = Path(args.key) if args.key else Path(args.ledger).parent / "signing" / "ed25519.pub"
    if key_path.exists():
        key = VerifyingKey.load(key_path)
    else:
        print(f"  no public key at {key_path} - checking chain links only, not signatures")

    ok, problems = ledger.verify(key)

    print()
    print(f"  ledger   {args.ledger}")
    print(f"  entries  {len(ledger)}")
    print(f"  head     {ledger.head[:32]}")
    if key:
        print(f"  key id   {key.key_id}")
    print()

    if ok:
        print(
            "  INTACT - every entry links to its predecessor"
            f"{' and verifies against the issuing key' if key else ''}."
        )
        print()
        for entry in ledger:
            print(
                f"    {entry.seq:4}  {entry.timestamp}  {entry.device_id:24} "
                f"verify:{entry.verification_hash}"
            )
        print()
        return 0

    print("  TAMPERED - this ledger does not verify:")
    for problem in problems:
        print(f"    - {problem}")
    print()
    return 2


def _cmd_rules(args: argparse.Namespace) -> int:
    from crucible.policy.ruleset import load_rules

    ruleset = load_rules(args.rules)
    if args.framework:
        ruleset = ruleset.for_framework(args.framework)

    print()
    print(f"  {len(ruleset)} rules   digest {ruleset.version_digest}")
    print(f"  frameworks: {', '.join(ruleset.frameworks())}")
    print()
    for rule in ruleset:
        probe = rule.verify.get("probe") if rule.verify else None
        marker = f"  [probe: {probe}]" if probe else ""
        print(f"    {rule.severity.value:8} {rule.id:14} {rule.title}{marker}")
        print(f"             {' ' * 14} assert: {rule.assertion.source}")
    print()
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    """Parse a device and print its IR. The debugging view for a parser author."""
    from crucible.ingest.bundle import load
    from crucible.pipeline import build_ir

    bundles = load(args.target)
    for bundle in bundles:
        parsed = build_ir(bundle)
        if args.json:
            print(json.dumps(parsed.ir.to_dict(), indent=2, sort_keys=True))
            continue

        ir = parsed.ir
        print()
        print(
            f"  {bundle.device_id}   {ir.vendor} {ir.device.get('os') or ''}   "
            f"confidence {ir.device.get('fingerprint_confidence_bp', 0) / 100:.0f}%"
        )
        print(f"  {ir.coverage.statement()}")
        print()
        for path, provenance in sorted(ir.facts().items()):
            resolution = ir.resolve(path)
            value = resolution.value if resolution.found else "-"
            print(
                f"    {path:34} = {str(value)[:28]:30} {provenance.file.split('/')[-1]}:"
                f"{provenance.line} (tier {provenance.tier})"
            )
        print()
        if ir.coverage.unparsed_sample:
            print("  uninterpreted:")
            for entry in ir.coverage.unparsed_sample[:20]:
                print(f"    {entry['line']:5}  {entry['raw']}")
            print()
    return 0


# --------------------------------------------------------------------------
# Tiers 2 and 3, adapter packs and trust
# --------------------------------------------------------------------------


def _home(args: argparse.Namespace) -> Home:
    from crucible.api.home import Home

    return Home(getattr(args, "home", None))


def _proposer(args: argparse.Namespace) -> Proposer:
    from crucible.training.proposer import LexicalProposer, default_proposer

    if getattr(args, "ollama", False):
        proposer = default_proposer(args.ollama_url, args.ollama_model, enabled=True)
        if proposer.name == "lexical":
            print("  ollama not reachable on loopback with that model - using the lexical proposer")
        return proposer
    return LexicalProposer()


def _sessions(args: argparse.Namespace) -> list[TrainingSession]:
    from crucible.ingest.bundle import load
    from crucible.training.session import TrainingSession

    packs = [] if args.no_packs else _home(args).packs()
    return [
        TrainingSession(bundle, packs=packs, hold_out=args.hold_out or [], proposer=_proposer(args))
        for bundle in load(args.target)
    ]


def _cmd_propose(args: argparse.Namespace) -> int:
    from crucible.training.session import families_text

    for session in _sessions(args):
        summary = session.summary()
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True, default=str))
            continue
        coverage = summary["coverage"]
        print()
        print(
            f"  {summary['device_id']}   vendor {summary['vendor']}   "
            f"proposer {summary['proposer']}"
        )
        print(
            f"  parsed {coverage['parsed']}/{coverage['total']} lines   "
            f"{len(session.families)} uninterpreted families"
        )
        print()
        print(families_text(session.families))
        print()
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    """Non-interactive training: accept confident proposals, sign, export.

    The interactive version - where an administrator confirms and corrects
    each family - is the training view in the console. This command is for
    scripting and for a reproducible demonstration.
    """
    sessions = _sessions(args)
    if len(sessions) != 1:
        print("crucible: train one device at a time", file=sys.stderr)
        return 2
    session = sessions[0]
    accepted = session.accept_proposals(args.accept_above)
    if not accepted:
        print(f"  no proposal reached {args.accept_above:.2f}; train this one in the console")
        return 2
    home = _home(args)
    pack = session.build_pack(
        pack_id=args.pack_id,
        vendor=args.vendor,
        os=args.os,
        author=args.author,
        key=home.publisher_key(),
    )
    print()
    print(f"  pack {pack.id}   vendor {pack.vendor}   {len(pack.mappings)} mapping(s)")
    for mapping in pack.mappings:
        print(f"    {mapping.ir_path:32} {mapping.transform:17} {mapping.match}")
    if args.out:
        Path(args.out).write_text(pack.to_yaml(), encoding="utf-8")
        print(f"  written   {args.out}")
    if args.install:
        print(f"  installed {home.install(pack, replace=True)}")
    after = session.audit_with(pack)
    before = session.device.ir.coverage
    print(
        f"  coverage  {before.parsed_lines}/{before.total_lines} -> "
        f"{after.ir.coverage.parsed_lines}/{after.ir.coverage.total_lines} lines"
    )
    print()
    return 0


def _cmd_pack(args: argparse.Namespace) -> int:
    from crucible.adapters.pack import export_ready, load_pack

    home = _home(args)
    if args.action == "list":
        packs = home.packs()
        if not packs:
            print(f"  no packs installed in {home.packs_dir}")
        for pack in packs:
            signer = (pack.signature or {}).get("key_id", "?")
            print(
                f"  {pack.id:28} {pack.vendor:12} {len(pack.mappings):3} mappings   "
                f"signed by {signer}   digest {pack.digest}"
            )
        return 0
    if not args.name:
        print("crucible: name a pack (or a file, for import and verify)", file=sys.stderr)
        return 2
    if args.action in ("show", "export"):
        text = export_ready(home.get(args.name))
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"  written {args.out}")
        else:
            print(text)
        return 0
    if args.action == "import":
        pack = load_pack(Path(args.name))
        target = home.install(pack)
        signer = (pack.signature or {}).get("key_id", "?")
        print(f"  imported {pack.id} from publisher {signer}")
        print(f"  installed {target}")
        return 0
    if args.action == "remove":
        print("  removed" if home.remove(args.name) else "  no such pack")
        return 0
    if args.action == "verify":
        pack = load_pack(Path(args.name))
        key_id = home.trust.admit(pack)
        print(f"  {pack.id}: signature valid, publisher {key_id} is trusted")
        return 0
    return 2


def _cmd_trust(args: argparse.Namespace) -> int:
    home = _home(args)
    if args.action == "key":
        sys.stdout.write(home.public_pem().decode("ascii"))
        return 0
    if args.action == "list":
        own = home.publisher_key().key_id
        for key_id in sorted(home.trust.keys()):
            print(f"  {key_id}{'   (this deployment)' if key_id == own else ''}")
        return 0
    if not args.value:
        print("crucible: add takes a public key file, remove takes a key id", file=sys.stderr)
        return 2
    if args.action == "add":
        key_id = home.trust.add(Path(args.value).read_bytes())
        print(f"  now trusting publisher {key_id}")
        return 0
    if args.action == "remove":
        print("  removed" if home.trust.remove(args.value) else "  no such key")
        return 0
    return 2


def _cmd_tier2_eval(args: argparse.Namespace) -> int:
    from crucible.ingest.bundle import load
    from crucible.training.evaluate import evaluate_held_out

    for bundle in load(args.target):
        report = evaluate_held_out(bundle, proposer=_proposer(args), threshold=args.threshold)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
            continue
        print()
        print(report.text())
        print()
        for row in report.rows:
            if not (row["expected"] or row["proposed"]):
                continue
            if row["field_ok"]:
                mark = "ok"
            elif row["expected"]:
                mark = "XX"
            else:
                mark = "--"
            print(
                f"    {mark}  {row['line']:4}  {row['text'][:52]:52}  "
                f"{row['proposed'] or '-':28} {row['confidence'] or ''}"
            )
        print()
    return 0


def _cmd_stig_import(args: argparse.Namespace) -> int:
    """Import a DISA STIG, and say plainly how much of it a machine can check."""
    from crucible.policy.ruleset import load_rules
    from crucible.policy.xccdf import import_benchmark, load_benchmark, load_bindings

    benchmark = load_benchmark(args.benchmark)
    bindings = load_bindings(args.bindings) if args.bindings else []
    reference: list[Any] = list(load_rules(args.rules)) if Path(args.rules).exists() else []
    result = import_benchmark(benchmark, bindings, reference_rules=reference)

    print()
    print(f"  {result.summary()}")
    print(f"  severities: {result.benchmark.by_severity()}")
    if not bindings:
        print("  no bindings given, so nothing is evaluated: every control needs one")
    print()

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result.rules_yaml(), encoding="utf-8")
        catalogue = out.with_suffix(".catalogue.json")
        catalogue.write_text(result.catalogue_json(), encoding="utf-8")
        print(f"  rules      {out}")
        print(f"  catalogue  {catalogue}")
        print()
    else:
        for rule in result.rules:
            print(f"    {rule['severity']:8} {rule['id']:22} {rule['title'][:60]}")
        print()
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    """Measure the tool against hand-labelled ground truth, and print the number."""
    from crucible.policy.ruleset import load_rules
    from crucible.validation import load_labels, validate

    labels = load_labels(args.labels)
    report = validate(labels, load_rules(args.rules), devices_root=args.devices)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    print(report.text())
    if args.all:
        for device in report.devices:
            if not device.disagreements:
                continue
            print(f"  {device.config_id}")
            for item in device.disagreements:
                if "rule_id" in item:
                    print(
                        f"      {item['rule_id']:14} labelled {item['expected']:8}"
                        f" reported {item['reported']}"
                    )
                elif "expected_line" in item:
                    print(
                        f"      {item['ir_path']:28} cited line {item['reported_line']}"
                        f", labeller cited {item['expected_line']}"
                    )
                else:
                    print(
                        f"      {item['ir_path']:28} labelled {item['expected']!r},"
                        f" read {item['reported']!r}"
                    )
            print()
    else:
        print("  (--all lists every disagreement, which is where the work is)")
        print()
    return 0


def _cmd_drift(args: argparse.Namespace) -> int:
    """What moved between two audits of one device.

    Exit 1 when the posture regressed, so a pipeline can fail on it.
    """
    from crucible.report.drift import compare

    def read(path: str) -> dict[str, Any]:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            # Pointing this at the wrong file is the likely mistake, so say so
            # here rather than failing on a missing key three frames down.
            raise ValueError(f"{path} is not an audit document")
        return document

    try:
        report = compare(
            read(args.before),
            read(args.after),
            before_ir=read(args.before_ir) if args.before_ir else None,
            after_ir=read(args.after_ir) if args.after_ir else None,
        )
    except (OSError, ValueError) as exc:
        print(f"crucible: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report.to_dict(), indent=2) if args.json else report.text())
    return 1 if report.regressed else 0


def _add_learning_options(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--hold-out",
        action="append",
        metavar="VENDOR",
        help="switch off a vendor's built-in parser (the unseen-vendor demonstration)",
    )
    command.add_argument("--no-packs", action="store_true", help="ignore installed adapter packs")
    command.add_argument("--home", help="deployment state directory (default $CRUCIBLE_HOME)")


def _add_model_options(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--ollama", action="store_true", help="use a local Ollama model when reachable"
    )
    command.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    command.add_argument("--ollama-model", default="qwen2.5-coder:7b-instruct-q4_K_M")


def _register_learning(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    propose = sub.add_parser("propose", help="Tier-2 proposals for the lines nobody understood")
    propose.add_argument("target")
    propose.add_argument("--json", action="store_true")
    _add_learning_options(propose)
    _add_model_options(propose)
    propose.set_defaults(func=_cmd_propose)

    train = sub.add_parser("train", help="build and sign an adapter pack from confident proposals")
    train.add_argument("target")
    train.add_argument("--pack-id", required=True)
    train.add_argument("--vendor", required=True)
    train.add_argument("--os")
    train.add_argument("--author")
    train.add_argument("--accept-above", type=float, default=0.85)
    train.add_argument("--out", help="write the signed pack here")
    train.add_argument("--install", action="store_true", help="install it in this deployment")
    _add_learning_options(train)
    _add_model_options(train)
    train.set_defaults(func=_cmd_train)

    pack = sub.add_parser("pack", help="manage installed adapter packs")
    pack.add_argument("action", choices=["list", "show", "export", "import", "remove", "verify"])
    pack.add_argument("name", nargs="?", help="pack id, or a file for import and verify")
    pack.add_argument("--out")
    pack.add_argument("--home")
    pack.set_defaults(func=_cmd_pack)

    trust = sub.add_parser("trust", help="manage trusted pack publishers")
    trust.add_argument("action", choices=["list", "add", "remove", "key"])
    trust.add_argument("value", nargs="?", help="public key file for add, key id for remove")
    trust.add_argument("--home")
    trust.set_defaults(func=_cmd_trust)

    tier2 = sub.add_parser(
        "tier2-eval", help="measure Tier 2 on a vendor with its built-in parser held out"
    )
    tier2.add_argument("target")
    tier2.add_argument("--threshold", type=float, default=0.85)
    tier2.add_argument("--json", action="store_true")
    _add_model_options(tier2)
    tier2.set_defaults(func=_cmd_tier2_eval)

    stig = sub.add_parser(
        "stig-import", help="import a DISA STIG benchmark (XCCDF XML or the published zip)"
    )
    stig.add_argument("benchmark", help="path to the XCCDF file or DISA zip")
    stig.add_argument("--bindings", help="YAML binding controls to IR assertions")
    stig.add_argument(
        "--rules", default=DEFAULT_RULES, help="rules whose remediation may be reused"
    )
    stig.add_argument("--out", help="write the imported rules here (catalogue written beside it)")
    stig.set_defaults(func=_cmd_stig_import)

    validate_cmd = sub.add_parser(
        "validate", help="measure precision and recall against hand-labelled configurations"
    )
    validate_cmd.add_argument("--labels", required=True, help="a label file or a directory")
    validate_cmd.add_argument("--devices", required=True, help="the configurations they label")
    validate_cmd.add_argument("--rules", default=DEFAULT_RULES)
    validate_cmd.add_argument("--all", action="store_true", help="list every disagreement")
    validate_cmd.add_argument("--json", action="store_true")
    validate_cmd.set_defaults(func=_cmd_validate)

    drift = sub.add_parser("drift", help="what changed between two audits of one device")
    drift.add_argument("before", help="the earlier <device>.audit.json")
    drift.add_argument("after", help="the later <device>.audit.json")
    drift.add_argument("--before-ir", help="the earlier <device>.ir.json, for fact-level drift")
    drift.add_argument("--after-ir", help="the later <device>.ir.json")
    drift.add_argument("--json", action="store_true")
    drift.set_defaults(func=_cmd_drift)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crucible",
        description="AI-driven multi-vendor network security compliance auditor. Runs offline.",
    )
    parser.add_argument("--version", action="version", version=f"crucible {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="audit one device or a directory of devices")
    audit.add_argument("target", help="config file, device directory, bundle directory or .zip")
    audit.add_argument(
        "--rules", default=DEFAULT_RULES, help=f"rule directory (default: {DEFAULT_RULES})"
    )
    audit.add_argument("--out", help="write reports here; omit to print to the terminal only")
    audit.add_argument("--framework", help="filter rules by framework, e.g. CIS or STIG")
    audit.add_argument("--format", default="json,md,pdf", help="json,md,pdf,ir")
    audit.add_argument("--no-sign", action="store_true", help="skip ledger commit and signing")
    audit.add_argument("--all", action="store_true", help="list findings of every severity")
    audit.add_argument("--json", action="store_true", help="emit machine-readable output")
    audit.add_argument(
        "--verify",
        action="store_true",
        help="boot a twin per device and demonstrate the high and critical findings",
    )
    _add_learning_options(audit)
    audit.set_defaults(func=_cmd_audit)

    verify = sub.add_parser(
        "verify",
        help="verify a ledger is unaltered, or prove a finding against a disposable twin",
    )
    verify.add_argument("ledger", nargs="?", help="path to ledger.jsonl")
    verify.add_argument("--key", help="issuing public key (default: alongside the ledger)")
    verify.add_argument("--device", help="a device to boot a twin for, instead of a ledger check")
    verify.add_argument("--finding", help="prove only this rule id")
    verify.add_argument("--rules", default=DEFAULT_RULES)
    verify.add_argument("--json", action="store_true")
    _add_learning_options(verify)
    verify.set_defaults(func=_cmd_verify)

    rules = sub.add_parser("rules", help="list the loaded rule set")
    rules.add_argument("--rules", default=DEFAULT_RULES)
    rules.add_argument("--framework")
    rules.set_defaults(func=_cmd_rules)

    show = sub.add_parser("show", help="parse a device and print its normalised IR")
    show.add_argument("target")
    show.add_argument("--json", action="store_true")
    show.set_defaults(func=_cmd_show)

    _register_learning(sub)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CrucibleError as exc:
        # A tool that cannot run says so on stderr and exits 2. It never exits 0
        # with an empty report, which a caller would read as "nothing wrong".
        print(f"crucible: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError) as exc:
        print(f"crucible: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
