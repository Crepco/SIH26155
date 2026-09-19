"""Command line interface.

    crucible audit corpus/ --out reports/
    crucible verify reports/ledger.jsonl
    crucible rules --framework CIS
    crucible show corpus/core-sw-01/

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

from crucible import __version__
from crucible.common.errors import CrucibleError
from crucible.common.types import Severity, Verdict

__all__ = ["main"]

DEFAULT_RULES = "rules/cis"

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

    job = run_audit(
        args.target,
        rules_path=args.rules,
        output_dir=args.out,
        framework=args.framework,
        formats=formats,
        sign=not args.no_sign,
        workdir=args.out,
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

        if not report.parser_applied:
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

    if job.ledger_path:
        print(f"  ledger  {job.ledger_path}")
        print()

    return _exit_code(job)


def _exit_code(job: object) -> int:
    """Non-zero when something that matters failed."""
    results = getattr(job, "results", [])
    for result in results:
        for finding in result.report.findings:
            if finding.verdict is Verdict.FAIL and finding.severity in (
                Severity.CRITICAL,
                Severity.HIGH,
            ):
                return 1
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
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
    audit.set_defaults(func=_cmd_audit)

    verify = sub.add_parser("verify", help="verify an audit ledger has not been altered")
    verify.add_argument("ledger", help="path to ledger.jsonl")
    verify.add_argument("--key", help="issuing public key (default: alongside the ledger)")
    verify.set_defaults(func=_cmd_verify)

    rules = sub.add_parser("rules", help="list the loaded rule set")
    rules.add_argument("--rules", default=DEFAULT_RULES)
    rules.add_argument("--framework")
    rules.set_defaults(func=_cmd_rules)

    show = sub.add_parser("show", help="parse a device and print its normalised IR")
    show.add_argument("target")
    show.add_argument("--json", action="store_true")
    show.set_defaults(func=_cmd_show)

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
