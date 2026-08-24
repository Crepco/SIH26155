# DISA STIG rules

**Generated, not hand-authored. Do not edit files in this directory by hand.**

DISA publishes STIGs as machine-readable XCCDF XML. One importer turns an official benchmark
release into hundreds of real controls. This is the highest-leverage half-day in the entire plan:
it is the difference between *claiming* multi-framework support and *demonstrating* it.

## Import flow

    official XCCDF XML release
            |
            v
    XCCDF importer (lxml, external entities disabled)
            |
            +--> rule id, title, severity, control identifiers   -> emitted directly
            +--> check content                                   -> mapped to an IR assertion
            +--> fix text                                        -> mapped to remediation, per target
            |
            v
    rules/stig/<benchmark>-<version>.yaml   (generated, checked in, reviewed)

## Why the output is checked in

The generated YAML is committed rather than produced at runtime for three reasons: an air-gapped
deployment cannot fetch a benchmark; a reviewer can diff exactly what changed between benchmark
releases; and the ledger needs the rule set that produced a report to be reproducible years
later.

## Mapping is not fully automatic, and we say so

XCCDF check content is prose plus vendor-specific check commands. Where the importer can derive a
mechanical assertion over the IR it does so. Where it cannot, the control is imported with its
identity, severity and text intact but marked as requiring manual assertion authoring, and it
does not silently evaluate to PASS. Unmapped controls appear in the report as UNKNOWN with a
reason, consistent with invariant 3.

## Licensing

DISA STIG content and NIST SP 800-53 control text are United States Government publications and
may be quoted. CIS Benchmark text may not, and never appears in this directory.

## Provenance

Every generated file records the source benchmark title, release, publication date and the SHA-256
of the XCCDF file it was produced from, so that a report citing `STIG-NET0993` can be traced to an
exact upstream document.
