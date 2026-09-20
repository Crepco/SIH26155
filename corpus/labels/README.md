# Ground truth labels

Twenty configurations, hand-labelled by the team in Phase 0. Precision and recall in
[docs/16](../../docs/16-validation-plan.md) are computed against these files, and they are the
reason we can quote a number instead of a claim.

## One label file per configuration

    config_id: cisco-ios-core-01
    labelled_by: <team member>
    labelled_on: 2026-08-29
    ir_facts:
      mgmt.telnet_enabled:
        value: false
        line: 4410
      mgmt.idle_timeout_min:
        value: 10
        line: 4412
      device.serial:
        value: FDO1234ABCD
        file: show-version.txt
        line: 27
    expected_verdicts:
      CIS-NET-1.1.1: pass
      CIS-NET-1.2.4: pass
      CIS-NET-2.1.2: fail
      CIS-NET-5.3.1: unknown
    notes: >
      Mixed indentation in the vty block. Two ACL entries where the second is
      shadowed by the first. Deliberately kept in the corpus for that reason.

## What is labelled today

`fixtures/` labels the six configurations shipped in
`backend/tests/fixtures/devices`, so `crucible validate` produces a number on a
clean clone with no corpus:

```bash
crucible validate --labels corpus/labels/fixtures --devices backend/tests/fixtures/devices --all
```

Those labels were written from the configurations and the control text by an AI
assistant and **have not been reviewed by a person**. Every report says so, and
the number must be quoted that way or not at all. Rule 2 below - two people per
file - is what turns them into ground truth, and it has not happened yet.

They have already earned their place: the first run against them found a rule
whose assertion was stricter than its own title, an Arista eAPI reading that
failed a correctly configured device, and four controls answered UNKNOWN where
the file did in fact decide them.

## Labelling rules

1. **Label from the file, not from the tool.** If you run the auditor first and then label, the
   ground truth measures agreement with ourselves and is worthless.
2. **Two people per file**, disagreements resolved by reading the vendor documentation rather
   than by voting.
3. **`unknown` is a legitimate expected verdict.** If the configuration genuinely does not say,
   the correct behaviour is UNKNOWN and the label should demand it. Labelling it `pass` teaches
   the metric to reward silent false passes, which is the exact failure we exist to prevent.
4. **Record the line number.** A label without a line cannot check invariant 2.
5. **Never edit a label to make a test pass.** If the label is wrong, fix it in its own commit
   with the reasoning stated. If the tool is wrong, fix the tool.
