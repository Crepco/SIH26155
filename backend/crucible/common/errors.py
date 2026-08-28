"""Error types.

The distinction that matters: a parser raising on hostile input is acceptable,
a parser returning PASS on input it did not understand is a critical defect.
Everything here exists so that failures are loud rather than silent.
"""

from __future__ import annotations


class CrucibleError(Exception):
    """Base for everything this package raises deliberately."""


class IngestError(CrucibleError):
    """Input could not be accepted at all - missing, unreadable, or not a config."""


class UnsafeArchiveError(IngestError):
    """An uploaded archive tried something it should not.

    Path traversal, absolute members, symlinks, or a decompression ratio that
    looks like a zip bomb. Configuration files are untrusted input and archives
    are the most hostile shape they arrive in.
    """


class ParseError(CrucibleError):
    """A parser could not proceed.

    Note that a *line* the parser does not understand is not an error: it falls
    through the cascade and is counted as unparsed. This is for the case where
    the file itself is unusable.
    """


class RuleError(CrucibleError):
    """A rule file is malformed, or an assertion cannot be compiled.

    A rule that does not load is loud and fatal. There is no partial rule set,
    because a silently dropped rule is a silently missing control.
    """


class LedgerError(CrucibleError):
    """The audit ledger is inconsistent, or a signature did not verify."""
