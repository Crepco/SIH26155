"""Unified ingestion - NTRO requirement 1.

Single or bulk upload of configuration files from any device, through one entry
point. Accepts a file, a directory, or an archive, and groups what it finds into
per-device bundles.

The detail most teams miss: serial numbers and hardware details are explicitly
required in the report and are usually *not present in the running configuration
at all*. They live in ``show version`` output. So the unit of ingestion is a
bundle of files, never a single config file.
"""

from crucible.ingest.bundle import DeviceBundle, SourceFile, load

__all__ = ["DeviceBundle", "SourceFile", "load"]
