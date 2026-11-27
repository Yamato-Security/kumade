# Analyze the collection

Keep the original collection and its verification records unchanged. Parse or
export to a separate working directory. Recheck coverage gaps before concluding
that missing evidence means an action never happened.

## Windows event logs

[Hayabusa](https://yamato-security.github.io/hayabusa/) scans EVTX records and
creates investigation timelines with its bundled detection rules. Point it at
the retained event-log tree or a supported evidence input. Its
[Getting Started guide](https://yamato-security.github.io/hayabusa/getting-started/)
explains current flags and output profiles.

[Takajo](https://github.com/Yamato-Security/takajo) performs post-analysis on
compatible Hayabusa JSONL output, including script blocks, logons and process
relationships. It does not replace the original event logs.

## Other Windows artifacts

[Juntei](https://yamato-security.github.io/juntei/) parses collected NTFS,
registry, file, ESE and SQLite artifacts. Its automatic parsing can group
Kumade drive folders using the sealed host marker. Keep registry transaction
logs, ESE recovery files and SQLite WAL companions with their databases.
Follow Juntei's current command reference for supported input formats.

## Containers and remote collections

Use the [container guides](index.md) for read-only handling and fidelity limits.
Do not run recovered executables. For SFTP, verify the delivery first, then
restore a separate working copy with `verify-delivery --restore` if downstream
tools need ordinary paths. For [S3](../S3.md), use `verify-s3 --restore` with the
printed URI and SHA-256 of the collection or the phase you need. Restored files
carry their source provenance in the inventories;
its visible file timestamps/ACLs are not a replacement for source observations.

## Correlate instead of overinterpreting

A file's presence is not necessarily execution. A source metadata timestamp is
not necessarily attack time. A YARA or entropy lead is not a verdict. Use
independent artifacts, source semantics and timeline context to test the conclusion.
