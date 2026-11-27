# Troubleshooting

## Help appears without collecting

Running Kumade without arguments deliberately displays help. Use `collect --wizard` to
start the wizard or `collect --yes` for unattended defaults.

## An option does not exist

Compare `--version`, `collect --help` and the release notes. This site tracks
`main`, while an older release binary may not contain a recent feature.
Use the native package for your architecture and avoid relying on version text
alone when different development commits share that version.

## Access denied or a locked file fails

Run an elevated native Windows binary. Review `Errors.csv`, `DiscoveryIssues.csv`
and the acquisition method in the manifest. Raw NTFS can acquire supported
locked files, but it does not bypass every inaccessible directory, encryption
scheme or protected content type. See [locked files](../collection/locked-files.md).

## The run exits with code 3

This is a partial result, not necessarily corrupt output. Inspect source-change
notes, failed families, live-provider failures, YARA coverage and metadata errors.
Run the applicable verifier. [Integrity and completeness](../output/verification.md)
are separate conclusions.

## VSS cannot start or clean up

Read the reported snapshot IDs and error. Use a native elevated Windows build
and review the [VSS prerequisites](../vss.md). Do not delete unrelated restore
points. Kumade owns only the snapshots it created; cleanup failures remain explicit.

## RAM capture fails

Check the external toolkit architecture/hash, privileges, free space and driver
policy. Do not assume a helper's success message proves a full dump. Kumade
checks its result and layout. Follow [RAM troubleshooting](../memory-acquisition.md).

## SFTP upload finishes but is not verified

An upload acknowledgement is not trusted readback. Keep the collector's Delivery
SHA256 and obtain a successful receiver receipt after the temporary account is
revoked. See [receiver verification](../SFTP-Receiver.md). Interrupted evidence
is retained; do not overwrite it to retry.

## An S3 collection stopped before delivery finished

For hybrid or fully staged collection, retain the **S3 recovery workspace** and
run `resume-s3` with the original bucket, prefix and endpoint. Hybrid recovery
can reuse acknowledged disk files and identify missing ones. A new acquisition
is needed for evidence that never reached S3 or the workspace. For `--s3-direct`,
see the [lost-acknowledgement instructions](../S3.md#direct-streaming-retries-limits-and-costs).

## Output uses more space or time than expected

Sparse logical sizes differ from allocated space. RAM, E01/container staging,
VSS copy-on-write, entropy discovery and receiver restoration need additional
headroom. Read [output choices](../output/index.md) and [benchmarks](../benchmarks/index.md).

For a bug report, include the command with credentials/private paths redacted,
binary/source version, platform, summary counters and relevant errors. Do not
attach raw memory, registry hives, account secrets or private evidence publicly.
