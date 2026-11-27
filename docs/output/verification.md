# Manifests and verification

## Which report answers which question?

| File | What to use it for |
|---|---|
| `Plan.json` | Planned sources, selected files/streams, profile roots, issues and estimates |
| `Run.json` | Run context and acquisition settings |
| `Manifest.csv` / `Manifest.jsonl` | Per-observation source path, method, bytes, hashes and outcome |
| `Coverage.csv` | Family-level planned/acquired/partial/failed/absent accounting |
| `DiscoveryIssues.csv` | Inaccessible, excluded or unsupported sources/paths |
| `Errors.csv` | Partial and failed acquisition records |
| `Summary.json` | Overall counters, completeness and optional-provider results |
| `Seal.json` | Recorded hashes binding metadata and manifest state |
| `client_info.json` | Host grouping marker for downstream tools |

Additional feature/container reports are described in their respective guides.

## Important manifest fields

| Field | Meaning |
|---|---|
| `Computer`, `SourceId`, `SourcePath`, `StreamName` | Observed host, source namespace, path and named stream |
| `RelativeOutputPath` | Where the retained bytes are mapped in this collection |
| `Method` | The acquisition path actually used, for example `FileAPI` or `RawNTFS` |
| `Status`, `Reason` | Outcome and its explanation; read both |
| `BytesRead`, `LogicalSize` | Captured byte count and observed source length |
| `SHA-256`, `Verified` | Recorded content hash and stored-byte check state |
| `ChangedDuringRead` | A source-generation/metadata-change condition; retained bytes can still hash correctly |
| `StartedUtc`, `FinishedUtc` | Observation interval, not the time of an attacker action |
| `CreatedUtc`, `ModifiedUtc`, `AccessedUtc`, `SourceFileId` | Source metadata/identity where available |

## Local verification

```powershell
.\kumade.exe verify E:\Evidence\HOST01_2026-11-25_09-00-00
```

The verifier checks metadata seals, accounting, safe paths and referenced
payload hashes. Keep the whole collection together. Do not modify manifests
or remove a failed/partial record merely to make the summary appear complete.

A hash seal is not currently an authenticated signing identity. Hash agreement
is not structural validation of a hive, database, EVTX or memory image. An
attacker or administrator controlling both payload and seal is outside that
stored-byte verification claim.

## Remote verification

An SFTP record can be `Transferred` with `Verified=false` while waiting for the
receiver. Compare the collector's Delivery SHA256 over a trusted channel, revoke
the upload credential and obtain a successful trusted readback receipt. The
[built-in receiver](../SFTP-Receiver.md) performs this automatically at final delivery.
`verify-delivery` supports independent verification and optional restoration.

For S3, record the URI and SHA-256 printed by the collector. An analyst with
separate read credentials runs `verify-s3` against those values. Hybrid and
fully staged runs support verification of individual published phases before
the whole case arrives. Direct mode uses the final delivery record. Preserve
the verification receipt with the case. See [S3 verification and restore](../S3.md).

A valid receipt does not repair partial source coverage, prove source authenticity
or turn live acquisition into an atomic snapshot. Ordinary `verify` deliberately
refuses an unverified remote metadata directory.

## Exit codes

Collection/verification generally use `0` for completed work, `3` for a partial
result and `2` for a fatal/setup error. Interpret the selected command's reports
as well. In process scanning, rule matches alone do not set a failure code;
incomplete process coverage is a separate state.
