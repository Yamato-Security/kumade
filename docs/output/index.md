# Output guide

Choose one destination per collection. The hostname/UTC naming and manifests
keep provenance, but the modes have different storage and fidelity behavior.

| Mode | How to select it | Useful for | Important differences |
|---|---|---|---|
| Directory | `-o E:\Evidence` | Straightforward parser input and browsing | Payloads plus separate provenance; generic ADS discovery/fidelity is limited |
| NTFS VHDX | `--vhdx E:\Evidence` | Native NTFS streams and metadata in one image | Dynamic NTFS container; needs creation, finalization and headroom |
| E01 | `--e01 E:\Evidence` | Compressed segmented container | Same selected NTFS collection model, with compression and readback work |
| Amazon S3 | `--s3 s3://BUCKET/PREFIX/` | Hybrid collection into a separate prefix per host | Retains volatile evidence and streams disk files. Use `resume-s3` for recovery and `verify-s3` for readback |
| SFTP | `--sftp SERVER ...` | Stream to remote evidence storage | Gzip objects, metadata staging and trusted receiver verification; no VHDX upload |

These are alternative destinations. A VHDX/E01 artifact collection is not a
bit-for-bit copy of the source partition. For that, use [forensic-copy](../forensic-copy.md).

## Read the output correctly

- [Directory layout](directory.md) explains the run and drive folders.
- [Verification](verification.md) explains manifests, seals and completeness.
- [VHDX](../vhdx-output.md) and [E01](../e01-output.md) describe native metadata fidelity.
- [Amazon S3](../S3.md) covers the three upload modes, temporary credentials, recovery and independent readback.
- [SFTP](../SFTP.md) and the [receiver](../SFTP-Receiver.md) describe delivery and readback.
- [Analysis handoff](analysis.md) explains what to preserve for downstream tools.

File lengths, compressed bytes, allocated blocks, virtual container capacity
and temporary peak usage are different measurements. The [benchmarks](../benchmarks/index.md)
show those differences on the tested VM.
