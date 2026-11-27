# Commands

Run `kumade.exe` or `kumade.exe -h` for the command list. Run a command by itself (for example, `kumade.exe collect`) or add `-h` to see its usage and options. Collection flags also work without writing the `collect` subcommand.

| Command | Purpose |
|---|---|
| [`collect`](collect.md) | Collect forensic artifacts |
| [`doctor`](doctor.md) | Inspect compiled capabilities |
| [`forensic-copy`](forensic-copy.md) | Image a logical partition |
| [`list`](list.md) | List acquisition families |
| [`list-vss`](list-vss.md) | List existing shadow copies |
| [`live-info`](live-info.md) | Capture current host state |
| [`plan`](plan.md) | Inspect scope and size estimates |
| [`receive`](receive.md) | Receive upload-only SFTP evidence |
| [`scan-processes`](scan-processes.md) | Hunt in live process memory |
| [`update-rules`](update-rules.md) | Download compressed YARA Forge rules |
| [`verify`](verify.md) | Check a retained local collection |
| [`verify-delivery`](verify-delivery.md) | Verify or restore an SFTP delivery |
| [`resume-s3`](resume-s3.md) | Resume a hybrid or fully staged S3 delivery |
| [`verify-s3`](verify-s3.md) | Verify or restore an S3 delivery |

[Root help snapshot](help/kumade.txt). These pages describe current source behavior. A release sharing the same version label may predate recent flags.

Start with [installation](../getting-started/index.md) or [your first collection](../getting-started/first-collection.md).
