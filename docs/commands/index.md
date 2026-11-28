# Commands

Run `kumade.exe` or `kumade.exe -h` for the command list. Run `kumade.exe check-support` for the support report. Add `-h` to any command to see its usage and options. Collection flags also work without writing the `collect` subcommand.

| Command | Purpose |
|---|---|
| [`check-support`](check-support.md) | Check platform support and acquisition prerequisites |
| [`collect`](collect.md) | Collect DFIR artifacts |
| [`forensic-copy`](forensic-copy.md) | Create a bit-for-bit image of a logical Windows partition |
| [`list-artifacts`](list-artifacts.md) | List supported DFIR artifacts |
| [`list-vss`](list-vss.md) | List local Volume Shadow Copies |
| [`live-info`](live-info.md) | Capture live Windows response data |
| [`collect-test`](collect-test.md) | Discover files and write a plan without copying evidence |
| [`receive-sftp`](receive-sftp.md) | Receive evidence through a temporary upload-only SFTP account |
| [`scan-processes`](scan-processes.md) | Scan running Windows processes with YARA Forge or local YARA rules |
| [`update-rules`](update-rules.md) | Download or update a compressed YARA Forge rule package |
| [`verify`](verify.md) | Verify the integrity of a local Kumade collection |
| [`verify-delivery`](verify-delivery.md) | Verify an SFTP delivery locally and optionally reconstruct files |
| [`resume-s3`](resume-s3.md) | Resume phased S3 uploads from a protected workspace without reading original sources |
| [`verify-s3`](verify-s3.md) | Verify an S3 collection against its delivery hash and optionally restore it |

[Root help snapshot](help/kumade.txt). These pages describe current source behavior. A release sharing the same version label may predate recent flags.

Start with [installation](../getting-started/index.md) or [your first collection](../getting-started/first-collection.md).
