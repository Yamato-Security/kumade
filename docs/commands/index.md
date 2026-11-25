# Commands

Run `kumade.exe --help` for the root menu, or `kumade.exe COMMAND --help` for a command. With no arguments, Kumade displays help without starting a collection. Collection flags also work without writing the `collect` subcommand.

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
| [`verify`](verify.md) | Check a retained local collection |
| [`verify-delivery`](verify-delivery.md) | Verify or restore an SFTP delivery |

[Root help snapshot](help/kumade.txt). These pages describe current source behavior. A release sharing the same version label may predate recent flags.

Start with [installation](../getting-started/index.md) or [your first collection](../getting-started/first-collection.md).
