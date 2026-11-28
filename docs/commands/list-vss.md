# `list-vss`

List local Volume Shadow Copies.

List local VSS snapshots without creating or deleting them.

```powershell
.\kumade.exe list-vss --all
.\kumade.exe list-vss --volume C: -o E:\Snapshots.csv
.\kumade.exe list-vss --volume C: -t jsonl
```

Requires elevated, native Windows. The table includes volume paths, snapshot
IDs and UTC creation times. CSV/JSON/JSONL output has PascalCase fields;
`-t` without `-o` writes structured stdout without a banner.
See [historical collection](../vss-existing.md).

## Full command help

Snapshot from `kumade 0.1.0`. Check your binary's `--help` when using a different source/release revision.

??? info "Show full help"

    ```text
    ┏┓┏━┓┓ ┏┓━┓┏━┓━━━┓━━━┓━━━┓
    ┃┃┃┏┛┃ ┃┃ ┗┛ ┃┏━┓┃┓┏┓┃┏━━┛
    ┃┗┛┛┃┃ ┃┃┏┓┏┓┃┃ ┃┃┃┃┃┃┗━━┓
    ┃┏┓┃┃┃ ┃┃┃┃┃┃┃┗━┛┃┃┃┃┃┏━━┛
    ┃┃┃┗┓┗━┛┃┃┃┃┃┃┏━┓┃┛┗┛┃┗━━┓
    ┗┛┗━┛━━━┛┛┗┛┗┛┛ ┗┛━━━┛━━━┛
        by Yamato Security

    Version: 0.1.0

    List local Volume Shadow Copies

    Usage: kumade list-vss [OPTIONS]

    Options:
          --all              List snapshots from all local volumes
          --volume <VOLUME>  Filter by local source volume; repeat for multiple volumes
      -o, --output <FILE>    Write a fresh CSV/JSON/JSONL file (otherwise display a table)
      -t, --format <FORMAT>  Structured output format; without -o write structured rows to stdout [possible values: csv, json, jsonl]
      -q, --quiet            Hide the banner and summary
      -h, --help             Print help
    ```

[Download plain-text help](help/list-vss.txt).
