# `scan-processes`

Hunt in live process memory.

Run a native Windows build with suitable privileges. This is a live memory
scan, not disk-file scanning or an offline RAM-image parser.

```powershell
.\kumade.exe scan-processes -o E:\Yara-Core
.\kumade.exe scan-processes --ruleset full --rules-release 20261122 -o E:\Yara-Full
.\kumade.exe scan-processes --rules .\local.yar --pid 1234 -t jsonl -o E:\Yara-Selected
```

Matching bundled packs load offline; standard binaries download Core. Pin a release or provide local ZIP/source rules for
repeatability. Protected/inaccessible processes, read gaps, exits and timeouts
remain visible. A match is a lead; no match is not a clean bill of health.
See [process-memory scanning](../yara-process-scan.md) for evaluator semantics,
chunk boundaries and rule-selection limitations.

Integrated collection uses `--scan-processes --yara-ruleset full`, not the
standalone `--ruleset` spelling. Its result files are sealed with the collection.

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

    Scan running Windows processes with YARA Forge or local YARA rules

    Usage: kumade scan-processes [OPTIONS] --output <DIR>

    Options:
      -o, --output <DIR>                   New result directory (existing directories are refused)
          --ruleset <RULESET>              YARA Forge package (bundled selection by default, otherwise core) [default: core] [possible values: core, extended, full]
          --rules-release <RULES_RELEASE>  Forge release tag YYYYMMDD, or latest [default: latest]
          --rules <FILE>                   Local Forge ZIP or UTF-8 YARA source (offline; includes disabled)
      -t, --format <FORMAT>                Result table format [default: csv] [possible values: csv, jsonl]
          --pid <PID>                      Limit scanning to a PID; repeat (default: all except this collector)
      -T, --threads <THREADS>              Concurrent processes (default: 2 to limit live-system pressure) [default: 2]
          --timeout <TIMEOUT>              Deadline per process in seconds; expired scans retain partial matches [default: 60]
          --chunk-mib <CHUNK_MIB>          Memory read chunk size in MiB; patterns crossing chunks may be missed [default: 16]
      -q, --quiet                          Suppress progress and routine console messages
      -h, --help                           Print help
    ```

[Download plain-text help](help/scan-processes.txt).
