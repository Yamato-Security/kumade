# `live-info`

Capture live Windows response data.

Collect current process, network, account, service, security and regional
configuration observations without ordinary disk-artifact acquisition.

```powershell
.\kumade.exe live-info --list
.\kumade.exe live-info -o E:\Live-Inventory
.\kumade.exe live-info --dataset Processes --dataset TcpConnections -t jsonl -o E:\Live-Network
```

Use a new output directory. Standalone query concurrency defaults to two
workers; the collection integration also uses at most two. Provider failures
are explicit rather than empty success. See [live inventory](../live-info.md)
and its [generated field reference](../collection/live-datasets.md).

## Full command help

Snapshot from `kumade 0.1.0`. Check your binary's `--help` when using a different source/release revision.

??? info "Show full help"

    ```text
    ┏┓┏━┳┓ ┏┳━┓┏━┳━━━┳━━━┳━━━┓
    ┃┃┃┏┛┃ ┃┃ ┗┛ ┃┏━┓┃┓┏┓┃┏━━┛
    ┃┗┛┛┃┃ ┃┃┏┓┏┓┃┃ ┃┃┃┃┃┃┗━━┓
    ┃┏┓┃┃┃ ┃┃┃┃┃┃┃┗━┛┃┃┃┃┃┏━━┛
    ┃┃┃┗┓┗━┛┃┃┃┃┃┃┏━┓┃┛┗┛┃┗━━┓
    ┗┛┗━┻━━━┻┛┗┛┗┻┛ ┗┻━━━┻━━━┛
        by Yamato Security

    Version: 0.1.0

    Capture live Windows response data

    Usage: kumade live-info [OPTIONS]

    Options:
      -o, --output <DIR>       New output directory (existing directories are refused)
          --list               List the embedded inventory data sets without querying the system
      -t, --format <FORMAT>    Output format [default: csv] [possible values: csv, json, jsonl]
          --dataset <NAME>     Select a named data set; repeat (default: all)
      -T, --threads <THREADS>  Concurrent PowerShell queries [default: 2]
          --timeout <TIMEOUT>  Deadline for each query in seconds [default: 90]
      -q, --quiet              Suppress progress
      -h, --help               Print help
    ```

[Download plain-text help](help/live-info.txt).
