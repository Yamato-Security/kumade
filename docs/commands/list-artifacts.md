# `list-artifacts`

List supported DFIR artifacts.

Inspect the embedded catalogue before narrowing a collection. This lists
acquisition definitions, not every matching file on the computer.

```powershell
.\kumade.exe list-artifacts --builtin
.\kumade.exe list-artifacts --catalog .\custom-catalogue.yaml
```

Use an explicit `--catalog` to select custom definitions. Kumade does not
silently load a catalogue found beside the executable. See the
[generated catalogue reference](../collection/catalogue.md).

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

    List supported DFIR artifacts

    Usage: kumade list-artifacts [OPTIONS]

    Options:
          --builtin            Show the embedded acquisition catalog
          --catalog <CATALOG>  Load an acquisition catalog from this file
      -h, --help               Print help
    ```

[Download plain-text help](help/list-artifacts.txt).
