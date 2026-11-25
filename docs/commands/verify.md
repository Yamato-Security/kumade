# `verify`

Check a retained local collection.

Read the saved collection, validate seals/accounting and compare retained
payload hashes without reading original source evidence.

```powershell
.\kumade.exe verify E:\Evidence\HOST01_2026-11-25_09-00-00
```

For containers, inspect a read-only mounted run directory using the
[container guide](../output/index.md). For remote delivery, use the trusted
receiver or `verify-delivery`, rather than treating local upload metadata as
verified evidence. A verified partial collection remains partial.
Read [verification semantics](../output/verification.md).

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

    Verify the seal and every stored payload; never reads original sources

    Usage: kumade verify <DIRECTORY>

    Arguments:
      <DIRECTORY>

    Options:
      -h, --help  Print help
    ```

[Download plain-text help](help/verify.txt).
