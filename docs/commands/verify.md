# `verify`

Verify the integrity of a local Kumade collection.

Read the saved collection, validate seals/accounting and compare retained
payload hashes without reading original source evidence.

```powershell
.\kumade.exe verify E:\Evidence\HOST01_2026-11-25_09-00-00
```

For containers, inspect a read-only mounted run directory using the
[container guide](../output/index.md). For SFTP, use the trusted receiver or `verify-delivery`. For S3, use
`verify-s3` with the collector’s printed URI and SHA-256. A verified partial collection remains partial.
Read [verification semantics](../output/verification.md).

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

    Verify the integrity of a local Kumade collection

    Usage: kumade verify <DIRECTORY>

    Arguments:
      <DIRECTORY>  Collection directory containing the manifest

    Options:
      -h, --help  Print help
    ```

[Download plain-text help](help/verify.txt).
