# `doctor`

Inspect compiled capabilities.

Use this before a collection to see platform capabilities and provider limits.
It does not acquire evidence or guarantee that every protected source is readable.

```powershell
.\kumade.exe doctor --check
```

Use the native package for the host architecture. See
[capabilities](../overview/capabilities.md) and [installation](../getting-started/index.md).

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

    Inspect platform support and acquisition prerequisites

    Usage: kumade doctor [OPTIONS]

    Options:
          --check  Check platform support and collection prerequisites
      -h, --help   Print help
    ```

[Download plain-text help](help/doctor.txt).
