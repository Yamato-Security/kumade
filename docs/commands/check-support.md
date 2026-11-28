# `check-support`

Check platform support and acquisition prerequisites.

Use this before a collection to see platform capabilities and provider limits.
On Windows, the live acquisition row checks the current session for elevation and the backup privilege.
If it says `Not available (run as administrator)`, reopen the terminal as administrator and run the check again.

```powershell
.\kumade.exe check-support
```

Use the native package for the host architecture. See
[capabilities](../overview/capabilities.md) and [installation](../getting-started/index.md).

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

    Check platform support and acquisition prerequisites

    Usage: kumade check-support

    Options:
      -h, --help  Print help
    ```

[Download plain-text help](help/check-support.txt).
