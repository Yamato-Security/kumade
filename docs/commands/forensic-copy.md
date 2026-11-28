# `forensic-copy`

Bit-for-bit copy a partition.

This is separate from artifact collection. It writes a logical partition image
and a receipt, not the physical whole disk and not only catalogue files.
Use a destination on a different external physical disk.

```powershell
.\kumade.exe forensic-copy -s C: -o E:\Evidence
.\kumade.exe forensic-copy -s C: --vss -o E:\Evidence
```

The command enforces source/destination separation, reserve checks and readback
hashing. Review [partition imaging](../forensic-copy.md) before running it;
live bytes can change and VSS remains crash-consistent.

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

    Bit-for-bit copy a partition

    Usage: kumade forensic-copy [OPTIONS] --source <VOLUME> --output <DIR>

    Options:
      -s, --source <VOLUME>            Logical volume to read, for example C: or a volume GUID
      -o, --output <DIR>               Destination directory on a different external physical drive
          --vss                        Read from an owned, crash-consistent VSS snapshot
          --vss-timeout <VSS_TIMEOUT>  VSS snapshot creation deadline in seconds
          --reserve-mib <RESERVE_MIB>  Keep this much destination space free (MiB) [default: 2048]
      -q, --quiet                      Suppress progress and routine console messages
      -h, --help                       Print help
    ```

[Download plain-text help](help/forensic-copy.txt).
