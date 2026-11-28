# `receive-sftp`

Receive evidence through a temporary upload-only SFTP account.

Start one listener for a single collector or add `--sources N` for multiple
computers. Each source gets a temporary upload-only credential, separate storage
and independent readback verification. The receiver prints one host-key
fingerprint shared by all sources.

```powershell
.\kumade.exe receive-sftp --listen 0.0.0.0:2222 --allow-ip 192.0.2.20 --output D:\Evidence --expires 2h
```

Replace the example source address with the collector's actual address.
The password is printed once: do not put it in shared logs. Pin the displayed
host key on the collector. The default listen address is loopback; an explicit
interface is required for remote collection.

The receiver can also be built from source on Linux. Follow the complete
[receiver guide](../SFTP-Receiver.md) for quotas, expiry, receipts and recovery.
Keep both the collector and receiver running for automatic reconnect after a network interruption.

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

    Receive evidence through a temporary upload-only SFTP account

    Usage: kumade receive-sftp [OPTIONS] --output <OUTPUT>

    Options:
      -h, --help  Print help

    Listener and Access:
          --listen <LISTEN>                    Bind address (explicitly select a network interface for remote collection) [default: 127.0.0.1:2222]
          --sources <SOURCES>                  Number of independent collectors to issue temporary credentials to [default: 1]
          --expires <EXPIRES>                  Credential lifetime: seconds, or a suffix s/m/h (maximum: 7 days) [default: 2h]
          --allow-ip <ALLOW_IPS>               Accept connections only from these exact IP addresses; repeat
          --max-connections <MAX_CONNECTIONS>  Maximum simultaneous SSH connections (authenticated or not) [default: 8]

    Storage and Limits:
      -o, --output <OUTPUT>                    Evidence parent; creates a new protected session directory
          --reserve-mib <RESERVE_MIB>          Keep this much free disk space in MiB [default: 2048]
          --max-gib <MAX_GIB>                  Maximum stored upload bytes per source in GiB (compressed bytes) [default: 100]
          --max-decoded-gib <MAX_DECODED_GIB>  Maximum decoded bytes per source during readback in GiB [default: 1024]
          --max-files <MAX_FILES>              Maximum upload objects per source, including journals and probes [default: 100000]
    ```

[Download plain-text help](help/receive-sftp.txt).
