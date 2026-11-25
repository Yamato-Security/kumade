# `receive`

Receive upload-only SFTP evidence.

Run a fresh receiver per acquisition. It creates temporary credentials and a
host-key fingerprint, accepts append-only object uploads, revokes the
credential, and verifies received objects in place.

```powershell
.\kumade.exe receive --listen 0.0.0.0:2222 --allow-ip 192.0.2.20 --output D:\Evidence --expires 2h
```

Replace the example source address with the collector's actual address.
The password is printed once: do not put it in shared logs. Pin the displayed
host key on the collector. The default listen address is loopback; an explicit
interface is required for remote collection.

The receiver can also be built from source on Linux. Follow the complete
[receiver guide](../SFTP-Receiver.md) for quotas, expiry, receipts and recovery.
It accepts one collection per invocation and does not create an OS login account.

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

    Receive evidence through a temporary upload-only SFTP account

    Usage: kumade receive [OPTIONS] --output <OUTPUT>

    Options:
          --listen <LISTEN>
              Bind address (explicitly select a network interface for remote collection) [default: 127.0.0.1:2222]
      -o, --output <OUTPUT>
              Evidence parent; creates a new protected session directory
          --expires <EXPIRES>
              Credential lifetime: seconds, or a suffix s/m/h (maximum: 7 days) [default: 2h]
          --max-gib <MAX_GIB>
              Maximum stored upload bytes in GiB (compressed bytes) [default: 100]
          --max-decoded-gib <MAX_DECODED_GIB>
              Maximum total decoded bytes during readback in GiB [default: 1024]
          --max-files <MAX_FILES>
              Maximum number of upload objects, including journals and probes [default: 100000]
          --max-connections <MAX_CONNECTIONS>
              Maximum simultaneous SSH connections (authenticated or not) [default: 8]
          --allow-ip <ALLOW_IPS>
              Accept connections only from these exact IP addresses; repeat
          --reserve-mib <RESERVE_MIB>
              Keep this much free disk space in MiB [default: 2048]
      -h, --help
              Print help
    ```

[Download plain-text help](help/receive.txt).
