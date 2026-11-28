# `verify-delivery`

Verify an SFTP delivery locally and optionally reconstruct files.

Use the trusted receiver's files after the upload credential is revoked.
Obtain the final delivery object's name and SHA256 independently from the
collector. A new receipt is required; restoration is optional and needs extra space.

```powershell
.\kumade.exe verify-delivery --incoming D:\Evidence\SESSION\incoming `
  --delivery UUID-delivery.json --sha256 COLLECTOR_PRINTED_SHA256 `
  --receipt D:\Evidence\NewReceipt.json --uploader-revoked
```

Add `--restore D:\Evidence\RestoredCase` for a separate working copy. Replace
all example identifiers and paths. Do not reconstruct files over the originals.
The verifier checks stored/decoded hashes and metadata bindings; it does not
prove source authenticity or atomic acquisition.

See [SFTP receiver verification/restoration](../SFTP-Receiver.md#independent-readback-and-restoration)
and [remote output](../SFTP.md).

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

    Verify an SFTP delivery locally and optionally reconstruct files

    Usage: kumade verify-delivery [OPTIONS] --incoming <INCOMING> --delivery <DELIVERY> --sha256 <SHA256> --uploader-revoked --receipt <RECEIPT>

    Options:
      -h, --help  Print help

    Delivery Verification:
          --incoming <INCOMING>  Flat incoming object directory from an SFTP delivery
          --delivery <DELIVERY>  Final UUID-delivery.json object name
          --sha256 <SHA256>      Delivery SHA256 printed by the collector (compare independently)
          --uploader-revoked     Confirm upload credentials have been revoked and existing sessions ended

    Output and Restore:
          --receipt <RECEIPT>                  New readback receipt path (will not overwrite an existing file)
          --restore <RESTORE>                  Optional new directory in which to reconstruct files (extra server disk space)
          --max-decoded-gib <MAX_DECODED_GIB>  Maximum total decoded GiB, including sparse logical zero ranges [default: 1024]
    ```

[Download plain-text help](help/verify-delivery.txt).
