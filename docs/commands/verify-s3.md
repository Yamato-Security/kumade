# `verify-s3`

Verify or restore an S3 delivery.

Use a separate read role to verify the full delivery or an individual phase using its URI and SHA-256 printed
by the collector. Choose a new local receipt path. Add `--restore DIR` to
reconstruct the collection. See [S3 setup and verification](../S3.md).

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

    Verify an S3 collection against its delivery hash and optionally restore it

    Usage: kumade verify-s3 [OPTIONS] --s3 <S3> --sha256 <SHA256> --receipt <RECEIPT>

    Options:
          --s3 <S3>
              Full s3:// URI of the delivery or phase manifest printed by the collector
          --s3-region <S3_REGION>
              AWS region (default: AWS_REGION, AWS_DEFAULT_REGION or us-east-1)
          --s3-endpoint <S3_ENDPOINT>
              Explicit S3-compatible HTTPS endpoint (HTTP allowed on loopback for testing)
          --sha256 <SHA256>
              SHA-256 recorded independently from the collector
          --receipt <RECEIPT>
              New local receipt file
          --restore <RESTORE>
              Optional new local directory for restored evidence
          --max-decoded-gib <MAX_DECODED_GIB>
              Maximum total decoded GiB [default: 1024]
      -h, --help
              Print help
    ```

[Download plain-text help](help/verify-s3.txt).
