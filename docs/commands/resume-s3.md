# `resume-s3`

Resume a phased S3 delivery.

Supply the protected workspace printed by the collector and the original S3 destination. The uploader reuses acknowledged chunks and never rereads a live source. See [hybrid collection](../S3.md#hybrid-collection) and [full phased recovery](../S3.md#recoverable-phased-collection).

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

    Resume phased S3 uploads from a protected workspace without reading original sources

    Usage: kumade resume-s3 [OPTIONS] --workspace <WORKSPACE> --s3 <S3>

    Options:
          --workspace <WORKSPACE>      Protected run workspace printed by collect
          --s3 <S3>                    Original s3://BUCKET/PREFIX supplied to collect
          --s3-region <S3_REGION>      AWS region (default: AWS_REGION, AWS_DEFAULT_REGION or us-east-1)
          --s3-endpoint <S3_ENDPOINT>  Explicit S3-compatible HTTPS endpoint (HTTP allowed on loopback for testing)
      -h, --help                       Print help
    ```

[Download plain-text help](help/resume-s3.txt).
