# `update-rules`

Download or update a compressed YARA Forge rule package.

Download one versioned Core, Extended or Full ZIP and validate its release-asset
SHA-256 and compilation before saving it. Existing different contents are refused.

```powershell
.\kumade.exe update-rules --ruleset core
.\kumade.exe update-rules --ruleset extended
.\kumade.exe update-rules --ruleset full
```

Use the ZIP path printed by the command with `scan-processes --rules <ZIP>` or
`collect --scan-processes --yara-rules <ZIP>`. Without `-o`, download beside the
executable, without creating a subdirectory. Updating does not rewrite the embedded executable.
See [compressed/offline rules](../yara-process-scan.md#compressedoffline-rule-inputs-and-updates).

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

    Download or update a compressed YARA Forge rule package

    Usage: kumade update-rules [OPTIONS]

    Options:
          --ruleset <RULESET>              YARA Forge ruleset to download [default: core] [possible values: core, extended, full]
          --rules-release <RULES_RELEASE>  Forge release tag YYYYMMDD or latest [default: latest]
      -o, --output <DIR>                   Destination for versioned ZIP files (default: same directory as this executable)
      -q, --quiet                          Suppress routine messages
      -h, --help                           Print help
    ```

[Download plain-text help](help/update-rules.txt).
