# `check-support`

Check platform support and acquisition prerequisites.

Use this before a collection to see platform capabilities and provider limits.
Unavailable capabilities and checks that could not be completed appear in red. If a row says
`Not available (run as administrator)`, reopen the terminal as administrator and run the check again.
On Windows, Kumade checks the token privileges used by live collection, raw NTFS reads, partition imaging,
VSS, RAM capture, container output and collection uploads. VSS also needs a native-architecture build.
For RAM it validates the default DumpIt executable without launching it. A custom toolkit can be supplied
with `--dumpit` during collection. The container check looks for Windows PowerShell and its Storage module.
Destination space, driver policy, volume eligibility and remote credentials still need to be checked at collection time.
If the binary has no embedded YARA Forge rules, the value appears in red. You can supply a local ZIP or use `update-rules` to download one.

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
