# `collect`

Collect forensic artifacts.

Use an elevated, native Windows build for live/raw evidence. With no source,
Kumade discovers fixed volumes; `-d` selects explicit offline roots.

```powershell
.\kumade.exe collect -o E:\Evidence
.\kumade.exe collect --yes --volume C: --vss --vhdx E:\Evidence
```

`--yes` selects feature defaults plus explicit flags. It does not enable RAM,
paging, VSS or scans automatically. Directory (`-o`), VHDX, E01 and SFTP are
alternative outputs. Read [the wizard](../collection-wizard.md),
[collection guide](../collection/index.md), [RAM](../memory-acquisition.md)
and [output guide](../output/index.md).

Acquisition defaults to available logical CPUs capped at four. `-T` accepts
1–128 workers, bounded by work items. `--reserve-mib` defaults to 2048.
More workers need not improve a constrained disk or network path.

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

    Collect selected artifacts into a new, hash-verified run directory

    Usage: kumade collect [OPTIONS]

    Options:
          --yes
              Accept collection defaults without interactive prompts (for scripts)
          --wizard
              Force the collection wizard, including when answers are piped
          --paging
              Include paging, swap, hibernation and existing memory dumps (default: off)
          --scan-processes
              Scan live process memory after hot disk artifacts (default: off)
          --yara-ruleset <YARA_RULESET>
              YARA Forge package for the optional process scan (default: core) [possible values: core, extended, full]
          --yara-rules <YARA_RULES>
              Use local YARA rules instead of downloading YARA Forge
          --yara-release <YARA_RELEASE>
              YARA Forge release for the process scan (default: latest)
      -d, --source <DIR>
              Mounted Windows volume directory; repeat for additional volumes
          --volume <VOLUME>
              Select a live volume such as C:; repeat (default: all discovered fixed volumes)
          --vss
              Acquire live files from owned, crash-consistent VSS snapshots
          --vss-existing [<SELECTION>]
              Also collect existing snapshots: all, newest, newest N per volume, or a GUID
          --vss-timeout <SECONDS>
              VSS snapshot creation deadline in seconds
      -o, --output <DIR>
              Output parent directory; plan writes Plan.json here
          --vhdx [<FILE_OR_DIR>]
              Save to an NTFS VHDX; a directory (or no value: Kumade-Results beside the executable) names it by hostname and UTC start time
          --vhdx-size-gib <GIB>
              Virtual capacity in GiB (default: automatic, dynamically allocated)
          --e01 [<FILE_OR_DIR>]
              Save to compressed E01 segments; a directory (or no value: Kumade-Results beside the executable) names them by hostname and UTC start time
          --e01-size-gib <GIB>
              NTFS capacity in GiB before E01 compression (default: automatic)
          --no-live-info
              Skip the automatic live-response inventory (offline sources always skip it)
          --live-info-format <LIVE_INFO_FORMAT>
              Live-response inventory output format [default: csv] [possible values: csv, json, jsonl]
          --live-info-timeout <LIVE_INFO_TIMEOUT>
              Per-provider live-response deadline in seconds [default: 90]
          --computer <COMPUTER>
              Computer name for offline evidence
          --catalog <CATALOG>
              Explicit acquisition catalog; executable-directory configs are never auto-loaded
          --artifact <ID>
              Limit scope to an artifact ID; repeat to include several
          --profile-root <DIR>
              Additional local profile root under a selected source
      -T, --threads <THREADS>
              Maximum acquisition workers (default: available logical CPUs, at most 4) [default: 4]
          --reserve-mib <RESERVE_MIB>
              Keep this much destination space free (MiB) [default: 2048]
      -m, --memory
              Acquire physical RAM first with a separately supplied DumpIt toolkit
          --no-memory-pagefile
              Do not copy active pagefiles during RAM capture (default: copy)
          --dumpit <FILE_OR_DIR>
              DumpIt toolkit directory or executable (otherwise tools/DumpIt beside Kumade)
          --dumpit-sha256 <SHA256>
              Trust a different DumpIt release by its independently verified SHA-256
          --memory-timeout <MEMORY_TIMEOUT>
              RAM capture deadline in seconds [default: 1800]
          --memory-staging-dir <DIR>
              Explicit RAM staging parent (required with --memory and SFTP; prefer external storage)
      -q, --quiet
              Suppress progress and routine console messages
          --high-entropy
              Scan selected source drives for high-entropy PE candidates and collect them
          --entropy-threshold <ENTROPY_THRESHOLD>
              Entropy threshold in bits/byte (default: 7.2; range >0 through 8)
          --entropy-scope <ENTROPY_SCOPE>
              Candidate criterion (default: executable-sections) [possible values: file, executable-sections, either]
          --entropy-min-bytes <ENTROPY_MIN_BYTES>
              Minimum measured region size in bytes (default: 4096)
          --entropy-max-file-mib <ENTROPY_MAX_FILE_MIB>
              Optional size cap for entropy analysis; no default file-size limit
          --entropy-max-candidates <ENTROPY_MAX_CANDIDATES>
              Optional limit on additional binary files selected for collection
          --entropy-max-collect-mib <ENTROPY_MAX_COLLECT_MIB>
              Optional total MiB cap on additional binary collection
          --entropy-exclude <GLOB>
              Exclude a source-relative glob from entropy discovery; repeat as needed
          --entropy-coverage <ENTROPY_COVERAGE>
              Built-in extension list to open: standard (exe dll sys scr com cpl ocx xll drv pyd node), broad (adds wll ax acm tsp ime bpl efi) or comprehensive (adds bin dat tmp ini cfg png jpg cmd) [possible values: standard, broad, comprehensive]
          --entropy-extension <EXT>
              Also open files with this extension (case-insensitive, dot optional); repeat as needed
          --entropy-all-files
              Open every regular file instead of only the built-in extension list
          --sftp <HOST>
              Stream evidence to this SFTP host (no local payload copies)
          --sftp-user <SFTP_USER>
              Temporary upload-only account name
          --sftp-host-key <SFTP_HOST_KEY>
              Required pinned SSH host-key fingerprint, e.g. SHA256:... from the server administrator
          --sftp-port <SFTP_PORT>
              SFTP port (default: 22)
          --sftp-directory <SFTP_DIRECTORY>
              Pre-provisioned upload directory inside the server chroot (default: /incoming)
          --sftp-password-stdin
              Read the password from the first stdin line instead of a hidden terminal prompt
          --sftp-staging-dir <SFTP_STAGING_DIR>
              Parent for private metadata-only staging (default: system temporary directory)
          --sftp-timeout <SFTP_TIMEOUT>
              Per-operation network deadline in seconds (default: 60)
          --sftp-no-compression
              Disable gzip payload compression (sparse zero ranges will use network bandwidth)
      -v, --verbose
              List each file being copied instead of displaying a progress bar
      -h, --help
              Print help
    ```

[Download plain-text help](help/collect.txt).
