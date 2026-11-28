---
hide:
  - toc
---

# Kumade

<div class="km-hero" markdown>

![Kumade — Windows triage collector](assets/kumade-golden-waves.png){ .km-hero-art width="1254" height="1254" }

<p class="tagline"><strong>Windows evidence collection by Yamato Security.</strong><br>
Collect forensic artifacts, preserve live-response context, and deliver evidence
for investigation with Hayabusa, Takajo and Juntei.</p>

<div class="km-cta" markdown>
[Get started](getting-started/index.md){ .md-button .md-button--primary }
[Command reference](commands/index.md){ .md-button }
[Benchmarks](benchmarks/index.md){ .md-button }
[Compare collectors](tool-comparison.md){ .md-button }
</div>

</div>

## Start with the evidence you need

<div class="grid cards" markdown>

-   :material-folder-search:{ .lg .middle } __Artifact collection__

    ---

    Collect the shipped artifact families across selected volumes and profiles,
    including supported locked files and NTFS metadata.

    [Browse the catalogue](collection/catalogue.md)

-   :material-access-point-network:{ .lg .middle } __Live response__

    ---

    Preserve running processes, network connections, DNS cache, accounts,
    services, security settings and regional configuration.

    [Explore live inventory](live-info.md)

-   :material-memory:{ .lg .middle } __RAM and pagefiles__

    ---

    Opt into an external DumpIt provider, acquire RAM first, and capture active
    pagefiles alongside it.

    [Capture memory](memory-acquisition.md)

-   :material-package-variant-closed:{ .lg .middle } __Local and remote output__

    ---

    Save to a directory, NTFS VHDX or compressed E01. Send evidence remotely
    with SFTP or use Amazon S3 for resumable hybrid delivery.

    [Choose an output](output/index.md)

-   :material-radar:{ .lg .middle } __Optional hunting__

    ---

    Scan live process memory with YARA Forge, or discover and collect
    high-entropy PE binaries for investigation.

    [Compare the scans](getting-started/choose-options.md)

-   :material-shield-check:{ .lg .middle } __Verify and review__

    ---

    Check stored hashes and metadata seals, then review partial, failed,
    absent and excluded evidence explicitly.

    [Understand verification](output/verification.md)

</div>

## A practical first collection

From an elevated Windows PowerShell terminal, with an evidence destination on `E:`:

```powershell
.\kumade.exe check-support --check
.\kumade.exe collect -o E:\Evidence
```

The second command opens the collection wizard. For unattended collection with
feature defaults, use `collect --no-wizard -o E:\Evidence`. RAM, VSS, entropy and
YARA are opt-in. See the [first-collection guide](getting-started/first-collection.md).

Kumade is in active development under **RPL-1.5**. This documentation tracks
`main`; check your binary's help and release notes when a feature is missing.
Hash verification establishes stored-byte integrity, not complete coverage,
an atomic snapshot or the structural validity of every artifact.
