# Install Kumade

## Download the native Windows package

Get the executable and `SHA256SUMS.txt` from the
[official release page](https://github.com/Yamato-Security/kumade/releases/latest).

| Computer | Package name |
|---|---|
| 64-bit Intel/AMD Windows | `win-x64` |
| ARM64 Windows | `win-aarch64` |
| 32-bit Windows | `win-x86` |

Each platform has a standalone `.exe` and a ZIP containing only that executable.
`LICENSES.txt` is a separate release asset. Choose the architecture of the
computer being collected; emulation is not a substitute for native acquisition.
Native 32-bit live acquisition and older Windows versions require further
qualification even when a package builds successfully.

Check the downloaded file against its entry in `SHA256SUMS.txt`:

```powershell
Get-FileHash .\kumade-0.1.0-win-x64.exe -Algorithm SHA256
```

Rename your executable to `kumade.exe` for the examples in this site.
No Python or .NET runtime installation is required for the collector itself.
The optional RAM provider is separate; follow [RAM setup](../memory-acquisition.md).

## Check the binary before collecting

Open PowerShell as Administrator for live/raw acquisition:

```powershell
.\kumade.exe --version
.\kumade.exe doctor --check
.\kumade.exe collect --help
```

This site describes the current `main` branch. A published release with the
same version label may predate recent features. The v0.1.0 release packages
predate S3. For S3 collection, use a Windows artifact from a matching
[Release packages run](https://github.com/Yamato-Security/kumade/actions/workflows/release.yml)
or [build the matching source](build.md). Check that `collect --help` lists `--s3`.

Continue with [your first collection](first-collection.md).
