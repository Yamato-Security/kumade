# Build from source

The source requires Rust **1.99 or later**. Release/CI toolchains are pinned in
the repository workflows; build with the committed lockfile.

```sh
git clone https://github.com/Yamato-Security/kumade.git
cd kumade
cargo build --release --locked
```

On Windows the result is `target\release\kumade.exe`. Native MSVC builds need
the Windows C++ build tools for the small native VSS component. The Windows
release packages link the C runtime statically; Windows system DLLs remain required.

## Match the collection architecture

Use native x64 for x64 Windows and native ARM64 for ARM64 Windows. A successfully
cross-built binary has not necessarily been runtime-tested on that platform.
An x86 CI test through WOW64 is not qualification of live acquisition on a native
32-bit Windows installation. See the [validation history](../testing.md).

Linux/macOS source builds support applicable offline/receiver tooling; the
published collector packages are Windows packages. Native Windows features are
not made available by building on another operating system.

For development checks, see [development](../resources/development.md).
