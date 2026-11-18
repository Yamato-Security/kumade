# Dependency license notices

`crates.txt` contains the license texts for runtime Rust dependencies from
`Cargo.lock`, including platform-specific dependencies. Release archives include
this file alongside Kumade's `LICENSE` and `COPYRIGHT`.

To regenerate with `cargo-about 0.9.3`:

```bash
cargo fetch --locked
cargo about generate --frozen --fail -c THIRD_PARTY_NOTICES/about.toml THIRD_PARTY_NOTICES/about.hbs -o THIRD_PARTY_NOTICES/crates.txt
```

The synthetic NTFS fixture is not part of the release binaries. Its notices and
provenance are in `tests/fixtures/`.
