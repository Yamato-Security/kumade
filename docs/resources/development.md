# Development

[Build from source](../getting-started/build.md) with the committed lockfile.
Useful checks include:

```sh
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Native Windows/VSS/container tests have additional requirements; follow the
repository's [CI](https://github.com/Yamato-Security/kumade/blob/main/.github/workflows/ci.yml)
and [validation history](../testing.md). Do not substitute private payloads for
redistributable fixtures in a public PR.

## Maintain the docs

Source guides live in `docs/`. Navigation/theme/build tooling lives in `website/`.
The site generates catalogue, inventory-field, logo and changelog content from
canonical source files. Command help can be refreshed from a matching binary:

```sh
python website/scripts/generate_commands.py --binary target/release/kumade
python website/scripts/check_reference.py
python -m mkdocs build --strict --config-file website/mkdocs.yml
python website/scripts/check_site.py website/site
```

See [website maintenance instructions](https://github.com/Yamato-Security/kumade/blob/main/website/README.md).
Pull requests build without deployment credentials. The `main` branch deploys
the validated HTML through GitHub Pages.

## Current implementation and future design

The [architecture document](../architecture.md) is a proposal, not a list of
implemented features. [Implementation status](../implementation-status.md)
separates the two. Proposed providers, cloud destinations or resume semantics
must not be advertised as working until implemented and qualified.
