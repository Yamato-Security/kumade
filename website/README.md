# Kumade documentation website

The English site uses Material for MkDocs, matching the Hayabusa/Juntei documentation.
The public URL is <https://yamato-security.github.io/kumade/>.

Existing guides in `docs/` remain canonical. `website/mkdocs.yml` supplies the
navigation and theme; no second copy of those guides is maintained. The build
hook adds the logo from `art/`, the changelog, acquisition catalogue and
live-inventory field reference directly from their versioned sources.

## Local preview

Use Python 3.11 or later; documentation CI uses Python 3.13.

```sh
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r website/requirements.txt
.venv-docs/bin/python -m mkdocs serve --config-file website/mkdocs.yml
```

On Windows use `.venv-docs\Scripts\python.exe` in place of `.venv-docs/bin/python`.
The preview URL includes the project prefix: <http://127.0.0.1:8000/kumade/>.

## Validate and build

```sh
python website/scripts/check_reference.py
python -m mkdocs build --strict --config-file website/mkdocs.yml
python website/scripts/check_site.py website/site
```

To refresh command help after CLI changes:

```sh
python website/scripts/generate_commands.py --binary target/release/kumade
```

The generator only invokes help/version commands. Do not run collections to build docs.
The generated help tracks the source revision used to build that binary; it is
not a claim that every download with the same version label has the same features.

GitHub Actions builds and checks the site for pull requests using a read-only
repository token. Only `main` can deploy to the `github-pages` environment;
deployment has separate Pages/OIDC permissions. All action references are pinned
to full commit hashes. The existing Pages setting must use **GitHub Actions**.

English is the only configured language. Add translations when they are ready;
there is no language selector advertising untranslated pages.
