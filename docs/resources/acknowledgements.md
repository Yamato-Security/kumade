# Acknowledgements

Kumade is an independent Rust implementation. Reference work informs acquisition
coverage and validation; naming a reference does not imply that its code was
copied or that Kumade has demonstrated feature parity.

## Reference projects

- [Washizukami Collector](https://github.com/tadmaddad/Washizukami-Collector): Windows triage collection and deployment reference.
- [CDIR](https://github.com/CyberDefenseInstitute/CDIR): Windows first-response and raw acquisition reference.
- [triage-collector](https://github.com/herosi/triage-collector): expanded collection paths and memory/paging workflow reference.
- [Velociraptor](https://docs.velociraptor.app/): live-response artifact references; individual inventory definitions retain their source links.
- [libewf](https://github.com/libyal/libewf) and [Sleuth Kit](https://www.sleuthkit.org/): independent E01/filesystem validation tools.
- [ntfs-3g](https://github.com/tuxera/ntfs-3g): independent NTFS validation.

## Libraries, providers and ecosystem

- [Boreal](https://github.com/vthib/boreal) and [YARA Forge](https://yarahq.github.io/) provide the evaluator and optional rule-source ecosystem. Rules retain their original authors and licenses.
- [ntfs](https://github.com/ColinFinck/ntfs) supports read-only NTFS parsing.
- [Yamato Security's ys-e01-parser](https://github.com/Yamato-Security/ys-e01-parser) supplies native EWF functionality.
- [russh](https://github.com/Eugeny/russh) and [russh-sftp](https://github.com/AspectUnk/russh-sftp) supply SSH/SFTP protocol components.
- Microsoft documents the Windows/VSS APIs; externally supplied DumpIt remains a separately licensed provider and is not bundled.
- [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) powers this documentation, following the Hayabusa/Juntei site conventions.

The repository's [third-party notices](https://github.com/Yamato-Security/kumade/tree/main/THIRD_PARTY_NOTICES)
and [fixture provenance](https://github.com/Yamato-Security/kumade/blob/main/tests/fixtures/SOURCES.md)
record dependency and test-data terms. The [reference-tool comparison](../tool-comparison.md)
explains the original design research and reviewed revisions.
