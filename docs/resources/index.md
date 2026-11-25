# Further reading

## Yamato Security analysis tools

- [Hayabusa documentation](https://yamato-security.github.io/hayabusa/): Windows event-log detection and DFIR timelines.
- [Juntei documentation](https://yamato-security.github.io/juntei/): Windows artifact parsing and interpretation.
- [Takajo](https://github.com/Yamato-Security/takajo): post-analysis of Hayabusa JSONL timelines.

## Collection and verification

- [Microsoft Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service): snapshots and writers.
- [Microsoft NTFS overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview): filesystem capabilities and context.
- [Microsoft complete memory dumps](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/complete-memory-dump): dump format and scope.
- [MemProcFS](https://github.com/ufrisk/MemProcFS): memory analysis and paging-file input.
- [YARA Forge](https://yarahq.github.io/): rule packs and selection guidance.
- [Boreal](https://github.com/vthib/boreal): the Rust YARA evaluator used by Kumade.
- [OpenSSH SFTP server manual](https://man.openbsd.org/sftp-server): server-side operations and policy.

Each collection guide includes feature-specific references. For source maintenance,
see [development](development.md). For issues, use the
[Kumade issue tracker](https://github.com/Yamato-Security/kumade/issues) with
private data and credentials removed.
