# Direct SFTP evidence delivery

Kumade can stream collected files and raw NTFS streams directly to a dedicated
Linux OpenSSH evidence server. No local evidence-payload copy or container is
created. Compression is streaming gzip (fast level); sparse logical zero ranges
compress in transit. Memory is bounded per worker, rather than proportional to
file size. This mode is separate from VHDX/E01 output.

## Collector

Obtain a **new temporary account per acquisition** and the server's SHA-256 SSH
host-key fingerprint from the administrator over a trusted channel. Then run from
an elevated Windows terminal:

```powershell
.\kumade.exe collect --sftp evidence.example.org --sftp-user kuTEMPORARY `
  --sftp-host-key "SHA256:REPLACE_WITH_REAL_FINGERPRINT" `
  --sftp-staging-dir E:\Metadata --yes
```

Create the metadata staging parent directory first on a protected filesystem.
The password is prompted without echo. For automation, `--sftp-password-stdin`
reads only the first stdin line; supply it from your secret manager. There is no
password command-line option or password environment variable. Do not put secrets
in shell history, scripts, transcripts or collection catalogs. Password memory is
cleared on a best-effort basis, not guaranteed against a compromised OS.

Options: `--sftp-port` (22), `--sftp-directory` (`/incoming`),
`--sftp-timeout` (60 seconds per operation), `--sftp-no-compression`, and
`--sftp-staging-dir` (system temporary directory). Set `-T` for upload workers;
start with the conservative default, particularly on slow disks/networks.
All normal selection, VSS and live-info options still apply. `plan` does not upload.

Kumade verifies the pinned host key **before password authentication**. It creates
an isolated random probe and refuses collection unless reads, reopening/truncating
closed files, chmod, deletion, rename, hardlinks, symlinks and directory listing
are explicitly denied. The server must support SFTP v3 and `fsync@openssh.com`.
This probe is a useful policy check, not a proof that the server administrator or
kernel is trustworthy. A normal SFTP server will deliberately fail this check.

## Harden the server, not just the client

A leaked credential can be used with another SFTP client. `CREATE|EXCL` in Kumade
alone cannot prevent that client from destroying evidence.

On a **dedicated Linux OpenSSH server**, install `openssh-server`, Python 3 and
`acl`, create a root-owned `/srv/kumade`, then run:

```sh
sudo python3 scripts/sftp_account.py --base /srv/kumade --ttl-seconds 3600
```

To obtain the ED25519 host-key fingerprint (verify the key chosen by your SSH
service), run `sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256` on
the server. Deliver it through a trusted channel, separately from the password.

This creates a random account/password, a chroot and a root-owned incoming
directory with mode `1733`. It removes inherited/default ACLs and schedules a
persistent systemd timer to lock the account **and kill existing sessions**, with
a shadow-account expiry as a coarse backup. The timer survives a server reboot;
keep the server clock synchronized. The helper installs its expiry service/timer
under `/etc/systemd/system` and retains the locked account to avoid UID reuse.
Install the
printed `sshd-match.conf` as an SSH configuration fragment, validate with
`sudo sshd -t`, and reload SSH after reviewing it. The helper does not alter/reload
your running SSH configuration. Restrict network access to collectors; use
filesystem quotas and storage alerts on the server. Size the TTL for the case and
explicitly revoke the account as soon as the transfer completes.

The critical forced command is:

```text
internal-sftp -d /incoming -u 0777 -p open,close,write,fsync,realpath,limits
```

New files are writable through their initial open handle, but have mode `0000`
after creation. Once closed, the uploader cannot open them again. No default ACL
may grant access: **umask alone is insufficient on a directory with inherited
ACLs**. SFTP setstat/fsetstat, read, remove, rename, directory changes and link
operations are denied. The account has no shell, forwarding, PTY or alternate
SSH authentication path. Do not grant it local login, sudo, another service or
membership in a privileged group. Do not reuse the account or its UID while files
remain owned by that UID. Do not substitute Windows SFTP without equivalent
independently tested access controls.

A stolen credential can still upload garbage, exhaust the quota, or alter objects
through a handle that remains open. It cannot reopen completed objects under this
configuration. **Lock the account and terminate all its sessions before trusted
readback.** Root/server compromise remains outside this protection. A matching
password does not establish who collected evidence; retain the delivery digest
from the collector in your case notes over an independent trusted channel.

## Object layout, integrity and recovery

Remote object names are random case IDs plus opaque object IDs, not source paths.
Exclusive create is required; no retries that overwrite, resume or remote deletion
are attempted. An incremental fsynced journal maps source observations to objects.
The final `UUID-delivery.json` is written **last**, after all payload acknowledgements
and metadata sealing. A missing final delivery descriptor means an interrupted
transfer, even if some blobs exist. Retain those objects and the journal for manual
recovery; never assume an interrupted collection is complete.

For each completed object the delivery inventory records both compressed/stored
and original/logical byte counts and SHA-256 hashes. Acquisition records are
`Transferred`, with `Verified=false`. `PendingServerReadbackVerification` is
**not** an integrity verdict. Changed files, missing providers and acquisition
errors remain partial/failed, even after every uploaded byte verifies.

After revoking the account and ending sessions, on the trusted server run:

```sh
sudo python3 scripts/sftp_restore.py --incoming /srv/kumade/CASE/chroot/incoming \
  --delivery UUID-delivery.json --sha256 COLLECTOR_PRINTED_DELIVERY_SHA256 \
  --output /srv/restored/NEW-CASE --receipt /srv/receipts/NEW-CASE.json \
  --uploader-revoked
```

Create the trusted output/receipt parents first. Neither output nor receipt may
already exist. This standard-library verifier checks the operator-supplied
manifest hash, all stored and decompressed payload hashes, the sealed collection
metadata and the acquisition manifest. It restores ordinary files under the
computer/date directory layout in a **new** directory, rejecting path traversal,
symlinks, hardlinks, duplicate/conflicting paths and excess decoded lengths. It
never executes recovered content or applies source ACLs. All recovered content
must continue to be treated as untrusted evidence.

The receipt confirms server readback, separately from acquisition completeness.
A successful upload exits 0 only if acquisition did not report a partial state;
server verification is still required. `kumade verify` intentionally refuses a
remote delivery's metadata directory; use the trusted server receipt instead.

Named NTFS streams are exported into the disjoint `_KumadeStreams/<drive>/...`
namespace and retain `StreamName`/source mappings. They are not recreated as native
ADS. Source timestamps, identity and change-during-read are recorded in the
manifest. On Windows, the NTFS metadata inventory also records permissions/SDDL,
attributes and extended attributes where available; raw-only limitations remain
explicit. Restored file mtimes/ACLs are those of restoration, not the source: use
the inventories for forensic interpretation. Generic ADS exports may need mapping
for downstream tools that expect a particular acquisition layout.

## Forensic footprint and limits

Payloads are streamed without local staging, including locked-file raw NTFS
fallback. **Metadata is staged locally** in a private directory: plans, manifests,
seals, live inventory and optional entropy/YARA reports. These can be substantial
for a comprehensive entropy inventory. Prefer an external drive or a preconfigured
RAM-backed directory with sufficient capacity and access controls (NTFS on Windows;
FAT/exFAT staging is refused on Windows). They are removed only after the
final delivery acknowledges durability; failures retain metadata for recovery.
No silent fallback writes evidence payloads to the source disk.

Source reads may update access metadata, Windows can page process memory, optional
YARA downloads/cache writes and VSS snapshot copy-on-write consume local storage,
and the OS/AV can write independently. VSS is crash-consistent, not a coordinated
application snapshot. This does not promise zero writes or atomic live evidence.
Slow network backpressure can lengthen the time over which live data changes.
Use offline acquisition for stronger isolation when possible.

Deferred entropy scanning cannot read back the write-only uploaded files. It
re-reads source candidates; mismatches with the earlier streamed version are
reported as partial and `HashMatchesAnalysis=false`, rather than attributing a
later classification to earlier bytes. RAM capture is still unsupported in this
prototype; selecting it records a failed request, not a memory image.

References: [OpenSSH sftp-server](https://man.openbsd.org/sftp-server),
[sshd_config](https://man.openbsd.org/sshd_config),
[POSIX ACL creation semantics](https://man7.org/linux/man-pages/man5/acl.5.html).
