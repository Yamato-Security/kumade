# Built-in upload-only SFTP receiver

Run Kumade on the evidence server as well as the Windows computer being collected.
The receiver is part of the same executable: no OpenSSH installation, operating
system upload account, Python runtime, administrator account or filesystem mount
is required. Firewall policy may require administrator help. Store evidence on a
trusted filesystem with persistent access controls (NTFS on Windows).

## Start a receiver

```powershell
.\kumade.exe receive --listen 0.0.0.0:2222 --output D:\Evidence --expires 2h
```

The default bind address is `127.0.0.1:2222`. Select an explicit network interface
or `0.0.0.0` to accept remote connections, and allow the chosen port through your
firewall. Use `--allow-ip 192.0.2.20` to restrict the exact collector IP; repeat the
option for several addresses. On dual-stack listeners such as `[::]:2222`, IPv4
addresses and their IPv4-mapped IPv6 representations match the same allowlist entry;
native IPv6 addresses remain distinct. The default is one collection.

### Collect from several computers

```powershell
.\kumade.exe receive --listen 0.0.0.0:2222 --output D:\Evidence --sources 6 --expires 4h
```

The receiver prints six numbered credential pairs. Distribute one pair per
computer along with the common server address, port and fingerprint. Each
collector uses the standard command below. Sources can start and finish in
any order. Under the receiver directory, `source-01` through `source-06` each
contain their own `Receiver.json`, `incoming` directory and verification result.
The single-source default retains the existing directory layout.

Each source's credentials expire when it finishes or reaches the deadline.
Another source can still upload while a completed collection is being verified.
Choose the expected number of sources (1–64). The receiver waits for all
requested sources until completion, expiry or Ctrl+C. An unused source is
recorded as incomplete. If more than eight collectors will connect at once,
raise `--max-connections` to accommodate them (maximum 64).

Kumade displays a temporary username, a cryptographically random password, an SSH
host-key fingerprint and the new evidence directory. Transfer those details to
the collector over a trusted channel. **The generated password is displayed once
on the server console**; do not publish that console output or capture it in
shared logs. It is not written to `Receiver.json`. No real OS account is created.
Host keys and credential hashes are ephemeral: restarting generates new credentials
and a new fingerprint, and never reopens an old evidence session.

On the Windows computer being collected:

```powershell
.\kumade.exe collect --sftp SERVER_ADDRESS --sftp-port 2222 `
  --sftp-user GENERATED_USERNAME --sftp-host-key "SHA256:SERVER_FINGERPRINT" `
  --sftp-staging-dir E:\Metadata --no-wizard
```

Create the metadata staging parent first. The password prompt does not echo.
The same streaming, source-change checks, raw NTFS locked-file reads and
metadata-only local staging described in [SFTP delivery](SFTP.md) apply.

## If the connection drops

With updated Kumade binaries at both ends, the collector reconnects automatically.
The default is three attempts in total across the running collection. Set
`collect --sftp-retries 10` for a less reliable link, or `--sftp-retries 0` to
disable retries. The collector checks the pinned host key again on reconnect.
The receiver reports how many bytes it already accepted for each interrupted
object. The collector can send the remaining bytes from its buffered writes
and continue reading the same stream, including compressed or raw NTFS data.

Both processes must stay running and the credential must still be valid.
Restarting either program requires a fresh acquisition. Plain OpenSSH and older
Kumade receivers support the existing one-connection transfer. If the network
fails just as the final delivery closes, the receiver may already have revoked
the credential. The collector reports the expected delivery name and SHA-256 if
it lost the final acknowledgement. Compare them with that source's
`ReadbackReceipt.json` before starting over. An incomplete source has no
successful receipt.

## What the receiver permits

The SFTP endpoint is a small virtual namespace, `/incoming`. Remote names must be
flat, bounded ASCII object IDs belonging to the first collection ID. Remote paths
are never used as arbitrary local filesystem paths. Files are created exclusively.
The receiver accepts new objects, writes **at the next sequential offset**,
fsync and close. Reattaching to an in-progress object also requires its random
per-object secret, held in collector memory. Reattachment invalidates the old
write handle. A sealed object stays immutable. The receiver denies reading,
listing, truncating, overwriting earlier bytes, deleting, renaming, chmod and
link creation. SSH shells, commands and forwarding are unavailable. Local files
remain readable by the trusted receiver for independent hash verification; this
does not grant network clients read access.

Upload permissions are enforced by Kumade itself on Windows and Linux. They do
not depend on an OpenSSH umask or giving an uploader ownership of OS files.
The collector still probes the policy before collecting evidence. Possession of
the upload credential does not grant a Windows/Linux login.

The credential is revoked when the final delivery object closes, the monotonic
expiry deadline passes, or the operator presses Ctrl+C. Established sessions are
also disconnected. No later network operation can pass the revocation check.
A delivery cannot finalize while any other upload handle remains open. Incomplete
uploads are retained; expired/interrupted cases have `ReceiverInterrupted.json`
and no successful readback receipt. Files are never deleted as part of recovery.

A leaked credential can still submit garbage or exhaust its allotted resources;
it cannot prove collector identity. Use a new credential per case, limit network
exposure and compare the final **Delivery SHA256** printed by both computers over
an independent channel. Server administrator/kernel compromise is outside this
protection.

## Limits and server resource use

- `--expires 2h`: seconds or an `s`, `m` or `h` suffix; maximum seven days.
- `--max-gib 100`: maximum stored/compressed upload bytes per source.
- `--max-files 100000`: maximum objects per source, including journals and probes.
- `--reserve-mib 2048`: keep this much destination disk space free.
- `--max-connections 8`: bound SSH connections, including unauthenticated ones.
- `--max-decoded-gib 1024`: bound logical data processed during verification of each source.

There are also bounded protocol packets and open handles, a handshake deadline,
three authentication attempts per connection, and a ten-failures-per-minute
authentication throttle per known credential. Failed authentications do not log passwords. Large files
stream through bounded buffers, but manifests/inventories use memory proportional
to object count. Individual JSON metadata documents are limited to 128 MiB; each
acquisition-manifest record to 1 MiB. Readback has a one-hour deadline. Choose limits
appropriate to the case and the receiver's resources.

## Independent readback and restoration

After the final delivery, the receiver freezes network writes, revokes credentials
and re-reads every object from disk. It checks the stored and decoded SHA-256
hashes, collection seals, record inventory and summary counters. Gzip decoding is
bounded by declared lengths and the configured total decoded quota. Corruption,
missing/unlisted objects, malformed paths and inconsistent records prevent a
successful `ReadbackReceipt.json`.

The receipt's `PayloadHashesVerified` describes server readback. `AcquisitionState`
remains `Partial` for partial collections; a successful pending collection becomes
`CompleteWithinSelectedPrototypeScope`. `CollectorAcquisitionState` retains the
original sender state. Verification does not establish source authenticity,
atomic acquisition or structural validity of each forensic artifact.

Received objects remain in their original uploaded form. Automatic verification
does **not** create a second full evidence copy. To reconstruct ordinary drive
folders without Python, run:

```powershell
.\kumade.exe verify-delivery --incoming D:\Evidence\SESSION\incoming `
  --delivery UUID-delivery.json --sha256 COLLECTOR_PRINTED_SHA256 `
  --receipt D:\Evidence\RestoredReceipt.json --restore D:\Evidence\RestoredCase `
  --uploader-revoked
```

The receipt file and restore directory must be new and outside `incoming`.
Restoration needs extra server disk space. Corrupt/incomplete restoration results
are retained for examination but do not get a successful receipt. Files are
restored with access controls and sparse zero handling; nothing is executed.
Original timestamps/ACLs remain in the inventories and are not applied by this
export. Named streams remain under `_KumadeStreams`; they are not native ADS.
Treat all recovered content as untrusted evidence.

For a standalone Linux OpenSSH destination instead, see [SFTP delivery](SFTP.md).
