# Live-response inventory

Kumade captures live Windows system state **before copying artifact files**, using 50 independent read-only providers. It runs automatically for live collection and is stored inside the directory, VHDX or E01 collection under `LiveInfo/`. Offline `--source` collections do not query the analyst's machine. `plan` never queries live inventory.

```powershell
# Full collection: CSV live inventory is included by default
.\kumade.exe -o E:\Evidence
.\kumade.exe --e01 E:\Evidence\HOST01.e01 --live-info-format jsonl
.\kumade.exe --vhdx E:\Evidence\HOST01.vhdx --live-info-format json

# Inventory only; output must be a new directory
.\kumade.exe live-info -o E:\Evidence\HOST01-LiveInfo -t csv
.\kumade.exe live-info -o E:\Evidence\HOST01-Json -t json
.\kumade.exe live-info -o E:\Evidence\HOST01-Jsonl -t jsonl -T 2 --timeout 90

# A restricted inventory; repeat --dataset to select providers
.\kumade.exe live-info -o E:\Evidence\Network --dataset TcpConnections --dataset Processes

# Explicitly omit live inventory from a live artifact collection
.\kumade.exe -o E:\Evidence --no-live-info

# Verify inventory-only output, or a complete directory collection
.\kumade.exe verify E:\Evidence\HOST01-LiveInfo
```

`--artifact` filters the file-acquisition catalog. The live inventory is a separate scope: use `--no-live-info` to disable it, or `live-info --dataset` for selected live data sets. Collection uses at most two inventory workers; inventory-only `-T` accepts 1–8. The default per-provider deadline is 90 seconds (`--timeout` or collection's `--live-info-timeout`, 1–3600 seconds).

## Requirements and behavior

Live inventory requires Windows with built-in Windows PowerShell, normally 5.1 on Windows 10/11. There is no Velociraptor, Python or external collector dependency. PowerShell is resolved through the Windows directory API, uses the native system executable even from a 32-bit collector, loads no profile, and restricts module discovery to built-in PowerShell modules. Only embedded queries are executed. Existing group policy, application control and security products may restrict those queries; the manifest preserves the result.

Elevated collection gives more complete process, Defender, servicing-package, SMB, local-account and security data. Missing optional cmdlets/providers are recorded as `Unsupported`; access-denied and other query errors are failures. A missing PowerShell executable produces failed provider entries during ordinary file collection, allowing file acquisition to proceed as partial.

No commands recovered from the host are executed. Queries do not install patches, change security settings, load unloaded user hives, export certificate private keys or enumerate every account in a trusted AD forest. Installed-software inventory reads uninstall keys and Appx packages; it never uses `Win32_Product`, which can trigger Windows Installer consistency checks and repairs.

## Files, fields and integrity

Each provider writes one CSV, JSON array or JSONL file. All exported field names use PascalCase. Every row includes:

| Field | Meaning |
|---|---|
| `Computer` | The computer queried, obtained inside the provider process. |
| `CollectedUtc` | UTC observation time for that row, RFC 3339 with fractional seconds. |
| `Provider` | The embedded provider name. |

Provider-specific timestamps ending in `Utc` are converted to UTC. Some source fields, such as the uninstall registry's `InstallDate` and QFE's `InstalledOn`, are retained as source date strings because they do not establish an exact UTC instant. CSV represents null as an empty cell and arrays/objects as JSON text in one cell. JSON/JSONL preserve nulls, arrays, objects, numbers and booleans. A blank/null property does not prove the underlying information does not exist: OS versions and access restrictions can affect individual fields.

`LiveInfo/Manifest.json` and `Manifest.csv` describe every requested provider, including zero-row results, with start/end UTC times, elapsed seconds, row count, relative output path, size, SHA-256 and diagnostic message. Statuses are:

- `Success`: the provider emitted rows and its completion marker/count matched.
- `Empty`: a completed query returned zero rows.
- `Unsupported`: a command, namespace or class is unavailable.
- `Failed`: execution or parsing failed without usable rows.
- `TimedOut` / `OutputLimit`: a deadline or bounded output was exceeded without usable rows.
- `Partial`: valid preceding rows were retained but the provider subsequently failed, exceeded a limit or did not finish. The message records the cause.

Each provider has a 32 MiB stdout limit, a 64 KiB stderr limit and a 100,000-row limit. Partial JSON lines are never accepted as observations. Worker counts bound simultaneous process and output-buffer usage; each PowerShell process also has its own memory overhead. Destination reserves are checked before each provider writes. Container output also checks physical host reserves. Inventory is bounded but is not a zero-impact snapshot.

Optional unsupported features remain visible in the manifest without forcing partial status when the applicable providers complete. Missing required host/OS/process/IP providers, all providers unsupported, failed queries and partial results make inventory incomplete. This contributes to `LiveInfoFailedProviders` in `Summary.json` and acquisition exit code 3. The inventory-only command also returns 3 when incomplete.

`LiveInfo/Seal.json` hashes every inventory table and both manifests. Ordinary collections additionally include all inventory files and that seal in their outer `Seal.json`. `kumade verify` checks both layers, including incomplete-provider counts. These are integrity hashes, not a digital signature or proof of complete acquisition. Files in an E01/VHDX can be verified after exposing the internal collection read-only.

## Interpretation and limitations

- Queries are not atomic. Use the per-row and per-provider times when correlating them. Processes and connections can change during collection; closed connections and terminated processes may be absent.
- TCP and UDP rows include best-effort process context joined by PID from a nearby process snapshot. PID reuse can misattribute that context; compare process creation times and other evidence. This is not a historical connection timeline or packet capture. UDP rows describe bound endpoints, not their remote peers.
- Process owners, executable paths and command lines can be unavailable for protected/exited processes. Command lines and configuration fields may contain credentials or other sensitive operational data; output directories receive Kumade's existing access protection.
- Local accounts are queried with `LocalAccount=True`. Group and logon association reference strings let analysts join identities; domain group membership nesting and effective AD privileges are not resolved.
- Software uninstall inventories include machine 64/32-bit views and **loaded** user hives. Appx packages are a separate table. Portable applications, unloaded profiles and removed packages may be absent. Hotfix/QFE and servicing package tables represent different inventories, not a guarantee that every vulnerability is patched.
- Defender and Security Center availability differs on servers and systems using third-party protection. A missing provider is not evidence that antivirus was disabled.
- Firewall rules and their port/application/address filters are separate tables. Preserve their instance identifiers when correlating them; this is configuration inventory, not proof that traffic was allowed or blocked.
- PowerShell/CIM queries create their own processes, log activity and system load. Capture times and the collector's own command lines can appear in the results. File acquisition follows inventory, so it may collect those new logs too.
- This feature does not add memory acquisition, process dumps, handle enumeration, packet capture, historical deleted-state recovery or automated maliciousness verdicts.

## Provider catalog

The following field lists omit the three common provenance fields above.

### HostInfo

`HostInfo.<csv|json|jsonl>`: `Name`, `Domain`, `PartOfDomain`, `Workgroup`, `Manufacturer`, `Model`, `SystemType`, `NumberOfLogicalProcessors`, `TotalPhysicalMemory`, `UserName`, `DomainRole`.

### OperatingSystem

`OperatingSystem.<csv|json|jsonl>`: `Caption`, `Version`, `BuildNumber`, `OsArchitecture`, `SerialNumber`, `SystemDirectory`, `WindowsDirectory`, `SystemDrive`, `CountryCode`, `Locale`, `InstallTimeUtc`, `BootTimeUtc`, `LocalTimeUtc`, `UptimeSeconds`, `ProductType`, `ServicePackMajorVersion`, `ServicePackMinorVersion`.

### OsBuild

`OsBuild.<csv|json|jsonl>`: `ProductName`, `DisplayVersion`, `ReleaseId`, `CurrentBuildNumber`, `Ubr`, `BuildLabEx`, `EditionId`, `InstallationType`, `InstallTimeUtc`.

### TimeZone

`TimeZone.<csv|json|jsonl>`: `Id`, `DisplayName`, `StandardName`, `DaylightName`, `BaseUtcOffsetMinutes`, `CurrentUtcOffsetMinutes`, `SupportsDaylightSavingTime`, `IsDaylightSavingTime`.

### Bios

`Bios.<csv|json|jsonl>`: `Manufacturer`, `Name`, `SerialNumber`, `SmbiosBiosVersion`, `Version`, `ReleaseTimeUtc`.

### Hotfixes

`Hotfixes.<csv|json|jsonl>`: `HotfixId`, `Description`, `Caption`, `InstalledBy`, `InstalledOn`.

### NetworkAdapters

`NetworkAdapters.<csv|json|jsonl>`: `DeviceId`, `Name`, `Description`, `NetConnectionId`, `NetConnectionStatus`, `AdapterType`, `MacAddress`, `Manufacturer`, `PhysicalAdapter`, `Speed`, `ServiceName`, `Guid`.

### IpConfiguration

`IpConfiguration.<csv|json|jsonl>`: `Index`, `Description`, `SettingID`, `MacAddress`, `IPEnabled`, `IpAddress`, `IpSubnet`, `DefaultIPGateway`, `DhcpEnabled`, `DhcpServer`, `DnsDomain`, `DnsHostName`, `DnsServerSearchOrder`, `DnsDomainSuffixSearchOrder`, `WinsPrimaryServer`, `WinsSecondaryServer`, `DhcpLeaseObtainedUtc`, `DhcpLeaseExpiresUtc`.

### IpAddresses

`IpAddresses.<csv|json|jsonl>`: `InterfaceIndex`, `InterfaceAlias`, `AddressFamily`, `IpAddress`, `PrefixLength`, `PrefixOrigin`, `SuffixOrigin`, `AddressState`, `SkipAsSource`.

### Routes

`Routes.<csv|json|jsonl>`: `InterfaceIndex`, `InterfaceAlias`, `AddressFamily`, `DestinationPrefix`, `NextHop`, `RouteMetric`, `InterfaceMetric`, `Protocol`, `State`, `Publish`.

### Neighbors

`Neighbors.<csv|json|jsonl>`: `InterfaceIndex`, `InterfaceAlias`, `IpAddress`, `LinkLayerAddress`, `AddressFamily`, `State`.

### DnsCache

`DnsCache.<csv|json|jsonl>`: `Entry`, `RecordName`, `RecordType`, `Status`, `Section`, `TimeToLive`, `Data`.

### NetworkProfiles

`NetworkProfiles.<csv|json|jsonl>`: `Name`, `InterfaceAlias`, `InterfaceIndex`, `NetworkCategory`, `Ipv4Connectivity`, `Ipv6Connectivity`.

### FirewallProfiles

`FirewallProfiles.<csv|json|jsonl>`: `Name`, `Enabled`, `DefaultInboundAction`, `DefaultOutboundAction`, `AllowInboundRules`, `AllowLocalFirewallRules`, `AllowLocalIPsecRules`, `LogAllowed`, `LogBlocked`, `LogFileName`.

### FirewallRules

`FirewallRules.<csv|json|jsonl>`: `Name`, `DisplayName`, `Description`, `Enabled`, `Direction`, `Action`, `Profile`, `Owner`, `PolicyStoreSourceType`, `PolicyStoreSource`, `PrimaryStatus`, `Status`.

### SmbSessions

`SmbSessions.<csv|json|jsonl>`: `SessionId`, `ClientComputerName`, `ClientUserName`, `NumOpens`, `Dialect`, `SecondsExists`, `SecondsIdle`, `Signed`, `Encrypted`.

### SmbConnections

`SmbConnections.<csv|json|jsonl>`: `ServerName`, `ShareName`, `UserName`, `Credential`, `Dialect`, `NumOpens`, `Signed`, `Encrypted`.

### SmbOpenFiles

`SmbOpenFiles.<csv|json|jsonl>`: `FileId`, `SessionId`, `Path`, `ShareRelativePath`, `ClientComputerName`, `ClientUserName`.

### Processes

`Processes.<csv|json|jsonl>`: `ProcessId`, `ParentProcessId`, `Name`, `ExecutablePath`, `CommandLine`, `SessionId`, `HandleCount`, `ThreadCount`, `WorkingSetSize`, `PrivatePageCount`, `VirtualSize`, `CreationTimeUtc`, `Owner`.

### TcpConnections

`TcpConnections.<csv|json|jsonl>`: `LocalAddress`, `LocalPort`, `RemoteAddress`, `RemotePort`, `State`, `OwningProcess`, `AppliedSetting`, `OffloadState`, `ProcessName`, `ExecutablePath`, `CommandLine`, `ProcessCreationTimeUtc`, `ProcessOwner`.

### UdpEndpoints

`UdpEndpoints.<csv|json|jsonl>`: `LocalAddress`, `LocalPort`, `OwningProcess`, `ProcessName`, `ExecutablePath`, `CommandLine`, `ProcessCreationTimeUtc`, `ProcessOwner`.

### LocalUsers

`LocalUsers.<csv|json|jsonl>`: `Name`, `Domain`, `Sid`, `FullName`, `Description`, `Disabled`, `Lockout`, `PasswordRequired`, `PasswordChangeable`, `PasswordExpires`, `Status`.

### LocalGroups

`LocalGroups.<csv|json|jsonl>`: `Name`, `Domain`, `Sid`, `Description`, `Status`.

### GroupMemberships

`GroupMemberships.<csv|json|jsonl>`: `GroupComponent`, `PartComponent`.

### UserProfiles

`UserProfiles.<csv|json|jsonl>`: `Sid`, `LocalPath`, `Loaded`, `Special`, `Status`, `LastUseTimeUtc`.

### LogonSessions

`LogonSessions.<csv|json|jsonl>`: `LogonId`, `LogonType`, `AuthenticationPackage`, `StartTimeUtc`.

### LogonAssociations

`LogonAssociations.<csv|json|jsonl>`: `Antecedent`, `Dependent`.

### Services

`Services.<csv|json|jsonl>`: `Name`, `DisplayName`, `Description`, `State`, `StartMode`, `StartName`, `ProcessId`, `PathName`, `ServiceType`, `ExitCode`, `Started`, `AcceptPause`, `AcceptStop`.

### Drivers

`Drivers.<csv|json|jsonl>`: `Name`, `DisplayName`, `State`, `StartMode`, `StartName`, `PathName`, `ServiceType`.

### StartupCommands

`StartupCommands.<csv|json|jsonl>`: `Name`, `Command`, `Location`, `User`, `UserSid`.

### Shares

`Shares.<csv|json|jsonl>`: `Name`, `Path`, `Description`, `Type`, `Status`, `AllowMaximum`, `MaximumAllowed`.

### LogicalDisks

`LogicalDisks.<csv|json|jsonl>`: `DeviceId`, `VolumeName`, `VolumeSerialNumber`, `FileSystem`, `DriveType`, `Size`, `FreeSpace`, `ProviderName`.

### Disks

`Disks.<csv|json|jsonl>`: `Index`, `DeviceId`, `Model`, `Manufacturer`, `SerialNumber`, `FirmwareRevision`, `InterfaceType`, `MediaType`, `Size`, `Partitions`, `PnpDeviceId`, `Status`.

### InstalledSoftware

`InstalledSoftware.<csv|json|jsonl>`: `Scope`, `RegistryPath`, `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`, `InstallLocation`, `InstallSource`, `UninstallString`, `QuietUninstallString`, `SystemComponent`, `WindowsInstaller`, `EstimatedSize`.

### Autoruns

`Autoruns.<csv|json|jsonl>`: `RegistryPath`, `ValueName`, `Command`.

### ScheduledTasks

`ScheduledTasks.<csv|json|jsonl>`: `TaskName`, `TaskPath`, `State`, `Description`, `Author`, `UserId`, `LogonType`, `RunLevel`, `Actions`, `Triggers`, `LastRunTimeUtc`, `NextRunTimeUtc`, `LastTaskResult`, `NumberOfMissedRuns`.

### WmiEventFilters

`WmiEventFilters.<csv|json|jsonl>`: `Name`, `EventNamespace`, `QueryLanguage`, `Query`, `CreatorSID`.

### WmiEventConsumers

`WmiEventConsumers.<csv|json|jsonl>`: `Name`, `CreatorSID`, `CommandLineTemplate`, `ExecutablePath`, `ScriptingEngine`, `ScriptText`.

### WmiBindings

`WmiBindings.<csv|json|jsonl>`: `Filter`, `Consumer`, `DeliverSynchronously`, `DeliveryQoS`, `MaintainSecurityContext`.

### DefenderStatus

`DefenderStatus.<csv|json|jsonl>`: `AmServiceEnabled`, `AntivirusEnabled`, `AntispywareEnabled`, `RealTimeProtectionEnabled`, `BehaviorMonitorEnabled`, `IoavProtectionEnabled`, `NisEnabled`, `IsTamperProtected`, `AmProductVersion`, `AmEngineVersion`, `AntivirusSignatureVersion`, `AntivirusSignatureLastUpdatedUtc`, `QuickScanEndTimeUtc`, `FullScanEndTimeUtc`.

### SecurityProducts

`SecurityProducts.<csv|json|jsonl>`: `DisplayName`, `InstanceGuid`, `PathToSignedProductExe`, `PathToSignedReportingExe`, `ProductState`, `Timestamp`.

### ProxySettings

`ProxySettings.<csv|json|jsonl>`: `RegistryPath`, `ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigUrl`.

### DefenderPreferences

`DefenderPreferences.<csv|json|jsonl>`: `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableIoavProtection`, `DisableScriptScanning`, `DisableArchiveScanning`, `PuaProtection`, `ExclusionPath`, `ExclusionProcess`, `ExclusionExtension`, `MapsReporting`, `SubmitSamplesConsent`.

### SharePermissions

`SharePermissions.<csv|json|jsonl>`: `ShareName`, `AccountName`, `AccessControlType`, `AccessRight`.

### Certificates

`Certificates.<csv|json|jsonl>`: `Store`, `Subject`, `Issuer`, `Thumbprint`, `SerialNumber`, `NotBeforeUtc`, `NotAfterUtc`, `HasPrivateKey`, `DnsNames`.

### AppxPackages

`AppxPackages.<csv|json|jsonl>`: `Name`, `PackageFullName`, `PackageFamilyName`, `Version`, `Publisher`, `InstallLocation`, `Architecture`, `SignatureKind`, `Status`, `NonRemovable`, `IsFramework`.

### WindowsPackages

`WindowsPackages.<csv|json|jsonl>`: `PackageName`, `PackageState`, `ReleaseType`, `InstallTimeUtc`.

### FirewallPortFilters

`FirewallPortFilters.<csv|json|jsonl>`: `InstanceId`, `Protocol`, `LocalPort`, `RemotePort`, `IcmpType`, `DynamicTarget`.

### FirewallApplicationFilters

`FirewallApplicationFilters.<csv|json|jsonl>`: `InstanceId`, `Program`, `Package`.

### FirewallAddressFilters

`FirewallAddressFilters.<csv|json|jsonl>`: `InstanceId`, `LocalAddress`, `RemoteAddress`.

## Reference coverage

Coverage was informed by Velociraptor’s public Windows artifact catalog. Queries and exporters here are independently implemented using built-in Windows interfaces; no Velociraptor executable or VQL plugin is bundled.

- https://docs.velociraptor.app/artifact_references/pages/windows.network.arpcache/
- https://docs.velociraptor.app/artifact_references/pages/windows.network.netstat/
- https://docs.velociraptor.app/artifact_references/pages/windows.network.netstatenriched/
- https://docs.velociraptor.app/artifact_references/pages/windows.persistence.permanentwmievents/
- https://docs.velociraptor.app/artifact_references/pages/windows.sys.allusers/
- https://docs.velociraptor.app/artifact_references/pages/windows.sys.diskinfo/
- https://docs.velociraptor.app/artifact_references/pages/windows.sys.drivers/
- https://docs.velociraptor.app/artifact_references/pages/windows.sys.firewallrules/
- https://docs.velociraptor.app/artifact_references/pages/windows.sys.interfaces/
- https://docs.velociraptor.app/artifact_references/pages/windows.sys.programs/
- https://docs.velociraptor.app/artifact_references/pages/windows.sys.startupitems/
- https://docs.velociraptor.app/artifact_references/pages/windows.sys.users/
- https://docs.velociraptor.app/artifact_references/pages/windows.system.dnscache/
- https://docs.velociraptor.app/artifact_references/pages/windows.system.domainrole/
- https://docs.velociraptor.app/artifact_references/pages/windows.system.localadmins/
- https://docs.velociraptor.app/artifact_references/pages/windows.system.pslist/
- https://docs.velociraptor.app/artifact_references/pages/windows.system.services/
- https://docs.velociraptor.app/artifact_references/pages/windows.system.shares/
- https://docs.velociraptor.app/artifact_references/pages/windows.system.taskscheduler/
- https://docs.velociraptor.app/artifact_references/pages/windows.system.wmiquery/
