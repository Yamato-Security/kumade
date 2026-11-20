# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$WorkDirectory
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$Binary = (Resolve-Path -LiteralPath $Binary).Path
if (Test-Path -LiteralPath $WorkDirectory) { throw 'Use a fresh validation directory' }
$null = New-Item -ItemType Directory -Path $WorkDirectory
$WorkDirectory = (Resolve-Path -LiteralPath $WorkDirectory).Path
# Independent test access to Windows basic information, EA bytes and backup reads.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public static class KumadeNativeTest {
    [StructLayout(LayoutKind.Sequential)] public struct Basic {
        public long Created, Accessed, Written, Changed; public uint Attributes;
    }
    [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct Privilege { public uint Count; public Luid Id; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int type,out Basic info,uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int type,ref Basic info,uint size);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid id);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref Privilege state,uint size,IntPtr previous,IntPtr returned);
    [DllImport("ntdll.dll")] static extern int NtSetEaFile(SafeFileHandle h,out IoStatus status,byte[] bytes,uint size);
    [DllImport("ntdll.dll")] static extern int NtQueryEaFile(SafeFileHandle h,out IoStatus status,byte[] bytes,uint size,bool single,IntPtr list,uint listSize,IntPtr index,bool restart);
    public static void Enable(string name) {
        IntPtr token; Luid id;
        if (!OpenProcessToken(GetCurrentProcess(),0x28,out token)) throw new Win32Exception();
        try {
            if (!LookupPrivilegeValue(null,name,out id)) throw new Win32Exception();
            Privilege state = new Privilege {Count=1,Id=id,Attributes=2};
            if (!AdjustTokenPrivileges(token,false,ref state,0,IntPtr.Zero,IntPtr.Zero) || Marshal.GetLastWin32Error()==1300) throw new Win32Exception();
        } finally {CloseHandle(token);}
    }
    static SafeFileHandle Open(string path,uint rights) {
        SafeFileHandle h=CreateFile(path,rights,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        if (h.IsInvalid) {h.Dispose();throw new Win32Exception();} return h;
    }
    public static Basic Read(string path) {
        using (SafeFileHandle h=Open(path,0x80)) {
            Basic b; if (!GetFileInformationByHandleEx(h,0,out b,(uint)Marshal.SizeOf(typeof(Basic)))) throw new Win32Exception(); return b;
        }
    }
    public static void Set(string path,long time,uint attributes) {
        using (SafeFileHandle h=Open(path,0x100)) {
            Basic b = new Basic {Created=time,Accessed=time+1,Written=time+2,Changed=time+3,Attributes=attributes};
            if (!SetFileInformationByHandle(h,0,ref b,(uint)Marshal.SizeOf(typeof(Basic)))) throw new Win32Exception();
        }
    }

    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint code,IntPtr input,uint inputSize,IntPtr output,uint outputSize,out uint returned,IntPtr overlapped);
    public static void MakeSparse(string path) {
        using(SafeFileHandle h=Open(path,0xC0000000)) {
            uint returned;
            if(!DeviceIoControl(h,0x900C4,IntPtr.Zero,0,IntPtr.Zero,0,out returned,IntPtr.Zero))throw new Win32Exception();
            using(FileStream stream=new FileStream(h,FileAccess.ReadWrite)) {
                stream.SetLength(64L*1024*1024);
                stream.WriteByte(0x41);stream.Position=stream.Length-1;stream.WriteByte(0x42);
            }
        }
    }
    public static void SetEA(string path) {
        byte[] name=Encoding.ASCII.GetBytes("KUMADE"), value=Encoding.ASCII.GetBytes("evidence");
        byte[] bytes=new byte[8+name.Length+1+value.Length];
        bytes[5]=(byte)name.Length;bytes[6]=(byte)value.Length;
        Array.Copy(name,0,bytes,8,name.Length);Array.Copy(value,0,bytes,9+name.Length,value.Length);
        using (SafeFileHandle h=Open(path,0x10)) {IoStatus status;int code=NtSetEaFile(h,out status,bytes,(uint)bytes.Length);if(code<0)throw new Exception("SetEA status: "+code);}
    }
    public static string EA(string path) {
        using (SafeFileHandle h=Open(path,8)) {
            byte[] bytes=new byte[65536];IoStatus status;int code=NtQueryEaFile(h,out status,bytes,(uint)bytes.Length,false,IntPtr.Zero,0,IntPtr.Zero,true);
            if(code==unchecked((int)0xC0000052))return "";
            if(code<0)throw new Exception("QueryEA status: "+code);
            return BitConverter.ToString(bytes,0,(int)status.Information.ToUInt64());
        }
    }
    public static string Hash(string path) {
        using (SafeFileHandle h=Open(path,0x80000000))
        using (FileStream stream=new FileStream(h,FileAccess.Read))
        using (SHA256 hash=SHA256.Create()) {return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();}
    }
}
'@
foreach ($privilege in 'SeBackupPrivilege','SeRestorePrivilege','SeSecurityPrivilege','SeManageVolumePrivilege') { [KumadeNativeTest]::Enable($privilege) }

function Get-SourceKey([string]$Path) {
    if ($Path.StartsWith('\\?\')) { $Path = $Path.Substring(4) }
    return $Path.TrimEnd([char]92)
}
function Invoke-Collector([string[]]$Arguments, [string]$Log) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Binary
    # These arguments are Windows paths or fixed options; no double quote is
    # legal in their filenames. A quoted trailing slash would need escaping.
    $quoted = foreach ($argument in $Arguments) {
        if ($argument.Contains('"') -or $argument.EndsWith('\')) { throw 'Unexpected test argument quoting' }
        '"' + $argument + '"'
    }
    $info.Arguments = $quoted -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $info.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    $null = $process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $text = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $WorkDirectory $Log),$text,(New-Object Text.UTF8Encoding($false)))
    $code = $process.ExitCode
    $process.Dispose()
    return $code
}
$source = Join-Path $WorkDirectory 'source'
$prefetch = Join-Path $source 'Windows\Prefetch'
$null = New-Item -ItemType Directory -Path $prefetch -Force
$file = Join-Path $prefetch 'Capture.pf'
$other = Join-Path $prefetch 'Other.pf'
$sparse = Join-Path $prefetch 'Sparse.pf'
[IO.File]::WriteAllBytes($file,[Text.Encoding]::UTF8.GetBytes('Synthetic evidence payload: 100 ns timestamps, ACLs and named streams.'))
[IO.File]::WriteAllBytes($other,[Text.Encoding]::UTF8.GetBytes('Second payload verifies directory timestamps after all children.'))
[IO.File]::WriteAllBytes($sparse,[byte[]]@())
[KumadeNativeTest]::MakeSparse($sparse)
Set-Content -LiteralPath $file -Stream 'Zone.Identifier' -Value '[ZoneTransfer] ZoneId=3' -Encoding ASCII -NoNewline
Set-Content -LiteralPath $file -Stream 'extra.evidence' -Value 'additional bytes' -Encoding ASCII -NoNewline
[KumadeNativeTest]::SetEA($file)
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetSecurityDescriptorSddlForm(('O:SYG:BAD:P(D;;0x1;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;'+$user+')S:(AU;SAFA;FR;;;WD)'))
Set-Acl -LiteralPath $file -AclObject $acl
# Distinct non-round 100 ns values; restore times after all fixture writes.
$epoch = [DateTime]::Parse('2024-03-04T05:06:07Z').ToUniversalTime().ToFileTimeUtc() + 1234567
[KumadeNativeTest]::Set($file,$epoch,0x23)
[KumadeNativeTest]::Set($other,$epoch+100,0x20)
[KumadeNativeTest]::Set($sparse,$epoch+500,0x20)
[KumadeNativeTest]::Set($prefetch,$epoch+200,0x12)
[KumadeNativeTest]::Set((Join-Path $source 'Windows'),$epoch+300,0x10)
[KumadeNativeTest]::Set($source,$epoch+400,0x10)
$paths = @($source,(Join-Path $source 'Windows'),$prefetch,$file,$other,$sparse)
$before = @{}
foreach ($path in $paths) { $before[$path]=[KumadeNativeTest]::Read($path) }
$security = (Get-Acl -LiteralPath $file -Audit).Sddl
$ea = [KumadeNativeTest]::EA($file)
$hashes = @{}
foreach ($path in @($file,$other,$sparse,($file+':Zone.Identifier'),($file+':extra.evidence'))) { $hashes[$path]=[KumadeNativeTest]::Hash($path) }
$image = Join-Path $WorkDirectory "Evidence 'quoted'.vhdx"
$arguments = @('collect','-d',$source,'--computer','SYNTHETIC','--artifact','windows.prefetch','--vhdx',$image,'--vhdx-size-gib','1','--reserve-mib','0','-T','2')
$code = Invoke-Collector $arguments 'collect.txt'
if ($code -ne 0) { throw ('Collection failed ('+$code+'): '+(Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $WorkDirectory 'collect.txt'))) }
if ((Get-DiskImage -ImagePath $image).Attached) { throw 'Image remained attached after collection' }
$imageBeforeReadOnly = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash
$mounted = $false
try {
    $null = Mount-DiskImage -ImagePath $image -Access ReadOnly -NoDriveLetter
    $mounted = $true
    $volumes = @(Get-DiskImage -ImagePath $image | Get-Disk | Get-Partition | Get-Volume | Where-Object FileSystem -eq 'NTFS')
    if ($volumes.Count -ne 1) { throw 'Expected one read-only NTFS volume' }
    # Discover this real, unlettered NTFS image through the default live path.
    # Planning reads source state but does not run live inventory or acquire files.
    $scopeDirectory = Join-Path $WorkDirectory 'live-volume-plan'
    $scopeCode = Invoke-Collector @('plan','-o',$scopeDirectory,'--artifact','windows.ntfs.mft','--reserve-mib','0') 'live-volume-plan.txt'
    if ($scopeCode -notin @(0,3)) { throw ('Live volume planning failed: '+$scopeCode) }
    $scope = Get-Content -Raw -LiteralPath (Join-Path $scopeDirectory 'Plan.json') | ConvertFrom-Json
    $volumeName = $volumes[0].UniqueId.TrimEnd('\')
    $dataSource = @($scope.Sources | Where-Object { $_.RawDevice -and $_.RawDevice.TrimEnd('\') -eq $volumeName })
    if ($dataSource.Count -ne 1 -or $dataSource[0].MetadataOnly) { throw 'Additional NTFS volume was not discovered with the catalog scope' }
    $dataFiles = @($scope.Files | Where-Object SourceId -eq $dataSource[0].Id)
    if ($dataFiles.Count -ne 1 -or $dataFiles[0].RelativePath -ne '$MFT') { throw 'Additional NTFS volume did not retain its raw MFT task' }
    $runs = @(Get-ChildItem -LiteralPath $volumes[0].UniqueId -Directory | Where-Object Name -like 'SYNTHETIC_*')
    if ($runs.Count -ne 1) { throw 'Expected one acquisition run' }
    $run = $runs[0].FullName
    $summary = Get-Content -Raw -LiteralPath (Join-Path $run 'Summary.json') | ConvertFrom-Json
    if ($summary.MetadataErrors -ne 0 -or $summary.Collected -ne 5) { throw 'Unexpected acquisition/metadata counts' }
    $reports = @(Get-Content -LiteralPath (Join-Path $run 'NTFS-Metadata.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    $csv = @(Import-Csv -LiteralPath (Join-Path $run 'NTFS-Metadata.csv'))
    if ($reports.Count -ne 6 -or $csv.Count -ne $reports.Count) { throw 'Missing file/directory metadata records' }
    foreach ($row in $reports) {
        if ($row.CaptureStatus -ne 'Captured' -or $row.RestoreStatus -ne 'Restored') { throw ('Metadata restoration incomplete: '+($row | ConvertTo-Json -Compress)) }
        $destination = Join-Path $run $row.RelativeOutputPath
        $sourceKey = Get-SourceKey $row.SourcePath
        $expected = $before[$sourceKey]
        if (-not $expected) { throw ('Unexpected source metadata: '+$row.SourcePath) }
        $actual = [KumadeNativeTest]::Read($destination)
        # Access times can change during source reads/planning. The image must
        # exactly retain the observed source metadata, including all 100 ns digits.
        $observed = @{Created=$row.CreationFiletime;Accessed=$row.AccessFiletime;Written=$row.WriteFiletime;Changed=$row.ChangeFiletime;Attributes=$row.Attributes}
        foreach ($name in 'Created','Accessed','Written','Changed','Attributes') {
            if ($actual.$name -ne $observed[$name]) { throw ('Metadata mismatch '+$name+' on '+$row.RelativeOutputPath+': '+$actual.$name+' != '+$observed[$name]) }
        }
        foreach ($name in 'Created','Written','Changed','Attributes') {
            if ($actual.$name -ne $expected.$name) { throw ('Configured source metadata changed: '+$name+' on '+$sourceKey) }
        }
    }
    $target = Join-Path $run 'source\Windows\Prefetch\Capture.pf'
    if ((Get-Acl -LiteralPath $target -Audit).Sddl -ne $security) { throw 'Owner/group/DACL/SACL changed' }
    if ([KumadeNativeTest]::EA($target) -ne $ea) { throw 'Extended attributes changed' }
    # Reading file data can update NTFS's cached access time even on a read-only
    # mount. Check stored metadata first, then verify that image bytes stay fixed.
    $verifyCode = Invoke-Collector @('verify',$run) 'verify.txt'
    if ($verifyCode -ne 0) { throw ('Integrity verification failed: '+(Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $WorkDirectory 'verify.txt'))) }
    foreach ($row in @(Import-Csv -LiteralPath (Join-Path $run 'Manifest.csv'))) {
        $sourcePath = Get-SourceKey $row.SourcePath
        if ($row.StreamName) { $sourcePath += ':'+$row.StreamName }
        $payload = Join-Path $run $row.RelativeOutputPath
        if ([KumadeNativeTest]::Hash($payload) -ne $hashes[$sourcePath]) { throw 'Independent payload/ADS hash mismatch' }
    }
    # A second run must leave this existing image untouched.
    $imageHash = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash
    $noOverwriteCode = Invoke-Collector $arguments 'no-overwrite.txt'
    if ($noOverwriteCode -ne 2 -or (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash -ne $imageHash) { throw 'Existing VHDX was changed' }
    if ((Get-Item -LiteralPath $image).Length -ge 60MB) { throw 'Sparse payload expanded into allocated zero-filled output' }
    $result = [pscustomobject]@{Payloads=$summary.Collected;MetadataRecords=$reports.Count;NTFSTimestamps100ns='passed';OwnerGroupDaclSacl='passed';ExtendedAttributes='passed';NamedStreams='passed';SparseAllocation='passed';IndependentHashes='passed';NoOverwrite='passed';ReadOnlyVerification='passed';Image=$image}
} finally {
    if ($mounted) { $null = Dismount-DiskImage -ImagePath $image }
}
if ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash -ne $imageBeforeReadOnly) { throw 'Read-only inspection changed image bytes' }
$result | Add-Member -NotePropertyName ReadOnlyImageUnchanged -NotePropertyValue 'passed'
$result | ConvertTo-Json | Tee-Object -FilePath (Join-Path $WorkDirectory 'result.json')
