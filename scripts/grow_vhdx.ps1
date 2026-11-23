# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$images=@(Get-DiskImage -ImagePath $env:KUMADE_VHDX_PATH -ErrorAction Stop)
if($images.Count -ne 1 -or -not $images[0].Attached){throw 'Owned image is not attached'}
$disks=@($images[0] | Get-Disk -ErrorAction Stop)
if($disks.Count -ne 1 -or $disks[0].Number -ne [uint32]$env:KUMADE_VHDX_DISK_NUMBER -or $disks[0].UniqueId -ne $env:KUMADE_VHDX_DISK_ID){throw 'Owned disk identity changed'}
$number=$disks[0].Number
Update-Disk -Number $number -ErrorAction Stop
$disk=Get-Disk -Number $number -ErrorAction Stop
if($disk.IsBoot -or $disk.IsSystem -or ([uint16]$disk.CimInstanceProperties['BusType'].Value) -ne 15){throw 'Refusing to resize a non-owned/system disk'}
if($disk.UniqueId -ne $env:KUMADE_VHDX_DISK_ID -or $disk.Size -lt [uint64]$env:KUMADE_VHDX_NEW_SIZE){throw 'Expanded disk identity or size mismatch'}
$parts=@(Get-Partition -DiskNumber $number -ErrorAction Stop | Where-Object {$_.AccessPaths -contains $env:KUMADE_VHDX_VOLUME})
if($parts.Count -ne 1){throw 'Expected the owned NTFS data partition'}
$size=Get-PartitionSupportedSize -DiskNumber $number -PartitionNumber $parts[0].PartitionNumber -ErrorAction Stop
if($size.SizeMax -lt $parts[0].Size){throw 'Refusing to shrink the evidence partition'}
if($size.SizeMax -gt $parts[0].Size){$null=$parts[0] | Resize-Partition -Size $size.SizeMax -Confirm:$false -ErrorAction Stop}
$volume=@(Get-Partition -DiskNumber $number -PartitionNumber $parts[0].PartitionNumber | Get-Volume -ErrorAction Stop)
if($volume.Count -ne 1 -or $volume[0].UniqueId -ne $env:KUMADE_VHDX_VOLUME -or $volume[0].FileSystem -ne 'NTFS'){throw 'Expanded volume identity mismatch'}
@{DiskNumber=$number;VolumePath=$volume[0].UniqueId;Size=$volume[0].Size} | ConvertTo-Json -Compress
