# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
# Built-in read-only queries. No user-supplied script or profile is evaluated.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$OutputEncoding=[Console]::OutputEncoding
function Utc($value) {
    if($null -eq $value){return $null}
    if($value -is [DateTime]){return $value.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)}
    if($value -is [DateTimeOffset]){return $value.UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)}
    throw 'Unexpected timestamp type'
}
function ProcessOwner($process) {
    if($null -eq $process){return $null}
    try {
        $o=Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
        if($o.ReturnValue -eq 0){return ($o.Domain+'\'+$o.User)}
    } catch { }
    return $null
}
