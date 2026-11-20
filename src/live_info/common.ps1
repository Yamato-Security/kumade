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
    if($value -is [DateTime]){
        if($value -eq [DateTime]::MinValue){return $null}
        return $value.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)
    }
    if($value -is [DateTimeOffset]){return $value.UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)}
    throw 'Unexpected timestamp type'
}
function Str($value) {
    if($null -eq $value){return $null}
    return [string]$value
}
function Label($map,$value) {
    if($null -eq $value){return $null}
    $code=[int]$value
    if($map.ContainsKey($code)){return $map[$code]}
    return [string]$code
}
function Sid($bytes) {
    if($null -eq $bytes -or $bytes.Count -eq 0){return $null}
    try { return (New-Object Security.Principal.SecurityIdentifier(([byte[]]$bytes),0)).Value } catch { return $bytes }
}
function ProcessOwner($process) {
    if($null -eq $process){return $null}
    try {
        $o=Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
        if($o.ReturnValue -eq 0){return ($o.Domain+'\'+$o.User)}
    } catch { }
    return $null
}
