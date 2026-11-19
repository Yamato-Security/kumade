# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
# Read-only locale/keyboard inventory. Never activates an input method, loads
# a layout DLL, changes regional settings, impersonates users or mounts hives.
function Loaded-LocaleHives {
    Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' | Where-Object {
        $_.PSChildName -eq '.DEFAULT' -or $_.PSChildName -match '^S-1-\d+(?:-\d+)+$'
    } | ForEach-Object {
        $name=$_.PSChildName
        $profile=$null
        $profileKey='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$name
        if(Test-Path -LiteralPath $profileKey){$profile=(Get-Item -LiteralPath $profileKey).GetValue('ProfileImagePath',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
        [pscustomobject]@{HiveName=$name;UserSid=if($name -eq '.DEFAULT'){$null}else{$name};ProfilePath=$profile;Scope=if($name -eq '.DEFAULT'){'SystemDefaultHive'}else{'LoadedUserHive'};Root=('Registry::'+$_.Name)}
    }
}
function Optional-LocaleKey([string]$path) {
    if(Test-Path -LiteralPath $path){return Get-Item -LiteralPath $path}
    return $null
}
function LocaleValue($key,[string]$name) {
    if($null -eq $key){return $null}
    # No environment expansion, indirect resource loading or command evaluation.
    return $key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
}
function LocaleCulture([string]$name) {
    if([string]::IsNullOrEmpty($name)){return $null}
    try {return [Globalization.CultureInfo]::GetCultureInfo($name).Name} catch {return $null}
}
function Keyboard-Definition([string]$id) {
    if($id -match '^[0-9a-fA-F]{8}$'){
        return Optional-LocaleKey ('Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\'+$id)
    }
    return $null
}
function Resolve-KeyboardLayout($substitutes,[string]$id) {
    $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $links=New-Object 'System.Collections.Generic.List[object]'
    $current=$id;$state='Unchanged'
    for($depth=0;$depth -lt 16;$depth++){
        if($current -notmatch '^[0-9a-fA-F]{8}$'){$state='InvalidLayoutId';break}
        if(!$seen.Add($current)){$state='SubstitutionCycle';break}
        $next=LocaleValue $substitutes $current
        if($null -eq $next){break}
        $links.Add([ordered]@{FromLayoutId=$current;ToLayoutId=[string]$next})
        $current=[string]$next;$state='Substituted'
        if($depth -eq 15){$state='DepthLimit'}
    }
    [pscustomobject]@{LayoutId=$current;State=$state;Links=@($links.ToArray())}
}
