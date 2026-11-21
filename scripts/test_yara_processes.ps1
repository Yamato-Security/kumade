# Read-only baseline + inert positive controls. Run on a Windows test host with a native build.
param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$Output,
    [ValidatePattern('^[0-9]{8}$')][string]$Release='20261115'
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$Binary=(Resolve-Path -LiteralPath $Binary).Path
if(Test-Path -LiteralPath $Output){throw 'Use a new output directory'}
$Root=(New-Item -ItemType Directory -Path $Output).FullName
$os=Get-CimInstance Win32_OperatingSystem
$system=Get-CimInstance Win32_ComputerSystem
[ordered]@{
    CollectedUtc=[DateTime]::UtcNow.ToString('o'); OS=$os.Caption; Build=$os.BuildNumber
    Architecture=$os.OSArchitecture; RAMBytes=[uint64]$system.TotalPhysicalMemory
    LogicalProcessors=$system.NumberOfLogicalProcessors; RunnerPID=$PID
    BinarySHA256=(Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'Environment.json')
foreach($set in @('core','extended','full')) {
    $scanArgs=@('scan-processes','--rules-release',$Release,'-o',(Join-Path $Root "Scan-$set"))
    # Omit --ruleset in the Core run to verify the default.
    if($set -ne 'core'){$scanArgs+=@('--ruleset',$set)}
    & $Binary @scanArgs *> (Join-Path $Root "Scan-$set-console.txt")
    $code=$LASTEXITCODE
    if($code -notin @(0,3)){throw "Baseline $set failed: exit $code"}
    [ordered]@{Set=$set;ExitCode=$code} | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $Root 'ScanProgress.jsonl')
}
# The following controls run AFTER the baseline, so intended signature hits cannot count as FPs.
$marker='KumadeHarmlessControl_'+[Guid]::NewGuid().ToString('N')
$ready=Join-Path $Root 'ControlReady.txt'
$readyLiteral=$ready.Replace("'","''")
$body="`$a=[Text.Encoding]::ASCII.GetBytes('$marker');`$w=[Text.Encoding]::Unicode.GetBytes('$marker');[IO.File]::WriteAllText('$readyLiteral','ready');while(`$true){[GC]::KeepAlive(`$a);[GC]::KeepAlive(`$w);Start-Sleep 1}"
$child=Start-Process powershell.exe -ArgumentList '-NoProfile','-EncodedCommand',([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))) -PassThru -WindowStyle Hidden
try {
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    while(!(Test-Path -LiteralPath $ready)){if([DateTime]::UtcNow -gt $deadline){throw 'Control startup timeout'};Start-Sleep -Milliseconds 100}
    $rules=@"
rule ascii_control { strings: `$x="$marker" ascii condition: `$x and not defined filesize }
rule wide_control { strings: `$x="$marker" wide condition: `$x and not defined filesize }
rule negative_control { strings: `$x="Absent_$([Guid]::NewGuid().ToString('N'))" condition: `$x }
rule disk_only_control { strings: `$x="$marker" condition: `$x and filesize > 0 }
"@
    $ruleFile=Join-Path $Root 'Control.yar'
    [IO.File]::WriteAllText($ruleFile,$rules,[Text.UTF8Encoding]::new($true)) # Exercise Windows UTF-8 BOM support.
    $dest=Join-Path $Root 'PositiveControl'
    & $Binary scan-processes --rules $ruleFile --pid $child.Id --pid 4294967295 -t jsonl -o $dest *> (Join-Path $Root 'PositiveControl-console.txt')
    if($LASTEXITCODE -ne 3){throw 'Missing PID must make the result Partial / exit 3'}
    $hits=@(Get-Content -LiteralPath (Join-Path $dest 'YaraDetections.jsonl') | ConvertFrom-Json)
    if($hits.Count -ne 2 -or !($hits.Rule -contains 'ascii_control') -or !($hits.Rule -contains 'wide_control')){throw 'ASCII/UTF-16/negative/file-only control mismatch'}
} finally {Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue}
# These bytes are inert rule patterns, never executed, injected or written as a program.
$hex='48007463707069766F74000048006E616D65647069700000800008650000810068747470000080000473000066810077670000668100646E000080000273000081006D746C73'
$payload=[byte[]]::new($hex.Length/2)
for($i=0;$i -lt $payload.Length;$i++){$payload[$i]=[Convert]::ToByte($hex.Substring(2*$i,2),16)}
$encoded=[Convert]::ToBase64String($payload)
$ready=Join-Path $Root 'ForgeControlReady.txt';$readyLiteral=$ready.Replace("'","''")
$body="`$b=[Convert]::FromBase64String('$encoded');[IO.File]::WriteAllText('$readyLiteral','ready');while(`$true){[GC]::KeepAlive(`$b);Start-Sleep 1}"
$child=Start-Process powershell.exe -ArgumentList '-NoProfile','-EncodedCommand',([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))) -PassThru -WindowStyle Hidden
try {
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    while(!(Test-Path -LiteralPath $ready)){if([DateTime]::UtcNow -gt $deadline){throw 'Forge control startup timeout'};Start-Sleep -Milliseconds 100}
    foreach($set in @('core','extended','full')){
        $dest=Join-Path $Root "ForgeControl-$set"
        & $Binary scan-processes --rules (Join-Path $Root "Scan-$set\Rules.yar") --pid $child.Id -t jsonl -o $dest *> (Join-Path $Root "ForgeControl-$set-console.txt")
        $code=$LASTEXITCODE
        if($code -notin @(0,3)){throw "Forge $set control failed: $code"}
        $hits=@(Get-Content -LiteralPath (Join-Path $dest 'YaraDetections.jsonl') | ConvertFrom-Json)
        if(!($hits.Rule -contains 'GCTI_Sliver_Implant_64Bit')){throw "Forge $set did not detect its expected inert control"}
        [ordered]@{Set=$set;ExpectedRule='GCTI_Sliver_Implant_64Bit';Matched=$true;Rules=$hits.Rule;ExitCode=$code} | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $Root 'ForgeControlResults.jsonl')
    }
} finally {Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue}
'Passed' | Set-Content -LiteralPath (Join-Path $Root 'Validation.txt')
Write-Host "Validation results: $Root"
