# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$order=0
Get-WinUserLanguageList | ForEach-Object {
    $order++
    [ordered]@{Scope='CollectorAccount';UserSid=$identity.User.Value;UserName=$identity.Name;Order=$order;LanguageTag=$_.LanguageTag;Autonym=$_.Autonym;EnglishName=$_.EnglishName;LocalizedName=$_.LocalizedName;ScriptName=$_.ScriptName;InputMethodTips=@($_.InputMethodTips);Spellchecking=$_.Spellchecking;Handwriting=$_.Handwriting}
}
