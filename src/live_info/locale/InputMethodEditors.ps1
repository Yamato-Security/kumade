# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
foreach($root in @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CTF\TIP','Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\CTF\TIP')){
    if(!(Test-Path -LiteralPath $root)){continue}
    foreach($tip in Get-ChildItem -LiteralPath $root){
        $languageRoot=$root+'\'+$tip.PSChildName+'\LanguageProfile'
        if(!(Test-Path -LiteralPath $languageRoot)){continue}
        foreach($language in Get-ChildItem -LiteralPath $languageRoot){
            foreach($localeProfile in Get-ChildItem -LiteralPath ('Registry::'+$language.Name)){
                [ordered]@{Scope='MachineRegistration';RegistryPath=$localeProfile.Name;RegistryView=if($root -match 'WOW6432Node'){'32Bit'}else{'Native'};TipId=$tip.PSChildName;LanguageId=$language.PSChildName;ProfileId=$localeProfile.PSChildName;Description=(LocaleValue $localeProfile 'Description');Enabled=(LocaleValue $localeProfile 'Enable');IconFile=(LocaleValue $localeProfile 'IconFile');IconIndex=(LocaleValue $localeProfile 'IconIndex')}
            }
        }
    }
}
