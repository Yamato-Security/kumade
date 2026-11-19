# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
Get-ChildItem -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MUI\UILanguages' | ForEach-Object {
    [ordered]@{Scope='MachineRegistration';RegistryPath=$_.Name;LanguageTag=$_.PSChildName;Lcid=(LocaleValue $_ 'LCID');Type=(LocaleValue $_ 'Type');DefaultFallback=(LocaleValue $_ 'DefaultFallback')}
}
