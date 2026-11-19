# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
Get-ChildItem -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts' | ForEach-Object {
    [ordered]@{Scope='MachineRegistration';RegistryPath=$_.Name;LayoutId=$_.PSChildName;LayoutText=(LocaleValue $_ 'Layout Text');LayoutDisplayName=(LocaleValue $_ 'Layout Display Name');LayoutFile=(LocaleValue $_ 'Layout File');LayoutVariantId=(LocaleValue $_ 'Layout Id');ImeFile=(LocaleValue $_ 'IME File')}
}
