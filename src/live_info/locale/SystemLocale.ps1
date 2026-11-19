# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
$s=Get-WinSystemLocale
$language=Get-Item -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language'
$pages=Get-Item -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\CodePage'
[ordered]@{Scope='System';LocaleName=$s.Name;Lcid=$s.LCID;EnglishName=$s.EnglishName;NativeName=$s.NativeName;DefaultLanguageId=(LocaleValue $language 'Default');InstallLanguageId=(LocaleValue $language 'InstallLanguage');AnsiCodePage=(LocaleValue $pages 'ACP');OemCodePage=(LocaleValue $pages 'OEMCP');MacCodePage=(LocaleValue $pages 'MACCP')}
