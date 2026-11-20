# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
foreach($hive in (Loaded-LocaleHives)){
    $intl=Optional-LocaleKey ($hive.Root+'\Control Panel\International')
    if($null -eq $intl){continue}
    $geo=Optional-LocaleKey ($hive.Root+'\Control Panel\International\Geo')
    $localeProfile=Optional-LocaleKey ($hive.Root+'\Control Panel\International\User Profile')
    $desktop=Optional-LocaleKey ($hive.Root+'\Control Panel\Desktop')
    [ordered]@{Scope=$hive.Scope;UserSid=$hive.UserSid;HiveName=$hive.HiveName;ProfilePath=$hive.ProfilePath;RegistryPath=$intl.Name;LocaleId=(LocaleValue $intl 'Locale');LocaleName=(LocaleValue $intl 'LocaleName');Language=(LocaleValue $intl 'sLanguage');ShortDatePattern=(LocaleValue $intl 'sShortDate');LongDatePattern=(LocaleValue $intl 'sLongDate');ShortTimePattern=(LocaleValue $intl 'sShortTime');TimePattern=(LocaleValue $intl 'sTimeFormat');DateSeparator=(LocaleValue $intl 'sDate');TimeSeparator=(LocaleValue $intl 'sTime');DecimalSeparator=(LocaleValue $intl 'sDecimal');ThousandsSeparator=(LocaleValue $intl 'sThousand');CurrencySymbol=(LocaleValue $intl 'sCurrency');MeasurementSystem=(LocaleValue $intl 'iMeasure');FirstDayOfWeek=(LocaleValue $intl 'iFirstDayOfWeek');GeoNation=(LocaleValue $geo 'Nation');GeoName=(LocaleValue $geo 'Name');Languages=@(LocaleList $localeProfile 'Languages');PreferredUiLanguages=@(LocaleList $desktop 'PreferredUILanguages');PendingPreferredUiLanguages=@(LocaleList $desktop 'PreferredUILanguagesPending')}
}
