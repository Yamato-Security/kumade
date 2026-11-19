# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
foreach($hive in (Loaded-LocaleHives)){
    $localeProfile=Optional-LocaleKey ($hive.Root+'\Control Panel\International\User Profile')
    if($null -eq $localeProfile){continue}
    $order=0
    foreach($language in @(LocaleValue $localeProfile 'Languages')){
        if([string]::IsNullOrEmpty($language)){continue};$order++
        # Treat registry language tags as data, never as arbitrary subpaths.
        $key=$null
        if($language -match '^[a-zA-Z0-9-]+$'){$key=Optional-LocaleKey ($hive.Root+'\Control Panel\International\User Profile\'+$language)}
        $tips=@();$values=@()
        if($null -ne $key){foreach($name in $key.GetValueNames()){
            $values+=,[ordered]@{ValueName=$name;ValueType=[string]$key.GetValueKind($name);ValueData=(LocaleValue $key $name)}
            if($name -match '^[0-9a-fA-F]{4}:'){$tips+=$name}
        }}
        [ordered]@{Scope=$hive.Scope;UserSid=$hive.UserSid;HiveName=$hive.HiveName;ProfilePath=$hive.ProfilePath;RegistryPath=$localeProfile.Name;Order=$order;LanguageTag=$language;CultureName=(LocaleCulture $language);InputMethodTips=@($tips);Settings=@($values)}
    }
}
