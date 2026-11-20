# Copyright (C) 2026 Shirofune Security Co., Ltd.
# SPDX-License-Identifier: RPL-1.5
foreach($hive in (Loaded-LocaleHives)){
    $preload=Optional-LocaleKey ($hive.Root+'\Keyboard Layout\Preload')
    $subs=Optional-LocaleKey ($hive.Root+'\Keyboard Layout\Substitutes')
    if($null -eq $preload){continue}
    foreach($name in ($preload.GetValueNames() | Sort-Object)){
        $id=[string](LocaleValue $preload $name);$resolved=Resolve-KeyboardLayout $subs $id
        $definition=$null
        if($resolved.State -notin @('SubstitutionCycle','DepthLimit','InvalidLayoutId')){$definition=Keyboard-Definition $resolved.LayoutId}
        [ordered]@{Scope=$hive.Scope;UserSid=$hive.UserSid;HiveName=$hive.HiveName;ProfilePath=$hive.ProfilePath;RegistryPath=$preload.Name;PreloadValueName=$name;ConfiguredLayoutId=$id;ResolvedLayoutId=$resolved.LayoutId;SubstitutionState=$resolved.State;Substitutions=@($resolved.Links);Registered=($null -ne $definition);LayoutText=(LocaleValue $definition 'Layout Text');LayoutDisplayName=(LocaleValue $definition 'Layout Display Name');LayoutFile=(LocaleValue $definition 'Layout File');ImeFile=(LocaleValue $definition 'IME File')}
    }
}
