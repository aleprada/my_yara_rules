rule attck_android_ta0035_t1435
{
    meta:
        author = "Alejandro Prada"
        date = "27-10-2021"
        description = "Rule for detecting the ATT&CK technique T1435: Access Calendar entries"
    strings:
        $a1 = "READ_CALENDAR"  fullword ascii wide
        $a2 = "CalendarContract" ascii wide
	condition:
        1 of ($a*) 
}

rule attck_android_ta0035_t1433
{
    meta:
        author = "Alejandro Prada"
        date = "27-10-2021"
        description = "Rule for detecting the ATT&CK technique T1433: Access Call log"
    strings:
        $a1 = "READ_CALL_LOG"  fullword ascii wide
        $a2 = "CallLog.Calls.NUMBER" fullword ascii wide
        $a3 = "CallLog.Calls.CACHED_NAME" fullword ascii wide
        $a4 = "CallLog.Calls.DURATION" fullword ascii wide
	condition:
        2 of ($a*) 
}

rule attck_android_ta0035_t1432{
    meta:
        author = "Alejandro Prada"
        date = "27-10-2021"
        description = "Rule for detecting the ATT&CK technique T1432: Access Contact List"
    strings:
        $a1 = "READ_CONTACTS"  fullword ascii wide
        $a2 = "CallLog.Calls.NUMBER" fullword ascii wide
        $a3 = "CallLog.Calls.CACHED_NAME" fullword ascii wide
        $a4 = "CallLog.Calls.DURATION" fullword ascii wide
	condition:
        2 of ($a*) 
}


rule attck_android_ta0035_t1517{
    meta:
        author = "Alejandro Prada"
        date = "27-10-2021"
        description = "Rule for detecting the ATT&CK technique T1517: Access Notifications"
    strings:
        $a1 = "DevicePolicyManager.setPermittedCrossProfileNotificationListeners"   ascii wide
        $a2 = "DevicePolicyManager.setApplicationHidden"  ascii wide
	condition:
        1 of ($a*) 
}