rule privacy_abusing_android_permissions{
    meta:
        author = "Alejandro Prada"
        date = "08-10-2021"
        description = "Rule for detecting abusive intents related to SMS and calls in AndroidManifest.xml and .DEX files"
    strings:
        //security
        $a1 = "ACTION_CALL"  fullword ascii wide
        $a2 = "ACTION_SENDTO" fullword ascii wide
        $a3 = "ACTION_SEND" fullword ascii wide
        $a4 = "ACTION_SEND_MULTIPLE" fullword ascii wide
	condition:
        2 of ($a)
}