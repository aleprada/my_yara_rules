rule privacy_abusing_android_methods{
    meta:
        author = "Alejandro Prada"
        date = "19-10-2021"
        description = "Rule for detecting abusive privacy permissions in AndroidManifest and DEX files"
    strings:
        //abusive privacy permissions
        $b1 = "ACCESS_COARSE_LOCATION" fullword ascii wide
        $b2 = "ACCESS_FINE_LOCATION" fullword ascii wide
        $b3 = "ACCESS_MEDIA_LOCATION" fullword ascii wide
        $b4 = "ANSWER_PHONE_CALLS" fullword ascii wide
        $b5 = "CAMERA" fullword ascii wide
        $b6 = "GET_ACCOUNTS" fullword ascii wide
        $b7 = "READ_CALENDAR" fullword ascii wide
        $b8 = "READ_CALL_LOG" fullword ascii wide
        $b9 = "READ_EXTERNAL_STORAGE" fullword ascii wide
        $b10 = "READ_PHONE_NUMBERS" fullword ascii wide
        $b10 = "RECEIVE_WAP_PUSH" fullword ascii wide
        $b11 = "USE_SIP" fullword ascii wide
        

	condition:
        4 of ($a*) 
}
