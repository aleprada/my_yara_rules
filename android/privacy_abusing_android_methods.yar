rule privacy_abusing_android_methods{
    meta:
        author = "Alejandro Prada"
        date = "08-10-2021"
        description = "Rule for detecting potential abuse of Android Methods in Dex file"
    strings:
        $a1 = "getDeviceId"  fullword ascii wide
        $a2 = "getLine1Number" fullword ascii wide
        $a3 = "getDeviceSoftwareVersion" fullword ascii wide
        $a4 = "getNetworkOperator" fullword ascii wide
        $a5 = "getNetworkOperatorName" fullword ascii wide
        $a6 = "getSimSerialNumber" fullword ascii wide
        $a7 = "getActiveNetworkInfo" fullword ascii wide
        $a8 = "getNetworkPreference" fullword ascii wide
        $a9 = "getDisplayLanguage" fullword ascii wide
        $a10 = "getDisplayCountry" fullword ascii wide
        
        $a11 = "getSubscriberId" fullword ascii wide
        $a12 = "getLongitude" fullword ascii wide
        $a13 = "getLatitude" fullword ascii wide
        $a14 = "getCellLocation" fullword ascii wide
        $a15 = "getPhoneType" fullword ascii wide
        $a16 = "getAccounts" fullword ascii wide
        $a17 = "setPassword" fullword ascii wide
        $a18 = "getNetworkInfo" fullword ascii wide
        $a19 = "getAllNetworkInfo" fullword ascii wide
        $a20 = "getPackageName" fullword ascii wide

        $a21 = "getManufacturer" fullword ascii wide
        $a22 = "getAboutMe" fullword ascii wide
        $a23 = "getBirthday" fullword ascii wide
        $a24 = "getAboutMe" fullword ascii wide
        $a25 = "getBirthday" fullword ascii wide
        $a26 = "getCircledByCount" fullword ascii wide
        $a27 = "getCover" fullword ascii wide
        $a28 = "getCurrentLocation" fullword ascii wide
        $a29 = "getDisplayName" fullword ascii wide
        $a30 = "getGender" fullword ascii wide

        $a31 = "getImage" fullword ascii wide
        $a32 = "getId" fullword ascii wide
        $a33 = "getLanguage" fullword ascii wide
        $a34 = "getNickname" fullword ascii wide
        $a35 = "getOrganizations" fullword ascii wide
        $a36 = "getPlacesLived" fullword ascii wide
        $a37 = "getPlusOneCount" fullword ascii wide
        $a38 = "getRelationshipStatus" fullword ascii wide
        $a39 = "getTagline" fullword ascii wide
        $a40 = "getUrl" fullword ascii wide
        $a41 = "getUserName" fullword ascii wide
        $a42 = "getPostalCode" fullword ascii wide
        $a43 = "getApiKey" fullword ascii wide

	condition:
        15 of ($a*) 
}




















