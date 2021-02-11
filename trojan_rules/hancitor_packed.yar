rule hancitor_packed {

    meta:
        author = "Alejandro Prada"
        description = "Yara rule for detecting hancitor packed version "
        date = "2021-02-11"
        version = "0.1"
        hash_md5 = "ff9d0327538ab33468a8ad2142eff416"
        hash_sha1 = "2afd1263c090e9aff5aa9106c7dd908119ba10a0"
        hash_sha256 = "eea0083ac04f8bfb3042acd615cabd7be77dee410c8db229b5980379b224e93f"
    
    strings:

        $x1 = "8pRCgEXTvSSERDD7" fullword ascii
        $x2 = "7777G7775777i77777777777777w77" fullword ascii
        $x3 = "$xBCGBCsRUBPdCE^YPv7" fullword ascii

        $a1 = "6 6$6(6,6064686<6@6D6H6L6d8h8l8p8t8x8|8"  fullword ascii
        $a2 = "4 4$4(4,4044484<4@4D4H4L4P4T4X4\\4`4d4h4l4p4t4x4|"  ascii
        $a3 = "D1H1L1P1T1X1\\1`1x1|1" fullword ascii


        $s1 =  "IDI_LOGO" wide 
        $s2 =  "WinExec" fullword ascii 
        $s3 =  "VirtualProtect" fullword ascii
     

    condition:
        (uint16(0) == 0x5A4D and filesize < 70KB) and 1 of ($x*) and (2 of ($a*) or all of ($s*))  
    
}
