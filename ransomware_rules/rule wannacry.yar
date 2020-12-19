rule wannacry {

    meta:
        author = "Alejandro Prada"
        description = "Yara rule for detecting Wannacry Ransomware"
        date = "2020-11-10"
        version = "0.1"
        hash_md5 = "84c82835a5d21bbcf75a61706d8ab549"
        hash_sha1 = "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467"
    
    strings:

        $x1 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
        $x2 = "cmd.exe /c \"%s" fullword ascii
        $x3 = "WanaCrypt0r" wide
        $x4 = "WNcry@2ol7" ascii
        $x5 = "WANACRY!" ascii

        $a1 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" fullword ascii
        $a2 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" fullword ascii
        $a3 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" fullword ascii
        $a4 = "tasksche.exe" ascii
        $a5 = "taskse.exed" ascii

        $s1 = "CryptGenKey" ascii 
        $s2 = "CryptEncrypt" ascii
        $s3 = "CryptDecrypt" ascii
        $s4 = "CryptDestroyKey" ascii
        $s5 = "CryptImportKey" ascii
        $s6 = "CryptAcquireContextA" ascii
        $s7 = "CryptReleaseContext" ascii

    condition:
        (uint16(0) == 0x5A4D and filesize < 4000KB) and 2 of ($x*) and (3 of ($a*) or all of ($s*))  
    
}