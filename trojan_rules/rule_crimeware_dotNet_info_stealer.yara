rule crimeware_dotNet_info_stealer {

    meta:
        author = "Alejandro Prada"
        description = "Yara rule for detecting .NET info stealer "
        date = "2021-02-07"
        version = "0.1"
        hash_md5 = "dc4200ac514006f084ead7f83b84c928"
        hash_sha1 = "52e8f04d6b495d238f1a49283a10e2acc053123b"
    
    strings:

        $x1 = "http://ziraat-helpdesk.com/components/com_content/limpopapa" fullword wide
        $x2 = "ziraat_limpi.exe" fullword ascii
        $x3 = "MiniTool Solution Ltd." fullword wide

        $a1 = "Software\IMVU\\username"  fullword wide
        $a2 = "FileZilla\recentservers.xml" fullword wide
        $a3 = "FileZilla\sitemanager.xml" fullword wide
        $a4 = "Software\Paltalk\\" fullword wide
        $a5 = "SetWindowsHookEx" fullword ascii
        $a6 = "UnhookWindowsHookEx" fullword ascii
        $a7 = "CallNextHookEx" fullword ascii
        $a8 = "Important.exe" fullword wide
        $a9 = "Software\IMVU\\username" fullword wide

        $s1 =  "Browsers.txt" fullword wide 
        $s2 =  "KeyBase" wide
        $s3 =  "JDownloader" wide 
        $s4  = "LoadLibrary" fullword wide
        $s5 =  "\Mails.txt" fullword wide


    condition:
        (uint16(0) == 0x5A4D and filesize < 500KB) and 1 of ($x*) and (4 of ($a*) or all of ($s*))  
    
}