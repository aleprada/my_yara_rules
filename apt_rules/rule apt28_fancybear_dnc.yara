rule apt28_fancybear_dnc {

    meta:
        author = "Alejandro Prada"
        description = "Yara rule for detecting APT28 Fancy Bear DNC malware"
        date = "2020-11-12"
        version = "0.1"
        hash_md5 = "ad44a7c5e18e9958dda66ccfc406cd44"
        hash_sha1 = "e2101519714f8a4056a9de18443bc6e8a1f1b977"
    
    strings:

        $x1 = "C:\\Users\\hannes\\dev\\proj\\install4j\\build\\src\\c\\windows\\JavaVMLauncher.cpp" fullword ascii
        $x2 = "SOFTWARE\\ej-technologies\\exe4j\\pids\\" fullword ascii
        $x3 = "C://program files (x86)//mingw//bin//..//lib//gcc-lib//mingw32//2.95.3-6//..//..//..//..//include//g++-3//std//bastring.cc" fullword ascii

        $a1 = "@MSG_ERROR_DIALOG_OK@"  wide
        $a2 = "@MSG_ERROR_DIALOG_TEXT@" wide
        $a3 = "@MSG_ERROR_DIALOG_CAPTION@" wide
        $a4 = "../../../src/mingw/mthr_stub.c"

        $s1 = "com/exe4j/runtime/Exe4JController" ascii 
        $s2 = "com/exe4j/runtime/WinLauncher" ascii
        $s3 = "%s\\bin\\splashscreen.dll" ascii fullword


    condition:
        (uint16(0) == 0x5A4D and filesize < 2500KB) and 2 of ($x*) and (2 of ($a*) or all of ($s*))  
    
}