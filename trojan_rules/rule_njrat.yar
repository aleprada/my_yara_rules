
rule njrat_test{

    meta:
        author = "Alejandro Prada"
        description = "Rule for detecting the Njrat malware.Version 0.7"
        date = "2020/02/11"
	version = "0.2"
        md5 = "70ea9c044c9a766330d3fe77418244a5"
    
    strings:
        $x1 = "NJRAT.NJRAT" fullword wide 
        $x2 = "njq8" fullword wide         //coder
        $x3 = "C:\\Users\\HMJ\\Desktop\\njRAT v0.7d (SRC)\\SRC - NjRAT 0.7D\\NjRAT\\obj\\Debug\\NjRat 0.7D.pdb" wide
        $x4 = "NjRat 0.7D.exe" fullword wide 
        $x5 = "NJRAT.Mynoip.resources" wide ascii
        $x6 = "NJRAT.up.resources" wide ascii

        
        $a1 =  "www.angusj.com" wide ascii //web for dowloading the software Resources Hacker
        $a2 = "SOFTWARE\\Borland\\Delphi\\RTL" wide ascii
        $a3 = "Software\\Borland\\Delphi\\Locales" wide ascii
        $a4 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" wide
        $a5 = "$c0a9a70f-63e8-42ca-965d-73a1bc903e62" wide ascii
        $a6 = "C57C7AB5-C088-443D-9417-DEB759459283" wide ascii
        
        $s1 = "HID.exe" wide ascii
        $s2 = "dotNET_Reactor.exe" wide ascii
	    $s3 = "b77a5c561934e089" fullword wide ascii
	    $s4 = "b03f5f7f11d50a3a" fullword wide ascii

    condition:
    	 (uint16(0) == 0x5A4D and filesize > 8000KB) and 2 of ($x*) and (2 of ($a*) or all of ($s*))
}
