rule emotet_maldoc {

    meta:
        author = "Alejandro Prada"
        description = "Yara rule for detecting .NET info stealer "
        date = "2021-03-10"
        version = "0.1"
        hash1_sha1 = "3d06ce8d02d172c286a2833292ea32c852d13515"
        hash2_sha2= "733AC95DB66B97785CD3C481397B2B089388D0C1"
    strings:

        $magicheader1 = { 50 4B 03 04 14 00 06 00 } //docx 
        $magicheader2 = { D0 CF 11 E0 A1 B1 1A E1 } //doc 

        $x1 = "Macros" wide
        $x2 = "Document_open" fullword ascii

        $a1 = "1Normal.ThisDocument" fullword wide
        $a2 = "Louise Fleury" fullword ascii
        $a3 = "Recusandae." ascii
        $a4 = "Hic." ascii
        $a5 = "07B0DDE8-F2CA-4A45-84B8-99DFF1D8BE4A" fullword wide
        $a6 = "83116EF2-8058-4EA2-9178-C1BD9BEAC0F6" fullword wide
        $a7 =  "jjkgS []" fullword
        $a8 = "Lucas Fernandez" fullword ascii
        
    condition:
       ($magicheader1 at 0 or $magicheader2 at 0) and (all of ($x*) and 2 of ($a*))
           
}
