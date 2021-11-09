rule premium_sms
{
    meta:
        author = "Alejandro Prada"
        date = "08-10-2021"
        description = "Rule for detecting potential premium sms apps."
    strings:
        $a1 = "SEND_SMS"  fullword ascii wide
        $a2 = "sendTextMessage()" fullword ascii wide
        $a3 = "android.telephony.SmsManager" ascii wide
        $a4 = "Landroid/telephony/SmsManager.m" ascii wide
        $a5 = "sendMultipartTextMessage" fullword
  

	condition:
        2 of ($a*) 
}
