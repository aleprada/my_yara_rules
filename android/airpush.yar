rule airpush
{
    meta:
        author = "Alejandro Prada"
        date = "07-10-2021"
        md5 = "1122a7f505e96524406ca4db45bdf370"
        link = "https://koodous.com/apks/3828e73b6dcf44001abeb72e37616d9f95b426f03cc902e0c4b1ac55d55294c3"
    strings:
        $ap1 = "https://api.airpush.com/dialogad/adclick.php" 
		$ap2 = "https://api.airpush.com/testmsg2.php"
		$ap3 = "https://api.airpush.com/v2/api.php"
		$ap4 = "https://api.airpush.com/fullpage/adcall.php?"

        $b1 = "airpushNotificationPref" fullword
        $b2 = "raising airpush" fullword
        $b3 = "stopping airpush" fullword
        $b4 = "Airpush.java" fullword
        $b5 = "AirpushSDK" fullword
        $b6 = "AirpushWebClient" fullword 
        $b7 = "Airpush SDK started from BootReciver." 

	condition:
		2 of ($ap*) and 3 of ($b*)
}

