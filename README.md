**My Yara rules**

This repository contains some yara rules that I've created for analysing different well-known malware. I will try to add more rules from time to time.

The repository is divided in 3 categories:

* APT
* Ransomware
* Trojans

**Methodology**

The rules have been created following the Florian Roth methodology described in the 
article "How to write Simple but Sound Yara rules": [Part 1](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/) and [Part2](https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/).
According to Florian, the majority of Yara rules shared on the Internet generate a 
lot of false positives. Besides, a high percentage rules are too specific to match on more that one sample.

To solve this, the author of the articles proposes to check all the strings and to put them into at least 2 
different categories of the following list:
* **Very specific strings** = hard indicators for a malicious sample
* **Rare strings** = likely that they do not appear in goodware samples, but possible
* **Strings that look common** = (Optional) e.g. yarGen output strings that do not seem to be specific but didn’t appear in the goodware string database.

