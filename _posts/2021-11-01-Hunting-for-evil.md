---
title: "Hunting for Evil" 
layout: "post"
---

__Threat__ __hunting__ - the act of aggressively intercepting, tracking and eliminating cyber adversaries as early as possible in the Cyber Kill Chain.
Threats are human. Focused and funded adversaries will not be countered by security boxes on the network alone. Threat hunters are actively searching for threats to prevent or minimize damage before it happens.







This concept can be easily summarized with the Locard's Exchange Principle, which says that: "Every Contact leave a trace"

<p align="center">
  <img src="/assets/posts/2021-11-01-Hunting-for-Evil/pyramidofpain.JPG">
</p>


## 1) Introduction to Threat hunting 

In traditional security monitoring approach, most of the blue teamers look out for threats based on the alerts being triggered out by SIEM or other security devices.
In addition to alert–driven approach, why can’t we add a continuous process for finding stuff from the data without any alerts driving us for incident. 
That’s the process of Threat hunting, proactively looking out for threats in network. 
Those threats which are not identified by your existing security solutions or attacks which bypassed your solutions can be hunted down using this process.

As a baseline the following steps are needed to perform hunting activities: 

- Develop Hypothesis – Hypothesis means what u want to look for, like looking out for powershell commands making connection to internet etc.
- Gather data – Based on the hypothesis, look out for data you need to collect for hunting.
- Test hypothesis and gather hunting – Once data is collected, look out for threats based on behavior, search queries .
- Automate certain tasks – Threat hunting can never be fully automated but semi-automated.
- Operationalize Threat Hunting – Now, instead of ad-hoc hunting, operationalize your hunting program so that we can perform continuous threat hunting.

Most of the threat hunting platforms uses “Attack MITRE” adversary model. MITRE ATT&CK™ is a globally-accessible knowledge base of adversary tactics and
techniques based on real-world observations. 

The Mitre team has listed down all those adversary behaviors and attack vectors carries out by an adversary on a victim machine. 
It provides you with description as well as some references regarding the threats, based on historical outbreak. 
It uses TTP’s Tactics, Techniques and Procedures and maps it to Cyber Kill chain.




Below some basic example of practical threat hunting approach based on hypothesis.

- 1 Word or excel file opening powershell which runs mimikatz command for hash dumping – To check this hypothesis, first look for data, do we have
proper data to hunt for this hypothesis, then hunt for __winword.exe__ __execl.exe__ process creating powershell.exe, and command line containing (
mimikatz ).

- 2 Downloading files from internet (Other than browser) – Look out for process which are used to download files from internet other than browser,
certutil.exe , hh.exe can be used for the same.

- 3 Powershell download cradles event_data.CommandLine:(*powershell* *pwsh* *SyncAppvPublishingServer*) AND event_data.CommandLine:(*BitsTransfer* *webclient* *DownloadFile* *downloadstring* *wget* *curl* *WebRequest* *WinHttpRequest* iwr irm "*internetExplorer.Application*" "*Msxml2.XMLHTTP*" "*MsXml2.ServerXmlHttp*")

- 4 Using certutil for downloading event_data.CommandLine:(*certutil*) AND event_data.CommandLine:(*urlcach* *url* *ping*) AND event_data.CommandLine:(*http* *ftp*)


__Note:__ Testing 


## 2) Basic LOLBAL Hunting with Splunk 