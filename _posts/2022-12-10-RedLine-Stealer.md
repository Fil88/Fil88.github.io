---
title: "Lapsus$ - RedLine Stealer Investigations" 
layout: "post"
---

 
## Description

RedLine Stealer is an information stealer malware sold on various online criminal forums (i.e. “Malware-as- a-Service”) by the Russian cybercriminal “REDGlade”, which has the objective to steal sensitive data such as usernames, passwords, cookies, payment card information, etc.
RedLine has been distributed since the first months of 2020 but has become more prevalent in 2021 and the stolen information are sold on multiple criminal shops, including Amigos Market and Russian Market. The malware is frequently distributed by phishing email and messaging on social media, abusing themes such as COVID-19. Moreover, it masquerades itself as legitimate software installer (e.g. Messaging app, privacy software, etc.).





RedLine Stealer can also be used to load additional malware onto the victim system, since it provides download and execution capabilities.
According to the threat actors who have developed RedLine Stealer, the malware has an admin panel developed in C# and it steals login data from multiple sources, including:

• All Chromium and Mozilla Gecko-based web browsers
• Cookies
• Account credentials
• Payment card data
• Autofill forms
• FTP and Instant messenger client data.

The following image shows a RedLine sales thread on the dark web. 

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/1.JPG">
</p>

The following image shows a RedLine Stealer build settings panel.

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/2.JPG">
</p>

The 24th of January 2022, the well-known online sandbox “ANY.RUN” published the list of the most uploaded cyber threats and RedLine Stealer was on top of this list.


<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/3.JPG">
</p>

## Hunting

The threat activities were focused on searching for:

• connections to RedLine Stealer command and control servers
• execution of RedLine Stealer on the endpoints monitored by the EDR
• presence of signs of persistence techniques correlated to RedLine Stealer


### 1. LastPass

In November 2021, CERT-AGID identified a RedLine Stealer sample that was delivered through a fake LastPass browser plugin installation. The malware was a PE file, written in .NET, with a “.ISO” file extension. By running the executable, the malware downloads via an encoded PowerShell script the second stage of the malware that was residing in the domain “cdn.discordapp.com”.
By searching for the following query, it is possible to identify suspicious process that do not belong to Discord or Browsers which perform connections to “cdn.discordapp.com”

```powershell 
DeviceNetworkEvents
| where RemoteUrl contains "cdn.discordapp.com"
| where InitiatingProcessParentFileName != @"Discord.exe"
| where InitiatingProcessFileName != @"msedge.exe"
| where InitiatingProcessFileName != @"chrome.exe"
| where InitiatingProcessFileName != @"opera.exe"
| where InitiatingProcessFileName != @"firefox.exe"
```

The above-mentioned query – executed on the last 30 days – has not produced any results

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/4.JPG">
</p>

The malware achieves persistence on the compromised endpoint by adding a key called “sys_w4” on the following registry:

• HKCU\Software\Microsoft\Windows\CurrentVersion\Run

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/5.JPG">
</p>

By searching for the following query, it is possible to identify run registry keys which are named “sys_w4”.

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/6.JPG">
</p>

```powershell 
DeviceRegistryEvents
| where RegistryKey contains "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
| where RegistryValueName contains "sys_w4"
```

The above-mentioned query – executed on the last 30 days – has not produced any results.

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/8.JPG">
</p>

Finally, it has been performed various queries to identify the IoCs described on CERT-AGID report. The queries – performed on the last 30 days – has not identified any match with the reported IoCs.

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/9.JPG">
</p>


### 2. Omicron Stats

The first days of 2022, Fortinet identified a RedLine Stealer sample named “Omicron Stats.exe” which probably has been distributed through COVID-theme emails. Once the malware is executed, it copies itself to the following path:

• C:\Users\[Username]\AppData\Roaming\chromedrlvers.exe

After, the malware creates the following scheduled task in order to achieve persistence:

• schtasks /create /sc minute /mo 1 /tn "Nania" /tr "'C:\Users\[Username]\AppData\Roaming\chromedrlvers.exe'" /f

By searching for the following query, it is possible to identify the execution of processes named “chromedrlvers” that could potentially be associated with RedLine Stealer.

```powershell 
DeviceProcessEvents
| where FileName contains @"chromedrlvers" 
```
The above-mentioned query – executed on the last 30 days – has not produced any results.

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/10.JPG">
</p>


```powershell 
DeviceProcessEvents
| where Filename contains @”schtasks”
| where ProcessCommandLine contains @”create /sc minute /mo” 
```

By searching for the following query, it is possible to identify the execution of potential persistence mechanism through scheduled tasks.

The above-mentioned query – executed on the last 30 days – has not produced any results. Finally, it has been performed various queries to identify the IoCs described on Fortinet report.
The queries performed on the last 30 days – has not identified any match with the reported IoCs.


### 3. Malicious Excel XLL file

In some cases, threat actors have created fake websites to host malicious Excel XLL files with the objective to compromise victims’ endpoints with RedLine Stealer malware. XLL files are DLL files that include a function name “xlAutoOpen” that is executed by Excel when the file is opened.


<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/12.JPG">
</p>


After executing the Excel XLL file, it downloads through the process “wget.exe” the RedLine Stealer malware and saves the second stage as “%UserProfile%\JavaBridge32.exe”. Moreover, the malware achieves persistence by adding a key into the Windows registry.


```powershell 
DeviceProcessEvents
| where InitiatingProcessFileName has @"excel.exe"
| where FileName has @"wget.exe" 
```

The above-mentioned query – executed on the last 30 days – has not produced any results.

### 4. Other RedLine Samples

During the threat hunting activities, the last RedLine Stealer samples uploaded on public sandboxes have been analyzed to identify specific techniques adopted by the malware:

•	Evasion: RedLine Stealer tries to disable Windows Defender real-time protection via PowerShell.

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/12.JPG">
</p>

By searching for the following query, it is possible to identify potential malicious processes that are trying to disable Windows Defender.

```powershell 
DeviceProcessEvents
| where InitiatingProcessFileName == @”cmd.exe”
| where FileName == @”powershell.exe”
| where ProcessCommandLine contains @”DisableRealtimeMonitoring”
```

The above-mentioned query – executed on the last 30 days – has not produced any results.

•	Persistence: RedLine Stealer creates a task that is executed every time a user login into the endpoint.

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/14.JPG">
</p>

By searching for the following query, it is possible to identify process that achieves persistence through scheduled tasks that are triggered every time a user logs in. 

```powershell 
DeviceProcessEvents
| where InitiatingProcessFileName == @”cmd.exe”
| where FileName == @”powershell.exe”
| where ProcessCommandLine contains @”DisableRealtimeMonitoring”
```

The above-mentioned query – executed on the last 30 days – has not produced any results.

Furthermore, other IoCs related to RedLine Stealer have been extracted from the databases of MalwareBazaar and ThreatFox and have been searched through the EDR.

The queries – performed on the last 30 days – has not identified any match with the specified IoCs.

<p align="center">
  <img src="/assets/posts/2022-12-10-RedLine-Stealer/15.JPG">
</p>


## References 

1. https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus- themed-email-campaign

2. https://cyber-anubis.github.io/malware%20analysis/redline/

3. https://www.fortinet.com/blog/threat-research/omicron-variant-lure-used-to-distribute-redline-stealer https://go.recordedfuture.com/hubfs/reports/mtp-2021-1014.pdf https://blogs.blackberry.com/en/2021/07/threat-thursday-redline-infostealer

4. https://cert-agid.gov.it/news/scoperto-il-malware-redline-stealer-veicolato-come-lastpass/

5. https://blogs.blackberry.com/en/2021/07/threat-thursday-redline-infostealer