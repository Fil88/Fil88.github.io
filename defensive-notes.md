---
title: "Defensive Notes" 
layout: "post"
---

## LOLBAS Use case

In the section below we will implement some LOLBAS use case using Splunk as a framework to perform our hunting activities.

__Note:__ These detections rules are specific to my environment


# 1) Bitsadmin Download File

The following query identifies Microsoft Background Intelligent Transfer Service utility bitsadmin.exe using the transfer parameter to download a remote object. 
In addition, look for download or upload on the command-line, the switches are not required to perform a transfer.

```powershell 
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_bitsadmin` Processes.process=*transfer* by Processes.dest Processes.user Processes.parent_process Processes.original_file_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `bitsadmin_download_file_filter`
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

# 5) wmic

__Note:__ This is not an exaustive list of LOLBAS to monitor but rather a baseline. Your environment define your tailor made detection rules.

https://docs.splunksecurityessentials.com/content-detail/certutil_download_with_urlcache_and_split_arguments/


# 6) Notepad cache

[lazy]People like me use __Notepad++__ as a note-taking thing. We create a 'new', then never get around to saving them.

They get cached here:
`C:\Users\{username}\AppData\Roaming\Notepad++\backup`

# 7) Procdump.exe 

If you rename __procdump.exe to __dump64.exe__ and place it in the "C:\Program Files (x86)\Microsoft Visual Studio\*" folder, you can bypass Defender and dump __LSASS__.


# 8) Disable Defender 

```powershell
shell Set-MpPreference -DisableRealtimeMonitoring $true 
shell Set-MpPreference -EnableRealtimeMonitoring $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableScanningNetworkFiles $true
Set-MpPreference -MAPSReporting 0
Set-MpPreference -DisableCatchupFullScan $True
Set-MpPreference -DisableCatchupQuickScan $True
```

# 9) SQldumper LSASS

0x01100:40 flag will create a Mimikatz compatible dump file.

__sqldumper.exe__ 540 0 0x01100:40

Usecase: Dump __LSASS.exe__ to Mimikatz compatible dump using PID.

