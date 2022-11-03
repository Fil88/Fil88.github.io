---
title: "Understanding CobaltStrike Malleable C2C profile" 
layout: "post"
---

One of the great and popular features of cobalt strike is the ability to create profiles  to shape and mask traffic, 
essentially a profile is used to tell the CS `teamserver` how traffic is going to look and how to respond to the data the beacon sends it.

<p align="center">
  <img src="/assets/posts/2021-10-03-Malleable-C2-profile/1.PNG">
</p>



## 1) Hunting CobaltStrike Sacrifical process

<p align="center">
  <img src="/assets/posts/2021-10-03-Malleable-C2-profile/dodgeCob.png">
</p>


Cobalt Strike is a commercial post-exploitation framework used by various malware families responsible for the initial infection stage (i.e. droppers), such as IcedID, ZLoader, QBot, Ursnif, etc.

Threat actors frequently chose Cobalt Strike since it provides enhanced post-exploitation capabilities (e.g. privilege escalation functionalities) and it is quite straightforward to use. The built-in features in Cobalt Strike support all phases of an attack, from reconnaissance and initial access to credential dumping and data exfiltration.

Moreover, Cobalt Strike has the feature to personalize the configuration of the backdoors, also called “beacons”. Therefore, threat actors can change parameters such as URI, user agent, protocol from the network communication to individual post-exploitation functions such as process injection and payload obfuscation capabilities.

Most of the Cobalt Strike features are implemented as Windows DLLs, meaning that every time a threat actor runs the built-in functionalities, Cobalt Strike spawns a temporary process to inject malicious code into it, and communicates the results back to the beacon. Those temporary processes are called __sacrificial__ __processes__.  


<p align="center">
  <img src="/assets/posts/2021-10-03-Malleable-C2-profile/sacrifical1.png">
</p>

Is important to underline that not all Cobalt Strike features require a sacrificial process to be executed. Beacon Object Files   for Cobalt Strike for example load everything via the beacon payload.
Cobalt Strike Beacon uses the Sacrificial Process pattern (also called Fork&Run pattern) for a number of reasons:

1.	This protects the agent if the capability crashes.
2.	Historically, this scheme makes it seamless for an x86 Beacon to launch x64 post-exploitation tasks. This was critical as Beacon didn't have an x64 build until 2016. 
3.	Some features can target a specific remote process. This allows the post-ex action to occur within different contexts without the need to migrate or spawn a payload in that other context. 
4.	This design decision keeps a lot of clutter (threads, suspicious content) generated by your post-ex action out of your Beacon process space
Below are the features that use this pattern:

Sacrificial Process pattern only:
1.	covertvpn
2.	execute-assembly
3.	powerpick

Target Explicit Process Only:
1.	browserpivot
2.	psinject

Sacrificial Process pattern or Target Explicit Process
1.	chromedump
2.	dcsync
3.	desktop
4.	hashdump
5.	keylogger
6.	logonpasswords
7.	mimikatz
8.	net *
9.	portscan
10.	printscreen
11.	pth
12.	screenshot
13.	screenwatch
14.	ssh
15.	ssh-key

The sacrificial processes that have to be used from the Cobalt Strike beacon can be modified directly from the post-ex section of Cobalt Strike Malleable C2 profile:

post-ex {
	# control the temporary process we spawn to
	set spawnto_x86 "%windir%\\syswow64\\rundll32.exe";
	set spawnto_x64 "%windir%\\sysnative\\rundll32.exe";
	…
}

The default configuration uses `rundll32.exe`.

## 2) Hunting Sacrifical Process 

Hunting the Cobalt Strike Sacrificial Process pattern, it's not an easy task for several reasons:

1.	Cobalt Strike is well known as a flexible, stealthy, and compatible framework. It can be configured and customized in different ways, starting from modifying the Malleable C2 profile up to using custom techniques in in others hide the beacon and make it as silent as possible.

2.	Cobalt Strike leverage the usage of system processes to hide and assimilate as much as possible with normal activities and processes running on the victim's machine. 

During a recent investigaction activity we have been able to collect 9174 Cobalt Strike Malleable C2 profile used “in to the wild”. Analysing and parsing them we can extract some very interesting information:

-	The executable `rundll32.exe` is by far the most used `spawnto` configuration
-	In the majority of `spawnto` configuration the process is expected to be spawned without any arguments

The graph below shows the top 20 “spawnto” configurations:

<p align="center">
  <img src="/assets/posts/2021-10-03-Malleable-C2-profile/spawnto.png">
</p>

It should be noted that `sysnative` folder is a virtual folder, a special alias, that can be used to access the 64-bit System32 folder from a 32-bit application or script. 

In approximately the 81% of the parsed configurations the sacrificial process is expected to be spawned without any arguments.
Two different approach will be used in order to identify the sacrificial process pattern:

1.	Abnormal system process creation events. 
  a.	Hunting for sacrificial processes spawned without any arguments

2.	Anomalous parent/child relationships.
  a.	Multiple sacrificial processes spawned by a single powershell process

The techniques that have been identified have been summarized in the following table and mapped based on __MITRE__ __ATT&CK__ knowledge base: 

```py
Execution	T1059.001 – Command and Scripting Interpreter: PowerShell
Defence Evasion	T1055.002 – Process Injection: Portable Executable Injection
```

### Abnormal system process creation events

T1055.002 – Process Injection: Portable Executable Injection - Sacrificial Processes spawned without any arguments

One of the most common and simple detection method which can be used in order to highlight an abnormal system process creation events related to Cobalt Strike is related to the command line used in order to execute the sacrificial process. Specifically, Cobalt Strike beacon spawn the sacrificial process without any arguments. 

By tracking down the Process Creation events from Microsoft Defender for Endpoint it was possible to identify, after filtering events that can be assimilated to normal activity, some interesting matches to analyze:

<p align="center">
  <img src="/assets/posts/2021-10-03-Malleable-C2-profile/huntSacr.png">
</p>

## 3) Hunting CobaltStrike Named Pipe

A named pipe is a logical connection, similar to a TCP session, between a client and server that are involved in a Common Internet File System (CIFS)/SMB/SMB Version 2 and Version 3 connection. The name of the pipe serves as the endpoint for communication in the same way that a port number serves as the endpoint for TCP sessions. This is called a named pipe endpoint.

A named pipe is a named, one-way or duplex pipe for communication between the pipe server and one or more pipe clients. Cobalt Strike uses named pipes in many ways and has default values used with the Artifact Kit and Malleable C2 Profiles

Considerable efforts have been made to build robust signatures for Cobalt Strike and its implant, Beacon. The aim of this post is to examine some previously unknown Indicators of Compromise (IoCs). This post is not going to cover signatures for the default Cobalt Strike configuration - other papers offer an in-depth look at this. Instead, we will focus our attention on some of the built-in modules that provide Cobalt Strike's post exploitation capability, such as the keylogger, Mimikatz and the screenshot modules.

Pipes are shared memory used for processes to communicate between each other. Fundamentally there are two types of pipe: named and unnamed.

- Named pipes, as the name implies, have a name and can be accessed by referencing this. 

- Unnamed pipes, that need their handle to be passed to the other communicating process in order to exchange data. This can be done in a number of ways. 

Cobalt Strike uses both named and unnamed pipes to exchange data between the beacon and its sacrificial processes.

The simple MDE query listed below can be used to hunt for lazy CS 4.2+ operators who don't customize default pipe names.

```cpp
let badPipeNames = pack_array(
  '\\csexecsvc'
  '\\MSSE-',
  '\\MSSE-',
  '\\msagent_', 
  '\\postex_');
// maximum lookback time
let minTimeRange = ago(7d);
// this is what should be constantly tweaked with default C2 framework names, search uses has_any (wildcard)
DeviceEvents
| where ActionType == "NamedPipeEvent" and Timestamp > minTimeRange
| extend ParsedFields=parse_json(AdditionalFields)
| where ParsedFields.FileOperation == "File created"
| where ParsedFields.PipeName has_any (badPipeNames)
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ParsedFields.FileOperation, ParsedFields.PipeName

```

### Anonymous Pipes

Not every Cobalt Strike command creates a named pipe, some of them will use anonymous (unnamed) pipes to achieve the same result. 
The image below shows an instance of a pipe created after issuing the "execute-assembly" command:

<p align="center">
  <img src="/assets/posts/2021-10-03-Malleable-C2-profile/anonymousPipe.png">
</p>

In theory, we could baseline processes that use anonymous pipes. The interesting result is that native Windows processes do not use anonymous pipes that often. So we could look for Windows processes that connect to an anonymous pipe and investigate from there.

We mention "Windows processes" because, more often than not, attackers use native Windows binaries as sacrificial processes within their malleable profiles. Examples of such are the binaries listed in the C2Concealer repository, a project used to create randomised malleable profiles. We can see the executables from the C2Concealer default configuration below:

<p align="center">
  <img src="/assets/posts/2021-10-03-Malleable-C2-profile/concealer.png">
</p>

As it is possible to see, the above-mentioned processes are used for post exploitation jobs. None of them usually use anonymous pipes to communicate with different processes; it would therefore be possible to use this to perform hunting and eventually create detection rules.

During experiments, the following Windows binaries were found to be using anonymous pipes for interprocess communication:

- `wsmprovhost.exe`
- `ngen.exe`
- `splunk.exe`
- `splunkd.exe`
- `firefox.exe`

The same applies to custom reflective DLLs that are executed via Cobalt Strike's dllspawn API, as the underlying mechanism for communication is the same. 
An example of such is the Outflank's Ps-Tools repository. Ps-Tools is a collection of rDLL fully compatible with Cobalt Strike that allow operators to monitor process activity. 
Let's execute the "psw" module, used to enumerate the active Windows, as shown below:

<p align="center">
  <img src="/assets/posts/2021-10-03-Malleable-C2-profile/execAss.png">
</p>

Executing this module, we can identify the same anonymous pipe behaviour we've seen in our previous example:

<p align="center">
  <img src="/assets/posts/2021-10-03-Malleable-C2-profile/anon.png">
</p>


### Detection Limitations & OPSEC consideration 

From a red teaming perspective, Cobalt Strike version 4.2 gives operators the ability to modify the aforementioned named pipe naming convention. In fact, it would be possible to configure the "pipename" parameter within the "post-ex" block with a name that would, ideally, blend-in with the pipes used in the environement.

An example of a "post-ex" block is shown below:

```cpp
post-ex {
    
    set spawnto_x86 "%windir%\\syswow64\\wusa.exe";
    set spawnto_x64 "%windir%\\sysnative\\wusa.exe";

    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";

    set pipename "pipe\\CtxSharefilepipe###,";
}
```

Additionally, choosing binaries that legitimately use anonymous pipes in the "spawnto_x86" and "spawnto_x64" parameters will decrease the chances of being detected.

The official malleable command reference and ThreatExpress' jQuery example profile are great resources for learning more about Cobalt Strike's malleable profile options.

Altought these are good practice for defender there are many resources that can generate random CobaltStrike Malleable profile making hunting activities hard to implement. Below some project used to generate random Cobalt Strike profile: 

- [random_c2_profile] (https://github.com/threatexpress/random_c2_profile) Cobalt Strike random C2 Profile generator

- [C2concealer] (https://github.com/FortyNorthSecurity/C2concealer) C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike

- [SourcePoint] (https://github.com/Tylous/SourcePoint) SourcePoint is a polymorphic C2 profile generator for Cobalt Strike C2s, written in Go

__Note:__ CobaltStrike can be customized in many different ways (Artifact Kit, Resource Kit, BOF, etc) Be creative in your hunting scenarios and attributes 🚩:


## References 

1.	https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_controll-post-exploitation.htm#_Toc65482859
2.	https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm 
3.	https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/ 
4. https://svch0st.medium.com/stats-from-hunting-cobalt-strike-beacons-c17e56255f9b
5. https://blog.securehat.co.uk/cobaltstrike/extracting-config-from-cobaltstrike-stager-shellcode
6. https://blog.zsec.uk/cobalt-strike-profiles/
7. https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/pipe_created_susp_cobaltstrike_pipe_patterns.yml
8. https://blog.sekoia.io/hunting-and-detecting-cobalt-strike/
9. https://github.com/xx0hcd/Malleable-C2-Profiles
10. https://reconshell.com/list-of-awesome-cobaltstrike-resources/



