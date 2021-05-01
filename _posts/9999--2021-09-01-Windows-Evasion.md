---
title: "Windows Evasion " 
layout: "post"
---

In the modern enterprise Windows  environment we often encounter lots of obstacles, which try to detect and stop our sneaky tools and techniques. Endpoint protection agents (AV, IDS/IPS, EDR, etc.) are getting better and better at this, so this requires an extended effort in finding a way into the system and staying undetected during post-exploitation activities.
We will try to highlight some tecniques and sample code used to bypass modern defenses. 









 






## Add File binary signature

1) `Simple Process Injection - GetProcAddress() > VirtualAlloc() > CreateRemoteThread()`


## Add AES paylod Encryption

2) `Add AES paylod Encryption`



## Anti analysis defenses

3) `Anti analysis defenses`

In order to protect our malware from being analyzed by security engenieer we will add some simple defenses tecniques used to protect our custom dropper. The objectives here, most of the time, is being able to detect if the malware is being opened in a __VirtualEnvironment__ like virtual box or any vistualization software. 

```cpp
// check CPU
SYSTEM_INFO systemInfo;
GetSystemInfo(&systemInfo);
DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
if (numberOfProcessors < 2) return 0;
```
__IMG 1:__ Checking CPU


## PPiD Spoofing 


## Silecing ETW 


