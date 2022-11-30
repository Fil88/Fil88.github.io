---
title: "Open Source Intelligence (OSINT)" 
layout: "post"
---

In this simple and humble post, I am going to cover the fundamentals of open source intelligence, including how it’s used and the tools and techniques that can be leveraged to gather and analyze it. 

Open-source intelligence (OSINT) is collecting and analysing data from open sources to get intelligence about that source. 
According to CIA, OSINT is intelligence “drawn from publicly available material”.
Open-source doesn’t mean the open-source software movement. It refers to describing the data being analysed as publicly available over open sources (eg. Internet, Social, etc)

OSINT does not require hack into systems or using confidential credentials to access data. 
Viewing someone’s public profile on social media is `OSINT`. Using their login details to information is not and is a criminal offence 🚩


### 1) OSINT Techniques and Tools


OSINT includes all publicly accessible sources of information and this information can be found either online or offline, in the airwaves and on paper. You can gather OSINT from: The Internet, including forums, blogs, social networking sites, video-sharing sites like, wikis, Whois records of registered domain names, metadata and digital files, dark web resources, geolocation data, IP addresses, people search engines, and anything that can be found online. 

Traditional mass media, including television, radio, newspapers, books, magazines, specialised journals, academic publications, dissertations, conference proceedings, company profiles, annual reports, company news, employee profiles, and résumés. Metadata in photos and videos and geospatial information from maps and commercial imagery. OSINT can be gathered from almost anywhere and even the most unlikely of places can provide you with valuable intelligence on the subject of your investigation.

There are two categories of OSINT reconnaissance (recon) techniques: __passive__ and __active__.
__Passive__ recon collects and analyses information about a target network, person or device without directly engaging with the system.
__Active__ recon directly engages with the target system, offering more accurate and, most of the time, more valuable information. 
Nmap is one of the most popular active recon tool to scan IP addresses and ports and provides a detailed view of the target network. But active recon can be risky because Firewalls, IPS devices or security monitoring software can detect and block the scan activity.

Following OSINT tools and techniques are practical for intelligence gathering;


### 1) OSINT Framework

<p align="center">
  <img src="/assets/posts/2021-02-01-Open-Source-Intelligence-(OSINT)/1.PNG">
</p>

The OSINT framework had been developing by Justin Nordine. It is not an application that runs on your server. 
It focuses on bringing the links of OSINT resources. Some of the tools included might require registration or offer more data for money, but you should be able to get at least a demo of the available information for free.

### 2) CheckUserNames

[CheckUserNames:](https://checkusernames.com) is a website searching for usernames for the most popular Social Media and Social Networking sites. Check for your brand, trademark, product or user name. By doing so, you can find the websites where usernames exist, and you can search their profiles on those websites.

### 3) HaveIbeenPwned

[HaveIBeenPwned:](https://haveibeenpwned.com) website is one of my favourite intelligence websites because of its precise and valuable information and user-friendly UI. Pwned means “owned” or “being compromised”, a popular term for online gamers. You can search your e-mail address and phone number to see if your mail or phone number is in any data breach and which ones.

### 4) Censys

[Censys:](https://censys.io) is a pioneer search engine for Internet-connected device attack surfaces. It helps to companies understand their risk. 
According to its website, Censys continuously scans the Internet to find new services and update information.

### 5) Wappalyzer

[Wappalyzer:](https://www.wappalyzer.com/) is a technology profiler that identifies technologies on websites. It finds out what CMS, framework, e-commerce platform, JavaScript libraries and much more technology the website uses

### 6) TheHarvester

[theHarvester:](https://github.com/laramies/theHarvester) is a Linux tool to find information about a company’s DNS servers, Public IP addresses, E-mails, subdomains etc. It uses public search engines to gather information like Google, Baidu, Bing, Yandex etc. It mostly uses passive reconnaissance methods. Next codes should be written sequentially as an example;

### 7) Shodan

[Shodan:](https://www.shodan.io/) is a deep web & internet of things search engine and network security monitor for hackers. John Matherly created it in 2009 to keep track of publicly accessible computers inside any network.

 Shodan can also be used to hunt for C2/Adversarial Infrastructure. Below some basic example of common C2C framework: 

```java
# Cobaltstrike
https://shodan.io/search?query=product%3A%22Cobalt+Strike+Beacon%22
```

```java
# Covenant
https://shodan.io/search?query=ssl%3A%E2%80%9DCovenant%E2%80%9D%20http.component%3A%E2%80%9DBlazor%E2%80%9D
```

```java
# Brute Ratel C4
https://shodan.io/search?query=http.html_hash%3A-1957161625
```

__Note:__ Ideally, for these kind of query a commercial API key is required🚩:

### 8) Creepy

[Creepy:](https://www.geocreepy.com/)is a geolocation OSINT tool that can get complete geolocation data from any post on social networking platforms like Twitter, Flickr, Facebook, etc.
Suppose anyone uploads an image to any social media with the geolocation information activated. In that case, you can see locations where this person has been on the map.

### 9) Nmap

[Nmap:](https://nmap.org/)is one of the most popular network auditing tools, and its name means “Network Mapper”. It is an open-source tool for security auditing and network exploration for not only local but also remote hosts. You can use Nmap anywhere, like macOS, Windows or Linux.
It has an IP detection scan, open port detection scan, OS information detection scan, application version detection scan and vulnerability detection scan features.

### 10) TinEye

[TinEye:](https://tineye.com/)focuses on reverse image searches. You can track the source of any images are appearing online.

### 10) Maltego

[Maltego:](https://www.maltego.com/)Is an amazing tool to track down footprints of any target you need to match. This piece of software has been developed by Paterva, and it’s part of the Kali Linux distribution. Using Maltego will allow you to launch reconnaissance tests against specific targets.

One of the best things this software includes is what they call ‘transforms’. Transforms are available for free in some cases, and on others, you will find commercial versions only. They will help you to run a different kind of tests and data integration with external applications. Once you have chosen your transforms, Maltego app will start running all the transforms from Maltego servers.

### 12) Jigsaw

[Jigsaw:](https://www.jigsawsecurityenterprise.com/)focuses on reverse image searches. You can track the source of any images are appearing online.

### 13) Spiderfoot
[Spiderfoot:](https://www.spiderfoot.net/) is one of the best reconnaissance tools out there if you want to automate OSINT and have fast results for reconnaissance, threat intelligence, and perimeter monitoring. It was written by our friend Steve Micallef, who did a great job building this app and writing the SecurityTrails Addon for Splunk
This recon tool can help you to launch queries over 100 public data sources to gather intelligence on generic names, domain names, email addresses, and IP addresses.

### 13) FOCA
[FOCA:](https://github.com/ElevenPaths/FOCA)(Fingerprinting Organizations with Collected Archives) is a tool written by ElevenPaths that can be used to scan, analyze, extract and classify information from remote web servers and their hidden information.
Foca has the ability to analyze and collect valuable data from MS Office suite, OpenOffice, PDF, as well as Adobe InDesign and SVG and GIF files. This security tool also works actively with Google, Bing and DuckDuckGo search engines to collect additional data from those files. Once you have the full file list, it starts extracting information to attempt to identify more valuable data from the files.



### References 

1. https://medium.com/block-magnates/open-source-intelligence-osint-996c8d2db362
2. https://medium.com/codex/what-is-open-source-intelligence-osint-43e56eb113b4
3. https://github.com/johnjohnsp1/osint_stuff_tool_collection






