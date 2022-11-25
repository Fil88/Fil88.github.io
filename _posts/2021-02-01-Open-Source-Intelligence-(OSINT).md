---
title: "Open Source Intelligence (OSINT)" 
layout: "post"
---
Open-source intelligence (OSINT) is collecting and analysing data from open sources to get intelligence about that source. 
According to CIA, OSINT is intelligence “drawn from publicly available material”.
Open-source doesn’t mean the open-source software movement. It refers to describing the data being analysed as publicly available over open sources (eg. Internet, Social, etc)

OSINT does not require hack into systems or using confidential credentials to access data. 
Viewing someone’s public profile on social media is `OSINT`; using their login details to information is not and is a criminal offence


### 1) OSINT Techniques and Tools

There are two categories of OSINT reconnaissance (recon) techniques: __passive__ and __active__.
__Passive__ recon collects and analyses information about a target network, person or device without directly engaging with the system.
__Active__ recon directly engages with the target system, offering more accurate and, most of the time, more valuable information. 
Nmap is one of the most popular active recon tool to scan IP addresses and ports and provides a detailed view of the target network. But active recon can be risky because Firewalls or IPS devices can detect and block the scanner.

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

[Creepy:](https://www.geocreepy.com/) is a geolocation OSINT tool that can get complete geolocation data from any post on social networking platforms like Twitter, Flickr, Facebook, etc.
Suppose anyone uploads an image to any social media with the geolocation information activated. In that case, you can see locations where this person has been on the map.

### 9) Nmap

[Nmap:](https://nmap.org/) is one of the most popular network auditing tools, and its name means “Network Mapper”. It is an open-source tool for security auditing and network exploration for not only local but also remote hosts. You can use Nmap anywhere, like macOS, Windows or Linux.
It has an IP detection scan, open port detection scan, OS information detection scan, application version detection scan and vulnerability detection scan features.

### 10) TinEye

[TinEye:](https://tineye.com/) focuses on reverse image searches. You can track the source of any images are appearing online.



### References 

1. https://medium.com/block-magnates/open-source-intelligence-osint-996c8d2db362
2. https://medium.com/codex/what-is-open-source-intelligence-osint-43e56eb113b4





