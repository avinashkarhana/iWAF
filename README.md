# iWAF
Intelligent Web Application Firewall

## RUN

### In one terminal/cmd in `iWaf` directory
> cd iwaf

> pip3 install -r requirements.txt

> export FLASK_APP=wafDashboard

> flask run
(This starts dashboard for firewall profile and filter managenemt) Username:Password :: WAFAdmin:DemoWAFuser

### In another terminal/cmd in `iWaf` directory
> cd iwaf

> python3 server.py {port any of choice} {DEBUG if required}

## Contents

- [Chapter 1: Introduction](#Chapter-1-Introduction)
   - [1.1 Aim:](#1-Aim)
   - [1.2 Scope](#12-Scope)
   - [1.3 Overview](#13-Overview)
- [Chapter 2: Literature Survey](#Chapter-2-Literature-Survey)
   - [2.1 What is a Firewall?](#21-What-is-a-Firewall)
      - [2.1.1 What I choose?](#211-What-I-choose)
   - [2.2 Selection of programming language to develop the project](#22-Selection-of-programming-language-to-develop-the-project)
      - [2.2.1 Options Available](#221-Options-Available)
      - [2.2.2 What I choose and why?](#222-What-I-choose-and-why)
- [Chapter 3: Implementation](#Chapter-3-Implementation)
      - [1. Pros of using this application-level system](#1-Pros-of-using-this-application-level-system)
- [Chapter 4: System Requirements](#Chapter-4-System-Requirements)
   - [4.1 Hardware specifications](#41-Hardware-specifications)
   - [4.2 Software specifications](#42-Software-specifications)
- [Chapter 5: Modules](#Chapter-5-Modules)
   - [5.2.1 Web Proxy Server](#521-Web-Proxy-Server)
   - [5.2.2 Filter Rules (Filtering)](#522-filter-rules-filtering)
   - [5.2.3 Intrusion Log](#523-intrusion-log)
- [Chapter 6: Testing](#chapter-6-testing)
   - [6.1 Testing](#61-Testing)
- [Chapter 7: Conclusion and Further enhancements](#chapter-7-conclusion-and-further-enhancements)
   - [7.1 Future Enhancements](#71-future-enhancements)
- [Chapter 8: References](#chapter-8-references)


## Chapter 1: Introduction

### 1. Aim:

The purpose behind this project i.e. Web Application Firewall is that the network connected

systems and applications are always prone to attacks and security of data/information on any

system becomes a prime focus, so to solve this issue either application have to become secure

or an external system has to be used to prevent any undesired happening, so this is where

firewalls come into action. Firewalls work by preventing unauthorized access and maintain

the security of a private network. These are often employed to prevent unauthorized Web

users or illicit software from gaining access to private networks connected to the Internet.

A firewall may work at packet/Network Level or at the application level or both. This project

works at the application level and works specifically for web-based applications using TCP/IP

and protects them from various possible attacks.

### 1.2 Scope

In the digitally connected era task to prevent web application from attacks that could harm

systems and data become very important. For this, we have scope for this Web Application

Firewall as follows

##### •```Providing security from data breaches.```
##### •```Making system immune to data tampering.```
##### •```Reducing runtime errors in applications due to user data.```
##### •```Robust.```
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/Visitor.png?raw=true "WAF")
```
Figure 1: Web Application Firewall WAF
```

### 1.3 Overview

This firewall is will work as the first line of defense in securing sensitive information. For

better safety, the respective applications can be strengthened in the sense of data using

cryptographic techniques.

This project starts by developing a web proxy server using socket programming, this

prototype just passes requests from one side to another.

After that, this proxy server is customized to serve data and request to and fro for specific

web application server.

Leading and the last task is to apply firewall rules to prevent known attacks and their pattern to

filter potential attack requests. Hence after refining filter rules and modifications, the web application firewall is deployed 

ahead of the actual web application server to work on behalf of it

mitigating any kind of threat.
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/server.py.png?raw=true "WAF")
```
Figure 2: Code Sample
```

## Chapter 2: Literature Survey

### 2.1 What is a Firewall?

A firewall is a network security system that monitors and controls incoming and

outgoing network traffic based on predetermined security rules. A firewall typically

establishes a barrier between a trusted internal network and untrusted external network, such

as the Internet. A firewall can be working at the packet/network level or application level or both, 

packet-level firewalls are more of network isolation type and application-level focuses

on request to specific application or application type.

#### 2.1.1 What I choose?

For this project, I choose Application Level to work more closely to target the web

applications.

### 2.2 Selection of programming language to develop the project

There are many programming languages available out there.

#### 2.2.1 Options Available

##### ➢```Python```
##### ➢```PHP (Hypertext Pre-processor)```
##### ➢```C++```
##### ➢```C```


#### 2.2.1 What I choose and why?

I selected Python as the programming language for this project. As it serves all necessary

features required including socket level programming, which is the key factor to handle

requests and filter non-legit ones from legit request and protect the web application from attacks

that could be a potential threat to data.
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/page4image12632480.png?raw=true "Python")
```
Figure 3: Python as a programming language
```

## Chapter 3: Implementation

Like any other type of firewall, this one also acts as the first line of defense to the application. The

four-step security lifecycle is critical during firewall installation:

##### •```Secure```
##### •```Monitor```
##### •```Test```
##### •```Improve```
This is a continuous process that loops back on itself in a persistent cycle of protection.

Before any device is connected to your network, make sure that you have documented the

network infrastructure and hardened the device or the box it will run on. This means applying

patches as well as taking the time to configure the device for increased security.
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/Destination.png?raw=true "WAF")

#### 1. Pros of using this application-level firewall system

1. More responsive
2. Better Customisability
3. Application targeting
4. Low cost
5. More Authentication measures
6. Actual sever hidden


## Chapter 4: System Requirements

### 4.1 Hardware specifications

The machine specifications to serve this Web Application Firewall are as follow

##### ➢```If code needs to be changed frequently```
   ##### ▪```A Python3 Installed System```
##### ➢```If the code is stable and needs no further enhancement```
   ##### ▪```Just enough computation power to run firewall server executable```
### 4.2 Software specifications

The software specifications for this type of system are as follow

##### ➢```Interpreter : Python```
##### ➢```Libraries : os, sys, socket, time, _thread```

## Chapter 5: Modules

The whole project works on a few modules such as

#### 5.2.1 Web Proxy Server
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/WAF%20%24%20python3%20server.py%208888%20debug.png?raw=true "WAF")
```
Figure 4: WAF Proxy
```
#### 5.2.2 Filter Rules (Filtering)
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/pythons%20server.py%208888%20debug.png?raw=true "WAF")
```
Figure 5: WAF Filter
```

#### 5.2.3 Intrusion Log
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/LOG.png?raw=true "WAF")
```
Figure 6: WAF Log File
```
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/LOG2.png?raw=true "WAF")
```
Figure 7: WAF Log
```

## Chapter 6: Testing

### 6.1 Testing

Accessing webserver behind WAF

Case 1 : Legit Request

##### ➢```Actual web application (online.hnbgu.ac.in) (website server)```
##### ➢```Firewall address : 127.0.0.1```
##### ➢```Firewall Port : 8888```
##### ➢```Visitor address : 192.168.43.60```
##### ➢```Page visited : root(http://127.0.0.1:8888/)```
##### ➢```Request : GET / HTTP/1.1 (LEGIT)```
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/case1.png?raw=true "WAF")
```
! Result : Not Filtered
```

Case 2 : Attacker Request

##### ➢```Actual web application (online.hnbgu.ac.in) (website server)```
##### ➢```Firewall address : 127.0.0.1```
##### ➢```Firewall Port : 8888```
##### ➢```Visitor address : 192.168.43.1```
##### ➢```Page visited : root(http://127.0.0.1:8888/cbcs2016/app_main.php)```
##### ➢```Request : POST /cbcs2016/app_main.php HTTP/1.```
{arguments: ?user_id=1+AND+SELECT+*+FROM+USER&pass=1} (SQL INJECTION)
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/case2.png?raw=true "WAF")
```
! Result : Filtered And Logged
```

Case 3 : Unwanted Request from blocked IP

##### ➢```Actual web application (online.hnbgu.ac.in) (website server)```
##### ➢```Firewall address : 127.0.0.1```
##### ➢```Firewall Port : 8888```
##### ➢```Visitor address : 192.168.43.131```
##### ➢```Page visited : root(http://127.0.0.1:8888/)```
##### ➢```Request : POST / HTTP/1.1 (UNKNOWN)```
![alt text](https://github.com/avinashkarhana/iWAF/blob/master/iwaf/tmp/case3.png?raw=true "WAF")
```
! Result : Filtered
```

## Chapter 7: Conclusion and Further enhancements

The conclusion of this project is that the solution understand web protection at the application

layer (HTTP and HTTPS conversations to your web applications, XML/SOAP, and Web

Services). And this type of prevention measure works better than other as compare on behalf

of implementation and deployment cost and security level.

### 7.1 Future Enhancements

There can be future the enhancements in the project like

##### ➢~~```Filter rule flexibility can be introduced```~~ 
Now Rule management available via database
##### ➢```Multi-Application handling can be added```
And many more.


## Chapter 8: References

##### ➢```Google (https://www.google.co.in/)```
##### ➢```RealPython (https://realpython.com/)```
##### ➢```pypi (https://pypi.org/)```
##### ➢```Python Docs (https://docs.python.org/)```
