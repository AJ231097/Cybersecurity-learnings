Things to Remember
==================

Filters for Web-Based Infection Traffic:
----------------------------------------

1.  HTTP traffic over UDP port 1900 is Simple Service Discovery Protocol (SSDP). SSDP is a protocol used to discover Plug & Play devices, and it is not associated with normal web traffic. Therefore, I filter this out using the following expression:

<mark>(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)</mark>

You can also use the following filter and achieve the same result:

<mark>(http.request or ssl.handshake.type == 1) and !(ssdp)</mark>

2.  We see some indicators of infection traffic, but not every indicator of the infection is revealed. In some cases, an infected host may try to connect with a server that has been taken off-line or is refusing a TCP connection. These attempted connections can be revealed by including TCP SYN segments in your filter by adding tcp.flags eq 0x0002. Try the following filter on the same traffic:  
    

<mark>(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)</mark>
  

Including the TCP SYN segments on your search reveals the infected host also attempted to connect with IP address over ports

Filters for Other Types of Infection Traffic:
---------------------------------------------

In some cases, post-infection traffic will not be web-based, and an infected host will contact command and control (C2) servers. These servers can be directly hosted on IP addresses, or they can be hosted on servers using domain names. Some post-infection activity, like C2 traffic caused by the Nanocore Remote Access Tool (RAT), is not HTTP or HTTPS/SSL/TLS traffic.

Therefore, I often add DNS activity when reviewing a pcap to see if any of these domains are active in the traffic. This results in the following filter expression:

<mark>(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)</mark>

Trickbot Infection:
--------------
Flowchart of Trickbot Infection
![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/11/word-image-61-1024x554.png)


1.  First two bytes of the file show as ASCII characters <mark>PK</mark> then the file is a zip archive

2.  First two bytes of the file show as ASCII characters <mark>MZ</mark> then the file is either an EXE or a DLL file

3. HTTP POST requests ending in <mark>81</mark> send cached password data from web browsers, email clients, and other application

4. HTTP POST requests ending in <mark>83</mark> send form data submitted by applications like web browsers

5. We can find system information sent through HTTP POST requests ending in <mark>90</mark>
