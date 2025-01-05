# detection-lab2

Objective

The Detection Lab project aimed to establish a environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within Splunk, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

Skills Learned

- Understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

Tools Used

- Splunk for log ingestion and analysis.
- Suricata for capturing and examining network traffic.
- Kali Linux and Atomic Red Team to create realistic network traffic and attack scenarios.

Network Diagram

![detection_lab2](https://github.com/user-attachments/assets/c5f14131-f48e-4ac4-922f-5e4a7c3a80cd)

Steps

In this lab, I created LAN network in VirtualBox with ‘NAT Network’.

1-Installation and Setup of Virtual Machines
- Kali Linux (attacker), Windows 10 (victim), Windows Server (AD), Ubuntu 22.04 (Suricata) and Ubuntu 22.04 (Splunk) were installed on VirtuelBox as virtual machines.
- Splunk Enterprise was installed on the Ubuntu machine to view logs.
- Universal Forwarder and Sysmon were installed on Windows 10 (victim) and Windows Server (AD) machine to send logs to Splunk.
- Also, Atomic Red Team was installed on Windows 10 (victim) to generate attack signatures.
- After selecting ‘NAT Network' as network, static IP address was determined on each virtual machine.
- After all that, we saw that the virtual machines were reachable with the ‘ping’ command.

2-Splunk
- First, I changed the IP address to static IP.
  - sudo nano /etc/netplan/00-installer-config.yaml
  - IP:192.168.10.10
- I installed Splunk and ran it.
  - sudo dpkg -i <splunk .deb folder>
  - sudo –u splunk bash #I switched to splunk user
  - $SPLUNK_HOME/bin/splunk start –accept-license
- I activated 'boot start'.
  - sudo $SPLUNK_HOME/bin/splunk enable boot-start -user splunk

3-Windows 10/Windows Server (AD)
- First, I changed the names of the machines.
  - PC>Settings> Windows 10: ‘target-PC’, Windows Server: ‘ADDC01’
- I then changed the IP address to static IP.
  - Internet Settings>Change Adapter Options>Ethernet>Properties>IPv4 Properties>Manual
  - Windows 10 IP:192.168.10.100, Windows Server IP:192.168.10.7
- I installed Splunk Forwarder
  - Receiving Server> Host/IP: 192.168.10.10, Port:9997
- After downloading Sysmon, I downloaded the configuration file (olaf configuration) from github. To do the installation in Powershell, I went to the sysmon file path and entered the command. Since the configuration file is in the previous folder, I specified it with '..\' when entering the command.
  - .\Sysmon64.exe -i ..\sysmonconfig.xml
- For Universal Forwarder we need to create the 'inputs.conf' file under \etc\system\local and specify the metrics we want to log in inputs.conf.
  - index=endpoint
- We should also remember to create an 'endpoint' indexer on the Splunk machine and add port 9997.

4-Active Directory Installation/Configuration
- First, I installed the Active Directory server, then I promoted the server to Domain Controller. After creating the users, I included the Windows 10 machine in this Domain.
- For Active Directory installation
  - Server Manager>Manage>Add Roles and Features 
	Installation Type> Role-Based or Feature-Based Installation 
	Server Selection> ADDC01 
	Server Roles> AD Domain Services 
- To Promote Server to Domain Controller
  - Server Manager>from open flag 
	Deployement Configuration> Add a new forest (Root Domain Name: lab.local) 
	Domain Controller Options> Password creation
- To create a user, I created an Organizational Unit under IT and HR and then created a user under each of them.
  - Server Manager>Tools>AD Users and Computers>lab.local>right click>New>Organizational Unit>IT/HR>right click>New>User
- After that I went to the Windows 10 machine and included it in the lab.local Domain. But what we need to do before that is to change the DNS server to AD server. The AD user and password must be entered when joining the domain.
  - PC>Properties>Advance System Settings>Computer Name>Change>Member of Domain: LAB.LOCAL

5- IDP/IPS (Suricata)
- First, I changed the IP address to static IP.
  - sudo nano /etc/netplan/00-installer-config.yaml
  - IP:192.168.10.9
- I installed Suricata
  - sudo apt-get install software-properties-common
  - sudo add-apt-repository ppa:oisf/suricata-stable
  - sudo apt-get update
  - sudo apt-get install suricata
- I made some changes in configuration file /etc/suricata/suricata.yaml
  - address-group: [192.168.10.0/24]
  - af-packet: enp0s3
  - pcap: enp0s3
  - community-id: true
- I installed Splunk Forwarder and ran it.
  - sudo dpkg -i <splunkforwarder .deb folder>
  - sudo –u splunkfwd bash #I switched to splunkfwd user
  - $SPLUNK_HOME/bin/splunk start –accept-license
- I activated 'boot start'.
  - sudo $SPLUNK_HOME/bin/splunk enable boot-start -user splunkfwd
- To monitor the logs and send those to Splunk, I entered these commands with splunkfwd user.
  - $SPLUNK_HOME/bin/splunk add forwarder-server 192.168.10.10:9997
  - $SPLUNK_HOME/bin/splunk monitor /var/log/suricata

6- Kali Linux/Brute-force attack
- First, I changed the IP address to static IP.
  - Ethernet>sag tikla>Edit connections>Wired connection 1>Ayarlar>IPv4 Settings>Method Manual>Add
  - IP: 192.168.10.250
- I created a folder called 'ad-project' and put the work there.
- I downloaded 'crowbar' for brute-force attack.
  - sudo apt-get install -y crowbar
- I opened the /usr/share/wordlists/rockyou.txt.gz file and copied it to the 'ad-project' folder.
  - sudo gunzip rockyou.txt.gz
  - cp rockyou.txt ~/Desktop/ad-project
- Since the file is very large, I used the first 100 word list and added the user password I created to the 'password.txt' file.
  - head -n 100 rockyou.txt > password.txt
  - nano password.txt
- After that we have to activate RDP port 3389 on the Windows 10 (target-PC) machine.
  - PC>Properties>Advance System Settings>System Properties>Remote>Remote Desktop>Allow remote connections to this computer>Select Users>Add>
- Finally, I launched a brute-force attack with 'crowbar' in Kali Linux.
  - crowbar -b rdp -u <user> -C password.txt -s 192.168.10.100/32

