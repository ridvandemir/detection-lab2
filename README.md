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
- I installed Splunk and ran it.
	- sudo dpkg -i <splunk .deb folder>
	- sudo –u splunk bash #I switched to splunk user
  - $SPLUNK_HOME/bin/splunk start –accept-license
- I activated 'boot start'.
  - sudo $SPLUNK_HOME/bin/splunk enable boot-start -user splunk

3-Windows 10/Windows Server
- First I changed the names of the machines.
  - PC>Settings Windows 10 --> ‘target-PC’, Windows Server --> ‘ADDC01’

- I then changed the IP address to static IP. 
	- Internet Settings>Change Adapter Options>Ethernet>Properties>IPv4 Properties>Manual 
