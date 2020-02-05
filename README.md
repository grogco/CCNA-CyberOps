# CCNA-CyberOps
Personal training repository for the CCNA Cyber Ops certification https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/associate/ccna-cyber-ops.html

## Cisco Security Fundamentals (210-250) 

Below is the list of exam topics, which can also be found [here](https://learningcontent.cisco.com/cln_storage/text/cln/marketing/exam-topics/210-250-secfnd.pdf), along with my answers (which may very well be incorrect - you have been warned :p).

### 1.0 Networking Concepts

#### 1.1 Describe the function of the network layers as specified by the OSI and the TCP/IP network models
> **OSI Model**  
> Layer 1 *Physical*: Handles bitstream, defines media type, connector type, signal type. SONET/SDH, IEEE, Bluetooth, etc.  
> Layer 2 *Data Link*: Arranges data into frames, error checks, direct data transfer. MAC addresses, ARP, Frame Relay, etc.  
> Layer 3 *Network*: Routes packets. IP addresses, IPSec, ICMP, etc.  
> Layer 4 *Transport*: Manages connection between hosts. Data segments, cyclic redundancy check, TCP, UDP.  
> Layer 5 *Session*: Manages session/dialogue between applications. Authentication, authorization, and session restoration.  
> Layer 6 *Presentation*: Transforms data to be presentable for a given application. Syntax, encryption, compression.  
> Layer 7 *Application*: Communicated with end-user. Handles resource availability/sharing, BGP, DNS, DHCP, Telnet, HTTP, etc.  

> **TCP/IP Model**  
> Application: User interface. BGP, DHCP, DNS, HTTP, LDAP, SMTP, POP, SSH, Telnet, TLS/SSL, etc.  
> Transport: Transports data. TCP, UDP, etc.  
> Internet: Connectionless communication. addressing, routing, IPSec, etc.  
> Link/Network Access: Provides access to physical network. ARP, OSPF, MAC, Ethernet, WiFi, Tunnels, etc.  

#### 1.2 Describe the operation of the following:  
##### 1.2a IP  
```Delivers packets based on IP addresses```  
##### 1.2b TCP  
```Reliable error-checked bit stream```  
##### 1.2c UDP  
```Connectionless bit stream/datagram service```  
##### 1.2d ICMP  
```Message protocol, error sending over TCP/UDP```  

#### 1.3 Describe the operation of these network services:  
##### 1.3a ARP  
```Discovers link layer addresses (MAC addresses) given an IP address```  
##### 1.3b DNS  
```Maps domain names to IP addresses```  
##### 1.3c DHCP  
```Assigns IP addresses so hosts can communicate```  

#### 1.4 Describe the basic operation of these network services:  
##### 1.4a Router  
```Routes packets based on information in the packet header and its routing table or policy```  
##### 1.4b Switch  
```Forwards frames to specified devices that it is connected to```  
##### 1.4c Hub  
```Repeats any signal it recieves to all of its ports```  
##### 1.4d Bridge  
```Creates a single aggregate network by bridging multiple networks together.```  
##### 1.4e Wireless Access Point  
```Offers wireless access to a wired network by using wireless LAN technology```  
##### 1.4f Wireless LAN Controller  
```Configures and manages wireless access points```  

#### 1.5 Describe the functions of these network security systems as deployed on the host, network, or the cloud:  
##### 1.5a Firewall  
```A host-based firewall generally focuses on malware and virus prevention and detection. A network-based firewall generally focuses on ingress and egress traffic, often times imposing a set of rules the traffic must abide by. A cloud-based firewall is generally used to protect cloud infrastructure and servers that exist in a more dynamic environment with a wider perimeter.```  
##### 1.5b Cisco Intrusion Prevention System (IPS)  
```Host-based IPS uses deep pack inspection and references a database of signatures to focus on intrusion detection. Next Generation IPS is utilized in the network, public cloud, and private cloud to focus more on monitoring.```  
##### 1.5c Cisco Advanced Malware Protection (AMP)  
```Scans files and detects malware```  
##### 1.5d Web Security Appliance (WSA) / Cisco Cloud Web Security (CWS)  
```For host/network the WSA filters traffic and uses Cisco Talos to analyze data, block URLs/IP addresses, and consider site reputation. Cloud environments use CWS for web scanning and filtering.```  
##### 1.5e Email Security Appliance (ESA) / Cisco Cloud Email Security (CES)  
```Security appliance dedicated for mail traffic.```  

#### 1.6 Describe IP subnets and communication within an IP subnet and between IP subnets  
```An IP subnet is a logical division of a network. Subnets communicate through routers.```  

#### 1.7 Describe the relationship between VLANs and data visibility  
```VLANs logically separate LANs on a switch so they behave as if they were physically separated; a frame originating on one VLAN has no way of reaching another, so there is no data visibility - VLANs are totally private from one another.```  

#### 1.8 Describe the operation of ACLs applied as packet filters on the interfaces of network devices  
```Access control lists grant or deny access to packets based on predefined criteria such as IP address ranges.```  

#### 1.9 Compare and contrast deep packet inspection with packet filtering and stateful firewall  
```Deep packet inspection analyzes metadata and traffic trends whereas packet filtering/stateful firewall allow or deny based on a set of rules. Results from deep packet inspection can influence the way packet filtering rules are written.```  

#### 1.10 Compare and contrast inline traffic interrogation and taps or traffic mirroring  
```Inline traffic interrogation analyzes traffic in real time and has the ability to prevent certain traffic from being forwarded, while taps/traffic mirroring are passive ways of monitoring traffic.```  

#### 1.11 Compare and contrast the characteristics of data obtained from taps or traffic mirroring and NetFlow in the analysis of network traffic  
```NetFlow give a more conprehensive view into a network's application flows, traffic applications and patterns, and usage than logic-less taps or traffic mirroring.```  

#### 1.12 Identify potential data loss from provided traffic profiles  
``` ? ```  

### 2.0 Security Concepts

#### 2.1 Describe the principles of the defense in depth strategy
```The defense in depth strategy proposes the implementation of a redundant, overlapping defense system so the failure of one defensive layer will likely be backed up by another.```  

#### 2.2 Compare and contrast these concepts:    
##### 2.2a Risk  
```Risk is the probability that a vulnerability may be exploited by a threat```  
##### 2.2b Threat  
```A threat is an entity that presents risk by having the ability to exploit a vulnerability```  
##### 2.2c Vulnerability  
```A vulnerability is anything that is at risk of being exploited by a threat```  
##### 2.2d Exploit  
```An exploit is any methodology that is at risk of being utilized by a threat against a vulnerability```  

#### 2.3 Describe these terms:  
##### 2.3a Threat Actor  
```a person or entity that is reponsible for the violation of safety or security```  
##### 2.3b Run Book Automation  
```A set of automated operations carried out to manage a computer system or network```  
##### 2.3c Chain of Custody  
```A list of everyone who has been in posession of an entity under question that is used to document physical security```  
##### 2.3d Reverse Engineering  
```The practice of deconstructing something to gain insight on its broader architecture and information it may contain```  
##### 2.3e Sliding Window Anomaly Detection  
```Limiting anomaly detection to a set time frame```  
##### 2.3f PII  
```Personally-Identifiable Information i.e. SSN, DoB, address, name```  
##### 2.3g PHI  
```Personal/Protected Health Information i.e. medical test results, diagnoses, medical history. Protected under HIPAA```  

#### 2.4 Describe these security terms:  
##### 2.4a Principle of least privilege  
```Users should have the least amount of privilege/access necessicary```  
##### 2.4b  Risk Scoring / Risk Weighing  
```Assessment of total possible risk surrounding vulnerabilities, encryption, system administration, historical data, etc.```  
##### 2.4c Risk Reduction  
```Methods of mitigating identified risks```  
##### 2.4d Risk Assessment  
```The identification and analysis of possible risk (giving a risk score)```  

#### 2.5 Compare and contrast these access control models:  
##### 2.5a Discretionary Access Control (DAC)
```Access is granted/denied based on an access policy created by the owner of the entity/location in question```  
##### 2.5b Mandatory Access Control (MAC)
```Access is granted/denied based on an access policy created by the administrator that discriminates based on user type```  
##### 2.5c Nondiscretionary Access Control
```Access is granted/denied uniformly across all users```  

#### 2.6 Compare and contrast these terms:  
##### 2.6a Network and host antivirus
```host antivirus software is generally designed to prohibit items based on virus definitions, wheras network antivirus considers the propogation of viruses across the network.```  
##### 2.6b Agentless and agent-based protections
```Agent-based security software actively searches for malware and viruses with file scanning and infrastructure scans, among other things. This is taxing on computation power so agentless protections that centralize security operations for multiple hosts can be used to lessen the impact.```  
##### 2.6c SIEM and log collection
```Log collection documents occurances and is a part of SIEM. Based on activity and log history SIEM tools act to prevent issues and respond to security events that were logged.```  

#### 2.7 Describe these concepts:  
##### 2.7a Asset Management  
```The management of assets such as servers, routers, etc. Providing asset management for a customer may entail monitoring and incident response for specific devices.```  
##### 2.7b Configuration Management  
```Managing the configuraiton of assets. Providing configuration management for a customer may include setting up, updating, and patching devices.```  
##### 2.7c Mobile device management  
```Management of mobile devices which may call for remote controlling and geofencing```  
##### 2.7d Patch Management
```Patch management```  
##### 2.7e Vulnerability Management  
```Vulnerability management is needed for anyting from a single application to a large enterprise network. Two main parts of vulnerability management is the regular checking for vulnerabilities and the mitigation of vulnerabilities that are found or exploited.```  

### 3.0 Cryptography

#### 3.1 Describe the use of a hash algorithm  
```Hash algorithms are used to map given data into a hash value, which is of fixed size and stored in a hash table. Storing data in this fashion is more secure than storing information in pain text for obvious reasons. Hash tables are more efficient on storage space due to their fixed size, and retrivial of a hash value is computationally more efficient than retrieving an unhashed value. The efficiency of hash tables makes them useful for building large data caches. The security of the hash algorithm proves useful for securely storing data. The efficient storage size and uniform characteristics of a hash value makes it useful for comparing data.```  

#### 3.2 Describe the uses of encryption algorithms 
```Encryption algorithms are similar to hash functions, but they make use of an encryption key that can decrypt the hash value to retrieve the original value. Encryption algorithms are useful for storing sensitive data that must eventually be retrieved. Unlike storing a password, where the password's hash is used to validate a password input, an encrypted hash can be decrypted so the hash's value may be retrived, not just compared against. Encryption algorithms are useful for siging data.```  

##### 3.3 Compare and contrast symmetric and asymmetric encryption algorithms  
```Symmetric encryption uses the same key to encode and decode the data, wheras asymmetric encryption used two keys, usually a private key and a shared key.```  

#### 3.4 Describe the processes of digital signature creation and verification  
```A digital signature is created with the use of a private key and a hash of the information on the document that is being signed - this ensures a private and unique signature. To verify the signature, the verifier hashed the document and uses the signer's public key to complete the hash. If the verifier's hash and the signature hash match then the signature is verified and it can be trusted that the document was not altered after being signed.```  

#### 3.5 Describe the operation of a PKI  
```Public Key Infrastructure uses a Certificate Authority and a Registration Authority to verify the identity of the public key holder.```  

#### 3.6 Describe the security impact of these commonly used hash algorithms:  
##### 3.6a MD5  
```Cryptographically insecure and can have collisions. Not ideal for security or usage that relies on collision resistance```  
##### 3.6b SHA-1  
```SHA is designed for cryptographic security - it produces an irreversible and unique 160-bit hash```  
##### 3.6c SHA-256  
```Improvement over SHA-1, 256-bit hash```  
##### 3.6d SHA-512  
```Improvement over SHA-256, 512-bit hash```  

#### 3.7 Describe the security impact of these commonly used encryption algorithms and secure communications protocols:  
##### 3.7a DES  
```Symmetric algorithm that uses a 56-bit block cypher. Has fallen prone to brute force attacks with the advances in computing power```  
##### 3.7b 3DES  
```Like DES but with a key 3x as long; not as vulnerable to brute force attacks```  
##### 3.7c AES
```The successor of DES; has a 128-bit block cypher```  
##### 3.7d AES256-CTR  
```AES with a 256-bit stream cypher in "integer counter" mode which improved speed```  
##### 3.7e RSA  
```Public key encryption standard used for sending data over public networks or for digital signatures```  
##### 3.7f DSA  
```Public key encryption only used for digital signatures```  
##### 3.7g SSH  
```File transfer protocol complete with data-in-motion encryption, server/client quthentication, and data integrity checks. Has more functionality than SSL/TLS i.e. terminal management.```  
##### 3.7h SSL/TLS  
```File transfer protocol complete with data-in-motion encryption, server/client quthentication, and data integrity checks. Employs X.509 digital certificates```  

#### 3.8 Describe how the success or failure of a cryptographic exchange impacts security investigation  
```If a cryptographic exchange fails it is likely that the integrity of the data has been compromised```  

#### 3.9 Describe these items in regards to SSL/TLS:  
##### 3.9a Cipher-suite  
```A combination of ciphers used to negotiate security settings during the SSL/TLS handshake```  
##### 3.9b X.509 certificates  
```The standard of formatting public key certificates, which are used in SSL/TLS connections```  
##### 3.9c Key exchange  
```A public key is exchanged as part of the SSL/TLS handshake```  
##### 3.9d Protocol version  
```?```  
##### 3.9e PKCS  
```Public Key Cryptography standards define the precesses behind encryption and signatures```  

### 4.0 Host-Bases Analysis

#### 4.1 Define these terms as they pertain to Microsoft Windows:  
##### 4.1a Processes  
```An instance of a program that is being executed```  
##### 4.1b Threads  
```A series of instructions that can be scheduled for execution by the operating system ```  
##### 4.1c Memory Allocation  
```Setting aside memory to be used for a chosen purpose (not sure how this particularly pertains to Windows)```  
##### 4.1d Windows Registry  
```Database that stores the kernel, device drivers, and other settings for the Windows operating system, as well as settings for applications that choose to use the registry.```  
##### 4.1e WMI  
```?```  
##### 4.1f Handles  
```A reference value to a memory address (a pointer or integer) that provides a layer of abstraction from memory addresses to the user.```  
##### 4.1g Services  
```In Windows a service is s program that operates in the background, similar to a daemon in UNIX```  

#### 4.2 Define these terms as they pertain to Linux:  
##### 4.2a Processes  
```A process represents a running program. It's the abstraction through which memory, processor time, and I/O resources can be managed and monitors.```  
##### 4.2b Forks  
```The Fork command creates a copy of a process with a new process ID. Since there are no UNIX system calls to start a new program from scratch, Fork must be initiated to create a new process which can then be used to execute the new program.```  
##### 4.2c Permissions  
```Linux permissions determine what modifications can be made to a file and by whom. The permissions for each file are indicated by three sets (owner, group, everyone else) of three permission bits (read, write, execute).```  
##### 4.2d Symlinks  
```Symbolic links point to a file by name, rather than pathname```  
##### 4.2e Daemon  
```Processes invoked by the kernel that run at startup and in the background```  

#### 4.3 Describe the functionality of these endpoint technologies in regards to security monitoring:  
##### 4.3a Host-based intrusion detection  
```Monitors a computer system to detect intrusion or unusual activity```  
##### 4.3b Antimalware and antivirus  
```Monitors for malware and viruses```  
##### 4.3c Host-Based Firewall  
```Filters ingress/egress traffic on a host```  
##### 4.3d Application-level whitelisting/blacklisting  
```Permits/denies the installation of applications based on a set of sules, such as the application publisher```  
##### 4.3e Systems-based sandboxing(such as Chrome, Java, Adobe reader)  
```Isolating certain applications to limit the propogation of malware```  

#### 4.4 Interpret these operating system logs to identify an event:  
##### 4.4a Windows security event logs  
``` ```  
##### 4.4b Unix-based syslog  
``` ```  
##### 4.4c Apache access logs  
``` ```  
##### 4.4d IIS access logs  
``` ```  

### 5.0 Security Monitoring

#### 5.1 Identify the types of data provided by these technologies: 
##### 5.1a TCP Dump  
```Captures packets from a specified interface, port, protocol, etc.```  
##### 5.1b NetFlow  
``` ```  
##### 5.1c Next-Gen Firewall  
``` ```  
##### 5.1d Traditional Stateful Firewall  
``` ```  
##### 5.1e Application visibility and control  
``` ```  
##### 5.1f Web content filtering  
``` ```  
##### 5.1g Email content filtering  
``` ```  

#### 5.2 Describe these types of data used in security monitoring:  

#### 5.3 Describe these concepts as they relate to security monitoring:
##### 5.3a Access Control List
##### 5.3b NAP/PAT
##### 5.3c Tunneling
##### 5.3d TOR
##### 5.3e Encryption
##### 5.3f P2P
##### 5.3g Encapsulation
##### 5.3h Load Balancing

#### 5.4 Describe these NextGen IPS event types
##### 5.4a Connection Event
##### 5.4b Intrusion Event
##### 5.4c Host or Endpoint Event
##### 5.4d Network Discovery Event
##### 5.4e NetFlow Event

#### 5.5 Describe the function of these protocols in the context of security monitoring:
##### 5.5a DNS
##### 5.5b NTP
##### 5.5c SMTP/POP/IMAP
##### 5.5d HTTP/HTTPS

### 6.0 Attack Methods
#### 6.1 Compare and contrast an attack surface and vulnerability
``` An attack surface is the part of the environment that an attacker attempts to exploit. Vulnerabilities may exist on the attack surface, and if an attacker is to find them, the attack surface could become compromised.```
#### 6.2 Describe these network attacks:
##### 6.2a Denial of Service
``` An attack that floods a network (or a service or device) with traffic to cause congestion. Common DoS attacks spam UDP traffic or TCP SYN packets to overwhelm a router or server. There are also DoS attacks that utilize vulnerabilities or unexpected types of traffic to shut down a service. ```
##### 6.2b Distributed Denial of Service
``` DDoS attacks are DoS attacks that come from multiple sources. DDoS attacks can be carried out by multiple compromised computers in a botnet, or random uncompromised computers can be used in a reflective attack where the attacker spoofs the target's IP address and requests responses from various places. Since the source IP appears to be the target machine, responses will be sent to the target, and overwhelm it if done effectively. ```
##### 6.2c Man in the Middle
``` MITM attacks allow an attacker to passively observe network traffic, or in some cases, modify traffic passing through the network. A common example would be impersonating a router - if you can fool a host into thinking that you are the router, then  you can recieve its data and pass it on to the actual router placing yourself "in the middle" where you can read the traffic, and modify what the host or router sees (as long as it is uncrypted or you can decrypt it...).```

#### 6.3 Describe these web application attacks:
##### 6.3a SQL Injection
``` Entering a SQL command into a field that expects a different type of input can allow an attacker to run malicious code. For example, if a website recieves input with this code:
  myInput = getRequestString("userInput");
  mySQLcode = "SELECT * FROM myTable WHERE myValue = " + userInput;
it probably expects userInput to be a basic string entered by the user. If an attacker was to enter the following into userInput:  
" x OR 1 = 1; DROP TABLE myTable "
all values would be returned and the table would be deleted; probably not the intended usage.
```
#####6.3b Command Injections
#####6.3c Cross-site Scripting
``` Modifying trusted scripts or adding malicious scripts to a trusted webpage, presenting the unsafe scripts to another user under the guise that they are part of the trusted site. ```

#### 6.4 Describe these attacks: 
##### 6.4a Social Engineering
``` A cyberattack that targets the user, rather than the technology, to extract information or commit some sort of exploitation by misleading someone. ```
##### 6.4b Phishing
``` A type of attack that aims to trick the user into falling into the trap - be it downloading malware, sharing information, etc. usually perpetrated in a counterfeit e-mail or message. ```
##### 6.4c Evasion Methods

#### 6.5 Describe these endpoint-based attacks:
##### 6.5a Buffer Overflows
``` Exceeding the buffer size in a section of memory to return information stored in a different, usually inaccessable, area in memory. ```
##### 6.5b Command and Control (C2)
##### 6.5c Malware
##### 6.5d Rootkit
##### 6.5e Port Scanning
##### 6.5f Host Profiling

#### Describe these evasion methods:
##### 6.6a Encryption and tunneling
##### 6.6b Resource exhaustion
##### 6.6c Traffic Fragmentation
##### 6.6d Protocol-level mininterpretation
##### 6.6e Traffic substitution and Insertion
##### 6.6f Pivot

#### 6.7 Define privilege escalation
``` Achieving a higher access profile when exploiting a system, such as escalaiting from user access to root access on a compromised host. ```
#### 6.8 Compare and contrast remote exploit and a local exploit




