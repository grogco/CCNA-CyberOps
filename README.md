# CCNA-CyberOps
Personal training repository for the CCNA Cyber Ops certification https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/associate/ccna-cyber-ops.html

## Cisco Security Fundamentals (210-250) 

Below is the list of exam topics, which can also be found [here](https://learningcontent.cisco.com/cln_storage/text/cln/marketing/exam-topics/210-250-secfnd.pdf), along with my answers (which may very well be incorrect - you have been warned :p).

### 1.0 Networking Concepts

1.1 Describe the function of the network layers as specified by the OSI and the TCP/IP network models
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

1.2 Describe the operation of the following:
1.2a IP
> Delivers packets based on IP addresses
1.2b TCP
> Reliable error-checked bit stream
1.2c UDP
> Connectionless bit stream/datagram service
1.2d ICMP
> Message protocol, error sending over TCP/UDP

1.2 Describe the operation of these network services:
1.3a ARP
> Discovers link layer addresses (MAC addresses) given an IP address
1.3b DNS
> Maps domain names to IP addresses
1.3c DHCP
> Assigns IP addresses so hosts can communicate

1.4 Describe the basic operation of these network services:
1.4a Router
> Routes packets based on information in the packet header and its routing table or policy
1.4b Switch
> Forwards frames to specified devices that it is connected to
1.4c Hub
> Repeats any signal it recieves to all of its ports
1.4d Bridge
> Creates a single aggregate network by bridging multiple networks together.
1.4e Wireless Access Point
> Offers wireless access to a wired network by using wireless LAN technology
1.4f Wireless LAN Controller
> Configures and manages wireless access points

1.5 Describe the functions of these network security systems as deployed on the host, network, or the cloud:
1.5a Firewall
> A host-based firewall generally focuses on malware and virus prevention and detection. A network-based firewall generally focuses on ingress and egress traffic, often times imposing a set of rules the traffic must abide by. A cloud-based firewall is generally used to protect cloud infrastructure and servers that exist in a more dynamic environment with a wider perimeter.
1.5b Cisco Intrusion Prevention System (IPS)
> Host-based IPS uses deep pack inspection and references a database of signatures to focus on intrusion detection. Next Generation IPS is utilized in the network, public cloud, and private cloud to focus more on monitoring.
1.5c Cisco Advanced Malware Protection (AMP)
> Scans files and detects malware
1.5d Web Security Appliance (WSA) / Cisco Cloud Web Security (CWS)
> For host/network the WSA filters traffic and uses Cisco Talos to analyze data, block URLs/IP addresses, and consider site reputation. Cloud environments use CWS for web scanning and filtering.
1.5e Email Security Appliance (ESA) / Cisco Cloud Email Security (CES)
> Security appliance dedicated for mail traffic.

1.6 Describe IP subnets and communication within an IP subnet and between IP subnets
> An IP subnet is a logical division of a network. Subnets communicate through routers.

1.7 Describe the relationship between VLANs and data visibility
> VLANs logically separate LANs on a switch so they behave as if they were physically separated; a frame originating on one VLAN has no way of reaching another, so there is no data visibility - VLANs are totally private from one another.

1.8 Describe the operation of ACLs applied as packet filters on the interfaces of network devices
> Access control lists grant or deny access to packets based on predefined criteria such as IP address ranges.

1.9 Compare and contrast deep packet inspection with packet filtering and stateful firewall
> Deep packet inspection analyzes metadata and traffic trends whereas packet filtering/stateful firewall allow or deny based on a set of rules. Results from deep packet inspection can influence the way packet filtering rules are written.

1.10 Compare and contrast inline traffic interrogation and taps or traffic mirroring
> Inline traffic interrogation analyzes traffic in real time and has the ability to prevent certain traffic from being forwarded, while taps/traffic mirroring are passive ways of monitoring traffic.

1.11 Compare and contrast the characteristics of data obtained from taps or traffic mirroring and NetFlow in the analysis of network traffic
> NetFlow give a more conprehensive view into a network's application flows, traffic applications and patterns, and usage than logic-less taps or traffic mirroring.

1.12 Identify potential data loss from provided traffic profiles 
> ?

### 2.0 Security Concepts

2.1 Describe the principles of the defense in depth strategy
> The defense in depth strategy proposes the implementation of a redundant, overlapping defense system so the failure of one defensive layer will likely be backed up by another.

2.2 Compare and contrast these concepts:
2.2a Risk
> Risk is the probability that a vulnerability may be exploited by a threat
2.2b Threat
> A threat is an entity that presents risk by having the ability to exploit a vulnerability
2.2c Vulnerability
> A vulnerability is anything that is at risk of being exploited by a threat
2.2d Exploit
> An exploit is any methodology that is at risk of being utilized by a threat against a vulnerability

2.3 Describe these terms:
2.3a Threat Actor
> a person or entity that is reponsible for the violation of safety or security
2.3b Run Book Automation
> A set of automated operations carried out to manage a computer system or network
2.3c Chain of Custody
> A list of everyone who has been in posession of an entity under question that is used to document physical security
2.3d Reverse Engineering
> The practice of deconstructing something to gain insight on its broader architecture and information it may contain
2.3e Sliding Window Anomaly Detection
> Limiting anomaly detection to a set time frame
2.3f PII
> Personally-Identifiable Information i.e. SSN, DoB, address, name
2.3g PHI
> Personal/Protected Health Information i.e. medical test results, diagnoses, medical history. Protected under HIPAA

2.4 Describe these security terms:
2.4a Principle of least privilege
> Users should have the least amount of privilege/access necessicary
2.4b  Risk Scoring / Risk Weighing
> Assessment of total possible risk surrounding vulnerabilities, encryption, system administration, historical data, etc.
2.4c Risk Reduction
> Methods of mitigating identified risks
2.4d Risk Assessment
> The identification and analysis of possible risk (giving a risk score)

2.5 Compare and contrast these access control models:
2.5a Discretionary Access Control (DAC)
> Access is granted/denied based on an access policy created by the owner of the entity/location in question
2.5b Mandatory Access Control (MAC)
> Access is granted/denied based on an access policy created by the administrator that discriminates based on user type
2.5c Nondiscretionary Access Control
> Access is granted/denied uniformly across all users

2.6 Compare and contrast these terms:
2.6a Network and host antivirus
> host antivirus software is generally designed to prohibit items based on virus definitions, wheras network antivirus considers the propogation of viruses across the network.
2.6b Agentless and agent-based protections
> Agent-based security software actively searches for malware and viruses with file scanning and infrastructure scans, among other things. This is taxing on computation power so agentless protections that centralize security operations for multiple hosts can be used to lessen the impact.
2.6c SIEM and log collection
> Log collection documents occurances and is a part of SIEM. Based on activity and log history SIEM tools act to prevent issues and respond to security events that were logged.

2.7 Describe these concepts:
2.7a Asset Management
> The management of assets such as servers, routers, etc. Providing asset management for a customer may entail monitoring and incident response for specific devices.
2.7b Configuration Management
> Managing the configuraiton of assets. Providing configuration management for a customer may include setting up, updating, and patching devices.
2.7c Mobile device management
> Management of mobile devices which may call for remote controlling and geofencing
2.7d Patch Management
> Patch management
2.7e Vulnerability Management
> Vulnerability management is needed for anyting from a single application to a large enterprise network. Two main parts of vulnerability management is the regular checking for vulnerabilities and the mitigation of vulnerabilities that are found or exploited.

3.0 Cryptography
3.1 Describe the use of a hash algorithm
> Hash algorithms are used to map given data into a hash value, which is of fixed size and stored in a hash table. Storing data in this fashion is more secure than storing information in pain text for obvious reasons. Hash tables are more efficient on storage space due to their fixed size, and retrivial of a hash value is computationally more efficient than retrieving an unhashed value. The efficiency of hash tables makes them useful for building large data caches. The security of the hash algorithm proves useful for securely storing data. The efficient storage size and uniform characteristics of a hash value makes it useful for comparing data.

3.2 Describe the uses of encryption algorithms 
> Encryption algorithms are similar to hash functions, but they make use of an encryption key to obfuscate the meaning of the hash value. Encryption algorithms are useful for storing sensitive data that must eventually be retrieved. Unlike storing a password, where the password's hash is used to validate a password input, an encrypted hash can be decrypted so the hash's value may be retrived, not just compared against. Encryption algorithms are useful for siging data.

3.3 Compare and contrast symmetric and asymmetric encryption algorithms
> Symmetric encryption uses the same key to encode and decode the data, wheras asymmetric encryption used two keys, usually a private key and a shared key.

3.4 Describe the processes of digital signature creation and verification
> A digital signature is created with the use of a private key and a hash of the information on the document that is being signed - this ensures a private and unique signature. To verify the signature, the verifier hashed the document and uses the signer's public key to complete the hash. If the verifier's hash and the signature hash match then the signature is verified and it can be trusted that the document was not altered after being signed.

3.5 Describe the operation of a PKI
> Public Key Infrastructure uses a Certificate Authority and a Registration Authority to verify the identity of the public key holder.

3.6 Describe the security impact of these commonly used hash algorithms:
3.6a MD5
3.6b SHA-1
3.6c SHA-256
3.6d SHA-512

3.7 Describe the security impact of these commonly used encryption algorithms and secure communications protocols:
3.7a DES
