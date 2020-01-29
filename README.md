# CCNA-CyberOps
personal training repository for the CCNA Cyber Ops certification https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/associate/ccna-cyber-ops.html

## Cisco Security Fundamentals (210-250) 

The following are a list of exam topics (found [here] (https://learningcontent.cisco.com/cln_storage/text/cln/marketing/exam-topics/210-250-secfnd.pdf)) and my answers (which may very well be incorrect - you have been warned :p) 

### 1.0 Networking Concepts

1.1 Describe the function of the network layers as specified by the OSI and the TCP/IP network models
> OSI Model
> Layer 1 *Physical*: Handles bitstream, defines media type, connector type, signal type. SONET/SDH, IEEE, Bluetooth, etc.
> Layer 2 *Data Link*: Arranges data into frames, error checks, direct data transfer. MAC addresses, ARP, Frame Relay, etc.
> Layer 3 *Network*: Routes packets. IP addresses, IPSec, ICMP, etc.
> Layer 4 *Transport*: Manages connection between hosts. Data segments, cyclic redundancy check, TCP, UDP.
> Layer 5 *Session*: Manages session/dialogue between applications. Authentication, authorization, and session restoration.
> Layer 6 *Presentation*: Transforms data to be presentable for a given application. Syntax, encryption, compression.
> Layer 7 *Application*: Communicated with end-user. Handles resource availability/sharing, BGP, DNS, DHCP, Telnet, HTTP, etc.

> TCP/IP Model:
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

1.7 


