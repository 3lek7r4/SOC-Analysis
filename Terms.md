ATTACK SURFACE VS VULNERABILITY:
ATTACK SURFACE: Potential entry points, vulnerabilities that can be exploited, web applications, API's, human error
VULNERABILITY: Weakness or flaw in system, process, human factor. Can be exploited to cause harm or gain unauthorised access
COMPARISON: Vulnerabilities are specific weaknesses that can be exploited, attack surface is the whole of potential entry points for attackers
SOC APPLICATION: SOC analyst focuses on detecting, analysing and responding to security incidents, using info on the attack surface and its vulnerabilities
	     E.g.: Open port on a misconfigured firewall


DATA TYPES: understanding data/tcp/firewalls
TCP DUMP: Captures full packet data- Headers, payloads, for forensic analysis. Provides full packet capture for detailed IOC inspection. SOC analysts use TCP dump or Wireshark for deep analysis
NETFLOW: Collects metadata; ports byte count, about traffic flows and that enables anomaly detection, data exfiltration
NEXT GEN FIREWALL(NGFW): Combines the functionality of a traditional firewall with advanced features like application control, intrusion prevention, and threat intelligence.
TRADITIONAL STATEFULL FIREWALL(TSF): Monitors and manages the state of active network connections to make informed decisions about whether to allow or block network traffic
APPLICATION VISIBILITY AND CONTROL(AVC): Allows administrators to identify, monitor, and manage applications, regardless of the port, protocol, or encryption used, enabling them to enforce policies and prioritize traffic based on 						application behavior. 
WEB CONTENT FILTERING: Regulates access to websites and online content based on predefined rules
EMAIL CONTENT FILTERING: Analyzes incoming and outgoing emails to identify and manage unwanted or harmful content
SOC APPLICATION: Analysts combine NetFlow (metadata) with Wireshark(full packet capture) and SIEM (alert data) to detect IOC's
		E.g.: NetFlow flags high outbound traffic; Wireshark confirms malware payload; and NGFW alerts block the c2 connection
  

IMPACT OF TECHNOLOGIES: port address translation, load balancing, encapsulation
ACCESS CONTROL LISTS(ACL's): Filter traffic, reducing visibility of blocked packets in packet capture; SOC analyst reviews ACL logs for denied traffic
NAT/PAT(NETWORK ADDRESS TRANSLATION, PORT ADDRESS TRANSLATION): Used in networking to map private IP addresses to public IP's; enables private network devises to communicate with the internet
TUNNELING: Encapsulates traffic like a VPN, hiding payload data from packet capture unless decrypted
TOR(THE ONION ROUTER): Masks traffic; Routes traffic through anonymised nodes, masking source IP's in NetFlow, hinder SOC tracking of c2 servers
ENCRYPTION: Hides packet payloads E.g.: transport layer security (TLS), limiting Wireshark visibility to headers. SOC analysts would use Metadata or Certificate Analysis
P2P: Decentralised traffic, BitTorrent, obscured end-points in NetFlow, requiring NGFW for application detection
ENCAPSULATION: Wraps data; GRE tunnels, hiding inner protocols from packet capture without decapsulation
LOAD BALANCCNG: Distributing traffic across servers, splitting NetFlow records requiring coloration for IOC detection, no single server gets overloaded
SOC APPLICATION: Analysts adjust tools like NGFW for encrypted traffic to maintain visibility despite these technologies
		E.g.: If encryption hides malware payloads in Wireshark, NetFlow metadata would help us to reveal suspicious IP's


USES OF DATA TYPES IN SECURITY MONITORING: applying full packet capture, session data, transaction data, statistical data, metadata and alert data in soc workflows
FULL PACKET CAPTURE: Detailed analysis of headers and payloads to confirm IOC's like malware payloads
SESSION DATA: Tracks connection details to detect unauthorised sessions
TRANSACTION DATA: Monitoring specific actions
		 E.g.: Web filtering, (AVC) to identify misuse (uploading of files without consent)
STATISTICAL DATA: Aggregating trends to detect anomalies, (example of aggregating trends) SIEM reports, (example of anomaly detection) traffic spikes indicating DDoS
METADATA: Summarises traffic; NetFlow, for lightweight anomaly detection e.g.: data exfiltration
ALERT DATA: Prioritizes IOC's, SIEM, NGFW alerts, SOC triage; EG: brute force alerts
SOC APPLICATION: Analysts use full packet capture for forensics, metadata for initial detection and alert data for prioritization
	     E.g.: SIEM alert data flags failed logins, NetFlow metadata shows suspicious IP's, Wireshark full packet capture confirms malware
EXAM FOCUS: CICSO Cybercops; data type applications


NETWORK ATTACKS: identifying different attacks, DDoS man in the middle, etc
PROTOCOL-BASED: Exploiting protocol weaknesses, user data, file transfer, SSH; detected via NetFlow or NGFW
DoS: Overwhelms a system; EG: SYND flood on port 80, impacting availability SOC: statistical data to detects spikes
DDoS: Multiple sources flood a target; e.g.: botnet http floods and usually detected via NetFlow metadata
MAN-IN-THE-MIDDLE: Intercepts traffic, ARP spoofing, risking confidentiality and Wireshark detects anomalies in packet headers
SOC APPLICATION: Analysts use SIEM to analyze data to identify threats, use ID/PS, Firewalls, Forensic analysis with Wireshark
Eg: NetFlow shows a DDoS traffic spike, firewall rules mitigate it
EXAM FOCUS: Test attack identification and detection methods


WEB APPLICATION ATTACKS: recognising SQL injections, command injections and cross site scripting
SQL INJECTION: SQL injection injects malicious SQL into webforms, extracting data; eg: customer records, risking confidentiality, detected via WAF logs
COMMAND INJECTION: Executes unauthorized commands; e.g.: input fields, compromising integrity, SIEM logs flag
CROSS-SITE SCRIPTING (XSS): Vulnerability that allows attackers to inject malicious scripts into websites; executed by unsuspecting users' browsers; steals cookies, session tokens, or control users browser session
SOC APPLICATION: Log analysis using Wireshark, IOC detection with SIEM, WAFs


SOCIAL ENGINEERING ATTACKS: phishing, Spearphishing and pretexting

END-POINT-BASED-ATTACKS: buffer overflows, malware, ransomware,c2 (command control)

EVASION AND OBFUSCATE TECHNIQUES: analysing tunneling, encryption and proxy's used to evade detection

CERTIFICATES AND SECURITY: understand public key infrastructure, certificates and components like cipher-suite, x.5o9 certificates, key exchange, protocol version and public key cryptography standards
CERTIFICATES: Verify identities; EG: x.5o9 for websites and SOC analysts inspect certificates for anomalies; EG: expired certificates
PUBLIC KEY INFRASTRUCTURE (PKI): Manages certificates for secure communication; EG: TLS, ensures confidentiality and integrity
COMPONENTS:
CIPHER-SUITE: Defines encryption algorithms; EG: AES-256, this impacts security monitoring visibility
X.5O9 CERTIFICATES: X.5o9 is the standard for certificates, contains public keys and issuer details
KEY EXHANGE: Shares keys securely; EG: RSA
PROTOCOL VERSION: Specifies TLS version
PKCS: Standard (Group) for cryptography
SOC APPLICATION: Analysts verify certificates in Wireshark to detect MITM attacks in cipher-suite; EG: Wireshark shows a self-signed certificate, indicating a potential MITM and SOC analysts would block the connection
EXAM FOCUS: Test significant components and their security monitoring

Chain of custody: ensures evidence integrity for legal and forensic purposes; it is a documented process of tracking evidence EG: hard drives/laptops from collection to court including who handled it, when and how
SOC USES: Analysts log evidence to ensure admissibility in legal proceedings, sealing hard drive, recording timestamps EG: laptop with malware is sealed, and stored securely; chain of custody ensures it's admissible in court
EXAM: would test chain of custody steps
STEPS:
COLLECTION AND DOCUMENTATION: Involves initial documentation, recording date, time and location aswell as the name of the person in possession
PHOTOGRAPHY/SKETCHING: helps to visually record the initial state of the evidence, documents scenes through photographs or sketches
PROPER PACKAGING: Evidence must be packaged appropriately to prevent containment or tampering; may involve the use of specific types of evidence bags or seals

TRANSFER AND RECIEPT:
HAVING DETAILED LOGS: when evidence is transferred from one person to another, a detailed log should be created; log should include date, time and names of people involved aswell as the purpose for the transfer
UNIQUE IDENTIFIERS: each piece of evidence should be assigned a unique identifier to track its movements and ensure it can be easily identified

STORAGE AND SECURITY: 
SECURE STORAGE: Evidence mut be stored in a secure location, with controlled access to prevent unauthorized handling or tampering
REGULAR VERIFICATION: Integrity and condition of evidence should be regularly verified to maintain its reliability

PRESENTAION IN COURT: 
ADMISSABILITY: The chain of custody is crucial for demonstrating the integrity of the evidence and ensuring its admissibility in court
UNBROKEN CHAIN: If the chain of custody is broken, or questionable, the evidence may be excluded from the trial or given less weight by the jury

COMPLIANCE AND POLICIES: 
COMPLIANCE: Ensured adherence to regulations such as HIPPA and PCIDSS
HIPPA (HEALTH INSURANCE PORTABILITY AND ACCOUNTABILITY ACT): Aims to protect sensitive patient health info from being disclosed without their consent or knowledge
PCIDSS (PAYMENT CARD INDUSTRY DATA SECURITY STANDARD): 
