---
title: Active Directory Basics
author: Adrià
date: 2022-06-21 9:47:00 +0800
categories: [Theory]
tags: Windows Active_Directory Basics
render_with_liquid: false
---

> The contents of this post are based on my understanding about the topic obtained while doing [this](https://academy.hackthebox.com/module/74/section/699) module from HTB Academy. If you detect something wrong, confusing or conflicting, please let me know. 
{: .prompt-warning }

During my university degree I haven't been able to learn anything related to Windows nor Active Directory (AD). However, almost all the organitzations use Windows systems, so learning how to deal with this workstations is a **must** if you want to do anything related with cybersecurity. For this reason, I put my hands to work as soon as possible and started to learn how Active Directory works. In this post you will find all the basic concepts that can help you build a solid knowledge about AD. 

# What is AD? 
***

Active Directory is a hierarchical structure that allows a centralized management of the organitzation. It has several services like domain services, file shares, group policies, and network devices management. 
It can be seen as a Read-Only database accessible to all users within the domain, regardless of their privilege level. This means that any user can enumerate most information about the AD and search for misconfigurations to exploit.
A user account without privileges can enumerate:
 
|                          |                             |
|--------------------------|-----------------------------|
| Domain Computers         | Domain Users                |
| Domain Group information | Organizational Units (OUs)  |
| Default DOmain Policy    | Functional Domain Levels    |
| Password Policy          | Group Policy Objects (GPOs) |
| Domain Trusts            | Access Control Lists (ACLs) |

 Consequently, there are a lot of vulnerabilities and exploiting tools that can vulnerate a whole AD environment. 

# Terminology
***
Throughout this post I'm going to use some terminologies that will be defined in this section: 
- **Object** 
: ANY resurce present within an Active Directory environment.  
- **Attributes**
: Objects inside AD have associated [attributes](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all) that define that object. For example, a computer contains attributes such as hostname and DNS name. All attributes have an associated LDAP name that can be used when performing LDAP queries. 
- **Schema**
: The AD schema defines the objects that can exist inside the AD and their attributes and stores information about them. 
- **Domain**
: Logical group of objects. They can be independent or connected to other domains with trust relationships. 
- **Forest**
: Is a collection of domains. It can also have trust relationships with other forests. 
- **Tree**
: A tree is the collection of subdomains that begins at a single root domain. A forest can have different trees. All domains in a tree share a standar **Global Catalog** which contains all information about the objects within that tree. 
- **Container**
: Is a type of object that contains other objects in a defined place within the directory hierarchy.
- **Leaf** 
: Leafs objects don't contain other objects
- **Global Unique Identifier (GUID)**
: This identifier is a 128-bit value assigned when a domain user/group is created. This identifier is stored in the **ObjectGUID** attribute. This value never changes. Every single object has a GUID.  
- **Security principals**
: Anything that the operating system can authenticate (not only users or accounts, but threads and processes too). In AD, security principles are the objects used to manage access to other resources. If we want to control resources localy inside a computer, it's not a AD task but a Security Accounts Manager (SAM) task. 
- **Security Identifier (SID)**
: This identifier is used for a security principal or group. Every account, group or process has its unique SID. SIDs are immutable and unique. For example, a security principal name can change but the SID will remain the same. They are used to grant access and check rights. There are **well-wnown** SIDs. 
- **Distinguished Name (DN)**
: A DN describes the full path to an object inside the AD environment. 
- **Relative Distinguished Name**
: Is a single component of the DN that identifies the object as unique inside the current level in the naming hiererchy. It is like you can't hafe two files with the same name in the same directory, but you can have them in diferent directories, where the directory in this example maps to the hierarchy level within the AD, and the filename maps to the object.  
- **sAMAccountName**
: It is the user logon name. It has to be a unique value with <= 20 characters. 
- **userPrincipalName**
: This attribute is another way to identify users in AD (not mandatory). It has a prefix which is the user account name and a suffix which is the domain name, both separated with "@". 
- **FSMO Roles**
: Flexible Single Master Operation roles (FSMO) allows a DC to have specific responsabilities. They are usefull when there are several DC within the domain. There are five FMOS: 
    - **Schema Master**: This role manages the read/write copy of the AD schema. Only one per forest.
    - **Domain Naming Master**: Manages the domain names.Only one per forest.
    - **Relative ID (RID) Master**: Assigns blocks of RIDs to other DC within the domain that can be used for new objects. It ensures that multiple objects doesn't have the same SID. A domain object SID is equal to the domain SID + RID. Only one per domain.
    - **Primary Domain Controller (PDC) Emulator**: The host with this role will be the authoritative DC and responds to authentication requests, password changes and manage GPOs. It also mantains time for a domain.Only one per domain.
    - **Infrastructure Master**: Translates GUIDs, SIDs and DNs between domains. Used whenever there are multiple domains within a forest. Only one per domain. 
The five roles are assigned to the first DC in the forest root domain. When a new domain is created, RID Master, PDC Emulator and Infrastructure Master roles are assigned to the new domain controller. 
- **Global Catalog**
A GC is a domain controller that has copies of ALL objects in the AD forest (Full copy of the objects belonging to the same domain and partial copy of the ones from other domains). It can perform authentication and object search.
- **Read Only Domain Controller (RODC)**
:  Is a DC that has a Read-Only Active Directory database. They also include a Read Only DNS server. 
- **Replication**
: Is a concept that happens in AD when objects are updated ant the changes are transfered from one Domain Controller to another. Connections between DC that allow this replication are made by the Knowledge Consistency Checker service. 
- **Service Principal Name (SPN)**
: A SPN uniquely identifies a service instance. Kerberos protocol uses them to associate a service with a logon account, allowing the client application to request the service without needing the account name. 
- **Group Policy Object**
: GPO are collections of policy settings. Each one has a GUID that identifies the GPO. It can contain a local file system settings or Active Directory settings that can be applied to users and computer objects. 
- **Access Control List (ACL)**
: An ACL is the ordered collection of Access Control Entities (ACEs) that apply to an object.
- **Access Control Entities (ACEs)**
: An ACE in a ACL identifies a **trustee** (user account, group account, or logon session) and lists all the rights and permisions that are allowed, denied or audited for that **trusteee*
- **Discretional Access Control List (DACL)**
: A DACL defines security principles to an object. It contains a list of ACE. If an object doesn't have a DACL, the system will grant full acces to everyone, but if the DACL exists and it has no ACE, all access will be denied. 
- **System Access Control Lists (SACL)**
: They permit the logging (security logs) the access attempts made to a secured object.
- **Fully Qualified Domain Name (FQDN)**
: Is the complete name for a specific computer or host. It is composed with: [hostname].[domain name].[tld]. It can be used to specify an object's location within the tree hierarchy. It allows to reference hosts without knowing their IP. For example the host **PC01** may have a FQDN like **PC01.EXAMPLECOMPANY.LOCAL**. 
- **Tombstone**
: It is a container object that holds deleted AD objects. Microsoft recomends a tmbstome lifetime of 180 days. When a object enters the Tombstone container, it looses most of its attributes. 
- **AD Recycle Bin**
: If the AD Recycle Bin is enabled, all deleted objects are preserved facilitating the restoration because almost all the attributes are preserved. 
- **SYSVOL**
: This folder stores copies of public files in the domain (system policies, GPO settings, logon/logoff scripts, etc..)
- **AdminSDHolder**
: This object is used to manage ACL for the members of the built-in groups in AD marked as privileged. It has a Security Descriptor that defines the ACLs that members of the protected groups should have. There is a SDProp (SD Propagator) that runs each hour and checks if all the users have the desired ACL. 
- **dsHeuristics**
: This attribute is a string value set on the Directory Service object and helps to define **forest-wide** configuration settings. One of this settings is to exclude built-in groups from the Protected Groups list. This will make that when the SDProp is executed, if any changes have been made to that object, they won't be reverted. 
- **adminCount**
: This attribute determines whether the SDProp protects a user. If its **0** or non defined, the user won't be protected, if it is **"value"**, the user will be prottected. If the value is **1** means that the account may be privileged. 
- **Active Directory Users and Computers (ADUC)**
: ADUC is a GUI used to manage users, groups, computers and contacts within the AD.
- **ASDI Edit**
: It's also a GUI tool that can manage objects in the AD. It provides more acces than ADUC and it allows to set and delete attributes on an object. 
- **sIDHistory**
: This attribute holds previous SIDs that the object was assigned previously. It can be abused allowing an attacker to gain previous privileges that an account had if SID Filtering is not enabled. 
- **NTDS.DIT**
: This file is the "heart" of the AD. It is stored on a Domain Controller (C:\Windows\NTDS\) and is a database. It contains information about user groups and group objects, group membership and password hashes for all users of the domain. Moreover, if the setting **Store password with reversible encryption** is enabled, the file will also contain the passwords in cleartext (that have been changed or created after the setting was enabled).

# AD Structure
***
AD follows a hierarchical tree structure. At the top of this structure we can find the **forest**, which contains one or more **domains** that can also contain more **subdomains**. A **forest** is the top logical container. "Best Practices" dictate that having a single forest is the simpler and best long-term solution; however, having a mult-forest organitzation can provide an extra layer of security across different domains since a **forest** is the security boundary within which all objects are under administrative control. Is it possible to create **trust relationships** between two forests that link them, but it can introduce several security issues if they are not administered propperly. Bidirectional trust between two root domains doesn't imply that subdomains also have this biderectional trust. 
Trusts can be transitive or not transitive: 
- **Transitive**: A transitive trust means that the trust will be extended to objects that the child domain also trust. 
- **Non-Transitive**: Only the child domain will keep the trust. 

They can be **one-way** or **two-way (bidirectional)**. In a bidirectional trust users from both domains can acces resources. However, in a one-way trust, only users in a trusted domain can acces the resources in a trusting domain. **The direction of the trust is opposite to the direcction of access**
There are several trusts types: 
- **Parent-child**: Domains within the same forest. The child domain has a two-way transitive trust with the parent domain. 
- **Cross-link**: A trust between child domains to speed up authentication. 
- **External**: This is a non-transitive trust. Its between two separate domains in separate forests that are not related by a forest trust. It uses SID filtering. 
- **Tree-root**: Two-way transitive trust between a forest root domain and a new tree domain. They are created by design, 
- **Forest**: Transitive trust between two forest root domains. 


A **domain** is a structure that cintains objects like users, computers and groups. It has built-in **Organizational Units (OUs)** such as **Domain Controllers, Users and Computers** but new **OUs** can be created. **sub-OUs** can be created to assign different privileges/group policies. 
Active Directory provides **authorization** and **authentication** within elements inside the same domain. 

Let's see a basic structure example: 

```
EXAMPLECOMPANY.LOCAL/
|--ADMIN.EXAMPLECOMPANY.LOCAL
|  |-- GPOs
|  |-- OU
|      |-- EMPLOYEES
|     	   |-- COMPUTERS
|          |   |-- PCO1
|	   |
|	   |-- GROUPS
|	   |   |-- HQ STAFF
|          |
|   	   |-- USERS
|              |-- adria.pages
|
|-- CORP.EXAMPLECOMPANY.LOCAL
```
In the previous example we only have one forest with one domain named **EXAMPLECOMPANY.LOCAL** (the root domain). This root domain has two subdomains named **ADMIN.EXAMPLECOMPANY.LOCAL and CORP.EXAMPLECOMPANY.LOCAL**. **EMPLOYEES** is a OU inside a subdomain and it has several **sub-OUs** like **COMPUTERS, GROUPS, USERS** etc.

# Active Directory Objects
***
As mentionet in the "Therminology Section" an Object is any resource present in the AD (Domains, OU, Computers, Groups, Users and Printers and [more](https://www.windows-active-directory.com/active-directory-objects-list.html)). 
## Users
Users are leaf objects (they can't contain more objects inside them). It is considered a security principal and has a SID and GUID. They have several attributes like name, email address, account description, last login time, and much more.
## Contacts
A contact object represents an external user. They are not security principals (securable objects) so they don't have SID but they have GUID. They have attributes like name, lstname, email address, etc. 
## Printers
This object points to a printer accessible within the AD network. It's not a security principal so they only have a GUID. They have attributes like printer name, drivers information, port number, etc. 
## Computers
A computer is also a leaf object but they are security principals. They are one of the main targets for the attackers. 
## Shared Folders
This object points to a shared folder on the specific computer. Acces control can be applied to them to restrict the acces only to authenticated users. They are not a security principal so they only have a GUID.
## Group
A group is a container object because it contains other objects such as objects and computers (even other groups). Groups are security principals and have a SID and a GUID. Groups makes the management of user permisions and acces to other securable objects much more easy. Nested groups can lead to users having unintended rights because they obtain permisions of all the grups where they participate. The tool [BloodHound](https://www.windows-active-directory.com/active-directory-objects-list.html) discovers attacks paths analyzing the AD and its permisions. It has seveal attributes like name, description, membership, etc. 
## Organizational Units (OUs)
They are containers that sysadmins use to store similar objects in order to make them easier to administrate. They are often used for administrative delegation of tasks without granting a user full administrative rights. Usually, OUs are used to manage Group Policy. 
## Domain 
Domains contain objects organized into container objects. Every domain has a separate database and a sets of policies. 
## Domain Controllers
Are the brains of the AD. They handle authentication requests, verify users on the network, control who can acces de resources, etc. All access requests are validated via de domain controller. 
## Sites
Sites are a set of computers connected using links. 
## Built-in
This is a container that has all the default groups and configurations. 
## Foreign Security Principals
An FSP is an object which is a security principal from a **trusted external forest**. They are created whenever a user/group/computer from another forest is added into a grup in the current domain. This object holds a SID that is used to reslove the object's name via the trust relationship. FTP objects are created ina specific container named ForeignSecurityPrincipals. 

# Important Protocols 
***
Active Directory requires Lightweight Directory Access Protocol (LDAP), Kerberos, DNS and MSRPC (A microsoft implementation of Remmote Procedure Call (RPC)).
## Kerberos
Kerberos is an authentication protocol and Windows servers use them since 2000. Kerberos protocol is based on tickets and doesn't depend on transmitting passwords and usernames. Kerberos protocol needs a Key Distribution Center (KDC) to issue the tickets. Domain Controllers have this KDC and when a user initiates a login request (AS-REQ), the client requests a ticket from the KDC. The request is NTLM encrypted with the user password hash. KDC also has the password so it will be able to decrypt the AS-REQ using it. Then, the KDC will create  Ticket Granting Ticket (TGK) and give it to the user. This TGK can be used to request a Ticket Granting Service (TGS), but since the Domain Controlled is the one that issues TGS, user has to send the TGK to the DC along with the service they want to use (encrypted with the associated NTLM password hash). Once the client has the TGS, the service can be used.

Let's take a deep look at this protocol with an image:

1. **Authentication Service Request**
: This is the first step and is where the client asks to de KDC for the Ticket Granting Ticket. To do this, the client sends the **KRB_AS_REQ** message to the KDC. This message has (among others): 
	- An encrypted timestamp (with the user private key) to authenticate the user. This is only necessary if the user requires preauthentication. If the attribute **DONT_REQ_PREAUTH** is set, it won't be necessary.  
	- The username of the authenticated user
	- A nonce
Once the KDC recieves this message, it will search to its database the username and obtain the used associated private key (NTLM hash). Once the KDC has the user private key, it will be able to decrypt the Timestamp and validate the user. 

2. **Authentication Service Response**
: Now, KDC will build a new message to give a response. This message is the **KRB_AS_REP**. This message has several contents: 
	- The Username
	- Encrypted data (encrypted with the user private key) which contains:
		- Session key (this key is a temporal key created with the KDC after the first step). 
		- Expiration date of the TGT
		- The user nonce (to prevent reply attacks). 
	- The Ticket Granting Ticket (TGK). This ticket is encrypted with a key shared between the AS and the TGS, so the user can't see the contents of this ticket: 
		- Username
		- Session key
		- Expiration date of the TGT
		- PAC (contains the user privileges and other info (SID, groups, etc.)

	Once the user recieves this message, is able to decrypt the encrypted data and obtain the Session key and the nonce. This will also authenticate the KDC so the user can trust that ticket. 
3. **TGS Request**
: Since the user has a TGT, it can be used agains the Ticket Granting Server to obtain another ticket (Ticket Grantig Service or TGS). Whenever the user wants to use a service, it will send a **KRB_TGS_REQ** to the Ticket Granting Server. This message has the following content: 
	- Encrypted with the session key (remember that the user can retrieve the session key because it was inside the **KRB_AS_REP** message encrypted with  its private key):
		- Username
		- Timestamp
	- The TGT (The user can't see its content but can use the ticket)
	- Service Principal Name of the service requested. 
	- A nonce generated by the user. 

	Since the Ticket Granting Server is able to decrypt the TGT and see it's content (specified at the second step **Authentication Service Response**) it will obtain the session key. The session key allows the decryption of the first message and authenticate the validity of the message checking both timestamps and usernames. 

4. **TGS Response**
: If the validity of the previous step has been succesfull, the Ticket Granting Server will sent back to the user a **KRB_TGS_REP** message that contains: 
	- Username
	- TGS (Encrypted with a key that only the Ticket Granting Server and the service share): 
		- Service session key (A key that will be used between the client and the service)
		- Username
		- Expiration date of TGS
		- PAC
	- Encrypted data (with the session key)
		- Service session key
		- Expiration date of the TGS
		- The user nonce. 

	Like the second step, the user will be able to decrypt de data and retrieve the service session key and the nonce, that will validate the message. 
5. **Service Request**
:  Now that the user has decrypted the encrypted data using the session key, the Service session key can be used to craft the new message, the **KRB_AP_REQ**, to the service. This message contains: 
	- The TGS (that the user is not able to decrypt)
	- Encrypted data (using the service session key):
		- Username	
		- Timestamp

	The service will be able to decrypt the TGS, obtain the service session key, and decrypt the data in order to check the validity. If it is valid, the server will respond with a **KRB_AP_REP** and the client will be able to use the service. 

Kerberos protocol runs on port 88, so we can locate domain controlers by searching for open port 88. 

![Kerberos Protocol](/img/posts/2022-06-21-Active-Directory/kerberos-protocol.png)

## DNS
Active Directory Domain Services (AD DS) uses DNS to facilitate the communication within de domain. This protocol is used to resolve hostnames to IP addresses.
AD has a database of services running on the network represented using service records (SRV) and the clients can locate them easily. When a client joins the network, it locates the Domain Controler by sending a query to the DNS service, retrieving the SRV of the Domain Controller and discovering the Domain Controller hostname. Then the client uses the hostname to obtain the IP addres. 

DNS protocol uses port 53 and TCP or UDP (UDP by default but it uses THC when UDP messages are larger than 512 bytes). 

Using the **nslookup** comand we can do **Forward DNS Lookup** or **Reverse DNS Lookup**. 
- Forward DNS Lookup with a name will give you the IP address (If you use a hostname, you will get its IP address, if you use a domain name, you will get the domain controller). 
- Reverse DNS Lookup with an IP will give you the hostname. 

## LDAP 
Lightweight Directory Acces Protocol  allows directory lookups. It uses port 389 but LDAP over SSL (LDAPS) uses port 636. LDAP is used for the applications to communicate with other servers that provide directory services. An LDAP session begins connecting to the LDAP server (Driectory Sistem Agent). The Domain Controller in the AD is listening for LDAP requests such as authentication requests. 

There are two types of LDAP authentication: 
	1. **Simple Authentication**
	: It includes anonymous authentication, unauthenticated authentication and username/password authentication. 
	2. **SASL Authentication**: 
	: Simple Authentication and Security Layer framework uses other authentication services (such as Kerberos) to bind to the LDAP server. The LDAP server uses the LDAP protocol to send a LDAP message to the authorization service and it initiates challenges/response messages resulting in a authentication. 

LDAP messages are send in cleartext by default, but you can use TLS encryption to protect the trafic. 

## MSRPC
This is the Microsoft implementation of the Remote Procedure Call. Windows systems uses four RPC interfaces:
- **lsarpc**: Several RPC calls to the LSA (local Security Authority) wich manages local security policy on a computer, controls audit policy and provides interactiva authentication. It is used to perform management on domain security policies. 
- **netlogon**: Is a windows process used to authenticate users and services in the domain environment. It is allwais being executed in the background
- **samr**: Remote SAM allows to manage the domain account database, storing information about users and groups. Attackers use the samr protocol to perform reconnaissence about the internal domain ussing tools like BloodHound. A good protection against it is to change the Windows registry key to only allow administrators to perform remote SAM queries (by thefault, all authenticated users can do SAM queries) 
- **drsuapi**: This is the Microsoft API that implements the Directory Replication Service (DRS) Remote protocol which is used to perform replication-related tasks in a multi-DC environment. Attackers use this to create a copy of the AD domain database (NTDS.dit) to retrieve password hashes for all accounts. 

# NTLM Authentication
***
Active Directory uses other authentication methods asida from Kerberos and LDAP, like NTLMv1 and NTLMv2. This protocols use the NTLM and the LM hash. 
## LM
**LAN Manager (LM)** is a old mechanism used by Windows to store passwords. If the system uses them, they are stored in the SAM database (if we are talking about a normal Windows host) or in the NTDS.DIT (if we are talking about a DC). Since the security algorithim has been broken, this hash has been turned off by default since Windows Vista/Server 2008. 
The passwors that use LM can be maximum 14 charecters long and they are not case sensitive (converted to uppercase before the hash). This makes them relatively easy to crack. 
If the password is less than 14 characters, it is padded with NULL characters. The 14 characters are splitted in two chunks and encrypted using the string ```KGS!@#$%``` creating two 8 byte values. These values are concatenated together creating the LM hash.
## NTHash (NTLM)
**NT LAN Manager (NTLM)** hashes are the ones used now. It is based on a challenge-response authentication protocol and uses three messages to authenticate: 
1. The client sends a **NEGOTIATE_MESSAGE** to the server
2. The response is a **CHALLENGE_MESSAGE** to verify the client's identity. 
3. The client responds with an **AUTHENTICATE_MESSAGE**. 

These hashes are stored locally in the SAM (if talking about a normal Windows host) or in the NTDS.DIT (if talking about the DC). The protocol has two possible hashed password values: the LM hash or the NT hash. The **NT** hash uses the MD4 algorithim of the little-endian UTF-16 value of the password: MD4(UTF-16-LE(password)).

They are stringer than LM hashes but they can also be brute forced. NTLM is allso vulnerable to the **pass-the-hash** attack, where an attacker just uses the NTLM hash to authenticate to other systems where the user is local admin, instead of needing the cleartext password. A NTLM hash looks like: 
```
Adri:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::
```
And it contains: 
- **Adri**: Is the username
- **500**: Is te RID. The 500 RID is the **administrator** account. 
- **aad3c435b514a4eeaad3b935b51304fe**: Is the LM hash. If they are disabled, this value is worthless.
- **e46b9e548fa0d122de7f59fb6d48eaa2**: This is the NT hash. It can be cracked offline or used for a pass-the-hash. 

The [Crack Map Execc](https://github.com/byt3bl33d3r/CrackMapExec) tool can be used to do a pass-the-hash attack. 

## NTLMv1 (Net-NTMLv1)
NTLMv1 uses NT and LM hash
The server sends to the client an 8-byte random number (which is tha challenge) and the client returns a 24-byte response. They can NOT be used for pass-the-hash attacks. 
An example of the challenge-response: 
```
X = 8-byte challenge from the server
K1 | K2 | K3 = LM/NT-hash | 5-bytes-0
response = DES(K1,X) | DES(K2,X) | DES(K3,X)

NTLMv1 hash example: 
u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```
## NTLMv2 (Net-NTLMv2)
It is a stronger version of the NTLMv1. NTLMv2 sends two responses to an 8-byte server challenge. Each response contains a 16-byte HMAC-MD5 hash of the server challenge (SC), a fully/partially randomly generated client challenge (CC), and an HMAC-MD5 hash of the user's password and other identifying information (v2-Hash). The two responses differ in the format of the client challenge (CC and CC*). The shorter response uses an 8-byte random value for this challenge. In order to verify the response, the server must receive as part of the response the client challenge. For this shorter response, the 8-byte client challenge appended to the 16-byte response makes a 24-byte package which is consistent with the 24-byte response format of the previous NTLMv1 protocol.: 
```
SC= 8-byte server challenge 
CC = 8-byte client challenge, random
CC*= (X,time, CC2, domain name)
v2-Hash = HMAC-MD5(NT-Hash, user name, domain name)
LMv2 = HMAC-MD5(v2-Hash, SC, CC) (1 response message)
NTv2 = HMAC-MD5(v2-Hash, SC, CC*) (2nd response message)
response = LMv2 | CC | NTv2 | CC*

NTLMv2 hash example: 
admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
```
## Domain Cached Credentials (MSCache2)
DCC is a protocol that doesn't need the the client to communicate with a domain controller. Hosts stores the last **10** hashes for any domain users that log into the machine in the **HKEY_LOCAL_MACHINE\SECURITY\Cache** registry key. This hashes are hard to crack but they can be obtained once the attacker has admin acces to the machine. It looks like this:
```
$DCC2$10240#adri#e4e938d12fe5974dc42a90120bd9c90f
```
# Accounts
***
There are accounts on local systems and in Active Directory to give a user/program the ability to log on and acces resources based on their rights. When a user logs in successfully, the system creates an acces token that describes the security content of a process/thread and the user's security identity and group membership. Users can be assigned to groups  that can contain one or more members. This groups allows an easier management of access controls because they only need to be assigned to the group instead of assigning them to each user. 
Usually, in the AD each user will have one user account, however some user can have different users (workers with different roles or processes). It is also common to have disabled accounts for audit purposes. User accounts present an immense attack surface and are usually a key focus for gaining a foothold during a penetration test. Users are often the weakest link in any organization.  

## Local Accounts
Local accounts are stored locally on a particular server/workstation. This accounts are considered security principals but can only manage acces on the standalone host. There are several default local user accounts: 
- **Administrator:** This account has the SID ```S-1-5-domain-500```. It has full controll and it can't be deleted or locked but it can be disabled and renamed. Since Windows 10 and Sercer 2016 it is disabled by default. 
- **Guest:** This account is also disabled by default. The purpose of this account is to allow users without an account on the computer to log in temporarily with limited access rights. 
- **SYSTEM or NT AUTHORITY\SYSTEM:** This is the default account and is the one used by the operating system to perform internal functions. SYSTEM is a service account and does not run entirely in the same context as a regular user. Many of the processes and services running on a host are run under the SYSTEM context. It can't be added to any groups. 
- **Network Service:** This is a predefined local account used by the Service Control Manager (SCM) for running Windows services. When a service runs in the context of this particular account, it will present credentials to remote services.
- **Local Service:** This is another predefined local account used by the Service Control Manager (SCM) for running Windows services. It is configured with minimal privileges on the computer and presents anonymous credentials to the network.

## Domain Users
Domain users are granted rights from the domain to access resources such as file servers, printers, intranet hosts, etc (based on the permissions granted). This users can log in to any host in the domain (unlike local users). One important account is the ```KRBTGT```. This account is a type of local account and acts as a service account for the Key Distribution service. It is a common target for attackers since gaining control or access will enable an attacker to have unconstrained access to the domain.

## User Naming Attributes
This attributes can be used to improve security: 
- **UserPrincipalName (UPN):** This is the main logon name for the user, by convention uses the email address. 
- **ObjectGUID:** Unique identifier of the user. It never changes and remains even if the used is removed.
- **SAMAccountName:** This is a logon name that supports the previous version of Windows clients and servers.
- **objectSID:** This is the user SID. This attribute identifies a user and its group memberships during security interactions with the server.
- **sIDHistory:** It contains the previous SIDs for the user object when moved from another domain.  After a migration occurs, the last SID will be added to the sIDHistory property, and the new SID will become its objectSID.

## Domain-joined vs. Non-Domain-joined Machines
There is a difference between a host that is inside the domain and a host that is only in a workgroup. 
### Domain joined
A host joined to a domain will acquire any configurations or changes necessary through the domain's Group Policy. It can acces and log in to any resources from ani host in the domain. 
### Non-domain joined
This computers are in a **workgroup** and are not managed by any domain policy. The advantage of this setup is that the individual users are in charge of any changes they wish to make to their host. Users created there only exist in that host and profiles are not migrated to other hosts within the workgroup. 

Having a **NT AUTHORITY\SYSTEM** level access will have similar rights as a standar domain user in the AD environment. This important because it allows to read data within the domain anf gather information. 
# AD Groups
***

Groups are usefull because they can place similar users together and mass assign rights and acces to them. The difference between groups and OUs is that groups are used to assign permissions to access resources while OUs can also be used to delegate administrative tasks to a user without giving them additional admin rights.

## Groups types and scopes
Groups have two fundamental characteristics: 
- **group type:** defines the group purpose (**security** or **distribution**). Security groups are for assigning permissions and rights while the distribution groups are used by email apps to distribute messages to all group members.
- **group scope:** shows how the group can be used within the domain or forest. There are three diferent scopes: 
	- **Domain Local Group:** This groups can only be used to manage permissions to domain rosources that exists in the domain where it was created. They can't be used in other domains but they can contain users from other domains.  Local groups can be nested into (contained within) other local groups but not within global groups.
	- **Global Group:** This groups can be used to frant access to resources in another domain. It can only contain accounts from the domain where it was created. They can be nested inside other Global Groups or Local Groups. 
	- **Universal Group:** This groups can be used to manage resources distributed across multiple domainds and have permissions to any object within the same forest. Unlike the other groups, they are stored in the Global Catalog (GC). It is recommended that administrators maintain other groups (such as global groups) as members of universal groups because global group membership within universal groups is less likely to change than individual user membership in global groups. If a user is changed inside a global group, the replication will be only triggered at a domain level, however, if they where directly inside the universal group, the replication will imply all the forest (and create network overhead).

There are built-in security groups and only users can be added to these groups. One example is the **Domain Admins** group, which is a Global security group. 

## Nested Groups

As mentioned previously, a Domain Local Group can be member of another Domain Local group. The privileges will be inherited and this can lead to some unintended privileges. [BloodHound](https://github.com/BloodHoundAD/BloodHound) is a tool that helps to detect unwanted privileges. 

## Group Attributes

Like users, groups have several attributes, the most important ones are: 
- **cn:** Or Common-Name is the name of the group. 
- **member:** All the user, groups and contact objects that are members of the group.
- **groupType:** An integrer to specify group type and scope.
- **memberOf:** List of any groups that contain this group.
- **objectSid:** The security indentifier of the group (the value that identify the group as a security principal).

# Active Directory Rights and Privileges
***
A **Right** is assigned to users or groups to **access** an object such as a file. A **Privilege** grant a user permission to **perform an action** such as executing something, shuting down a system, etc. Privileges can be assigned individually to a user or assign them via a group membership. 

##Built-in AD Group

This are some of the most common built-in groups (default security groups that AD contains): 

| **Group Name**                         | **Description**                                                                                                                                                                                                                                                                            |
|----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Account Operators**                  | Members can create and modify almost all accounts (users, local and global groups, etc.) except the Administrator account, administrative user accounts  nor members of the administrators, Server Operators, Account Operators, Backup Operators, or Print Operators groups.              |
| **Administrators**                     | Members of this group have full access to any computer and the entire domain.                                                                                                                                                                                                              |
| **Backup Operators**                   | Members can backup and restore all files (regardless file permissions). They can also log on and shut down computers, and DC. They can make shadow copies of the SAM/NTDS db.                                                                                                              |
| **DnsAdmins**                          | Members have acces to DNS information. This group is only created if the DNS server role has been installed.                                                                                                                                                                               |
| **Domain Admins**                      | Members can administer the domain and are members of the local administrator's group an al the domain-joined machines.                                                                                                                                                                     |
| **Domain Computers**                   | Any computers created in the domain (aside from domain controllers) are added to this group.                                                                                                                                                                                               |
| **Domain Controllers**                 | It contains al the DCs                                                                                                                                                                                                                                                                     |
| **Domain Guests**                      | This group includes the domain's built-in Guest account. Members of this group have a domain profile created when signing onto a domain-joined computer as a local guest.                                                                                                                  |
| **Domain Users**                       | It contains all users in a domain.                                                                                                                                                                                                                                                         |
| **Enterprise Admins**                  | This group only exists in the root domain of the AD forest. Members in this group are granted the ability to make forest-wide changes such as adding a child domain or creating a trust. The Administrator account for the forest root domain is the only member of this group by default. |
| **Event Log Readers**                  | Members can read event logs on local computers.                                                                                                                                                                                                                                            |
| **Group Policy Creator Owners**        | Members of this group can create, edit and delete GPO in the domain                                                                                                                                                                                                                        |
| **Hyper-V Administrators**             | Members have complete access to all features in Hyper-V. They should be considered Domain Admins if they are inside a virtual DC.                                                                                                                                                          |
| **IIS:IUSRS**                          | This is a built-in group used by Internet Information Services (IIS), beginning with IIS 7.0.                                                                                                                                                                                              |
| **Pre–Windows 2000 Compatible Access** | This group exists for backward compatibility for computers running Windows NT 4.0 and earlier.                                                                                                                                                                                             |
| **Print Operators**                    | Members can control printers. They can log on the DC locally.                                                                                                                                                                                                                              |
| **Read-only Domain Controllers**       | It contains all the read-only DCs                                                                                                                                                                                                                                                          |
| **Read-only Domain Controllers**       | Grants users and groups permission to connect using RDP.                                                                                                                                                                                                                                   |
| **Remote Management Users**            | This group can be used to grant users remote access to computers via Windows Remote Management (WinRM)                                                                                                                                                                                     |
| **Schema Admins**    | Members can modify the AD scheme. It only exists in the root domain of the forest and the Administrator account for the forest root domain is the only member of this group by default. |
| **Server Operators** | This group only exists on domain controllers. Members can modify services, access SMB shares, and backup files on domain controllers. By default, this group has no members.            |

## User Rights

Depending on thir group membership, users can have various rights assigned to them. This are some important examples:

| **Privilege**                     | **Description**                                                                                                                                                                                                                                              |
|-----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **SeRemoteInteractiveLogonRight** | It gives to the user the right to log on using RDP                                                                                                                                                                                                       |
| **SeBackupPrivilege**             | It grants the ability to create system backups. It can be used to retrieve passwords such as the SAM and SYSTEM Registry hives and the NTDS.dit Active Directory database file.                                                                          |
| **SeDebugPrivilege**              | This allows a user to debug and adjust the memory of a process. With this privilege, attackers could utilize a tool such as Mimikatz to read the memory space of the Local System Authority (LSASS) process and obtain any credentials stored in memory. |
| **SeImpersonatePrivilege**        | This privilege allows us to impersonate a token of a privileged account such as NT AUTHORITY\SYSTEM.                                                                                                                                                     |
| **SeLoadDriverPrivilege**         | A user with this privilege can load and unload device drivers that could potentially be used to escalate privileges or compromise a system.                                                                                                              |
| **SeTakeOwnershipPrivilege**      | SeTakeOwnershipPrivilege                                                                                                                                                                                                                                 |

If we want to see the privileges that the user has, after logging into the host, we can use the command **whoami /priv** to obtain a list of all user rights. Some rights are only for administrative users. Even if we have a domain account, if we are using a **non-elevated** console, the rights will also be very restricted. This is because, by default, Windows systems do not enable all rights to us unless we run the CMD or PowerShell console in an elevated context. This is controlled by the **User Account Control (UAC)**. If we execute the **whoami /priv** in a elevated console we will se several new privileges. 

# Hardening Measures
***

Since AD is not secure by default, it is important to add some hardening measures to protect the AD. 

## LAPS

The **Local Administrator Password Solution (LAPS) is a free software that provides a centralized management of the local accounts passwords in the AD protected with an ACL. It randomize the passwords of local administrator accounts and it allows some users to retrieve them using GPOs.

## Group Policy Security Settings

Group Policy Objects (GPOs) are virtual collections of policy settings that can be applied to specific users, groups, and computers at the OU level. The following list shows some types of security policies that can be applied: 

- **Account Policies**: They manage how user accounts interact with the domain. They include password policy, account lockout policy, and Kerberos-related settings. 
- **Local Policies**: This policies are applyed to a specific computer and  include the security event audit policy, user rights assignments (user privileges on a host), and specific security settings such as the ability to install drivers, whether the administrator and guest accounts are enabled, renaming the guest and administrator accounts, preventing users from installing printers or using removable media, and a variety of network access and network security controls.
- **Software Restriction Policies**: They control what software can be run on a host. 
- **Application Control Policies**: They controll what applications can be run by a specific user/host. 
- **Advanced Audit Policy Configuration**: A variety of settings that can be adjusted to audit activities such as file access or modification, account logon/logoff, policy changes, privilege usage, and more.

## Update Manafement (SCCM/WSUS)

The Windows Server Update Service is a software that can be installed as a role at any Windows Server and it helps to automatyze the task of patching Windows. The **System Center Configuration Manager is a paid solution that uses WSUS but has more functionalities. 

## Group Managed Service Accounts (gMSA)

A gMSA is an account managed by the domain that offers a higher level of security than other types of service accounts for use with non-interactive applications, services, processes, and tasks that are run automatically but require credentials to run. They provide automatic password management with a 120 character password generated by the domain controller. The password is changed at a regular interval and does not need to be known by any user. It allows for credentials to be used across multiple hosts.

## Security Groups

This groups offer acces to network resources. AD creates some default security groups as mentioned in the previous charapter.

## Account Separation

This measure consist about admins having separate accounts, one for their day-to-day work and another one, with privileges, for whenever they have to do a specific task that requires privileges. 

## Limiting Domain Admin Account Usage

The Domain Admin accounts should only be used to log in into the DC. This would ensure that Domain Admin account passwords are not left in memory on hosts throughout the environment.

## Periodically Auditing and Removing Stale Users and Objects

It's important to audit the AD and remove unused accounts to reduce the attack surface. 

## Audit Permissions and Acces

Organizations should also periodically perform access control audits to ensure that users only have the level of access required for their day-to-day work.

## Logging 

It is important to Log all the anomalous activity and important changes that take place within the AD. 

## Restricted Groups

Restricted Groups is a group policy that can be used to control the membership of the groups. They can be used for a number of reasons, such as controlling membership in the local administrator's group on all hosts in the domain by restricting it to just the local Administrator account and Domain Admins and controlling membership in the highly privileged Enterprise Admins and Schema Admins groups and other key administrative groups. Restricted groups allow an administrator to define the following two properties for security-sensitive (restricted) groups:
- Members
- Members Of
The Members list defines who should and shouldn't belong to the restricted group. The Member Of list specifies which other groups the restricted group should belong to.

## Limiting Server Roles

It is important not to install additional roles on sensitive hosts, such as installing the Internet Information Server (IIS) role on a Domain Controller. This would increase the attack surface of the Domain Controller, and this type of role should be installed on a separate standalone web server. 

## Limiting Local Admin and RDP Rights

Organizations should tightly control which users have local admin rights on which computers. As stated above, this can be achieved using Restricted Groups. The same goes for Remote Desktop (RDP) rights. If many users can RDP to one or many machines, this increases the risk of sensitive data exposure or potential privilege escalation attacks, leading to further compromise.

# Group Policy in depth
***

## GPOs

As mentioned in previous chapters, Group Policy Object is a virtual collection of policy settings that can be applied to user(s) or computer(s). Each GPO has a unique name and unique GUID and they can be linked to multiple containers. Some typical uses of GPOs include: 
- Define password policies. 
- Prevent the use of removable media devices
- Enforcing a screensaver with a password
- Restricting acces to applications that a standar user may not need (cmd.exe and PowerShell)
- Enforce logging policies
- Deploying software across a domain
- Blocking users from installing unapproved software
- Disallowing LM hash usage in the domain
- Runing scripts when computer start/shutdown or when users log in/out to their machine. 
- etc.


GPO settings are processed using a hierarchical structure of AD and are applied using the **Order of Precedence* rule. This rule defines several levels: 
- **Local Group Policy:** This policies are defined directly to the host. They will be overwritten for settings at a higher level. 
- **Site Policy:** Any policies specific to the Enterprise Site that the host resides in. 
- **Domain-wide Policy:** Any settings you wish to have applied across the domain as a whole. For example, setting the password policy complexity level, configuring a Desktop background for all users, and setting a Notice of Use and Consent to Monitor banner at the login screen.
- **Organizational Unit (OU):** These settings would affect users and computers who belong to specific OUs. You would want to place any unique settings here that are role-specific.
- **Any OU Policies nested within other OU's:** Settings at this level would reflect special permissions for objects within nested OUs.

A GPO attached to a specific OU would have precedence over a GPO attached at the domain level because it will be processed last and could run the risk of overriding settings in a GPO higher up in the domain hierarchy. The Default Domain Policy is the default GPO that is automatically created and linked to the domain. It has the highest precedence of all GPOs and is applied by default to all users and computers. The next picture shows the precedence order and how GPO are applied ![precedence_order](/img/posts/2022-06-21-Active-Directory/precedence.jpg). 

When more than one GPO is linked to the same OU, they are processed based on the **Link Order**. The GPO with the lowest Link Order is processed last, or the GPO with link order 1 has the highest precedence, then 2, and 3, and so on. Is it possible to specify the **Enforced** option to enforce settings in a GPO. This means that other policy settings CAN'T override other settings. Is it also possible to apply the **Block Inheritance** at a OU level to avoid aplying policies from higher elements of the precedence level. 

## Group Policy Refresh Frequency

Windows performs periodic Group Policy updates, which by default is done every 90 minutes with a randomized offset of +/- 30 minutes for users and computers. The period is only 5 minutes for domain controllers to update by default. When a new GPO is created and linked, it could take up to 2 hours (120 minutes) until the settings take effect. It is possible to change the default refresh interval within Group Policy itself. Furthermore, we can issue the command **gpupdate /force** to start the update process. 

## Security Considerations of GPOs

When a user has the rights to modify a GPO that applies to an OU where the used is contained, several attacks are possible. They may include adding additional rights, adding a local admin to a host, installing malware, etc. 
