## </0NET> - Web-Based Command and Control Framework



####   A python3 based command and control botnet framework for windows & linux based systems

###### This tool was made as a cyber security proof of concept (POC) and has been in development/testing since early 2023. To demonstrate and concept how malicious actors can control and maintain persistence over large amounts of Infected devices, for further information or queries contact me at: prv@anche.no

------------



![Onet-banner](https://i.ibb.co/ZRBPWKHs/0net-logo.jpg "Onet-banner")


------------


### Overview

0net is a Command and Control (C&C) framework developed in Python 3, capable of hosting both C&C servers and clients on Windows and Linux systems. It uses encrypted commands, leveraging a custom-built [Vigenère cipher](**http:/https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher/ "Vigenère cipher")  to encode and decode client-server communication, utilizing a numerically-based key string that ensures both simplicity and anonymity.

The framework is engineered for scalability, allowing the infection and management of multiple client machines, referred to as ‘bots,’ within a distributed infrastructure. These compromised systems can maintain persistent connections to a centralized web-based C&C server, even on fully updated operating systems, enabling long-term access and control. To achieve this persistence, 0net employs a variety of techniques tailored to different operating system defenses, making it resilient against security patches and mitigation efforts.

![](https://i.ibb.co/rGx2tzq1/sharpened-image.jpg)

Beyond basic control functionalities, 0net also provides an array of post-exploitation modules that extend its capabilities. These modules facilitate deep reconnaissance, privilege escalation, lateral movement within networks, data exfiltration, and network-based attacks. The operator can issue commands remotely, execute scripts, manipulate system processes, and gather intelligence in real time. Additionally, the modular nature of 0net allows for further expansion, making it adaptable for various operational needs, whether for penetration testing, red team operations, or adversarial simulations.

------------

### Host Configuration & Usage
<details>
<summary>[➕] Installation requirements </summary>
    
If the system you are launching the host file on does not meet the right requirements or the file detects you are launching for the first time, it may attempt to install it for you.
the following requirements for the host file are:

*Windows 10/11 OR Most versions of Linux (Debian)*

*Python3.9+ (https://www.python.org/downloads/)* 

</details>

<details>
<summary>
[➕] Startup & Initial Run 
</summary>

**File's & Configuration Setup**

Before you compile the host file, you must first configure it to set which variables you wish to use for things such as URL of C&C server, setting a encryption cypher key, FTP logins and locations of the server files.

You can do this using the first couple lines of the **host.py** file:

```

############################################################################################################################################################################
############################################################################################################################################################################

obfuscate = () # Set Ofuscate Var
encryption_key = "" #Encryption key for encrypting outgoing oommands using Vigenère Cipher 

ftp_server = ''     # Your FTP server
ftp_username = ''         # Your username for FTP server
ftp_password = ''     # Your password for FTP server
ftp_directory = '/var/www/html/'          # Your public/web facing directory


full_url = ""
response_file_url = "" # Full URL of the responses.txt file
information_file_url = ""   # Full URL of the data.txt file

command_file_name = 'pico-wifi.txt'                 # Local name/location of the pico-wifi command file
responses_file = ""       # Local location of the responses.txt file  
data_file = ""                 # Local location of data.txt file
screenshot_file = ""     # Local location for future 'screenshot.png' files

############################################################################################################################################################################
############################################################################################################################################################################
```


    
Once the hostfile has connected to the server, you will be presented with the following options for input:

![](https://i.ibb.co/Zp2bBr2Z/initial-screen.png)


**[0]** You can view the current configuration for your client, server and host files along with connecting IP addresses and locations of important configuration files:

![](https://i.ibb.co/JwCqHFvT/config-screen.png)



**[1]** The host file uses an encryped FTP tunnel to read and write to the server files, once connected, it will establish the connection with the set FTP credentials and clear any previous connection logs or IPs left in the following host files:

`['lock.txt', 'ips.txt', 'responses.txt']`

Once deleted, it will resume connection and finish the connection to the server:

![](https://i.ibb.co/Pdk6frv/login.png)

This will bring you into the (*/command:>* ) subsection allowing you to issue payloads to the server for connected clients to read and execute.

**[2]** You can establish a connection between you and the server using either a http/https, socks4/socks5 Proxy server or via the TOR network:

![](https://i.ibb.co/Rpb6XcB6/proxy-connect.png)

This connection requires TOR to be installed locally on the system on port 9050.

**[3]** You can generate a compiled payload file in either (.exe) Windows format or (.sh) Linux format depending on your current system and which type of client you with to infect, this will install on the local terminal via [PyInstaller](https://pypi.org/project/pyinstaller/)  and will output the payload file within the same directory the host file is stored:

![](https://i.ibb.co/1G1LFTJ6/Compile1.png)

It will remove any left over .pyw or uncompiled program files

![](https://i.ibb.co/s9kDNrMg/Compile2.png)

Before leaving the compiled ready to go payload locally on the system:

![](https://i.ibb.co/Hfbx4bDb/payload-file.png)

**(WARNING: Do NOT change the file extention of the payload file such as to .com or other executable file type, this may cause the file to get detected or deleted by antivirus)**

</details>

<details>
<summary>
[➕]  Commands & Usage</summary>

**Usage & Files**

The server file must have full administator/root privilages for reading/writing files onto the host system.

For the server file to run correctly, it must run along side a file in the same directory named **'bot_information'**, this is the file in which screenshots and extracted bot information is sent to the host system after a targeted command is issued.

**Viewing & Control**

[view] – Retrieves and displays a list of all currently connected bots within the botnet, providing real-time visibility into active infections.

[refresh] – Updates the list of connected bots and refreshes the command-and-control (C&C) server files, ensuring synchronization between the server and its compromised hosts.

[target] – Enables issuing specific commands to an individual bot by targeting its public IP address, allowing for more granular control over infected systems.

![](https://i.ibb.co/tT0kcn5h/botview.png)

**Anonymization & Anti-Analysis**

[obfuscate] – Temporarily modifies the payload file's properties, signature, and extension type to evade detection by security software. During this period, bots cease communication with the C&C server, reducing the risk of identification.

[proxy] – Routes all bot traffic through an HTTP proxy to obscure the origin of malicious activity, mitigating the effectiveness of network-based traffic analysis.

[disable] – Terminates processes associated with common antivirus (Windows) and anti-rootkit/file detection software (Linux) across all infected systems, preventing security tools from detecting or mitigating the botnet's presence.


**System Manipulation & Command Injection**

[echo] – Sends a text message to all bots' terminals for testing purposes, verifying connectivity and command execution.

[message] – Displays a GUI pop-up message on all infected machines (only functional if the system supports a graphical user interface).

[cmd] – Executes arbitrary system commands across all compromised machines, providing direct control over their operating systems.

[download] – Fetches and runs an executable file from a specified URL on all bots, enabling remote deployment of additional malware or utilities.

[redirect] – Opens a specified URL in the web browser of all infected machines, often used for phishing, ad fraud, or social engineering campaigns.

**DDoS & Network Abuse**

[icmp-ddos] – Initiates an ICMP flood attack from all bots to a target IP, overwhelming it with excessive ping requests to disrupt network availability.

[tcp-ddos] – Launches a TCP-based denial-of-service attack, typically by exhausting server connections and resources, leading to service disruption.

[udp-ddos] – Conducts a UDP flood attack by sending massive amounts of UDP packets to a specified IP and port, consuming bandwidth and server processing power.

<details>
    
<summary>[➕] Targeted commands (for individual systems)</summary>

    
**System Manipulation & Command Injection**

[echo] – Sends a text message output to the terminal of a specific infected machine, primarily for testing connectivity and command execution.

[message] – Displays a GUI pop-up message on a targeted system, provided it has a graphical user interface (GUI) enabled.

[cmd] – Executes an arbitrary system command on a single compromised machine, allowing direct control over its operating system.

[download] – Fetches and executes a file from a specified URL on the targeted system, enabling remote deployment of additional malware or scripts.

**Exfiltration & Reconnaissance**

[extract] – Gathers detailed system and network information from the infected machine, saving the results in a local text file on the attacker's system for further analysis.

[screenshot] – Forces the infected system to capture a full-display screenshot and temporarily upload it to the command-and-control (C&C) server for automatic retrieval. Requires a GUI-capable target.

[clipboard] – Extracts the latest contents from the targeted system’s clipboard and uploads it to the C&C server, potentially revealing sensitive copied data such as passwords or confidential text.

**Remote Access & Control**

[shell-external-tcp] – Commands the bot to establish a reverse TCP shell connection to an external system, providing the attacker with direct command-line access. The bot connects to a specified listening IP address and port number.

[shell-external-http] – Similar to the TCP shell but using an HTTP-based reverse shell, allowing covert communication over web traffic to bypass traditional network monitoring.

**Miscellaneous**

[back] – Exits the targeted shell and allows the attacker to select a new bot for further operations.
</details>
</details>

### Payload & Capabilities

<details>
<summary>[➕] Pre-infection & Anonymisation</summary>
    
The payload created by 0net can come in two different executable file types compiled via [PyInstaller](https://pypi.org/project/pyinstaller/) in either **.exe** or** .sh** format dependant on which OS you run and compile the payload on (Windows/Linux).

**Virtualisation Checks**

Upon first run of the payload file, it will firstly check whether the file is being run on a virtual machine, this is to prevent reverse engineering of the payload file and ensure the server is kept as anonymous as possible, if a VM is detected it will abort the initial infection process and not connect to the server- it can detect the following virtual machines for both Windows and Linux:

`common_vm_processes = ['vmware', 'vbox', 'qemu', 'virtualbox', 'vagrant', 'vmtoolsd'] # Windows` 

`lists = {"vmware", "vbox", "Phoenix", "innotek"} # Linux`

**Admin/Root privilege check**

The payload file will check if it has been ran on either Administator or Root privilages, if so it will log these accordingly or attempt to obtain them if certain persistence methods to not work.

**Information gathering & logging**

The payload file will also gather information about the system and network it is being ran on to report back to the server and further target the system more specifically, information such as:

 • Location/IP information
 • Network information
 • Hardware information
 • Operating system information 
 
 The payload will also create a *Unique ID* based of this information to assist the server in identifying machines bouncing on the same network made up of a collection of different information gathered from the system and encoded, this may look like so:
 
`Unique ID: (fdef1106)`

Multiple bots on the same network or under the same public IP use a [round-robin](https://en.wikipedia.org/wiki/Fast_flux) based algorithm technique, or more commonly known as 'Fast Flux' to keep the C&C server connected to the desired network, used to avoid heavy traffic loads and bounce around the network:

![](https://i.ibb.co/wNjn4XXz/flux.png)
</details>

<details>
<summary>
[➕] Communication (client to server) 
</summary>
    
The payload file communicates to send/recieve commands and data to the server using the following filetypes:

**`/pico-wifi.txt`**- the pico-wifi file, named after the wifi chip found in the raspberry PI pico W- is stored on the server and temporarily hosts the commands for the bots to read and execute before being deleted after a set amount of time.

**`/responses.txt`**- the responses file is used to store and register the responses from incomming connected bots, information such as unique ID, IP addresses and date & time logs for the server to read and temporarily store.

**`/data.txt`** - this file is where incomming clients information is dumped when either the *clipboard* or *extract* command is sent, information here is not publically facing due to the htaccess.txt configuration file found in the server and is automatically deleted after a short period of time.

**`/screenshot.png `**- the screenshot file in which the screenshot uploaded by an infected bot is stored, before being automatically downloaded to the host and then deleted by the server.

The payloads traffic and filetype does not get flagged by Windows Antivirus due to it using HTTP based traffic instead of TCP or UDP which traditional botnets use to send/receive commands, it sends these commands via 'Chunks' of HTTP GET/POST requests to the server making traffic and system usage: 

![](https://i.ibb.co/Kzxry0Lr/chunks.png)

 This significantly makes it less and harder to detect using forensics methods such antimalware or traffic analysis, this makes the sent & recieved commands and connections to the C&C server blend in with regular HTTP/S browser traffic and hard to prevent using firewall/network blocking.
 
 ![](https://i.ibb.co/0jv9LB75/traffic.png)
 
</details>
<details>
<summary>[➕] Persistence & Obfuscation
</summary>
    
The payload file upon completion of initial VM, and Privilege checks can run the following persistence methods based on which OS the file is executed on to keep the connection between client and server for long periods of time even after the file has stopped running, has been deleted or system has been restarted:

**Windows**

Startup file - the executable script, or shortcut in the Windows Startup folder:

`(C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup)`. 

This ensures automatic execution when the user logs in. It is a simple yet effective persistence mechanism that does not require administrative privileges.

Registery Key -  registry key to execute upon system boot or user login:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run `

By inserting a reference to the executable payload file, the file ensures persistence even after reboot and will be executed upon user login providing the original payload file has not been deleted or moved, this is as a backup incase the startup file is flagged, this is also harder to remove and requires administator privilages.

**Linux**

Bashrc startup script - payload injects commands into the `~/.bashrc` profile of the linux system which execute whenever the user starts a new shell session. This method is user-specific and primarily affects interactive login environments. If the infected user has administrative privileges, malware can execute privileged commands whenever they open a terminal.

System Cronjob/ System service - achieves persistence by scheduling execution through cron jobs or systemd services:
the payload generates a `.service` file in ` /etc/systemd/system/ ` to ensure execution during system startup. Systemd services can be configured to restart automatically, ensuring resilience against termination.
</details>

### Server & Setup

<details>
    
<summary>[➕] Requirements & Installation</summary>
    
For the server to run, the following requirements are needed on the system for the C&C server to fully function:

**- A fully functioning Linux system (Debain/Ubuntu preferred but not required)** [[?]](https://www.linux.org/pages/download/)

**- Nginx or Apache web server with ports 80 and/or 443 open**[ [?]](https://medium.com/@muhammadimron1410/guide-to-creating-a-simple-web-server-using-nginx-and-apache2-ae7d27b421c6)

**- PHP Version 8.2+ configured to Nginx**[ [?]](https://www.theserverside.com/blog/Coffee-Talk-Java-News-Stories-and-Opinions/Nginx-PHP-FPM-config-example)

**- Ports 22 & 21 open with SSH and FTP enabled** [ [?]](https://documentation.ubuntu.com/server/how-to/networking/ftp/index.html) 

The following configurations for the Nginx config file (/etc/nginx/nginx.conf):

````
nginx
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    # multi_accept on;
}

http {

    ##
    # Basic Settings
    ##

    client_max_body_size 1000M;

    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    # server_tokens off;

    # server_names_hash_bucket_size 64;
    # server_name_in_redirect off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ##
    # SSL Settings
    ##

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;

    ##
    # Logging Settings
    ##

    access_log /var/log/nginx/access.log;

    ##
    # Gzip Settings
    ##

    gzip on;

    # gzip_vary on;
    # gzip_proxied any;
    # gzip_comp_level 6;
    # gzip_buffers 16 8k;
    # gzip_http_version 1.1;
    # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    ##
    # Virtual Host Configs
    ##

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

#mail {
#    # See sample authentication script at:
#    # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#    # auth_http localhost/auth.php;
#    # pop3_capabilities "TOP" "USER";
#    # imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#    server {
#        listen     localhost:110;
#        protocol   pop3;
#        proxy      on;
#    }
#
#    server {
#        listen     localhost:143;
#        protocol   imap;
#        proxy      on;
#    }
#}
````

For PHP, no additional modifications are required to any configuration files.

</details>
<details>
    
<summary>[➕] Files & Setup</summary>

The following files must be uploaded to the **public web facing directory**:

`data.txt`
`ips.txt`
`pico-wifi.txt`
`screenshot.txt`
`store-data.php`
`index.php`
`lock.txt`
`responses.txt`
`server.php`
`.htaccess.txt`

After these have been uploaded it is ideal to refresh and restart any services such as nginx, php etc...

The **htaccess** file when put in place, hides the following files from public viewing in order to protect unencrypted client information:

`data.txt` `lock.txt` `ips.txt` `responses.txt` `screenshot.png`

using the following contents:

````
php_value display_errors 1

<Files "data.txt">
    Order deny,allow
    Deny from all
</Files>

<Files "lock.txt">
    Order deny,allow
    Deny from all
</Files>

<Files "ips.txt">
    Order deny,allow
    Deny from all
</Files>


<Files "responses.txt">
    Order deny,allow
    Deny from all
</Files>


<Files "screenshot.png">
    Order deny,allow
    Deny from all
</Files>
````
It is important to use this configuration file within your publically facing web directory to ensure incomming client information such as public IP's, Extract data and Screenshots are not accessable externally but can still be downloaded and accessed via the Host files FTP & SSH connections.

You may also have to give ALL the files uploaded into the main web directory full **root/administator privilages**, you can do this by using the `sudo CHMOD +x <filename>` command, this is to avoid any potential privilage errors that may occur during the upload/download process of the C&C server.

</details>

<details>

<summary>[➕] Usage & Deployment</summary>

Once all of the requirements are met for the server files to be run and the correct ports are open, just paste the files into the main publically facing web directory, in this case `/var/www/html/` for nginx:

![](https://i.ibb.co/d4ksdHk6/filesinweb.png)

and refresh the required services:

![](https://i.ibb.co/NgSzz9Mh/services.png)

once done, upon visiting the main page of the C&C server via a webbrowser- if successful the web page should look like such, with the following output:

![](https://i.ibb.co/C593J31h/success.png)

It is recommended that this file be stored or 'hidden' among legitimate website files to make it harder to be detected or users manually exploiting or viewing/sending data to the server via the webpage.

</details>
------------

### Disclosure

0net was developed as a proof-of-concept framework for evaluating operating system and network security. It serves as a tool for demonstrating the effectiveness of modern Command and Control (C&C) techniques, allowing cybersecurity professionals to assess defensive measures, identify vulnerabilities, and enhance security postures. By simulating real-world threats, it provides valuable insights into how systems respond to persistent access, encrypted communication, and post-exploitation activities.

This software is strictly intended for research, security testing, and authorized red team engagements. Its use must align with legal and ethical standards, ensuring compliance with established security policies. Responsibility for its application lies solely with the user, and any misuse falls outside the scope of the developer’s intent. Proper authorization is required before deploying this framework in any environment.

</details>












