#!/usr/env python3
# -*- encoding: utf-8 -*-


''' Importing Modules '''
import platform, os, time, re
import binascii, base64, urllib.parse, hashlib, requests, colored


''' Global Variables '''
option_mode = ''
option_alg = ''
x_string = ''
convert_result = ''
''' Coloring '''
	# for Style
cl_reset = colored.style.RESET
cl_bold = colored.attr("bold")
	# for Foreground
clfg_w = colored.fore.WHITE
clfg_r = colored.fore.LIGHT_RED
clfg_lg = colored.fore.LIGHT_GREEN
clfg_y = colored.fg(227)
clfg_b = colored.fore.BLUE
	# for Background
cl_bg_white = colored.back.WHITE
cl_bg_red = colored.back.LIGHT_RED
cl_bg_lgreen = colored.back.LIGHT_GREEN
cl_bg_yellow = colored.bg(227)
''' SETUP VARIABLE '''
sign_info = "{0}[{1}i{0}]".format(clfg_w,clfg_b)
sign_plus = "{0}[{1}+{0}]".format(clfg_w,clfg_lg)
sign_minus = "{0}[{1}-{0}]".format(clfg_w,clfg_r)
sign_proc = "{0}[*]".format(clfg_w)
sign_warn = "{0}[{1}!{0}]".format(clfg_w,clfg_r)
sign_input = "{0}[{1}>{0}]".format(clfg_w,clfg_y)


''' Banner and List Menu '''
banner = r'''{0}{1}
 ███████╗ ██████╗ ██████╗ ██████╗ ██╗   ██╗
 ██╔════╝██╔═══██╗██╔══██╗██╔══██╗██║   ██║
 ███████╗██║   ██║██████╔╝██████╔╝██║   ██║
 ╚════██║██║   ██║██╔══██╗██╔══██╗██║   ██║
 ███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝
 ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ 
 Coded by {2}Muhammad Rizky{1} [{2}XECTE-7{1}]
 version {2}1.3{1}

 Sobbu: Cryptography tool for encode-decode
        and encrypt-decrypt
'''.format(cl_reset, clfg_w,clfg_r)
list_mode = f'''{sign_info} Select Mode
 |
[{clfg_y}1{clfg_w}] Encode
[{clfg_y}2{clfg_w}] Decode
[{clfg_y}3{clfg_w}] Encrypt
[{clfg_y}4{clfg_w}] Decrypt'''
list_encode_decode = f'''{sign_info} Select Algorithm
 |
[{clfg_y}1{clfg_w}] Base32     [{clfg_y}4{clfg_w}] Hex       [{clfg_r}99{clfg_w}] Back to Main Menu
[{clfg_y}2{clfg_w}] Base64     [{clfg_y}5{clfg_w}] ASCII
[{clfg_y}3{clfg_w}] Binary     [{clfg_y}6{clfg_w}] URL'''
list_encrypt_decrypt = f'''{sign_info} Select Algorithm
 |
[{clfg_y}1{clfg_w}] MD5        [{clfg_y}7{clfg_w}]  SHA3-224
[{clfg_y}2{clfg_w}] SHA-1      [{clfg_y}8{clfg_w}]  SHA3-256
[{clfg_y}3{clfg_w}] SHA-224    [{clfg_y}9{clfg_w}]  SHA3-384
[{clfg_y}4{clfg_w}] SHA-256    [{clfg_y}10{clfg_w}] SHA3-512
[{clfg_y}5{clfg_w}] SHA-384
[{clfg_y}6{clfg_w}] SHA-512    [{clfg_r}99{clfg_w}] Back to Main Menu'''


''' Clear Screen Function '''
def clr_scr():
	if platform.system() == 'Windows':
		os.system('cls')
	else:
		os.system('clear')

''' Cracker Function '''
# def crack_hashtoolkit(string):
# 	response = requests.get(f"https://hashtoolkit.com/reverse-hash/?hash={string}").text
# 	found = re.search(r'/generate-hash/\?text=(.*?)"',str(response))
# 	if found:
# 		convert_result = found.group(1)
# 		return found.group(1)
# 	else:
# 		return False

# def crack_nitrxgen(string):
# 	response = requests.get(f"https://hashtoolkit.com/reverse-hash/?hash={string}, verify=False").text
# 	if response.text:
# 		convert_result = response
# 		return response.text
# 	else:
# 		return False

# def crack_md5decrypt(string, hash_type):
# 	response = requests.get(f"https://md5decrypt.net/Api/api.php?hash={string}&hash_type={hash_type}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728").text
# 	if len(response) != 0:
# 		convert_result = response
# 		return response
# 	else:
# 		convert_result = ''
# 		return False

# def crack_md5online(string, hash_type):
# 	global convert_result
# 	response = requests.get(f"http://www.md5online.it/index.lm?key_decript={string}")
# 	result = re.search('color:#004030;">(.*)<br></font>', response.text).group(1)
# 	if result == '' or result == None or result == 'NESSUN RISULTATO':
# 		convert_result = ''
# 	else:
# 		convert_result = result

def crack_md5decrypt(string, hash_type):
	global convert_result
	# Different Algorithm
	if hash_type == 'md5':
		host_url = 'https://md5decrypt.net/en/'
	elif hash_type == 'sha-1':
		host_url = 'https://md5decrypt.net/Sha1/'
	elif hash_type == 'sha-256':
		host_url = 'https://md5decrypt.net/Sha256/'
	elif hash_type == 'sha-384':
		host_url = 'https://md5decrypt.net/Sha384/'
	elif hash_type == 'sha-512':
		host_url = 'https://md5decrypt.net/Sha512/'
	if hash_type in ["md5","sha-1","sha-256"]:
		pattern = str(rf"<br/>{string} : <b>(.*)\n</b>")
	elif hash_type in ["sha-384", "sha-512"]:
		pattern = str(rf"<br/>{string} : <b>(.*)</b><br/><br/>Trouv")
	data_builder = {'hash':f'{string}','decrypt':'D%C3%A9crypter'}
	try:
		response = requests.post(host_url, data=data_builder)
		#print(f"[>] {pattern}")
		#print(f"[>] {data_builder}")
		result = re.search(pattern, response.text)
		#print(f"[>] {result}")
		#print(f"[>] {result.group(1)}")
		if result == '' or result == None:
			convert_result = ''
		else:
			convert_result = result.group(1)
	except:
		convert_result = ''


''' Converter Function '''
def converter(mode, alg, string):
	global convert_result
	# For Base32 Algorithm
	if alg == 'base32' and mode == 'encode':
		convert_result = str(base64.b32encode(bytes(string, 'utf-8')))
		convert_result = convert_result[2::].strip("'")
	elif alg == 'base32' and mode == 'decode':
		convert_result = str(base64.b32decode(bytes(string, 'utf-8')))
		convert_result = convert_result[2::].strip("'")
	# For Base64 Algorithm
	elif alg == 'base64' and mode == 'encode':
		convert_result = str(base64.b64encode(bytes(string, 'utf-8')))
		convert_result = convert_result[2::].strip("'")
	elif alg == 'base64' and mode == 'decode':
		convert_result = str(base64.b64decode(bytes(string, 'utf-8')))
		convert_result = convert_result[2::].strip("'")
	# For Binary Algorithm
	elif alg == 'binary' and mode == 'encode':
		try:
			bin_string = int(string)
			convert_result = f"{(bin(bin_string))[2:]}"
		except:
			for huruf in string:
				convert_result += f"{(bin(ord(huruf)))[2:]} "
	elif alg == 'binary' and mode == 'decode':
		for serpihan in string.split():
			ordo = int(bytes(serpihan, 'utf-8'),2)
			huruf = chr(ordo)
			convert_result += huruf
	# For Hex Algorithm
	elif alg == 'hex' and mode == 'encode':
		try:
			bin_string = int(string)
			convert_result = f"{(hex(bin_string))[2:]}"
		except:
			for huruf in string:
				convert_result += f"{(hex(ord(huruf)))[2:]} "
	elif alg == 'hex' and mode == 'decode':
		for serpihan in string.split():
			ordo = int(bytes(serpihan, 'utf-8'),16)
			huruf = chr(ordo)
			convert_result += huruf
	# For ASCII Algorithm
	elif alg == 'ascii' and mode == 'encode':
		for huruf in string:
			convert_result += f"{ord(huruf)} "
	elif alg == 'ascii' and mode == 'decode':
		for serpihan in string.split():
			convert_result += f"{chr(int(serpihan))}"
	# For URL Algorithm
	elif alg == 'url' and mode == 'encode':
		url = string.strip()
		convert_result = urllib.parse.quote(url, safe='')
	elif alg == 'url' and mode == 'decode':
		url = string.strip()
		convert_result = urllib.parse.unquote(url)
	# For Hash MD5 Algorithm
	elif alg == 'md5' and mode == 'encrypt':
		convert_result = hashlib.md5(bytes(string,'utf-8')).hexdigest()
	# For Hash SHA-1 Algorithm
	elif alg == 'sha-1' and mode == 'encrypt':
		convert_result = hashlib.sha1(bytes(string,'utf-8')).hexdigest()
	# For Hash SHA-224 Algorithm
	elif alg == 'sha-224' and mode == 'encrypt':
		convert_result = hashlib.sha224(bytes(string,'utf-8')).hexdigest()
	# For Hash SHA-256 Algorithm
	elif alg == 'sha-256' and mode == 'encrypt':
		convert_result = hashlib.sha256(bytes(string,'utf-8')).hexdigest()
	# For Hash SHA-384 Algorithm
	elif alg == 'sha-384' and mode == 'encrypt':
		convert_result = hashlib.sha384(bytes(string,'utf-8')).hexdigest()
	# For Hash SHA-512 Algorithm
	elif alg == 'sha-512' and mode == 'encrypt':
		convert_result = hashlib.sha512(bytes(string,'utf-8')).hexdigest()
	# For Hash SHA3-224 Algorithm
	elif alg == 'sha3-224' and mode == 'encrypt':
		convert_result = hashlib.sha3_224(bytes(string,'utf-8')).hexdigest()
	# For Hash SHA3-256 Algorithm
	elif alg == 'sha3-256' and mode == 'encrypt':
		convert_result = hashlib.sha3_256(bytes(string,'utf-8')).hexdigest()
	# For Hash SHA3-384 Algorithm
	elif alg == 'sha-384' and mode == 'encrypt':
		convert_result = hashlib.sha3_384(bytes(string,'utf-8')).hexdigest()
	# For Hash SHA3-512 Algorithm
	elif alg == 'sha3-512' and mode == 'encrypt':
		convert_result = hashlib.sha3_512(bytes(string,'utf-8')).hexdigest()
	# For Hash Decryption
	elif alg == 'hash' and mode == 'decrypt':
		if len(string) == 32:
			print(f"{sign_proc} Detected as MD5 hash type")
			hash_type = 'md5'
			crack_md5decrypt(string, 'md5')
		elif len(string) == 40:
			print(f"{sign_proc} Detected as SHA-1 hash type")
			hash_type = 'sha-1'
			crack_md5decrypt(string, 'sha-1')
		elif len(string) == 64:
			print(f"{sign_proc} Detected as SHA-256 hash type")
			hash_type = 'sha-256'
			crack_md5decrypt(string, 'sha-256')
		elif len(string) == 96:
			print(f"{sign_proc} Detected as SHA-384 hash type")
			hash_type = 'sha-384'
			crack_md5decrypt(string, 'sha-384')
		elif len(string) == 128:
			print(f"{sign_proc} Detected as SHA-512 hash type")
			hash_type = 'sha-512'
			crack_md5decrypt(string, 'sha-512')
		else:
			print(f"{sign_warn} This type of hash is not supported")
			convert_result = ''


''' Main Function of Program '''
def utama():
	global option_mode, option_alg, x_string, convert_result
	# Select Mode
	clr_scr()
	print(banner)
	print(list_mode)
	print(" |")
	select_mode = str(input(f"{sign_input} Select Mode : {clfg_lg}"))
	if select_mode == '1':
		option_mode = 'encode'
	elif select_mode == '2':
		option_mode = 'decode'
	elif select_mode == '3':
		option_mode = 'encrypt'
	elif select_mode == '4':
		option_mode = 'decrypt'
	elif select_mode == 'exit' or select_mode == '0':
		exit()
	else:
		print(f"{sign_warn} Invalid mode selected")
		input(f"{clfg_w}[{clfg_y}Press ENTER to continue...{clfg_w}]\n")
		utama()
	# Select Algorithm
	clr_scr()
	print(banner)
	# If the mode is Encode-Decode
	if option_mode == 'encode' or option_mode == 'decode':
		print(list_encode_decode)
		print(" |")
		select_alg = str(input(f"{sign_input} Select Algorithm : {clfg_lg}"))
		if select_alg == '1':
			option_alg = 'base32'
		elif select_alg == '2':
			option_alg = 'base64'
		elif select_alg == '3':
			option_alg = 'binary'
		elif select_alg == '4':
			option_alg = 'hex'
		elif select_alg == '5':
			option_alg = 'ascii'
		elif select_alg == '6':
			option_alg = 'url'
		elif select_alg == '99':
			utama()
		elif select_alg == 'exit' or select_alg == '0':
			exit()
		else:
			print(f"{sign_warn} Invalid algorithm selected")
			input(f"{clfg_w}[{clfg_y}Press ENTER to continue...{clfg_w}]\n")
			utama()
	# If the mode is Encrypt
	elif option_mode == 'encrypt':
		print(list_encrypt_decrypt)
		print(" |")
		select_alg = str(input(f"{sign_input} Select Algorithm : {clfg_lg}"))
		if select_alg == '1':
			option_alg = 'md5'
		elif select_alg == '2':
			option_alg = 'sha-1'
		elif select_alg == '3':
			option_alg = 'sha-224'
		elif select_alg == '4':
			option_alg = 'sha-256'
		elif select_alg == '5':
			option_alg = 'sha-384'
		elif select_alg == '6':
			option_alg = 'sha-512'
		elif select_alg == '7':
			option_alg = 'sha3-224'
		elif select_alg == '8':
			option_alg = 'sha3-256'
		elif select_alg == '9':
			option_alg = 'sha3-384'
		elif select_alg == '10':
			option_alg = 'sha3-512'
		elif select_alg == '99':
			utama()
		elif select_alg == 'exit' or select_alg == '0':
			exit()
		else:
			print(f"{sign_warn} Invalid algorithm selected")
			input(f"{clfg_w}[{clfg_y}Press ENTER to continue...{clfg_w}]\n")
			utama()
	# If the mode is Decrypt
	elif option_mode == 'decrypt':
		option_alg = 'hash'
		print()
		x_string = str(input(f"{cl_reset}[{clfg_y}{option_mode.upper()}::{option_alg.upper()}{clfg_w}] Hash Value : {clfg_lg}"))
	# Get the string to convert for Encode-Decode-Encrypt
	if option_mode in ['encode','decode','encrypt']:
		print()
		x_string = str(input(f"{cl_reset}[{clfg_y}{option_mode.upper()}::{option_alg.upper()}{clfg_w}] String : {clfg_lg}"))
	# Begin Encode-Decode-Encrypt-Decrypt
	if x_string == '' or x_string == None:
		print()
	else:
		convert_result = ''
		converter(option_mode, option_alg, x_string)
		print(f"{cl_reset}[{clfg_y}{option_mode.upper()}::{option_alg.upper()}{clfg_w}] Result : {clfg_lg}{convert_result}")
		print()
	input(f"{clfg_w}[{clfg_y}Press ENTER to continue...{clfg_w}]\n")
	utama()


if __name__ == '__main__':
	utama()
