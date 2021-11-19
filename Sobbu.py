#!/usr/bin/env python3
# -*- encode: utf-8 -*-

''' Version 1.0 start written on November 4th 2021 '''

### START Import Module SECTION
try:
	print("[*] Importing modules..")
	import colored, base64, hashlib
	import os, sys, platform, datetime
	print("[^] Successfully importing modules..")
except ImportError:
	print("[!] Error when importing module! Make sure you've installed all required modules..")
	print("    Use command: pip install -r requirements.txt")
	exit(0)


### START Coloring Variable SECTION
	# for Style
cl_reset = colored.style.RESET
cl_bold = colored.style.BOLD
	# for Foreground
cl_fg_white = colored.fore.WHITE
cl_fg_red = colored.fore.LIGHT_RED
cl_fg_lgreen = colored.fore.LIGHT_GREEN
cl_fg_yellow = colored.fg(227)
	# for Background
cl_bg_white = colored.back.WHITE
cl_bg_red = colored.back.LIGHT_RED
cl_bg_lgreen = colored.back.LIGHT_GREEN
cl_bg_yellow = colored.bg(227)


## START SHA Family Tool
sha_menu = '''
[{2}01{1}] SHA-1
[{2}02{1}] SHA-224
[{2}03{1}] SHA-256
[{2}04{1}] SHA-384
[{2}05{1}] SHA-512
'''.format(cl_reset, cl_fg_white, cl_fg_red)
def tool_sha():
	algo = ""
	plaintext = input(r"[{2}?{1}]--[{2}SHA-Family{1}] Plaintext >> ".format(cl_reset, cl_fg_white, cl_fg_red))
	if plaintext == "" or plaintext == None:
		tool_sha()
	print(sha_menu)
	opsi_sha = input(r"[{2}?{1}]--[{2}SHA-Family{1}] Choose algorithm >> ".format(cl_reset, cl_fg_white, cl_fg_red))
	if opsi_sha in ["1","01"]:
		algo = "SHA-1"
		ciphertext = hashlib.sha1(bytes(plaintext,'utf-8')).hexdigest()
	elif opsi_sha in ["2","02"]:
		algo = "SHA-224"
		ciphertext = hashlib.sha224(bytes(plaintext,'utf-8')).hexdigest()
	elif opsi_sha in ["3", "03"]:
		algo = "SHA-256"
		ciphertext = hashlib.sha256(bytes(plaintext,'utf-8')).hexdigest()
	elif opsi_sha in ["4", "04"]:
		algo = "SHA-384"
		ciphertext = hashlib.sha384(bytes(plaintext,'utf-8')).hexdigest()
	elif opsi_sha in ["5", "05"]:
		algo = "SHA-512"
		ciphertext = hashlib.sha512(bytes(plaintext,'utf-8')).hexdigest()
	elif opsi_sha in ["<","back","BACK","Back"]:
		main_menu()
	elif opsi_sha in ["exit","EXIT","Exit"]:
		sys.exit(0)
	else:
		print("{1}[!] There's no such option! Choose SHA-1 as default...".format(cl_reset, cl_fg_red))
	print("[{3}+{1}]--[{2}SHA-Family{1}] Ciphertext ({5}) >> {3}{4}{1}".format(cl_reset, cl_fg_white, cl_fg_red, cl_fg_lgreen, ciphertext, algo))
	print()
	jeda()
	main_menu()

## START MD5 Tool
def tool_md5():
	plaintext = input(r"[{2}?{1}]--[{2}MD5{1}] Plaintext >> ".format(cl_reset, cl_fg_white, cl_fg_red))
	if plaintext == "" or plaintext == None:
		tool_md5()
	#if plaintext != "" and plaintext[4::] != ".txt":
	#	mode = "string"
	#elif plaintext != "" and plaintext[4::] == ".txt":
	#	mode = "file"
	mode = "string"
	if mode == "string":
		try:
			ciphertext = hashlib.md5(bytes(plaintext,'utf-8')).hexdigest()
			print("[{3}+{1}]--[{2}MD5{1}] Ciphertext >> {3}{4}{1}".format(cl_reset, cl_fg_white, cl_fg_red, cl_fg_lgreen, ciphertext))
		except:
			print("{1}[!] ERROR!".format(cl_reset, cl_fg_red))
	print()
	jeda()
	main_menu()

### START Hex Tool
def tool_hex():
	mode = ""
	encodeco = ""
	# Choose Encode/Decode
	choose_encodeco = input(r"[{2}?{1}]--[{2}Hex{1}] Encode[1] / Decode[2] >> ".format(cl_reset, cl_fg_white, cl_fg_red))
	if choose_encodeco in ["1","01"]:
		encodeco = "encode"
	elif choose_encodeco in ["2","02"]:
		encodeco = "decode"
	elif choose_encodeco in ["<","back","BACK","Back"]:
		main_menu()
	elif choose_encodeco in ["exit","EXIT","Exit"]:
		sys.exit(0)
	else:
		tool_hex()

	print()
	# Mode Encode
	if encodeco == "encode":
		plaintext = input(r"[{2}?{1}]--[{2}Hex{1}] Plaintext >> ".format(cl_reset, cl_fg_white, cl_fg_red))
		if plaintext == "" or plaintext == None:
			tool_hex()
		#if plaintext != "" and plaintext[4::] != ".txt":
		#	mode = "string"
		#elif plaintext != "" and plaintext[4::] == ".txt":
		#	mode = "file"
		mode = "string"
		if mode == "string":
			try:
				ciphertext1 = plaintext.encode('utf-8').hex()
				ciphertext2 = "0x" + ciphertext1
				print("[{3}+{1}]--[{2}Hex{1}] Ciphertext >> {3}{4}{1} or {3}{5}{1}".format(cl_reset, cl_fg_white, cl_fg_red, cl_fg_lgreen, ciphertext1, ciphertext2))
			except:
				print("{1}[!] ERROR!".format(cl_reset, cl_fg_red))
		print()
		jeda()
		main_menu()
	# Mode Decode
	elif encodeco == "decode":
		ciphertext = input(r"[{2}?{1}]--[{2}Hex{1}] Ciphertext >> ".format(cl_reset, cl_fg_white, cl_fg_red))
		if ciphertext == "" or ciphertext == None:
			tool_hex()
		#if ciphertext != "" and ciphertext[4::] != ".txt":
		#	mode = "string"
		#elif ciphertext != "" and ciphertext[4::] == ".txt":
		#	mode = "file"
		mode = "string"
		if mode == "string":
			try:
				if ciphertext[:2] == "0x":
					ciphertext = ciphertext[2:]
				plaintext = bytes.fromhex(ciphertext).decode('utf-8')
				print("[{3}+{1}]--[{2}Hex{1}] Plaintext >> {3}{4}{1}".format(cl_reset, cl_fg_white, cl_fg_red, cl_fg_lgreen, plaintext))
			except:
				print("{1}[!] ERROR!".format(cl_reset, cl_fg_red))
		print()
		jeda()
		main_menu()

### START Base64 Tool
def tool_base64():
	mode = ""
	encodeco = ""
	# Choose Encode/Decode
	choose_encodeco = input(r"[{2}?{1}]--[{2}Base64{1}] Encode[1] / Decode[2] >> ".format(cl_reset, cl_fg_white, cl_fg_red))
	if choose_encodeco in ["1","01"]:
		encodeco = "encode"
	elif choose_encodeco in ["2","02"]:
		encodeco = "decode"
	elif choose_encodeco in ["<","back","BACK","Back"]:
		main_menu()
	elif choose_encodeco in ["exit","EXIT","Exit"]:
		sys.exit(0)
	else:
		tool_base64()
	
	print()
	# Mode Encode
	if encodeco == "encode":
		plaintext = input(r"[{2}?{1}]--[{2}Base64{1}] Plaintext >> ".format(cl_reset, cl_fg_white, cl_fg_red))
		if plaintext == "" or plaintext == None:
			tool_base64()
		#if plaintext != "" and plaintext[4::] != ".txt":
		#	mode = "string"
		#elif plaintext != "" and plaintext[4::] == ".txt":
		#	mode = "file"
		mode = "string"
		if mode == "string":
			try:
				ciphertext = base64.b64encode(bytes(plaintext,'utf-8'))
				ciphertext = str(ciphertext)
				stage1 = ciphertext[2::]
				stage2 = stage1.strip("'")
				print("[{3}+{1}]--[{2}Base64{1}] Ciphertext >> {3}{4}{1}".format(cl_reset, cl_fg_white, cl_fg_red, cl_fg_lgreen, stage2))
			except:
				print("{1}[!] ERROR!".format(cl_reset, cl_fg_red))
		print()
		jeda()
		main_menu()
	# Mode Decode
	elif encodeco == "decode":
		ciphertext = input(r"[{2}?{1}]--[{2}Base64{1}] Ciphertext >> ".format(cl_reset, cl_fg_white, cl_fg_red))
		if ciphertext == "" or ciphertext == None:
			tool_base64()
		#if ciphertext != "" and ciphertext[4::] != ".txt":
		#	mode = "string"
		#elif ciphertext != "" and ciphertext[4::] == ".txt":
		#	mode = "file"
		mode = "string"
		if mode == "string":
			try:
				plaintext = base64.b64decode(ciphertext)
				plaintext = str(plaintext)
				stage1 = plaintext[2::]
				stage2 = stage1.strip("'")
				print("[{3}+{1}]--[{2}Base64{1}] Plaintext >> {3}{4}{1}".format(cl_reset, cl_fg_white, cl_fg_red, cl_fg_lgreen, stage2))
			except:
				print("{1}[!] ERROR!".format(cl_reset, cl_fg_red))
		print()
		jeda()
		main_menu()

### START Base32 Tool
def tool_base32():
	mode = ""
	encodeco = ""
	# Choose Encode/Decode
	choose_encodeco = input(r"[{2}?{1}]--[{2}Base32{1}] Encode[1] / Decode[2] >> ".format(cl_reset, cl_fg_white, cl_fg_red))
	if choose_encodeco in ["1","01"]:
		encodeco = "encode"
	elif choose_encodeco in ["2","02"]:
		encodeco = "decode"
	elif choose_encodeco in ["<","back","BACK","Back"]:
		main_menu()
	elif choose_encodeco in ["exit","EXIT","Exit"]:
		sys.exit(0)
	else:
		tool_base32()
	
	print()
	# Mode Encode
	if encodeco == "encode":
		plaintext = input(r"[{2}?{1}]--[{2}Base32{1}] Plaintext >> ".format(cl_reset, cl_fg_white, cl_fg_red))
		if plaintext == "" or plaintext == None:
			tool_base32()
		#if plaintext != "" and plaintext[4::] != ".txt":
		#	mode = "string"
		#elif plaintext != "" and plaintext[4::] == ".txt":
		#	mode = "file"
		mode = "string"
		if mode == "string":
			try:
				ciphertext = base64.b32encode(bytes(plaintext,'utf-8'))
				ciphertext = str(ciphertext)
				stage1 = ciphertext[2::]
				stage2 = stage1.strip("'")
				print("[{3}+{1}]--[{2}Base32{1}] Ciphertext >> {3}{4}{1}".format(cl_reset, cl_fg_white, cl_fg_red, cl_fg_lgreen, stage2))
			except:
				print("{1}[!] ERROR!".format(cl_reset, cl_fg_red))
		print()
		jeda()
		main_menu()
	# Mode Decode
	elif encodeco == "decode":
		ciphertext = input(r"[{2}?{1}]--[{2}Base32{1}] Ciphertext >> ".format(cl_reset, cl_fg_white, cl_fg_red))
		if ciphertext == "" or ciphertext == None:
			tool_base32()
		#if ciphertext != "" and ciphertext[4::] != ".txt":
		#	mode = "string"
		#elif ciphertext != "" and ciphertext[4::] == ".txt":
		#	mode = "file"
		mode = "string"
		if mode == "string":
			try:
				plaintext = base64.b32decode(ciphertext)
				plaintext = str(plaintext)
				stage1 = plaintext[2::]
				stage2 = stage1.strip("'")
				print("[{3}+{1}]--[{2}Base32{1}] Plaintext >> {3}{4}{1}".format(cl_reset, cl_fg_white, cl_fg_red, cl_fg_lgreen, stage2))
			except:
				print("{1}[!] ERROR!".format(cl_reset, cl_fg_red))
		print()
		jeda()
		main_menu()

### START Clear Screen SECTION
def clr_scr():
	# This function used to clear the screen
	if sys.platform in ['win32','cygwin']:
		os_name = "Windows"
		os.system('cls')
	elif sys.platform in ['linux','linux2']:
		os_name = "Linux"
		os.system('clear')
	elif sys.platform == 'darwin':
		os_name = "OS X"
		os.system('clear')

def jeda():
	input("{1}[{2}:{1}] {2}Press 'ENTER' to continue ...".format(cl_reset, cl_fg_white, cl_fg_yellow))
	print()

### START Banner SECTION
def banner():
	print('''{1}
###---###---###------>>>{3}  SOBBU  {0}{1}<<<------###---###---###
#                                                       #
|  Cryptography tool for various encoding and decoding  |
|  algorithms. Made with {2}<3{1} by {2}Muhammad Rizky{1} ({2}Dr-3AM{1})  |
#                                                       #
###---###---###------>>> {2}ver 1.0{1} <<<------###---###---###'''.format(cl_reset, cl_fg_white, cl_fg_red, cl_bg_red, cl_fg_yellow))



### START Asking Control SECTION
def opt_control():
	opsi_menu = input(r"[{2}?{1}] Select option >> ".format(cl_reset, cl_fg_white, cl_fg_red))

	if opsi_menu == "" or opsi_menu == None:
		opt_control()
	elif opsi_menu in ["<","back","BACK","Back"]:
		main_menu()
	elif opsi_menu in ["exit","EXIT","Exit"]:
		sys.exit(0)
	elif opsi_menu in ["?","help","HELP","Help"]:
		print() # Some Shit Goes Here
	elif opsi_menu in ["1","01"]:
		print()
		tool_base32()
	elif opsi_menu in ["2", "02"]:
		print()
		tool_base64()
	elif opsi_menu in ["3", "03"]:
		print()
		tool_hex()
	elif opsi_menu in ["4", "04"]:
		print()
		tool_md5()
	elif opsi_menu in ["5", "05"]:
		print()
		tool_sha()
	else:
		print("[!] Error: {0} is not an option!")
		print()
		opt_control()

### START Main Execution of the program SECTION
def main_menu():
	clr_scr()
	banner()
	print('''
[{2}01{1}] Base32 Encode-Decode
[{2}02{1}] Base64 Encode-Decode
[{2}03{1}] Hex Encode-Decode
[{2}04{1}] MD5 Encode
[{2}05{1}] SHA Family Encode
[{2}06{1}] SHA3 (KECCAK) Family Encode
[{2}07{1}] SHAKE Family Encode
[{2}08{1}] BLAKE Family Encode
[{2}09{1}] Shift Cipher
[{2}10{1}] Substitution Cipher
[{2}11{1}] Vigenere Cipher
'''.format(cl_reset, cl_fg_white, cl_fg_red))
	opt_control()

if __name__ == '__main__':
	main_menu()