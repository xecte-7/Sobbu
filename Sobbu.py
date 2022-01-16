#!/usr/env python3
# -*- encode: utf-8 -*-

''' SOBBU version 1.1 coded by Muhammad Rizky (Dr-3AM) '''

### IMPORTING MODULES
import binascii
#from multiprocessing.sharedctypes import Value
#from pydoc import plain
#from statistics import mode
try:
    print("[*] Importing modules .", end='\r')
    import colored, hashlib, base64, urllib.parse
    print("[*] Importing modules ..", end='\r')
    import os, sys, platform, datetime
    print("[*] Importing modules ...")
    print("[+] Successfully import all required modules")
except:
    print("\n[!] Error when importing modules! Abort process..")
    print("      Make sure you've installed all required modules in 'requirements.txt'")
    exit()

### VARIABLE WARNA
	# for Style
cl_reset = colored.style.RESET
cl_bold = colored.attr("bold")
	# for Foreground
clfg_w = colored.fore.WHITE
clfg_r = colored.fore.LIGHT_RED
clfg_lg = colored.fore.LIGHT_GREEN
clfg_y = colored.fg(227)
	# for Background
cl_bg_white = colored.back.WHITE
cl_bg_red = colored.back.LIGHT_RED
cl_bg_lgreen = colored.back.LIGHT_GREEN
cl_bg_yellow = colored.bg(227)

### GLOBAL VARIABLE
opsys = platform.system()
mode_alg = ""

banner = r'''{0}{1}
    ::::::::   ::::::::  :::::::::  :::::::::  :::    :::     ::: ::: 
   :+:    :+: :+:    :+: :+:    :+: :+:    :+: :+:    :+:     :+: :+: 
   +:+        +:+    +:+ +:+    +:+ +:+    +:+ +:+    +:+     +:+ +:+ 
   +#++:++#++ +#+    +:+ +#++:++#+  +#++:++#+  +#+    +:+     +#+ +#+ 
          +#+ +#+    +#+ +#+    +#+ +#+    +#+ +#+    +#+     +#+ +#+ 
   #+#    #+# #+#    #+# #+#    #+# #+#    #+# #+#    #+#             
    ########   ########  #########  #########   ########      ### ###
{2}
 Cryptography Tool with various encoding and decoding algorithms (v1.1)
 Made with {3}<3 {2}by {3}Muhammad Rizky (Dr-3AM){2} // Special Thanks to {3}PentaByte
{0}'''.format(cl_reset, clfg_lg, clfg_w, clfg_r, cl_bold)

list_mode = '''{0}  {1}[{3}01{1}] {2}Encode
  {1}[{3}02{1}] {2}Decode{0}'''.format(cl_reset, clfg_lg, clfg_y, clfg_w)

list_alg = '''{0}
  {1}[{3}01{1}] {2}Base32       {1}[{3}07{1}] {2}SHA-1       {1}[{3}12{1}] {2}SHA3-224
  {1}[{3}02{1}] {2}Base64       {1}[{3}08{1}] {2}SHA-224     {1}[{3}13{1}] {2}SHA3-256
  {1}[{3}03{1}] {2}Binary       {1}[{3}09{1}] {2}SHA-256     {1}[{3}14{1}] {2}SHA3-384
  {1}[{3}04{1}] {2}Hex          {1}[{3}10{1}] {2}SHA-384     {1}[{3}15{1}] {2}SHA3-512
  {1}[{3}05{1}] {2}Ascii-Text   {1}[{3}11{1}] {2}SHA-512     {1}[{3}16{1}] {2}MD5
  {1}[{3}06{1}] {2}URL Encode
{0}'''.format(cl_reset, clfg_lg, clfg_y, clfg_w)
def jeda():
    input("\n{0}{1}[PRESS ENTER TO CONTINUE ...]{0}".format(cl_reset, clfg_r))

### CLEAR SCREEN
def clr_scr():
    if opsys == "Windows":
        os.system("cls")
    else:
        os.system("clear")

### ALGORITMA
# BASE32
def alg_base32(the_string,mode_alg):
    text = the_string.strip()
    if mode_alg == "Encode":
        try:
            ciphertext = str(base64.b32encode(bytes(text, 'utf-8')))
            ciphertext = ciphertext[2::].strip("'")
            print(f"{clfg_w}[Base32-{mode_alg}] Result : {clfg_lg}{ciphertext}")
        except binascii.Error:
            pass
    else:
        try:
            plaintext = str(base64.b32decode(text))
            plaintext = plaintext[2::].strip("'")
            print(f"{clfg_w}[Base32-{mode_alg}] Result : {clfg_lg}{plaintext}")
        except binascii.Error:
            pass
    jeda()
# BASE64
def alg_base64(the_string,mode_alg):
    text = the_string.strip()
    if mode_alg == "Encode":
        try:
            ciphertext = str(base64.b64encode(bytes(text, 'utf-8')))
            ciphertext = ciphertext[2::].strip("'")
            print(f"{clfg_w}[Base64-{mode_alg}] Result : {clfg_lg}{ciphertext}")
        except binascii.Error:
            pass
    else:
        try:
            plaintext = str(base64.b64decode(text))
            plaintext = plaintext[2::].strip("'")
            print(f"{clfg_w}[Base64-{mode_alg}] Result : {clfg_lg}{plaintext}")
        except binascii.Error:
            pass
    jeda()
# BINARY
def alg_binary(the_string,mode_alg):
    text = the_string.strip()
    if mode_alg == "Encode":
        try:
            string_format = int(the_string)
            mode_format = "int"
        except ValueError:
            string_format = the_string.strip()
            mode_format = "text"
        if mode_format == "int":
            cipher_bin = str(bin(string_format))[2:]
            print(f"{clfg_w}[Binary-{mode_alg}] Result : {clfg_lg}{cipher_bin}")
        else:
            cipher_builder = ""
            for huruf in string_format:
                cipher_bin = str(bin(ord(huruf)))[2:]
                cipher_builder += f"{cipher_bin} "
            print(f"{clfg_w}[Binary-{mode_alg}] Result : {clfg_lg}{cipher_builder}")
    else:
        text = the_string.strip()
        split_text = text.split()
        plaintext_builder = ""
        for section in split_text:
            ordo = int(bytes(section, 'utf-8'),2)
            huruf = chr(ordo)
            plaintext_builder += f"{huruf}"
        print(f"{clfg_w}[Binary-{mode_alg}] Result : {clfg_lg}{plaintext_builder}")
    jeda()
# HEXADECIMAL
def alg_hex(the_string,mode_alg):
    text = the_string.strip()
    if mode_alg == "Encode":
        try:
            string_format = int(the_string)
            mode_format = "int"
        except ValueError:
            string_format = the_string.strip()
            mode_format = "text"
        if mode_format == "int":
            cipher_bin = str(hex(string_format))[2:]
            print(f"{clfg_w}[Hexadecimal-{mode_alg}] Result : {clfg_lg}{cipher_bin}")
        else:
            cipher_builder = ""
            for huruf in string_format:
                cipher_hex = str(hex(ord(huruf)))[2:]
                cipher_builder += f"{cipher_hex} "
            print(f"{clfg_w}[Hexadecimal-{mode_alg}] Result : {clfg_lg}{cipher_builder}")
    else:
        text = the_string.strip()
        split_text = text.split()
        plaintext_builder = ""
        for section in split_text:
            ordo = int(bytes(section, 'utf-8'),16)
            huruf = chr(ordo)
            plaintext_builder += f"{huruf}"
        print(f"{clfg_w}[Hexadecimal-{mode_alg}] Result : {clfg_lg}{plaintext_builder}")
    jeda()
# ASCII-TEXT
def alg_ascii(the_string,mode_alg):
    text = the_string.strip()
    text_split = text.split()
    if mode_alg == "Encode":
        cipher_builder = ""
        for huruf in text:
            cipher_builder += str(ord(huruf)) + " "
        print(f"{clfg_w}[Ascii/Text-{mode_alg}] Result : {clfg_lg}{cipher_builder}")
    else:
        plaintext_builder = ""
        for ordo in text_split:
            plaintext_builder += str(chr(int(ordo)))
        print(f"{clfg_w}[Ascii/Text-{mode_alg}] Result : {clfg_lg}{plaintext_builder}")
    jeda()
# URL ENCODE
def alg_urlencode(the_url,mode_alg):
    url = the_url.strip()
    if mode_alg == "Encode":
        encoded_url = urllib.parse.quote(url, safe='')
        print(f"{clfg_w}[URL Encode-{mode_alg}] Result : {clfg_lg}{encoded_url}")
    else:
        decoded_url = urllib.parse.unquote(url)
        print(f"{clfg_w}[URL Decode-{mode_alg}] Result : {clfg_lg}{decoded_url}")
    jeda()
# SHA FAMILY
def alg_sha(the_string,mode_alg,sha_types):
    text = the_string.strip()
    if sha_types == "sha1":
        hash_value = hashlib.sha1(bytes(text,'utf-8')).hexdigest()
        print(f"{clfg_w}[SHA-1-ENCRYPT] Result : {clfg_lg}{hash_value}")
    elif sha_types == "sha224":
        hash_value = hashlib.sha224(bytes(text,'utf-8')).hexdigest()
        print(f"{clfg_w}[SHA-224-ENCRYPT] Result : {clfg_lg}{hash_value}")
    elif sha_types == "sha256":
        hash_value = hashlib.sha256(bytes(text,'utf-8')).hexdigest()
        print(f"{clfg_w}[SHA-256-ENCRYPT] Result : {clfg_lg}{hash_value}")
    elif sha_types == "sha384":
        hash_value = hashlib.sha384(bytes(text,'utf-8')).hexdigest()
        print(f"{clfg_w}[SHA-384-ENCRYPT] Result : {clfg_lg}{hash_value}")
    elif sha_types == "sha512":
        hash_value = hashlib.sha512(bytes(text,'utf-8')).hexdigest()
        print(f"{clfg_w}[SHA-512-ENCRYPT] Result : {clfg_lg}{hash_value}")
    jeda()
# SHA3 FAMILY
def alg_sha3(the_string,mode_alg,sha_types):
    text = the_string.strip()
    if sha_types == "sha3_224":
        hash_value = hashlib.sha3_224(bytes(text,'utf-8')).hexdigest()
        print(f"{clfg_w}[SHA3-224-ENCRYPT] Result : {clfg_lg}{hash_value}")
    elif sha_types == "sha3_256":
        hash_value = hashlib.sha3_256(bytes(text,'utf-8')).hexdigest()
        print(f"{clfg_w}[SHA3-256-ENCRYPT] Result : {clfg_lg}{hash_value}")
    elif sha_types == "sha3_384":
        hash_value = hashlib.sha3_384(bytes(text,'utf-8')).hexdigest()
        print(f"{clfg_w}[SHA3-384-ENCRYPT] Result : {clfg_lg}{hash_value}")
    elif sha_types == "sha3_512":
        hash_value = hashlib.sha3_512(bytes(text,'utf-8')).hexdigest()
        print(f"{clfg_w}[SHA3-512-ENCRYPT] Result : {clfg_lg}{hash_value}")
    jeda()
# MD5
def alg_md5(the_string,mode_alg):
    text = the_string.strip()
    hash_value = hashlib.md5(bytes(text,'utf-8')).hexdigest()
    print(f"{clfg_w}[MD5-ENCRYPT] Result : {clfg_lg}{hash_value}")
    jeda()

### PILIH ALGORITMA
def choose_tool(mode_alg):
    opsi_alg = input(f"{clfg_w}[{mode_alg}] Option > {clfg_y}")
    # BASE32
    if opsi_alg in ["01", "1"]:
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[Base32-{mode_alg}] Text > {clfg_y}")
        else:
            the_string = input(f"{clfg_w}[Base32-{mode_alg}] Ciphertext > {clfg_y}")
        if the_string != "" or the_string != None:
            alg_base32(the_string,mode_alg)
            main()
    # BASE64
    elif opsi_alg in ["02", "2"]:
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[Base64-{mode_alg}] Text > {clfg_y}")
        else:
            the_string = input(f"{clfg_w}[Base64-{mode_alg}] Ciphertext > {clfg_y}")
        if the_string != "" or the_string != None:
            alg_base64(the_string,mode_alg)
            main()
    # BINARY
    elif opsi_alg in ["03", "3"]:
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[Binary-{mode_alg}] Text > {clfg_y}")
        else:
            the_string = input(f"{clfg_w}[Binary-{mode_alg}] Ciphertext > {clfg_y}")
        if the_string != "" or the_string != None:
            alg_binary(the_string,mode_alg)
            main()
    # HEXADECIMAL
    elif opsi_alg in ["04", "4"]:
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[Hexadecimal-{mode_alg}] Text > {clfg_y}")
        else:
            the_string = input(f"{clfg_w}[Hexadecimal-{mode_alg}] Ciphertext > {clfg_y}")
        if the_string != "" or the_string != None:
            alg_hex(the_string,mode_alg)
            main()
    # ASCII-TEXT
    elif opsi_alg in ["05", "5"]:
        if mode_alg == "Encode":
            the_url = input(f"{clfg_w}[Ascii/Text-{mode_alg}] Text > {clfg_y}")
        else:
            the_url = input(f"{clfg_w}[Ascii/Text-{mode_alg}] Ciphertext > {clfg_y}")
        if the_url != "" or the_url != None:
            alg_ascii(the_url,mode_alg)
            main()
    # URL ENCODE
    elif opsi_alg in ["06", "6"]:
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[URL Encode-{mode_alg}] URL > {clfg_y}")
        else:
            the_string = input(f"{clfg_w}[URL Encode-{mode_alg}] Encoded URL > {clfg_y}")
        if the_string != "" or the_string != None:
            alg_urlencode(the_string,mode_alg)
            main()
    # SHA FAMILY
        # SHA-1
    elif opsi_alg in ["07", "7"]:
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[SHA-1-ENCRYPT] Text > {clfg_y}")
            if the_string != "" or the_string != None:
                alg_sha(the_string,mode_alg,"sha1")
                main()
        else:
            print("{1}[-] SHA-1 don't have Decryption mode ..{0}\n".format(cl_reset, clfg_r))
            choose_tool(mode_alg)
        # SHA-224
    elif opsi_alg in ["08", "8"]:
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[SHA-224-ENCRYPT] Text > {clfg_y}")
            if the_string != "" or the_string != None:
                alg_sha(the_string,mode_alg,"sha224")
                main()
        else:
            print("{1}[-] SHA-224 don't have Decryption mode ..{0}\n".format(cl_reset, clfg_r))
            choose_tool(mode_alg)
        # SHA-256
    elif opsi_alg in ["09", "9"]:
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[SHA-256-ENCRYPT] Text > {clfg_y}")
            if the_string != "" or the_string != None:
                alg_sha(the_string,mode_alg,"sha256")
                main()
        else:
            print("{1}[-] SHA-256 don't have Decryption mode ..{0}\n".format(cl_reset, clfg_r))
            choose_tool(mode_alg)
    elif opsi_alg == "10":
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[SHA-384-ENCRYPT] Text > {clfg_y}")
            if the_string != "" or the_string != None:
                alg_sha(the_string,mode_alg,"sha384")
                main()
        else:
            print("{1}[-] SHA-384 don't have Decryption mode ..{0}\n".format(cl_reset, clfg_r))
            choose_tool(mode_alg)
    elif opsi_alg == "11":
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[SHA-512-ENCRYPT] Text > {clfg_y}")
            if the_string != "" or the_string != None:
                alg_sha(the_string,mode_alg,"sha512")
                main()
        else:
            print("{1}[-] SHA-512 don't have Decryption mode ..{0}\n".format(cl_reset, clfg_r))
            choose_tool(mode_alg)
    # SHA3 FAMILY
        # SHA3-224
    elif opsi_alg == "12":
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[SHA3-224-ENCRYPT] Text > {clfg_y}")
            if the_string != "" or the_string != None:
                alg_sha3(the_string,mode_alg,"sha3_224")
                main()
        else:
            print("{1}[-] SH3-224 don't have Decryption mode ..{0}\n".format(cl_reset, clfg_r))
            choose_tool(mode_alg)
        # SHA3-224
    elif opsi_alg == "13":
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[SHA3-256-ENCRYPT] Text > {clfg_y}")
            if the_string != "" or the_string != None:
                alg_sha3(the_string,mode_alg,"sha3_256")
                main()
        else:
            print("{1}[-] SH3-256 don't have Decryption mode ..{0}\n".format(cl_reset, clfg_r))
            choose_tool(mode_alg)
        # SHA3-384
    elif opsi_alg == "14":
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[SHA3-384-ENCRYPT] Text > {clfg_y}")
            if the_string != "" or the_string != None:
                alg_sha3(the_string,mode_alg,"sha3_384")
                main()
        else:
            print("{1}[-] SH3-384 don't have Decryption mode ..{0}\n".format(cl_reset, clfg_r))
            choose_tool(mode_alg)
        # SHA3-512
    elif opsi_alg == "15":
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[SHA3-512-ENCRYPT] Text > {clfg_y}")
            if the_string != "" or the_string != None:
                alg_sha3(the_string,mode_alg,"sha3_512")
                main()
        else:
            print("{1}[-] SH3-512 don't have Decryption mode ..{0}\n".format(cl_reset, clfg_r))
            choose_tool(mode_alg)
    # MD5
    elif opsi_alg == "16":
        if mode_alg == "Encode":
            the_string = input(f"{clfg_w}[MD5-ENCRYPT] Text > {clfg_y}")
            if the_string != "" or the_string != None:
                alg_md5(the_string,mode_alg)
                main()
        else:
            print("{1}[-] MD5 don't have Decryption mode ..{0}\n".format(cl_reset, clfg_r))
            choose_tool(mode_alg)
    
    # LAIN-LAIN
    elif opsi_alg in ["back", "BACK", "Back"]:
        mode_alg = ""
        main()
    elif opsi_alg in ["exit", "Exit", "EXIT"]:
        print(cl_reset)
        exit()
    else:
        choose_tool(mode_alg)

### PILIH MENU
def choose_mode():
    opsi_menu = input("{0}{1}[?] Option > {2}".format(cl_reset, clfg_w, clfg_y))
    if opsi_menu in ["01", "1"]:
        mode_alg = "Encode"
        clr_scr()
        print(banner)
        print(list_alg)
        choose_tool(mode_alg)
    elif opsi_menu in ["02", "2"]:
        mode_alg = "Decode"
        clr_scr()
        print(banner)
        print(list_alg)
        choose_tool(mode_alg)
    elif opsi_menu in ["exit", "Exit", "EXIT"]:
        print(cl_reset)
        exit()
    else:
        choose_mode()

### MENU UTAMA
def main():
    if opsys == "Windows":
        os.system("@echo off")
        os.system("mode 75,25")
        os.system("title Sobbu (v1.1) by Muhammad Rizky (Dr-3AM)")
    clr_scr()
    print(banner)
    print(list_mode)
    print()
    choose_mode()

main()