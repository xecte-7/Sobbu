#!/bin/bash

# Sobbu version 1.4.5 for Linux
# Coded by Muhammad Rizky (XECTE-7)
# repository : https://github.com/xecte-7/Sobbu

echo "[*] Removing binary launcher from /usr/local/bin/"
sudo rm -rf /usr/local/bin/sobbu-*
echo "[*] Removing Sobbu directory on /opt/"
sudo rm -rf /opt/Sobbu/
echo "[+] Uninstall complete! Sobbu has been removed from your system!"