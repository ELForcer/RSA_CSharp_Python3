#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import print_function
import base64 
import pymssql #работа с MS SQL
import html #Unescape
import importlib.util
import os

#Криптография
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


spec = importlib.util.spec_from_file_location("module.name", "cgi-bin/TestAPI.py")
MyAPI = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MyAPI)

def Main(CurSessionID,Action,Vars,CurStationID):
    Vars=bytes(base64.standard_b64decode(Vars))
    print (str(len(Vars)))
    MVars=""
    CurHTML=""
    UserID="0"
    try:
        if (CurSessionID!=""):
            S=MyAPI.CheckSession(CurSessionID)
            UserID=S[2]
            CurStationID=S[3]
    except:
        
        Answer= "ERROR_DENIDED|Не удалось получить ваш ID по данному идентификатору сессии для проверки доступа!|"+str(S)
        MyAPI.API_SendLog( UserID,  "E",  "",Answer)
        return Answer
        
    
    #try:
    if (CurStationID!=""):
        if (os.path.isfile("Keys/S_"+CurStationID+".pem") ==False): return "ERROR|Не обнаружены ключи станции! Все операции запрещены!"
        with open("Keys/S_"+CurStationID+".pem",'r') as fp:
            private_key = RSA.importKey (fp.read())
            
        fp.close()
        
        
        


        #print('enc_session_key:',enc_session_key.encode('hex'))

        # Decrypt the session key with the private RSA key
        #cipher_rsa = PKCS1_OAEP.new(private_key)
        


        #cipher = PKCS1_OAEP.new(private_key.publickey())
        cipher = PKCS1_OAEP.new(private_key)

        full_packet_as_string = Vars
        enc_session_key = full_packet_as_string[: private_key.size()]
        nonce = full_packet_as_string[private_key.size(): private_key.size() + 16]
        tag = full_packet_as_string[private_key.size() + 16: private_key.size() + 32]
        ciphertext = full_packet_as_string[private_key.size() + 32:]

        #print (private_key.exportKey())
        #E=cipher.encrypt(Vars)
        
        
        #f = open("Test.txt",'wb')
        #f.write(bytes(E)); f.close()
    
        MVars = cipher.decrypt(Vars).decode("utf-8") #RSA.decrypt(Vars, private_key)
        
Vars= "QJdvQ2VsPMg6Py//5bNLXZ+arxy5Ee7adQs1XLCLtcSNWBuApimef93lYFK7lBftv99WDL2nS4AKjTrJTjl+oiI9TEv0/eBWE7cVm+XLmK5VNSYZ4Xbn78suTp9S1K1XDyRozuO+hzkk87XTt2pK15Tgickxd8oonUJI/TUurmYXRaujjvOXrOg/THZ2HVr/Ei7yWAaCdSHpmwmMu/oSslO3t3QJh60BLn1hUZuULVQrmTByOcdWTf8A1RloM4FDYgANb+y8yJEfml2ItgySJXKgprPZJ9tVWRELwfcZoXETUTRXIvRQc8hwWAwSBkO1V9I2XSL2iLL9cNGosRFiMA==" 
#Vars = b'123456789'
Main('','login',Vars,'ce3a1571-f74b-477d-87b8-0308e9b4f700')
 
