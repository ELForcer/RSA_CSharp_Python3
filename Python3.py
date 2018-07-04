#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64 
import pymssql #работа с MS SQL
import html #Unescape
import importlib.util
import os
import datetime #работа с датой и временем

#Криптография
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from base64 import b64decode
#spec = importlib.util.spec_from_file_location("module.name", "cgi-bin/TestAPI.py")
#spec = importlib.util.spec_from_file_location("module.name", "TestAPI.py")
#MyAPI = importlib.util.module_from_spec(spec)
#spec.loader.exec_module(MyAPI)



####
##Создаем ключи для станции
####
def CreateRSAKeys(IDStation):

    
    # Создаем ключи для филиала
    random_generator = Random.new().read
    privatekey = RSA.generate(2048, random_generator)
    #f = open('alisaprivatekey.txt','wb')
    
    #Отправляем его станции для получения
    PrivKey= privatekey.exportKey('PEM') 
    #f.write(bytes(privatekey.exportKey('PEM'))); f.close()


    #Сохраняем себе открытый ключ
    publickey = privatekey.publickey()
    f = open("Keys/C_"+IDStation+".pem",'wb')
    f.write(bytes(publickey.exportKey('PEM'))); f.close()

    #Создаем ключи для сервера
    random_generator = Random.new().read
    privatekey = RSA.generate(2048, random_generator)
    
    #Сохраняем его себе 
    f = open("Keys/S_"+IDStation+".pem",'wb')
    f.write(bytes(privatekey.exportKey('PEM'))); f.close()
    
    publickey = privatekey.publickey()
    #f = open('bobpublickey.txt','wb')
    PubKey= publickey.exportKey('PEM')
    #f.write(bytes(publickey.exportKey('PEM'))); f.close()
    return PrivKey.decode("utf-8"),PubKey.decode("utf-8")


def Login(MVars,CurStationID):
    Login=""
    PasswordHash=""
    
    #Расшифровка 
    for I in list(MVars):
        M=[]
        M= str(I).split('=')
        #CurHTML+=str(M)
        if (M[0]=="Login"): Login= M[1]
        if (M[0]=="PasswordHash"): PasswordHash= M[1]
    
    #Защита от пустого значения
    if (Login=="" or PasswordHash==""): return "WARNING|Пустое значение логина или пароля"
    
    Where="Login='"+Login+"' and PasswordHash='"+PasswordHash+"'"    
    UserID = MyAPI.GetValueByWhere("Dictionary","Users","UserID",Where)
    CurSessionID = MyAPI.CreateSession(UserID,"",CurStationID)
    if (UserID=="" or UserID=="0"): return "ERROR_LOGIN|Неверный логин или пароль" 
    return "OK|"+CurSessionID


def Main(CurSessionID,Action,Vars,CurStationID):
    MVars=""
    CurHTML=""
    UserID="0"
    if (CurStationID==None): CurStationID=""
    try:
        if (CurSessionID!=""):
            S=MyAPI.CheckSession(CurSessionID)
            UserID=S[2]
            CurStationID=S[4]
    except:
        
        Answer= "ERROR_DENIDED|Не удалось получить ваш ID по данному идентификатору сессии для проверки доступа!|"+str(S)
        MyAPI.API_SendLog( UserID,  "E",  "",Answer)
        return Answer
        

    try:
        if (CurStationID!="" and CurStationID!="None" ):
            if (os.path.isfile("Keys/S_"+CurStationID+".pem") ==False): return "ERROR|Не обнаружены ключи станции "+CurStationID+"! Все операции через сервер с этой станции запрещены!"
            #with open("Keys/S_"+CurStationID+".pem",'rb') as fp:
            
            #    private_key = RSA.PrivateKey.load_pkcs1(open("Keys/S_"+CurStationID+".pem").read())
                
            #fp.close()
            
            private_key_string = open("Keys/S_"+CurStationID+".pem","r").read()
            private_key = RSA.importKey(private_key_string)


            decrypted = private_key.decrypt(b64decode(Vars))
            
            
            f = open("TestD.txt",'wb')
            f.write(bytes(decrypted)); f.close()


            #Пока не поддерживается шифрование
            MVars=str(base64.standard_b64decode((decrypted)).decode("utf-8")).split('|')
        else:
            MVars=str(base64.standard_b64decode(html.unescape(Vars)).decode("utf-8")).split('|')
    except Exception as E:   
        Answer = "ERROR_VARS|Не удалось раскодировать переменные! Возможно, не совпадают ключи шифрования! "+str(E)+"|"+Vars
    #MyAPI.API_SendLog( UserID,  "E",  "",Answer.replace("'",""))
        return Answer 

    if (Action=="login"):
        Answer=Login(MVars,CurStationID)
        MyAPI.API_SendLog( UserID,  "O",  "",Answer.replace("'",""))
        return Answer
   
    Answer="ERROR|Неизвестное действие!"
    MyAPI.API_SendLog( UserID,  "E",  "",Answer.replace("'",""))
    return Answer 


Vars="Q28UzOAfrnMYMxmgAEGCzb7Nvum2kIFV7VtsrGi/+w3FwGe36JuvDpM1eTjfzhZpdP869sZ5UhmUak//A3a8KUc9Ij75YMvmaKNGCqy5zHunzgVUvODa2DC5AcTr4TWP50hdA1B+VRldFFCwseqGRhQ/jPNigkWKXalYFo/dCt0TCAgcoBCoVxptu3i/D97zMZUTlSI0oiG2okNDDz+SXhz5eUDGtrGF5gQozulPOeJ+B+OJzG3QYVi0wNwaV3r0PpIlzCiv6kSRVBO12f/Y/Or4jh5pgACciS6ZuX3MEvxZvA2VKClW3X0gPVlr2c6dJpCSENBoe1GO+66FGJhkoQ=="
CurStationID='5e954065-7434-4ed6-ab8c-884d1e4b99e8'
print (Main('','login',Vars,CurStationID))
