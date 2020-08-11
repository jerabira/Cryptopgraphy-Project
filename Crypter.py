from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from tkinter import filedialog
import os
from cryptography.fernet import Fernet
import hashlib
from hashlib import *
from base64 import b64encode, b64decode
from Crypto.Cipher import DES,AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
import gc

#tạo cửa sổ
win=Tk()
#setup tên title
win.title("cipher program by python")

FLAG1 = 0
FLAG2 = 0

lbPlaintext=Label(win, text="Plaintext/Ciphertext: ", font=("Times New Roman",13, "italic"), padx=10, pady=15)
lbPlaintext.grid(row=0, column=0)

entryCiphertext=entryPlaintext=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="")
entryPlaintext.grid(row=0, column=1)

lbKey=Label(win, text="Key: ", font=("Times New Roman",13, "italic"))   
lbKey.grid(row=1, column=0)##

entryKey=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="")
entryKey.grid(row=1, column=1)##

lbIV=Label(win, text="IV: ", font=("Times New Roman",13, "italic"))##
lbIV.grid(row=2, column=0)##

entryIV=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="",state='disabled')##
entryIV.grid(row=2, column=1)##

lbCipher=Label(win, text="Kind of cipher:", font=("Times New Roman",13, "italic"), pady=15)
lbCipher.grid(row=3, column=0)##

cbCipher=ttk.Combobox(win,values=["None","Caesar","Vigenere","DES","AES"],state="readonly")
cbCipher.current(0)
cbCipher.grid(row=3,column=1)##

cbCipher_mode=ttk.Combobox(win,values=["None","ECB","CBC","OFB","CFB"],state="disabled")
cbCipher_mode.current(0)
cbCipher_mode.grid(row=3,column=2)##


lbActionstt=Label(win,text="Action",font=("Times New Roman",13, "italic"))
lbActionstt.grid(row=4,column=0)##

cbAction=ttk.Combobox(win,values=["Encrypt", "Decrypt","Bruteforce-(Caesar)"],state="readonly")
cbAction.grid(row=4,column=1)##
cbAction.current(0)

Result=ScrolledText(win,width=50,height=10,font=("Times New Roman",13, "italic"),bd=5)
Result.grid(row=15,column=1)##

def vigenere_encrypt(plain, key):
    ciphertext =''
    num = 0
    
    for i in plain:
        if (i.isalpha()):
            if(i.isupper() and key[num % len(key)].isupper()):
                ciphertext += chr((ord(i) + ord(key[num % len(key)])) % 26 + 65)
            else:
                if (i.isupper() and key[num % len(key)].islower()):
                    ciphertext += chr((ord(i) + ord(key[num % len(key)].upper())) % 26 + 65)
                else:
                    if (i.islower() and key[num % len(key)].islower()):
                        ciphertext += chr((ord(i.upper()) + ord(key[num % len(key)].upper())) % 26 + 65).lower()
                    else:
                        ciphertext += chr((ord(i.upper()) + ord(key[num % len(key)])) % 26 + 65).lower()                        
            num = num + 1
    return ciphertext

def vigenere_decrypt(cipher, key):
    plaintext =''
    num = 0
    for i in cipher:
        if (i.isalpha()):
            if(i.isupper() and key[num % len(key)].isupper()):
                plaintext += chr((ord(i) - ord(key[num % len(key)])) % 26 + 65)
            else:
                if (i.isupper() and key[num % len(key)].islower()):
                    plaintext += chr((ord(i) - ord(key[num % len(key)].upper())) % 26 + 65)
                else:
                    if (i.islower() and key[num % len(key)].islower()):
                        plaintext += chr((ord(i.upper()) - ord(key[num % len(key)].upper())) % 26 + 65).lower()
                    else:
                        plaintext += chr((ord(i.upper()) - ord(key[num % len(key)])) % 26 + 65).lower()                       
            num = num + 1
    return plaintext


def caesar_encrypt(plaintext, key):
    ciphertext = ""
    for ch in plaintext:
        if (ch.isalpha()):
            if(ch.isupper()):
                ciphertext += chr((ord(ch) + key - 65)%26 + 65)
            else:
                ciphertext += chr((ord(ch) + key - 97)%26 + 97)
    return ciphertext

def caesar_decrypt(ciphertext, key):
    plaintext=""
    for ch in ciphertext:
        if (ch.isalpha()):
            if(ch.isupper()):
                plaintext += chr((ord(ch) - key - 65)%26 + 65)
            else:
                plaintext += chr((ord(ch) - key - 97)%26 + 97)
    return plaintext

def caesar_bruteforce(ciphertext):
    result=""
    for key in range(26):
        plaintext =""
        for ch in ciphertext:
            if (ch.isalpha()):
                if(ch.isupper()):
                    plaintext += chr((ord(ch) - key - 65)%26 + 65)
                else:
                    plaintext += chr((ord(ch) - key - 97)%26 + 97)
        result=result+"Shift key "+ str(key) +": "+plaintext+"\n"
    return result

def DES_enc(plaintext,key,mode,iv=0):##
    if mode == 1:
        cipher = DES.new(key,DES.MODE_ECB)
        return b64encode(cipher.encrypt(pad(plaintext.encode('utf-8'),DES.block_size)))
    elif mode == 2:
        cipher = DES.new(key,DES.MODE_CBC,iv)
    elif mode == 3:
        cipher = DES.new(key,DES.MODE_OFB,iv)
    elif mode == 4:
        cipher = DES.new(key,DES.MODE_CFB,iv)
    return b64encode(cipher.encrypt(pad(plaintext.encode('utf-8'),DES.block_size)))

def DES_dec(ciphertext,key,mode,iv=0):##
    ciphertext = b64decode(ciphertext)
    if mode == 2:
        cipher = DES.new(key,DES.MODE_CBC,iv=iv)
    elif mode == 3:
        cipher = DES.new(key,DES.MODE_OFB,iv=iv)
    elif mode == 4:
        cipher = DES.new(key,DES.MODE_CFB,iv=iv)
    else:
        cipher = DES.new(key,DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext),DES.block_size)

def AES_enc(plaintext,key,mode,iv=0):##
    if mode == 1:
        cipher = AES.new(key,AES.MODE_ECB)
        return b64encode(cipher.encrypt(pad(plaintext.encode('utf-8'),AES.block_size)))
    elif mode == 2:
        cipher = AES.new(key,AES.MODE_CBC,iv)
    elif mode == 3:
        cipher = AES.new(key,AES.MODE_OFB,iv)
    elif mode == 4:
        cipher = AES.new(key,AES.MODE_CFB,iv)
    return b64encode(cipher.encrypt(pad(plaintext.encode('utf-8'),AES.block_size)))

def AES_dec(ciphertext,key,mode,iv=0):##
    ciphertext = b64decode(ciphertext)
    if mode == 2:
        cipher = AES.new(key,AES.MODE_CBC,iv=iv)
    elif mode == 3:
        cipher = AES.new(key,AES.MODE_OFB,iv=iv)
    elif mode == 4:
        cipher = AES.new(key,AES.MODE_CFB,iv=iv)
    else:
        cipher = AES.new(key,AES.MODE_ECB)
    return cipher.decrypt(ciphertext),AES.block_size

def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("key.key", "rb").read()
    
def encrypt(filename, key):
    f = Fernet(key)
    try:
        with open(filename, "rb") as file:
            file_data = file.read()
        
        encrypted_data = f.encrypt(file_data)
        file.close()
        del file_data
        gc.collect()    
        with open(filename+'.enc', "wb") as file:
            file.write(encrypted_data)
        file.close()
        del encrypted_data
        gc.collect()
    except:
        messagebox.showerror("Error","No such file or directory")
    
def decrypt(filename, key):
    f = Fernet(key)
    try:
        with open(filename, "rb") as file:
            encrypted_data = file.read()

        file.close()
        decrypted_data = f.decrypt(encrypted_data)
        del encrypted_data
        gc.collect()
        with open(os.path.splitext(filename)[0], "wb") as file:
            file.write(decrypted_data)
        #os.rename(filename,os.path.splitext(filename)[0])
        file.close()
        del decrypted_data
        gc.collect()
    except:
        messagebox.showerror("Error","No such file or directory")
    
def file_DES_enc(filename, key, mode, iv=0):
    try:
        with open(filename, "rb") as file:
            file_data = file.read()
    except:
        messagebox.showerror("Error","No such file or directory")
    result=hashlib.md5(file_data)
    resulted=result.hexdigest()
    if mode == 1:
        cipher = DES.new(key,DES.MODE_ECB)
    elif mode == 2:
        cipher = DES.new(key,DES.MODE_CBC,iv)
    elif mode == 3:
        cipher = DES.new(key,DES.MODE_OFB,iv)
    elif mode == 4:
        cipher = DES.new(key,DES.MODE_CFB,iv)
        
    encrypted_data = b64encode(cipher.encrypt(pad(file_data,DES.block_size)))
    file.close()
    del file_data
    gc.collect()
    final_encrypted_data = addhash(encrypted_data, resulted)
    del encrypted_data
    gc.collect()
    try:
        with open(filename+'.enc', "wb") as file:
            file.write(final_encrypted_data)
        messagebox.showinfo("Successful","File Encrypted!")
    except:
        messagebox.showerror("Failed","An error occured while encrypting file...")
    file.close()
    del final_encrypted_data
    gc.collect()
 

def file_DES_dec(filename, key, mode, iv=0):
    try:
        with open(filename, "rb") as file:
            file_data = file.read()
    except:
        messagebox.showerror("Error","No such file or directory")
    try:
        file_data = delhash(file_data,filename) 
        file_data = b64decode(file_data)
        if mode == 2:
            cipher = DES.new(key,DES.MODE_CBC,iv=iv)
        elif mode == 3:
            cipher = DES.new(key,DES.MODE_OFB,iv=iv)
        elif mode == 4:
            cipher = DES.new(key,DES.MODE_CFB,iv=iv)
        else:
            cipher = DES.new(key,DES.MODE_ECB)
            
        decrypted_data = unpad(cipher.decrypt(file_data),DES.block_size)
    except:
        messagebox.showerror("Error","Incorrect Padding")
    file.close()
    del file_data    
    gc.collect()
    try:
        with open(os.path.splitext(filename)[0], "wb") as file:
            file.write(decrypted_data) 
        messagebox.showinfo('Successful',"File Decrypted!")
    except:
        messagebox.showerror('Failed',"An error occured while decrypting file...")
    file.close()
    del decrypted_data
    gc.collect()
        
def file_AES_enc(filename, key, mode, iv=0):
    try:
        with open(filename, "rb") as file:
            file_data = file.read()
    except:
        messagebox.showerror("File missing","No such file or directory")        
    result=hashlib.md5(file_data)
    resulted=result.hexdigest()
    if mode == 1:
        cipher = AES.new(key,AES.MODE_ECB)
    elif mode == 2:
        cipher = AES.new(key,AES.MODE_CBC,iv)
    elif mode == 3:
        cipher = AES.new(key,AES.MODE_OFB,iv)
    elif mode == 4:
        cipher = AES.new(key,AES.MODE_CFB,iv)
        
    encrypted_data = b64encode(cipher.encrypt(pad(file_data,AES.block_size)))
    file.close()
    del file_data
    gc.collect()
    final_encrypted_data = addhash(encrypted_data,resulted)
    del encrypted_data
    gc.collect()
    try:
        with open(filename+'.enc', "wb") as file:
            file.write(final_encrypted_data)
        messagebox.showinfo("Successful","File Encrypted!")
    except:
        messagebox.showerror("Failed","An error occured while encrypting file...")
    file.close()
    del final_encrypted_data
    gc.collect()

def file_AES_dec(filename, key, mode, iv=0):
    try:
        with open(filename, "rb") as file:
            file_data = file.read()
    except:
        messagebox.showerror("File missing","No such file or directory")   
    try:
        file_data = delhash(file_data,filename) 
        file_data = b64decode(file_data)
                
        if mode == 2:
            cipher = AES.new(key,AES.MODE_CBC,iv=iv)
        elif mode == 3:
            cipher = AES.new(key,AES.MODE_OFB,iv=iv)
        elif mode == 4:
            cipher = AES.new(key,AES.MODE_CFB,iv=iv)
        else:
            cipher = AES.new(key,AES.MODE_ECB)
        
        decrypted_data = unpad(cipher.decrypt(file_data),AES.block_size)
    except:
        messagebox.showerror("Error","Incorrect Padding")
    file.close()
    del file_data
    gc.collect()
    try:
        with open(os.path.splitext(filename)[0], "wb") as file:
            file.write(decrypted_data) 
        messagebox.showinfo('Successful',"File Decrypted!")
    except:
        messagebox.showerror('Failed',"An error occured while decrypting file...")
    file.close()
    del decrypted_data
    gc.collect()
        
    
        
def PrintPt():
    strPlain=entryPlaintext.get()
    strCipher=entryCiphertext.get()
    strKey=entryKey.get()
    strIV=entryIV.get()##
    selCipher=cbCipher.get()
    selCipher_mode=cbCipher_mode.get()##Ha
    selAction=cbAction.get()
    if strPlain:##
        if selCipher=="DES" and len(b64decode(strKey.encode()))==16 and selCipher_mode!=None:
            Generate_key()
            strKey=entryKey.get()
        elif selCipher=="AES" and len(b64decode(strKey.encode()))==8 and selCipher_mode!=None:
            Generate_key()
            strKey=entryKey.get()

        if selCipher=="DES" and (selCipher_mode !="ECB" and selCipher_mode !="None") and len(b64decode(strKey.encode()))==16:
            Generate_key()
            strKey=entryKey.get()
        if selCipher=="AES" and (selCipher_mode !="ECB" and selCipher_mode !="None") and len(b64decode(strKey.encode()))==8:
            Generate_key()
            strKey=entryKey.get()
            
        if selCipher=="DES" and (selCipher_mode !="ECB" and selCipher_mode !="None") and len(b64decode(strIV.encode()))==16:
            Generate_IV()
            strIV=entryIV.get()
        if selCipher=="AES" and (selCipher_mode !="ECB" and selCipher_mode !="None") and len(b64decode(strIV.encode()))==8:
            Generate_IV()
            strIV=entryIV.get()
    if strPlain:
        if strKey:
            if selCipher=="Caesar" and selAction=="Encrypt":
                ciphertext=caesar_encrypt(strPlain,int(strKey))
                ciphertext=str(ciphertext)
                Result.delete('1.0','end')##
                Result.insert(INSERT,ciphertext)
                
            elif selCipher=="Vigenere" and selAction=="Encrypt":
                ciphertext=vigenere_encrypt(strPlain,strKey)
                ciphertext=str(ciphertext)
                Result.delete('1.0','end')
                Result.insert(INSERT,ciphertext)
                
            if selCipher=="DES" and selCipher_mode=="ECB" and selAction=="Encrypt":##
                ciphertext=DES_enc(strPlain,b64decode(strKey.encode()),1).decode()
                Result.delete('1.0','end')
                Result.insert(INSERT,ciphertext)
            elif selCipher=="DES" and selCipher_mode=="CBC" and selAction=="Encrypt":##
                ciphertext=DES_enc(strPlain,b64decode(strKey.encode()),2,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,ciphertext.decode())
            elif selCipher=="DES" and selCipher_mode=="OFB" and selAction=="Encrypt":##
                ciphertext=DES_enc(strPlain,b64decode(strKey.encode()),3,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,ciphertext.decode())
            elif selCipher=="DES" and selCipher_mode=="CFB" and selAction=="Encrypt":##
                ciphertext=DES_enc(strPlain,b64decode(strKey.encode()),4,b64decode(strIV.encode()))                    
                Result.delete('1.0','end')
                Result.insert(INSERT,ciphertext.decode())
            elif selCipher=="AES" and selCipher_mode=="ECB" and selAction=="Encrypt":##
                ciphertext=AES_enc(strPlain,b64decode(strKey.encode()),1,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,ciphertext.decode())
            elif selCipher=="AES" and selCipher_mode=="CBC" and selAction=="Encrypt":##
                ciphertext=AES_enc(strPlain,b64decode(strKey.encode()),2,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,ciphertext.decode())
            elif selCipher=="AES" and selCipher_mode=="OFB" and selAction=="Encrypt":##
                ciphertext=AES_enc(strPlain,b64decode(strKey.encode()),3,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,ciphertext.decode())
            elif selCipher=="AES" and selCipher_mode=="CFB" and selAction=="Encrypt":##
                ciphertext=AES_enc(strPlain,b64decode(strKey.encode()),4,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,ciphertext.decode())
                
            if selCipher=="Caesar" and selAction=="Decrypt":
                plaintext=caesar_decrypt(strCipher,int(strKey))
                plaintext=str(plaintext)
                Result.delete('1.0','end')##
                Result.insert(INSERT,plaintext)
                
            elif selCipher=="Vigenere" and selAction=="Decrypt":
                plaintext=vigenere_decrypt(strCipher,strKey)
                plaintext=str(plaintext)
                Result.delete('1.0','end')##
                Result.insert(INSERT,plaintext)            
                
            elif selCipher=="DES" and selCipher_mode=="ECB" and selAction=="Decrypt":##
                plaintext=DES_dec(strCipher,b64decode(strKey.encode()),1).decode()
                Result.delete('1.0','end')
                Result.insert(INSERT,plaintext)
            elif selCipher=="DES" and selCipher_mode=="CBC" and selAction=="Decrypt":##
                plaintext=DES_dec(strCipher,b64decode(strKey.encode()),2,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,plaintext)
            elif selCipher=="DES" and selCipher_mode=="OFB" and selAction=="Decrypt":##
                plaintext=DES_dec(strCipher,b64decode(strKey.encode()),3,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,plaintext)
            elif selCipher=="DES" and selCipher_mode=="CFB" and selAction=="Decrypt":##
                plaintext=DES_dec(strCipher,b64decode(strKey.encode()),4,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,plaintext)
            elif selCipher=="AES" and selCipher_mode=="ECB" and selAction=="Decrypt":##
                plaintext=AES_dec(strCipher,b64decode(strKey.encode()),1,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,plaintext)
            elif selCipher=="AES" and selCipher_mode=="CBC" and selAction=="Decrypt":##
                plaintext=AES_dec(strCipher,b64decode(strKey.encode()),2,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,plaintext)
            elif selCipher=="AES" and selCipher_mode=="OFB" and selAction=="Decrypt":##
                plaintext=AES_dec(strCipher,b64decode(strKey.encode()),3,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,plaintext)
            elif selCipher=="AES" and selCipher_mode=="CFB" and selAction=="Decrypt":##
                plaintext=AES_dec(strCipher,b64decode(strKey.encode()),4,b64decode(strIV.encode()))
                Result.delete('1.0','end')
                Result.insert(INSERT,plaintext)
                
            
        else:
            if selAction=="Bruteforce-(Caesar)" and selCipher=="Caesar":
                plaintext=caesar_bruteforce(strCipher)
                plaintext=str(plaintext)
                Result.delete('1.0','end')##
                Result.insert(INSERT,plaintext)


def file_crypt():
    selAction=cbAction.get()
    strKey=entryKey.get()
    strIV=entryIV.get()##
    selCipher=cbCipher.get()
    selCipher_mode=cbCipher_mode.get()
    filename =  entryFile1.get()
    file_name=os.path.abspath(filename)
    
    if not os.path.exists('key.key'):
        write_key()
    f_key=load_key()
        
    if selCipher=="DES" and len(b64decode(strKey.encode()))==16:
        Generate_key()
        strKey=entryKey.get()
    elif selCipher=="AES" and len(b64decode(strKey.encode()))==8:
        Generate_key()
        strKey=entryKey.get()
    if selCipher=="DES" and (selCipher_mode !="ECB" and selCipher_mode !="None") and len(b64decode(strKey.encode()))==16:
        Generate_key()
        strKey=entryKey.get()
    if selCipher=="AES" and (selCipher_mode !="ECB" and selCipher_mode !="None") and len(b64decode(strKey.encode()))==8:
        Generate_key()
        strKey=entryKey.get()
        
    if selAction=="Encrypt" and selCipher=="None":
        encrypt(file_name,f_key)
        entryFile_state(filename,entryFile1)
    elif selCipher=="DES" and selCipher_mode=="ECB" and selAction=="Encrypt":##
        file_DES_enc(file_name,b64decode(strKey.encode()),1)
        entryFile_state(filename,entryFile1)
    elif selCipher=="DES" and selCipher_mode=="CBC" and selAction=="Encrypt":##
        file_DES_enc(file_name,b64decode(strKey.encode()),2,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="DES" and selCipher_mode=="OFB" and selAction=="Encrypt":##
        file_DES_enc(file_name,b64decode(strKey.encode()),3,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="DES" and selCipher_mode=="CFB" and selAction=="Encrypt":##
        file_DES_enc(file_name,b64decode(strKey.encode()),4,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="AES" and selCipher_mode=="ECB" and selAction=="Encrypt":##
        file_AES_enc(file_name,b64decode(strKey.encode()),1,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="AES" and selCipher_mode=="CBC" and selAction=="Encrypt":##
        file_AES_enc(file_name,b64decode(strKey.encode()),2,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="AES" and selCipher_mode=="OFB" and selAction=="Encrypt":##
        file_AES_enc(file_name,b64decode(strKey.encode()),3,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="AES" and selCipher_mode=="CFB" and selAction=="Encrypt":##
        file_AES_enc(file_name,b64decode(strKey.encode()),4,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)

    if selCipher=="None" and selAction=="Decrypt":
        decrypt(file_name,f_key)
        entryFile_state(filename,entryFile1)
    elif selCipher=="DES" and selCipher_mode=="ECB" and selAction=="Decrypt":##
        file_DES_dec(file_name,b64decode(strKey.encode()),1)
        entryFile_state(filename,entryFile1)
    elif selCipher=="DES" and selCipher_mode=="CBC" and selAction=="Decrypt":##
        file_DES_dec(file_name,b64decode(strKey.encode()),2,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="DES" and selCipher_mode=="OFB" and selAction=="Decrypt":##
        file_DES_dec(file_name,b64decode(strKey.encode()),3,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="DES" and selCipher_mode=="CFB" and selAction=="Decrypt":##
        file_DES_dec(file_name,b64decode(strKey.encode()),4,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="AES" and selCipher_mode=="ECB" and selAction=="Decrypt":##
        file_AES_dec(file_name,b64decode(strKey.encode()),1,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="AES" and selCipher_mode=="CBC" and selAction=="Decrypt":##
        file_AES_dec(file_name,b64decode(strKey.encode()),2,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="AES" and selCipher_mode=="OFB" and selAction=="Decrypt":##
        file_AES_dec(file_name,b64decode(strKey.encode()),3,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
    elif selCipher=="AES" and selCipher_mode=="CFB" and selAction=="Decrypt":##
        file_AES_dec(file_name,b64decode(strKey.encode()),4,b64decode(strIV.encode()))
        entryFile_state(filename,entryFile1)
        

def addhash(file_data,hash_str):
    data = file_data
    temp = "".encode()
    temp1 = "".encode()
    temp2 = "".encode()
    length_data = len(data)
    
    i = length_data - 1   
    while(data[i].to_bytes(1,'little') == "=".encode()):
        temp1 += "=".encode()
        length_data -= 1
        i -= 1
    if temp1 != "".encode():
        data = data[:i+1]
        
    length_data = b64encode(str(length_data).encode())
    len_num = len(length_data)
    k = len_num - 1
    while(length_data[k].to_bytes(1,'little') == "=".encode()):
        temp += "=".encode()
        len_num -= 1
        k -= 1
    if temp != "".encode():
        length_data = length_data[:k+1]     
        
    b64_hash = b64encode(hash_str.encode())
    j = len(b64_hash) - 1
    while(b64_hash[j].to_bytes(1,'little') == "=".encode()):
        temp2 += "=".encode()
        j -= 1
    if temp2 != "".encode():
        b64_hash = b64_hash[:j+1]
    
    equal_handle(temp2,temp)
    global FLAG1
    global FLAG2
    flag1 = str(FLAG1).encode()
    flag2 = str(FLAG2).encode()
    data = flag1 + flag2 + length_data + data + b64_hash + "/".encode() + str(len_num).encode() + temp1
    return data
        
def delhash(file_data,dirname):
    global FLAG1 
    global FLAG2
    data = file_data
    length_data = len(data)
    idx = length_data - 1
    temp = "".encode()
    while(data[idx].to_bytes(1,'little') == "=".encode()):
        temp += "=".encode()
        length_data -= 1
        idx -= 1
    if temp != "".encode():
        data = data[:idx+1]
    flag1 = int(data[0].to_bytes(1,'little').decode())
    flag2 = int(data[1].to_bytes(1,'little').decode())
    FLAG1 = flag1
    FLAG2 = flag2
    
    temp1, temp2 = flag_handle(FLAG1, FLAG2)
    data = data[2:]
    length_data -= 2
    for i in range(length_data-1,0,-1):
        if data[i].to_bytes(1,'little') == "/".encode():
            len_num = int(data[i+1:].decode())
            data = data[:i]
            break   
    hash_index = int(b64decode(data[:len_num]+temp2))
    data = data[len_num:]
    hash_string = data[hash_index:]
    hash_str = b64decode(hash_string + temp1)
    data = data[:hash_index] + temp
    save_file = os.path.dirname(dirname) + '\hash_' + os.path.split(os.path.splitext(dirname)[0])[1]
    with open(save_file, "wb") as file:
        file.write("MD5:".encode() + hash_str)
    return data
    
def entryFile_state(filename, entryFile):
    entryFile.configure(state='normal')
    entryFile.delete(0,'end')
    entryFile.insert(0,filename)
    entryFile.configure(state='disabled')
    
def file_open(entryFile):
    filename =  filedialog.askopenfilename(initialdir = "/",title = "Select file",filetypes = (("Text files","*.txt"),("all files","*.*"),("enc file","*.enc")))
    entryFile_state(filename,entryFile)

def entryHash_state(entryhashfile):
    entryhashfile.configure(state='normal')
    entryhashfile.delete(0,'end')
    
def genhash():
    file_name = entryFile1.get()
    try:
        with open(file_name, 'rb') as file:
            file_data=file.read()
    
        result=hashlib.md5(file_data)
        resulted1=result.hexdigest()
        entryHash_state(entryhashfile1)
        entryhashfile1.insert(INSERT,resulted1)
        entryhashfile1.configure(state='readonly')
        
        result=hashlib.sha1(file_data)
        resulted2=result.hexdigest()
        entryHash_state(entryhashfile2)
        entryhashfile2.insert(INSERT,resulted2)
        entryhashfile2.configure(state='readonly')
        
        result=hashlib.sha224(file_data)
        resulted3=result.hexdigest()
        entryHash_state(entryhashfile3)
        entryhashfile3.insert(INSERT,resulted3)
        entryhashfile3.configure(state='readonly')
        
        result=hashlib.sha256(file_data)
        resulted4=result.hexdigest()
        entryHash_state(entryhashfile4)
        entryhashfile4.insert(INSERT,resulted4)
        entryhashfile4.configure(state='readonly')
        
        result=hashlib.sha384(file_data)
        resulted5=result.hexdigest()
        entryHash_state(entryhashfile5)
        entryhashfile5.insert(INSERT,resulted5)
        entryhashfile5.configure(state='readonly')
        
        result=hashlib.sha512(file_data)
        resulted6=result.hexdigest()
        entryHash_state(entryhashfile6)
        entryhashfile6.insert(INSERT,resulted6)
        entryhashfile6.configure(state='readonly')
        file.close()
        del file_data
        gc.collect()
    except:
        entryHash_state(entryhashfile1)
        entryhashfile1.configure(state='readonly')
        entryHash_state(entryhashfile2)
        entryhashfile2.configure(state='readonly')
        entryHash_state(entryhashfile3)
        entryhashfile3.configure(state='readonly')
        entryHash_state(entryhashfile4)
        entryhashfile4.configure(state='readonly')
        entryHash_state(entryhashfile5)
        entryhashfile5.configure(state='readonly')
        entryHash_state(entryhashfile6)
        entryhashfile6.configure(state='readonly')
        messagebox.showerror("File missing","No such file or directory")
        
def mode_selection(event):##
    selCipher=cbCipher.get()   
    if selCipher=="DES" or selCipher=="AES":
        cbCipher_mode.configure(state='readonly')
    else:
        cbCipher_mode.configure(state='disabled')

def IV_avail(event):##
    selMode=cbCipher_mode.get()
    if selMode =="CBC" or selMode =="OFB" or selMode == "CFB":
        entryIV.configure(state='normal')
        btnIV_Generate.configure(state='normal')
    else:
        entryIV.configure(state='disabled')
        btnIV_Generate.configure(state='disabled')
        
def Generate_key():##
    selCipher=cbCipher.get()
    if selCipher=="DES":
        key = b64encode(get_random_bytes(8)).decode()
        if entryKey != None:
            entryKey.delete(0, 'end')
        entryKey.insert(INSERT,key)
    if selCipher=="AES":
        key = b64encode(get_random_bytes(16)).decode()
        if entryKey != None:
            entryKey.delete(0, 'end')
        entryKey.insert(INSERT,key)
        
def Generate_IV():##
    selCipher=cbCipher.get()
    selMode=cbCipher_mode.get()
    if selCipher=="DES":
        iv = b64encode(get_random_bytes(8)).decode()
    elif selCipher=="AES":
        iv = b64encode(get_random_bytes(16)).decode()
    if selMode =="CBC" or selMode =="OFB" or selMode == "CFB":
        if entryIV != None:
            entryIV.delete(0, 'end')
        entryIV.insert(INSERT,iv)

def check_hash():
    flag = 1
    entry_file = entryFile2.get()
    try:
        with open(entry_file, 'rb') as file:
            file_data = file.read()
    except:
        messagebox.showerror("File missing","No such file or directory")
        return
    resulted1=hashlib.md5(file_data).hexdigest()
    resulted2=hashlib.sha1(file_data).hexdigest()
    resulted3=hashlib.sha224(file_data).hexdigest()
    resulted4=hashlib.sha256(file_data).hexdigest()
    resulted5=hashlib.sha384(file_data).hexdigest()
    resulted6=hashlib.sha512(file_data).hexdigest()
    if entryhashfile1.get() != resulted1:
        flag = 0
    if entryhashfile2.get() != resulted2:
        flag = 0
    if entryhashfile3.get() != resulted3:
        flag = 0
    if entryhashfile4.get() != resulted4:
        flag = 0
    if entryhashfile5.get() != resulted5:
        flag = 0
    if entryhashfile6.get() != resulted6:
        flag = 0
    if entryhashfile1.get() == "":
        messagebox.showerror("File missing","File 1 is missing")
        return
    if flag == 1:
        entryCompareHash.configure(state='normal')
        entryCompareHash.delete(0,'end')
        entryCompareHash.insert(INSERT,"MATCH!")
        entryCompareHash.configure(fg="green")
        entryCompareHash.configure(state='readonly')
    else:
        entryCompareHash.configure(state='normal')
        entryCompareHash.delete(0,'end')
        entryCompareHash.insert(INSERT,"NOT MATCH!")
        entryCompareHash.configure(fg="red")
        entryCompareHash.configure(state='readonly')
        
def equal_handle(temp1,temp2):
    global FLAG1
    global FLAG2
    if temp1 == "=".encode():
        FLAG1 = 1
    elif temp1 == "==".encode():
        FLAG1 = 2
    else:
        FLAG1 = 0
        
    if temp2 == "=".encode():
        FLAG2 = 1
    elif temp2 == "==".encode():
        FLAG2 = 2
    else:
        FLAG2 = 0
        
def flag_handle(flag1,flag2):
    if flag1 == 1:
        temp1 = "=".encode()
    elif flag1 == 2:
        temp1 = "==".encode()
    else:
        temp1 = "".encode()
        
    if flag2 == 1:
        temp2 = "=".encode()
    elif flag2 == 2:
        temp2 = "==".encode()
    else:
        temp2 = "".encode()
    return temp1,temp2

lbCompareHash=Label(win,text="Compare Hash:",font=("Times New Roman",13, "italic"),pady=15)
lbCompareHash.grid(row=13,column=0)
entryCompareHash=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, state="disabled")
entryCompareHash.grid(row=13,column=1)
btncheckhash=Button(win,text="Check Integrity",width=15, height=1,command=check_hash)
btncheckhash.grid(row=13,column=2)

cbCipher.bind('<<ComboboxSelected>>',mode_selection)##
cbCipher_mode.bind('<<ComboboxSelected>>',IV_avail)##

btnKey_Generate=Button(win,text="Generate",width=10,height=1,command = Generate_key)##
btnKey_Generate.grid(row=1, column=2)##

btnIV_Generate=Button(win,text="Generate",width=10,height=1,command = Generate_IV, state="disabled")##
btnIV_Generate.grid(row=2, column=2)##

btnPrint=Button(win, text="Play", width=10, height=2, command = PrintPt)
btnPrint.grid(row=14, column=1)##

entryFile1=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="",state="readonly")
entryFile1.grid(row=5, column=1)##

lbSelfil1=Label(win, text="Select file 1:", font=("Times New Roman",13, "italic"),pady=15)
lbSelfil1.grid(row=5, column=0)##

btnselFile1=Button(win,text="Select file",width=12, height=2, command=lambda: [file_open(entryFile1),genhash()])
btnselFile1.grid(row=5,column=2)##

entryFile2=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="",state="readonly")
entryFile2.grid(row=12, column=1)##

lbSelfil2=Label(win, text="Select file 2:", font=("Times New Roman",13, "italic"),pady=15)
lbSelfil2.grid(row=12, column=0)##

btnselFile2=Button(win,text="Select file",width=12, height=2, command=lambda: file_open(entryFile2))
btnselFile2.grid(row=12,column=2)##

btnplayFile=Button(win,text="Enc/Dec file",width=12, height=2, command = file_crypt)
btnplayFile.grid(row=5,column=3)##

lbhashfile1=Label(win, text="MD5:",font=("Times New Roman",13, "italic"))
lbhashfile1.grid(row=6, column=0)##

entryhashfile1=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="", state="readonly")
entryhashfile1.grid(row=6,column=1)##

lbhashfile2=Label(win, text="SHA1:", font=("Times New Roman",13, "italic"))
lbhashfile2.grid(row=7, column=0)##

entryhashfile2=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="", state="readonly")
entryhashfile2.grid(row=7,column=1)##

lbhashfile3=Label(win, text="SHA224:", font=("Times New Roman",13, "italic"))
lbhashfile3.grid(row=8, column=0)##

entryhashfile3=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="", state="readonly")
entryhashfile3.grid(row=8,column=1)##

lbhashfile4=Label(win, text="SHA256:",font=("Times New Roman",13, "italic"))
lbhashfile4.grid(row=9, column=0)##

entryhashfile4=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="", state="readonly")
entryhashfile4.grid(row=9,column=1)##

lbhashfile5=Label(win, text="SHA384:", font=("Times New Roman",13, "italic"))
lbhashfile5.grid(row=10, column=0)##

entryhashfile5=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="", state="readonly")
entryhashfile5.grid(row=10,column=1)##

lbhashfile6=Label(win, text="SHA512:",font=("Times New Roman",13, "italic"))
lbhashfile6.grid(row=11, column=0)##

entryhashfile6=Entry(font=("Times New Roman",13, "italic"),fg="black", bg="white", width=50, bd=5, show="", state="readonly")
entryhashfile6.grid(row=11,column=1)##


#hiện và giữ cửa số
win.mainloop()
