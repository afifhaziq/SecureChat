import socket
import hashlib
import os
import time
import itertools
import threading
import sys
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP

# Security Configuration
SECURITY_LEVEL = "ENHANCED"
HASH_ALGORITHM = "SHA-256"
ENCRYPTION_MODE = "AES-GCM"
KEY_SIZE = "256-bit"
#server address and port number input from admin
host= input("Server Address - > ")
port = int(input("Port - > "))
#boolean for checking server and port
check = False
done = False

def animate():
    for c in itertools.cycle(['....','.......','..........','............']):
        if done:
            break
        sys.stdout.write('\rCHECKING IP ADDRESS AND NOT USED PORT '+c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r -----SERVER STARTED. WAITING FOR CLIENT-----\n')
try:
    #setting up socket
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind((host,port))
    server.listen(5)
    check = True
except BaseException:
    print("-----Check Server Address or Port-----")
    check = False

if check is True:
    # server Quit
    shutdown = False
# printing "Server Started Message"
thread_load = threading.Thread(target=animate)
thread_load.start()

time.sleep(4)
done = True
#binding client and address
client,address = server.accept()
print ("CLIENT IS CONNECTED. CLIENT'S ADDRESS ->",address)
print ("\n-----WAITING FOR PUBLIC KEY & PUBLIC KEY HASH-----\n")

#client's message(Public Key)
getpbk = client.recv(2048)

#conversion of string to KEY
server_public_key = RSA.importKey(getpbk)

#hashing the public key in server side for validating the hash from client
hash_object = hashlib.sha256(getpbk)
hex_digest = hash_object.hexdigest()

if getpbk != "":
    print (getpbk)
    client.send(b"YES")
    gethash = client.recv(1024).decode()
    print ("\n-----HASH OF PUBLIC KEY----- \n"+gethash)
if hex_digest == gethash:
    # creating cryptographically secure session key
    key_128 = os.urandom(32)  # 256-bit key for better security
    #encrypt GCM MODE session key (authenticated encryption)
    en = AES.new(key_128, AES.MODE_GCM)
    encrypto, tag = en.encrypt_and_digest(key_128)
    #hashing sha256
    en_object = hashlib.sha256(encrypto)
    en_digest = en_object.hexdigest()

    print ("\n-----SECURITY INFO-----")
    print ("Security Level: " + SECURITY_LEVEL)
    print ("Hash Algorithm: " + HASH_ALGORITHM)
    print ("Encryption Mode: " + ENCRYPTION_MODE)
    print ("Key Size: " + KEY_SIZE)
    print ("\n-----SESSION KEY-----\n"+en_digest)

    #encrypting session key and public key
    
    cipher = PKCS1_OAEP.new(server_public_key)
    E = cipher.encrypt(encrypto)
    print ("\n-----ENCRYPTED PUBLIC KEY AND SESSION KEY-----\n"+str(E))
    print ("\n-----HANDSHAKE COMPLETE-----")
    client.send(str(E).encode())
    while True:
        #message from client
        newmess = client.recv(1024).decode()
        #decoding the message from HEXADECIMAL to decrypt the ecrypted version of the message only
        decoded = bytes.fromhex(newmess)
        #making en_digest(session_key) as the key
        key = bytes.fromhex(en_digest)[:16]
        print ("\nENCRYPTED MESSAGE FROM CLIENT -> "+newmess)
        #decrypting message from the client (GCM mode)
        # Split the received data into ciphertext and tag
        ciphertext = decoded[:-16]  # Last 16 bytes are the tag
        tag = decoded[-16:]
        aesDecrypt = AES.new(key, AES.MODE_GCM, nonce=key[:12])
        dMsg = aesDecrypt.decrypt_and_verify(ciphertext, tag).decode()
        print ("\n**New Message**  "+time.ctime(time.time()) +" > "+dMsg+"\n")
        mess = input("\nMessage To Client -> ")
        if mess != "":
            aesEncrypt = AES.new(key, AES.MODE_GCM, nonce=key[:12])
            ciphertext, tag = aesEncrypt.encrypt_and_digest(mess.encode())
            eMsg = (ciphertext + tag).hex().upper()
            if eMsg != "":
                print ("ENCRYPTED MESSAGE TO CLIENT-> " + eMsg)
            client.send(eMsg.encode())
    client.close()
else:
    print ("\n-----PUBLIC KEY HASH DOESNOT MATCH-----\n")