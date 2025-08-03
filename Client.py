import time
import socket
import threading
import hashlib
import itertools
import sys
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
#animating loading
done = False
def animate():
    for c in itertools.cycle(['....','.......','..........','............']):
        if done:
            break
        sys.stdout.write('\rCONFIRMING CONNECTION TO SERVER '+c)
        sys.stdout.flush()
        time.sleep(0.1)

#public key and private key
random_generator = Random.new().read
key = RSA.generate(1024,random_generator)
public = key.publickey().exportKey()
private = key.exportKey()

#hashing the public key
hash_object = hashlib.sha256(public)
hex_digest = hash_object.hexdigest()

#Setting up socket
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#host and port input user
host = input("Server Address To Be Connected -> ")
port = int(input("Port of The Server -> "))
#binding the address and port
server.connect((host, port))
# printing "Server Started Message"
thread_load = threading.Thread(target=animate)
thread_load.start()

time.sleep(4)
done = True

def send(t,name,key):
    mess = input(name + " : ")
    key = bytes.fromhex(key)[:16]
    #merging the message and the name
    whole = name+" : "+mess
    aesEncrypt = AES.new(key, AES.MODE_GCM, nonce=key[:12])
    ciphertext, tag = aesEncrypt.encrypt_and_digest(whole.encode())
    #converting the encrypted message to HEXADECIMAL to readable
    eMsg = (ciphertext + tag).hex().upper()
    if eMsg != "":
        print ("ENCRYPTED MESSAGE TO SERVER-> "+eMsg)
    server.send(eMsg.encode())
def recv(t,key):
    newmess = server.recv(1024).decode()
    print ("\nENCRYPTED MESSAGE FROM SERVER-> " + newmess)
    key = bytes.fromhex(key)[:16]
    decoded = bytes.fromhex(newmess)
    # Split the received data into ciphertext and tag
    ciphertext = decoded[:-16]  # Last 16 bytes are the tag
    tag = decoded[-16:]
    aesDecrypt = AES.new(key, AES.MODE_GCM, nonce=key[:12])
    dMsg = aesDecrypt.decrypt_and_verify(ciphertext, tag).decode()
    print ("\n**New Message From Server**  " + time.ctime(time.time()) + " : " + dMsg + "\n")

while True:
    server.send(public)
    confirm = server.recv(1024)
    if confirm == b"YES":
        server.send(hex_digest.encode())

    #connected msg
    msg = server.recv(1024).decode()
    en = eval(msg)
    
    cipher = PKCS1_OAEP.new(key)
    decrypt = cipher.decrypt(en)
    # hashing sha256
    en_object = hashlib.sha256(decrypt)
    en_digest = en_object.hexdigest()

    print ("\n-----ENCRYPTED PUBLIC KEY AND SESSION KEY FROM SERVER-----")
    print (msg)
    print ("\n-----DECRYPTED SESSION KEY-----")
    print (en_digest)
    print ("\n-----HANDSHAKE COMPLETE-----\n")
    name = input("\nYour Name -> ")

    while True:
        thread_send = threading.Thread(target=send,args=("------Sending Message------",name,en_digest))
        thread_recv = threading.Thread(target=recv,args=("------Recieving Message------",en_digest))
        thread_send.start()
        thread_recv.start()

        thread_send.join()
        thread_recv.join()
        time.sleep(0.5)
    time.sleep(60)
    server.close()