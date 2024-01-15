#!/usr/bin/env python3
import socket
import sys
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
from Crypto.Random.random import randint

# g=2
#p=0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b
g=7
p=997
x = 0x9fdb8b8a004544f0045f1737d0ba2e0b274cdf1a9f588218fb435316a16e374171fd19d8d8f37c39bf863fd60e3e300680a3030c6e4c3757d08f70e6aa871033

def DHcalc(received, private):
    agreedKey = pow(received, private, p)
    h = SHA256.new()
    h.update(('%x' % agreedKey).encode('utf-8'))
    digest = h.digest()[0:32]
    return digest

arguments = sys.argv[1:]
intRegex = r'^\d+$'
validArguments = len(arguments) == 4 and re.match(intRegex, arguments[1]) and int(arguments[1]) > 0 and int(arguments[1]) < 65536
validArguments = validArguments and re.match(intRegex, arguments[3]) and int(arguments[3]) > 0 and int(arguments[3]) < 65536
if (not validArguments):
    print("Invalid command line options. Please conform to the following format: lj-proxy -l LISTEN_PORT SERVER_IP_ADDRESS SERVER_PORT")
else:
    # Eavesdrop on DH Key Exchange
    my_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_server_socket.bind(('localhost', int(arguments[1])))
    my_server_socket.listen(1)
    actual_client_socket, _ = my_server_socket.accept()
    fromClientBinary = actual_client_socket.recv(384)
    fromClient = int(fromClientBinary.decode('utf-8'))
    actual_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    actual_server_socket.connect((arguments[2], int(arguments[3])))
    actual_server_socket.send(fromClientBinary)
    fromServerBinary = actual_server_socket.recv(384)
    fromServer = int(fromServerBinary.decode('utf-8'))
    actual_client_socket.send(fromServerBinary)

    # Now proxy along and eavesdrop
    fullFile = []
    sizeBinary = actual_client_socket.recv(2)
    while sizeBinary:
        size = int.from_bytes(sizeBinary, byteorder='big')
        nonce = actual_client_socket.recv(16)
        tag = actual_client_socket.recv(16)
        encData = actual_client_socket.recv(size - 32)
        fullFile.append((encData, nonce, tag))
        actual_server_socket.send(sizeBinary + nonce + tag + encData)
        sizeBinary = actual_client_socket.recv(2)
    actual_server_socket.close()
    my_server_socket.close()
    actual_client_socket.close()
    forcedClientPrivate = 0
    while pow(g, forcedClientPrivate, p) != fromClient:
        forcedClientPrivate += 1
    forcedDigest = DHcalc(fromServer, forcedClientPrivate)
    for (data, nonce, _) in fullFile:
        cipher = AES.new(forcedDigest, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(data)
        sys.stdout.buffer.write(unpad(plaintext,16))
