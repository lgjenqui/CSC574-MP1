#!/usr/bin/env python3
import socket
import sys
import re
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random.random import randint

g=2
p=0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b

def DHcalc(received, private):
    agreedKey = pow(received, private, p)
    h = SHA256.new()
    h.update(('%x' % agreedKey).encode('utf-8'))
    digest = h.digest()[0:32]
    return digest

def client(address, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((address, port))
    alice = randint(0, p - 2)
    alicePublic = pow(g, alice, p)
    client_socket.send(str(alicePublic).rjust(384, '0').encode('utf-8'))
    fromBob = int(client_socket.recv(384).decode('utf-8'))
    digest = DHcalc(fromBob, alice)
    chunk = sys.stdin.buffer.read(1024)
    while chunk != b'':
        paddedChunk = pad(chunk, 16)
        cipher = AES.new(digest, AES.MODE_GCM)
        nonce = cipher.nonce
        encData, tag = cipher.encrypt_and_digest(paddedChunk)
        length = len(paddedChunk) + 32
        client_socket.send(length.to_bytes(length=2, byteorder='big') + nonce + tag + encData)
        chunk = sys.stdin.buffer.read(1024)
    client_socket.close()


def server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', port))
    server_socket.listen(1)
    client_socket, _ = server_socket.accept()
    fromAlice = int(client_socket.recv(384).decode('utf-8'))
    bob = randint(0, p - 2)
    bobPublic = pow(g, bob, p)
    client_socket.send(str(bobPublic).rjust(384, '0').encode('utf-8'))
    digest = DHcalc(fromAlice, bob)
    size = int.from_bytes(client_socket.recv(2), byteorder='big')
    while size:
        nonce = client_socket.recv(16)
        tag = client_socket.recv(16)
        encData = client_socket.recv(size - 32)
        cipher = AES.new(digest, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(encData)
        try:
            cipher.verify(tag)
            sys.stdout.buffer.write(unpad(plaintext,16))
        except ValueError:
            sys.stderr.write("Error: integrity check failed.")
        size = int.from_bytes(client_socket.recv(2), byteorder='big')
    client_socket.close()
    server_socket.close()

arguments = sys.argv[1:]
intRegex = r'^\d+$'
validArguments = len(arguments) == 2 and re.match(intRegex, arguments[1]) and int(arguments[1]) > 0 and int(arguments[1]) < 65536
if (not validArguments):
    print("Invalid command line options. Please conform to the following format: eft-dh [-l PORT] [SERVER_IP_ADDRESS PORT]")
else:
    if (arguments[0] == "-l"):
        server(int(arguments[1]))
    else:
        client(arguments[0], int(arguments[1]))
