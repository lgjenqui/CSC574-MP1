#!/usr/bin/env python3
import socket
import sys
import re
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def client(key, address, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((address, port))
    salt = get_random_bytes(16)
    client_socket.send(salt)
    generatedKey = PBKDF2(key, salt, dkLen=32)
    chunk = sys.stdin.buffer.read(1024)
    while chunk != b'':
        paddedChunk = pad(chunk, 16)
        cipher = AES.new(generatedKey, AES.MODE_GCM)
        nonce = cipher.nonce
        encData, tag = cipher.encrypt_and_digest(paddedChunk)
        length = len(paddedChunk) + 32
        client_socket.send(length.to_bytes(length=2, byteorder='big') + nonce + tag + encData)
        chunk = sys.stdin.buffer.read(1024)
    client_socket.close()


def server(key, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', port))
    server_socket.listen(1)
    client_socket, _ = server_socket.accept()
    salt = client_socket.recv(16)
    generatedKey = PBKDF2(key, salt, dkLen=32)
    size = int.from_bytes(client_socket.recv(2), byteorder='big')
    while size:
        nonce = client_socket.recv(16)
        tag = client_socket.recv(16)
        encData = client_socket.recv(size - 32)
        cipher = AES.new(generatedKey, AES.MODE_GCM, nonce=nonce)
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
validArguments = len(arguments) == 4 and arguments[0] == "-k" and re.match(intRegex, arguments[3]) and int(arguments[3]) > 0 and int(arguments[3]) < 65536
if (not validArguments):
    print("Invalid command line options. Please conform to the following format: eft -k KEY [-l PORT] [SERVER_IP_ADDRESS PORT]")
else:
    if (arguments[2] == "-l"):
        server(arguments[1], int(arguments[3]))
    else:
        client(arguments[1], arguments[2], int(arguments[3]))
