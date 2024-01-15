#!/usr/bin/env python3
import socket
import sys
import re
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

arguments = sys.argv[1:]
intRegex = r'^\d+$'
validArguments = len(arguments) == 4 and re.match(intRegex, arguments[1]) and int(arguments[1]) > 0 and int(arguments[1]) < 65536
validArguments = validArguments and re.match(intRegex, arguments[3]) and int(arguments[3]) > 0 and int(arguments[3]) < 65536
if (not validArguments):
    print("Invalid command line options. Please conform to the following format: dh-proxy -l LISTEN_PORT SERVER_IP_ADDRESS SERVER_PORT")
else:
    # Establish server role and DH exchange
    my_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_server_socket.bind(('localhost', int(arguments[1])))
    my_server_socket.listen(1)
    actual_client_socket, _ = my_server_socket.accept()
    fromAlice = int(actual_client_socket.recv(384).decode('utf-8'))
    bob = randint(0, p - 2)
    bobPublic = pow(g, bob, p)
    actual_client_socket.send(str(bobPublic).rjust(384, '0').encode('utf-8'))
    firstDigest = DHcalc(fromAlice, bob)

    # Now establish client role and DH exchange
    actual_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    actual_server_socket.connect((arguments[2], int(arguments[3])))
    alice = randint(0, p - 2)
    alicePublic = pow(g, alice, p)
    actual_server_socket.send(str(alicePublic).rjust(384, '0').encode('utf-8'))
    fromBob = int(actual_server_socket.recv(384).decode('utf-8'))
    secondDigest = DHcalc(fromBob, alice)

    # Now proxy along
    size = int.from_bytes(actual_client_socket.recv(2), byteorder='big')
    while size:
        nonce = actual_client_socket.recv(16)
        tag = actual_client_socket.recv(16)
        encData = actual_client_socket.recv(size - 32)
        cipher = AES.new(firstDigest, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(encData)
        try:
            cipher.verify(tag)
            newCipher = AES.new(secondDigest, AES.MODE_GCM)
            newNonce = newCipher.nonce
            newEncData, newTag = newCipher.encrypt_and_digest(plaintext)
            newLength = len(plaintext) + 32
            actual_server_socket.send(newLength.to_bytes(length=2, byteorder='big') + newNonce + newTag + newEncData)
        except ValueError:
            sys.stderr.write("Error: integrity check failed.")
        size = int.from_bytes(actual_client_socket.recv(2), byteorder='big')
    actual_server_socket.close()
    my_server_socket.close()
    actual_client_socket.close()
