#!/usr/bin/env python3
import socket
import sys
import re

def client(address, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((address, port))
    chunk = sys.stdin.buffer.read(1024)
    while chunk != b'':
        length = len(chunk)
        client_socket.send(length.to_bytes(length=2, byteorder='big') + chunk)
        chunk = sys.stdin.buffer.read(1024)
    client_socket.close()


def server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', port))
    server_socket.listen(1)
    client_socket, _ = server_socket.accept()
    size = client_socket.recv(2)
    data = client_socket.recv(int.from_bytes(size, byteorder='big'))
    while data:
        sys.stdout.buffer.write(data)
        size = client_socket.recv(2)
        data = client_socket.recv(int.from_bytes(size, byteorder='big'))
    client_socket.close()
    server_socket.close()

arguments = sys.argv[1:]
intRegex = r'^\d+$'
validArguments = len(arguments) == 2 and re.match(intRegex, arguments[1]) and int(arguments[1]) > 0 and int(arguments[1]) < 65536
if (not validArguments):
    print("Invalid command line options. Please conform to the following format: uft [-l PORT] [SERVER_IP_ADDRESS PORT]")
else:
    if (arguments[0] == "-l"):
        server(int(arguments[1]))
    else:
        client(arguments[0], int(arguments[1]))
