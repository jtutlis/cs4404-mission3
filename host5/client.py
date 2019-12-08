#!/usr/bin/env python3

import socket
import ssl
import sys

HOST = '10.4.8.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

def insecureSocket(host, message="Hello There"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, PORT))
        sock.sendall(message.encode("utf-8"))
        sock.close()


if __name__ == '__main__':
    insecureSocket(HOST)
