#! /usr/bin/env python3

import socket
import ssl
import subprocess
HOST = '10.4.8.1'
PORT = 65432

def insecureSocket():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        while(True):
            sock.listen(1)
            conn, addr = sock.accept()
            with conn:
                print('Client', addr)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(data.decode('utf-8'))
                        
if __name__ == '__main__':
    insecureSocket()
