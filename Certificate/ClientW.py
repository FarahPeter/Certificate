import socket
import subprocess
import os
import random
import string
import CertificateVerification
import json
import pickle
import re

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345


def execute_command(command):
    # Execute the command
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    return output.decode("utf-8")  # Decode bytes to string


def extract_between_Special(input_str, first, last):
    pattern = re.escape(first) + "(.*?)" + re.escape(last)
    match = re.search(pattern, input_str)
    if match:
        return match.group(1)
    else:
        return ""

def extract_between(x, first, last):
    start = x.find(first.encode())
    end = x.find(last.encode())

    if start == -1 or end == -1:
        return None

    start += len(first)
    return x[start:end]


def generate_symmetric_key(filename="symmetric_key.txt"):
    key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    with open(filename, 'w') as f:
        f.write(key)
    return key

def read_bin_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return None
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def write_string_to_file(input_string, file_path="Generated_symetricKey.txt"):
    try:
        with open(file_path, 'w') as file:
            file.write(input_string)
        #print("String has been written to", file_path)
    except IOError:
        print("Error: Unable to write to file", file_path)

def write_string_to_file_special(input_string, file_path="Generated_symmetricKey.txt"):
    try:
        with open(file_path, 'w') as file:
            file.write(input_string.replace('\\n', '\n').replace("\\",""))
        #print("String has been written to", file_path)
    except IOError:
        print("Error: Unable to write to file", file_path)

def write_bytes_to_bin_file(byte_data,filename):
    try:
        with open(filename, 'wb') as bin_file:
            bin_file.write(byte_data)
        #print("Bytes written to", filename, "successfully.")
    except IOError:
        print("Error writing to", filename)

def receive_file(socket, filename):
    with open(filename, 'wb') as f:
        while True:
            data = socket.recv(1024)
            if not data:
                break
            f.write(data)

def read_txt_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def main():

    # Connect to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print(f"[*] Connected to {SERVER_HOST}:{SERVER_PORT}")

    #received Server Certificate and signature
    i=1
    with open("CertificateReceived.txt", 'wb') as f:
        while i>0:
            data = client_socket.recv(4096)
            if not data:
                break
            f.write(data)
            i=i-1

    i=1
    with open("CertSignatureReceived.bin", 'wb') as f:
        while i>0:
            print("test2")
            data = client_socket.recv(4096)
            if not data:
                break
            f.write(data)
            i=i-1

    #receive_file(client_socket, "CertificateReceived.txt")
    #receive_file(client_socket, "CertSignatureReceived.bin")
    cerSigReceived=read_bin_file("CertSignatureReceived.bin")
    cerReceived=read_txt_file("CertificateReceived.txt")
    print("Received Server certificate and signature: "+str(cerReceived)+'    '+str(cerSigReceived))

    #verifiying certificate
    if not (CertificateVerification.verify_certificate("CertificateReceived.txt","CertSignatureReceived.bin")):
        client_socket.close()
        exit(1)
    else:
        write_string_to_file_special(extract_between_Special(cerReceived,"'public_key': '","'}"),"publicServerReceived.pem")

    # Generate symmetric key
    symmetric_key = generate_symmetric_key()
    write_string_to_file(str(symmetric_key))
    print("Symetric key generated: " + str(symmetric_key))

    # Encrypt symmetric key with server's public key
    execute_command('C:/"Program Files"/OpenSSL/bin/openssl pkeyutl -encrypt -pubin -inkey publicServerReceived.pem -in symmetric_key.txt -out encrypted_symetricKey.bin')
    encryptedSymetric_key =read_bin_file("encrypted_symetricKey.bin")
    print("Symetric Key encrypted with server public key: "+str(encryptedSymetric_key))

    #Send the Symetric key encrypted with the server public key
    client_socket.send(encryptedSymetric_key)
    print("Symetric Key encrypted with the server public key sent to server")

    #encrypt data.txt with symetric key
    execute_command('C:/"Program Files"/OpenSSL/bin/openssl enc -aes-256-cbc -base64 -pbkdf2 -in data.txt -out encryptedData.bin -pass pass:'+str(symmetric_key))
    encrypteddata = read_bin_file("encryptedData.bin")
    print("Data encrypted with symetric key: "+str(encrypteddata))

    # Send the encrypted data
    client_socket.send(encrypteddata)
    print("Encrypted Data sent to server")

if __name__ == "__main__":
    main()