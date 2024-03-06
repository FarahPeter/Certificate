import socket
import subprocess
import os
import CertificateAuthority
import pickle
import time

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

def execute_command(command):
    # Execute the command
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    return output.decode("utf-8")  # Decode bytes to string

def write_string_to_file(input_string, file_path):
    try:
        with open(file_path, 'w') as file:
            file.write(input_string)
        #print("String has been written to", file_path)
    except IOError:
        print("Error: Unable to write to file", file_path)

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

def write_bytes_to_bin_file(byte_data,filename):
    try:
        with open(filename, 'wb') as bin_file:
            bin_file.write(byte_data)
        #print("Bytes written to", filename, "successfully.")
    except IOError:
        print("Error writing to", filename)

def extract_between(x, first, last):
    start = x.find(first.encode())
    end = x.find(last.encode())

    if start == -1 or end == -1:
        return None

    start += len(first)
    return x[start:end]

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

def send_file(conn, filename):
    with open(filename, 'rb') as f:
        while True:
            data = f.read(1024)
            if not data:
                break
            conn.sendall(data)


def main():
    #generate Certificate on demand
    CertificateAuthority.generate_certificate("MyServer","publicServer.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)
    print(f"[*] Listening on {SERVER_HOST}:{SERVER_PORT}")

    while (True):
        client_socket, client_address = server_socket.accept()
        print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")
        # Send server's certificate to client
        i=1
        with open("Certificate.txt", 'rb') as f:
            while i>0:
                data = f.read(4096)
                if not data:
                    break
                client_socket.sendall(data)
                i=i-1

        i=1
        with open("CertSignature.bin", 'rb') as f:
            while i>0:
                data = f.read(4096)
                if not data:
                    break
                client_socket.sendall(data)
                i=i-1


        print("Server Certificate and signature sent to client")

        #receive the Symetric key encrypted with the server public key
        encryptedSymetricKey = client_socket.recv(4096)
        print("Received the Symetric key encrypted with the server public key: "+str(encryptedSymetricKey))

        #decrypt the Symetric key encrypted with the server public key
        execute_command('C:/"Program Files"/OpenSSL/bin/openssl pkeyutl -decrypt -inkey privateServer.pem -in encrypted_symetricKey.bin -out receivedUnincriptSymetricKey.txt')
        decrypted_symmetric_key=read_txt_file("receivedUnincriptSymetricKey.txt")
        print("Decrypted symmetric key with private key:", decrypted_symmetric_key)

        # receive the encrypted data
        encryptedData = client_socket.recv(4096)
        write_bytes_to_bin_file(encryptedData,"encrypted_data.bin")
        print("Received encrypted data: " + str(encryptedData))

        # decrypt the Data with the symetric key
        execute_command('C:/"Program Files"/OpenSSL/bin/openssl enc -d -aes-256-cbc -base64 -pbkdf2 -in encrypted_data.bin -out decrypteddata.txt -pass pass:'+str(decrypted_symmetric_key))
        decryptedData=read_txt_file("decrypteddata.txt")
        print("Decrypted the data:", decryptedData)

if __name__ == "__main__":
    main()