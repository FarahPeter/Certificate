import socket
import subprocess
import os
import random
import string

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345


def execute_command(command):
    # Execute the command
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    return output.decode("utf-8")  # Decode bytes to string



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


def main():

    # Connect to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print(f"[*] Connected to {SERVER_HOST}:{SERVER_PORT}")

    #received public key
    server_public_key = client_socket.recv(4096)
    print("Received Server public Key: "+str(extract_between(server_public_key,"-----BEGIN PUBLIC KEY-----","-----END PUBLIC KEY-----"))[4:-3])

    # Generate symmetric key
    symmetric_key = generate_symmetric_key()
    write_string_to_file(str(symmetric_key))
    print("Symetric key generated: " + str(symmetric_key))

    # Encrypt symmetric key with server's public key
    execute_command('C:/"Program Files"/OpenSSL/bin/openssl pkeyutl -encrypt -pubin -inkey publicServer.pem -in symmetric_key.txt -out encrypted_symetricKey.bin')
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