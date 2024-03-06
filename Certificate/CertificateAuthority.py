import subprocess
import json



def save_dict_to_json(dictionary, filename):
    with open(filename, 'w') as json_file:
        json.dump(dictionary, json_file)
def execute_command(command):
    # Execute the command
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    return output.decode("utf-8")  # Decode bytes to string

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
def generate_certificate(ID, public_key_path):
    public_key=read_txt_file(public_key_path)
    certificate={"identity":ID,"public_key":public_key}
    print("Certificate to issue: "+str(certificate))
    save_dict_to_json(str(certificate),"Certificate.txt")
    execute_command('C:/"Program Files"/OpenSSL/bin/openssl dgst -sha256 -sign ca-private-key.pem -out CertSignature.bin Certificate.txt')
    signatureOfCert=read_bin_file("CertSignature.bin")
    print("Certificate signed: "+str(signatureOfCert))

"""
generate_certificate("tizi",'''MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs5menJ+8huS6JfvCxeDy
N/lFTJ02zzf6o5JiQ9xNouEG7sIctMP2/UNhM3l3s35t5T/zPH8nKgD4cQuuel8m
tUBVZayzjkN+9YRXHsUEDv50FtUjsLZ+LR8m/BEHycyRMBpxLdErCzChCYK5sJlw
uTvmp8o7bLkOzzBZHwtzW/hD2O1yKJpPUNs3N01Ujpg4jko3A4KkM2YtQKq1ylBZ
evL38Id+0wZeLx9nwmJMo+atyLg/SJTeAxaEzoRghMRewwhPMDGS+JEtAlC0X06p
feM7CI0GxqmJQpOW+pIsgKaw77je+SDvpoMYhJAeDOtZsifjXBaI4MGcxgQVKd7s
DwIDAQAB''')
"""

#generate_certificate("tizi","publicServer.pem")