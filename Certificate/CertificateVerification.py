import subprocess

def execute_command(command):
    # Execute the command
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    return output.decode("utf-8")  # Decode bytes to string

def verify_certificate(Cert,Sig):
    #can replace ca-public-key.pem by the apropriate CA public key as needed
    result=execute_command('C:/"Program Files"/OpenSSL/bin/openssl dgst -sha256 -verify ca-public-key.pem -signature '+ str(Sig)+' '+str(Cert))
    print("Certificate is: "+ str(result))
    return ("Certificate is: "+ str(result)=="Certificate is: Verified OK\n")

#verify_certificate()