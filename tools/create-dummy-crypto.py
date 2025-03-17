#!/bin/env python3

# Creates safe dummy crypto certs/keys for lab, where there may be less security.

import os
import subprocess

sslFilePath = "sslFiles"
ssl_filenames = os.listdir(sslFilePath)

for file in ssl_filenames:
    if file.endswith(".key"):
        keyFileName = f"sslFiles/{file}"
        certFileName = keyFileName.replace(".key", ".crt" )
        
        opensslGetSubjOutput = subprocess.run( [f"/bin/openssl x509 -noout -subject -in {certFileName}"], shell=True, capture_output=True, text=True)
        if opensslGetSubjOutput.returncode != 0:
            print(f"OpenSSL Failure: {opensslGetSubjOutput.stderr} ")
        
        subject = opensslGetSubjOutput.stdout.strip().replace( " = ", "=" ).replace( "subject=", "/" ).replace(", ", "/")

        opensslOutput = subprocess.run( [f"/bin/openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj '{subject}' -keyout '{keyFileName}' -out '{certFileName}'"], shell=True, capture_output=True, text=True)
        
        if opensslOutput.returncode != 0:
            print(f"OpensSSL FAILURE for Cert and Key: {certFileName}, {keyFileName} with subject: {subject} Failure Msg: {opensslOutput.stderr}")
        else:
            print(f"Created new Cert and Key: {certFileName}, {keyFileName} with subject: {subject}")