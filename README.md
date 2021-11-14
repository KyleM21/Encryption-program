# Ecryption-program

## How to run

Download files from github
- fcrypt.py
- private.pem
- public.pem

Strcture: python3 fcrypt [Option] [RSA key] [input] [output]
To encrypt: ~ python3 fcrypt.py --encrypt public.pem secret.txt encrypted.txt
To decrypt: ~ python3 fcrypt.py --decrypt private.pem encrypted.txt decrypted.txt

## Description

This is a python file encryption project I did for my Computer Security class.
It will take the file given and encrypt it, it can also decrypt it.

