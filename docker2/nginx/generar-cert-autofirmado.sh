#/bin/bash
openssl req -x509 -nodes -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 9999
