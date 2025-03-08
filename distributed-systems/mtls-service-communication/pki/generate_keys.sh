openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.crt -config ca.conf -days 3650
