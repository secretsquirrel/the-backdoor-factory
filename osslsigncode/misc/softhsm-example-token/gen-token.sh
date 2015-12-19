#!/bin/bash

P11_ENGINE=/usr/lib/engines/engine_pkcs11.so
P11_MODULE=/usr/lib/softhsm/libsofthsm.so

## 

export SOFTHSM_CONF=softhsm.conf
cat>config.py<<EOF
DEBUG = True
SECRET = "secret1"
PKCS11MODULE = "$P11_MODULE"
PKCS11PIN = "secret1"
EOF
cat>softhsm.conf<<EOF
0: softhsm.db
EOF
cat>openssl.conf<<EOF
openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = $P11_ENGINE
MODULE_PATH = $P11_MODULE
PIN = secret1
init = 0

[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]
EOF

export SOFTHSM_CONF=softhsm.conf
softhsm --slot 0 --label test --init-token --pin secret1 --so-pin secret2
pkcs11-tool --module $P11_MODULE -l -k --key-type rsa:2048 --slot 0 --id a1b2 --label test --pin secret1
pkcs11-tool --module $P11_MODULE -l --pin secret1 -O
openssl req -new -x509 -subj "/cn=TEST" -engine pkcs11 -config openssl.conf -keyform engine -key a1b2 -passin pass:secret1 -out test.crt
openssl x509 -inform PEM -outform DER -in test.crt -out test.der
pkcs11-tool --module $P11_MODULE -l --slot 0 --id a1b2 --label test -y cert -w test.der --pin secret1
