#!/bin/sh

rm -f putty*.exe

PUTTY_URL="http://the.earth.li/~sgtatham/putty/0.64/x86/putty.exe"
[ -f putty.exe ] || wget -q -O putty.exe $PUTTY_URL
[ -f putty.exe ] || curl -o putty.exe $PUTTY_URL

if [ ! -f putty.exe ]; then
    echo "FAIL: Couldn't download putty.exe"
    exit 1
fi

rm -f key.* cert.*

keytool -genkey \
	-alias selfsigned -keysize 2048 -keyalg RSA -keypass passme -storepass passme -keystore key.ks << EOF
John Doe
ACME In
ACME
Springfield
LaLaLand
SE
yes
EOF


echo "Converting key/cert to PKCS12 container"
keytool -importkeystore \
	-srckeystore key.ks -srcstoretype JKS -srckeypass passme -srcstorepass passme -srcalias selfsigned \
	-destkeystore key.p12 -deststoretype PKCS12 -destkeypass passme -deststorepass passme

rm -f key.ks

echo "Converting key to PEM format"
openssl pkcs12 -in key.p12 -passin pass:passme -nocerts -nodes -out key.pem
echo "Converting key to PEM format (with password)"
openssl rsa -in key.pem -out keyp.pem -passout pass:passme
echo "Converting key to DER format"
openssl rsa -in key.pem -outform DER -out key.der -passout pass:passme
echo "Converting key to PVK format"
openssl rsa -in key.pem -outform PVK -pvk-strong -out key.pvk -passout pass:passme

echo "Converting cert to PEM format"
openssl pkcs12 -in key.p12 -passin pass:passme -nokeys -out cert.pem
echo "Converting cert to SPC format"
openssl crl2pkcs7 -nocrl -certfile cert.pem -outform DER -out cert.spc


../osslsigncode sign -spc cert.spc -key key.pem putty.exe putty1.exe
../osslsigncode sign -certs cert.spc -key keyp.pem -pass passme putty.exe putty2.exe
../osslsigncode sign -certs cert.pem -key keyp.pem -pass passme putty.exe putty3.exe
../osslsigncode sign -certs cert.spc -key key.der putty.exe putty4.exe
../osslsigncode sign -pkcs12 key.p12 -pass passme putty.exe putty5.exe
../osslsigncode sign -certs cert.spc -key key.pvk -pass passme putty.exe putty6.exe

echo ""
echo ""

check=`sha1sum putty[1-9]*.exe | cut -d' ' -f1 | uniq | wc -l`
cmp putty1.exe putty2.exe && \
	cmp putty2.exe putty3.exe && \
	cmp putty3.exe putty4.exe && \
	cmp putty4.exe putty5.exe && \
	cmp putty5.exe putty6.exe
if [ $? -ne 0 ]; then
	echo "Failure is not an option."
else
	echo "Yes, it works."
fi


