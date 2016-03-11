osslsigncode
============


== WHAT IS IT?

osslsigncode is a small tool that implements part of the functionality
of the Microsoft tool signtool.exe - more exactly the Authenticode
signing and timestamping. But osslsigncode is based on OpenSSL and cURL,
and thus should be able to compile on most platforms where these exist.


== WHY?

Why not use signtool.exe? Because I don't want to go to a Windows
machine every time I need to sign a binary - I can compile and build
the binaries using Wine on my Linux machine, but I can't sign them
since the signtool.exe makes good use of the CryptoAPI in Windows, and
these APIs aren't (yet?) fully implemented in Wine, so the signtool.exe
tool  would fail. And, so, osslsigncode was born.


== WHAT CAN IT DO?

It can sign and timestamp PE (EXE/SYS/DLL/etc), CAB and MSI files. It supports
the equivalent of signtool.exe's "-j javasign.dll -jp low", i.e. add a
valid signature for a CAB file containing Java files. It supports getting
the timestamp through a proxy as well. It also supports signature verification,
removal and extraction.


== INSTALLATION

The usual way:

  ./configure
  make
  make install


== USAGE

Before you can sign a file you need a Software Publishing
Certificate (spc) and a corresponding private key.

This article provides a good starting point as to how
to do the signing with the Microsoft signtool.exe:

  http://www.matthew-jones.com/articles/codesigning.html

To sign with osslsigncode you need the certificate file mentioned in the
article above, in SPC or PEM format, and you will also need the private
key which must be a key file in DER or PEM format, or if osslsigncode was
compiled against OpenSSL 1.0.0 or later, in PVK format.

To sign a PE or MSI file you can now do:

  osslsigncode sign -certs <cert-file> -key <der-key-file> \
        -n "Your Application" -i http://www.yourwebsite.com/ \
        -in yourapp.exe -out yourapp-signed.exe

or if you are using a PEM or PVK key file with a password together
with a PEM certificate:

  osslsigncode sign -certs <cert-file> \
        -key <key-file> -pass <key-password> \
        -n "Your Application" -i http://www.yourwebsite.com/ \
        -in yourapp.exe -out yourapp-signed.exe

or if you want to add a timestamp as well:

  osslsigncode sign -certs <cert-file> -key <key-file> \
        -n "Your Application" -i http://www.yourwebsite.com/ \
        -t http://timestamp.verisign.com/scripts/timstamp.dll \
        -in yourapp.exe -out yourapp-signed.exe

You can use a certificate and key stored in a PKCS#12 container:

  osslsigncode sign -pkcs12 <pkcs12-file> -pass <pkcs12-password> \
        -n "Your Application" -i http://www.yourwebsite.com/ \
        -in yourapp.exe -out yourapp-signed.exe

To sign a CAB file containing java class files:

  osslsigncode sign -certs <cert-file> -key <key-file> \
        -n "Your Application" -i http://www.yourwebsite.com/ \
        -jp low \
        -in yourapp.cab -out yourapp-signed.cab

Only the 'low' parameter is currently supported.

You can check that the signed file is correct by right-clicking
on it in Windows and choose Properties --> Digital Signatures,
and then choose the signature from the list, and click on
Details. You should then be presented with a dialog that says
amongst other things that "This digital signature is OK".



== CONVERTING FROM PVK TO DER

(This guide was written by Ryan Rubley)

If you've managed to finally find osslsigncode from some searches,
you're most likely going to have a heck of a time getting your SPC
and PVK files into the formats osslsigncode wants.

On the computer where you originally purchased your certificate, you
probably had to use IE to get it. Run IE and select Tools/Internet
Options from the menu, then under the Content tab, click the Certificates
button. Under the Personal tab, select your certificate and click the
Export button. On the second page of the wizard, select the PKCS #7
Certificate (.P7B) format. This file you export as a *.p7b is what you
use instead of your *.spc file. It's the same basic thing, in a different format.

For your PVK file, you will need to download a little utility called
PVK.EXE. This can currently be downloaded at

 http://support.globalsign.net/en/objectsign/PVK.zip

Run: pvk -in foo.pvk -nocrypt -out foo.pem

This will convert your PVK file to a PEM file.
From there, you can copy the PEM file to a Linux box, and run:

  openssl rsa -outform der -in foo.pem -out foo.der

This will convert your PEM file to a DER file.

You need the *.p7b and *.der files to use osslsigncode, instead of your
*.spc and *.pvk files.


== BUGS, QUESTIONS etc.

Send an email to pallansson@gmail.com

BUT, if you have questions related to generating spc files,
converting between different formats and so on, *please*
spend a few minutes searching on google for your particular
problem since many people probably already have had your
problem and solved it as well.
