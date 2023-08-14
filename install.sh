#!/usr/bin/env bash

#depends:
# capstone (newest)
# pefile
# python-capstone
# autoconf


if [[ $EUID -ne 0 ]]; then
  echo "You must be root" 2>&1
  exit 1
fi

#check if kali
uname -a | grep -i kali &> /dev/null 
if [ $? -eq 0 ]; then
	apt-get update
	apt-get install -y python3-capstone autoconf libtool curl libcurl4-openssl-dev
	wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb    
	dpkg -i libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb
	rm -rf libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb

	#install appack
	uname -a | grep -i "armv" &> /dev/null
	if [ $? -ne 0 ]; then
                echo "[*] installing appack for onionduke"
		sudo apt-get install -y libc6-dev-i386
		cd ./aPLib/example/
		gcc -c -I../lib/elf -m32 -Wall -O2 -s -o appack.o appack.c -v 
		gcc -m32 -Wall -O2 -s -o appack appack.o ../lib/elf/aplib.a -v 
		sudo cp ./appack /usr/bin/appack	
	else
		echo "Arm not supported for aPLib"
	fi
fi

#other linux
uname -a | grep -v "kali" | grep -i linux &> /dev/null 
if [ $? -eq 0 ]; then

	if hash pip3 2>/dev/null; then
		sudo apt-get install -y python3-pip autoconf libtool curl libcurl4-openssl-dev
	        pip3 install pefile
	        #install capstone
		pip3 install capstone
	else
	        echo '[!!!!] Install pefile and capstone manually, pip3 is not installed'
	        echo '[!!!!] or install pip3 and retry'
	        echo ""
	fi
	
	uname -a | grep -i "armv" &> /dev/null
        if [ $? -ne 0 ]; then
                echo "[*] installing appack for onionduke"
		echo "[*] installing dependences"
		sudo apt-get install libc6-dev-i386
                cd ./aPLib/example/
                gcc -c -I../lib/elf -m32 -Wall -O2 -s -o appack.o appack.c -v 
                gcc -m32 -Wall -O2 -s -o appack appack.o ../lib/elf/aplib.a -v 
                sudo cp ./appack /usr/bin/appack        
        else
                echo "[!!!!] Arm not supported for aPLib"
	fi
fi

#OS X appack install
uname -a | grep -i Darwin &> /dev/null
if [ $? -eq 0 ]; then
	brew install autoconf
	brew install automake
	brew install libtool
	
	pip3 install pefile
	pip3 install capstone
	
	cd ./aPLib/example/
	clang -c -I../lib/macho64 -Wall -O2  -o appack.o appack.c -v 
	clang -Wall -O2  -o appack appack.o ../lib/macho64/aplib.a -v 
	cp ./appack /usr/local/bin/appack
fi

