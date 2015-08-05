#!/usr/bin/env bash

#depends:
# capstone (newest)
# pefile
# python-capstone


if [[ $EUID -ne 0 ]]; then
  echo "You must be root" 2>&1
  exit 1
fi

#check if kali
uname -a | grep -i kali &> /dev/null 
if [ $? -eq 0 ]; then
	apt-get update
	apt-get install -y python-capstone 
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

	if hash pip 2>/dev/null; then
		sudo apt-get install -y python-pip
	        pip install pefile
	        #install capstone
		pip install capstone
	else
	        echo '[!!!!] Install pefile and capstone manually, pip is not installed'
	        echo '[!!!!] or install pip and retry'
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
	pip install pefile
	cd ./aPLib/example/
	clang -c -I../lib/macho64 -Wall -O2  -o appack.o appack.c -v 
	clang -Wall -O2  -o appack appack.o ../lib/macho64/aplib.a -v 
	cp ./appack /usr/bin/appack
fi

