#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
  echo "You must be root" 2>&1
  exit 1
fi

#install capstone
pip install capstone

uname -a | grep BSD &> /dev/null
if [ $? -eq 0 ]; then
	echo 'Installing Capstone python bindings for *bsd'
	rm -rf ./build
	python setup.py build -b ./build install
else
	make install
fi

#check if kali
uname -a | grep -i kali &> /dev/null 
if [ $? -eq 0 ]; then
	apt-get update
	apt-get install python-capstone
fi

#install pefile
#check for pip
if hash pip 2>/dev/null; then
        pip install pefile
else
        echo 'Install pefile manually, pip is not installed'
        echo ""
fi


