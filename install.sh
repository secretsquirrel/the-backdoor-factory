#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
  echo "You must be root" 2>&1
  exit 1
fi

#install capstone
git clone https://github.com/aquynh/capstone/

cd capstone

git checkout next

./make.sh

./make.sh install

cd bindings/python

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
	echo "Adding capstone path for Kali64 in /etc/ls.so.conf.d/capstone.conf"
	echo "#capstone shared libs" >> /etc/ld.so.conf.d/capstone.conf
	echo "/usr/lib64" >> /etc/ld.so.conf.d/capstone.conf
	ldconfig
fi

#install pefile
#check for pip
if hash pip 2>/dev/null; then
        pip install pefile
else
        echo 'Install pefile manually, pip is not installed'
        echo ""
fi


