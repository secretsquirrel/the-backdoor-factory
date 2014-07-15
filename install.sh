#!/bin/bash

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

make install

#check if kali
uname -a | grep -i kali &> /dev/null 
if [ $? -eq 0 ]; then
	echo "Adding capstone path for Kali"
	export LD_LIBRARY_PATH=/usr/lib64/:$LD_LIBRARY_PATH
fi

#install pefile

#check for pip
if hash pip 2>/dev/null; then
        pip install pefile
else
        echo 'Install pefile manually, pip is not installed'
        echo ""
fi


