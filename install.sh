#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "You must root" 2>&1
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

#install pefile

#check for pip
if hash pip 2>/dev/null; then
        pip install pefile
else
        echo 'Install pefile manually, pip is not installed'
        echo ""
fi


