#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
  echo "You must root" 2>&1
  exit 1
fi

#update capstone

cd capstone


if [[ `git pull` != "Already up-to-date." ]]; then

	git checkout b53a59af53ffbd5dbe8dbcefba41a00cf4fc7469

	./make.sh

	./make.sh install

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
else
	echo "Capstone is up-to-date."
fi

# update pefile

pip install --upgrade pefile
