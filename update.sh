#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "You must root" 2>&1
  exit 1
fi

#update capstone

cd capstone

if [[ `git pull` != "Already up-to-date." ]]; then

	git checkout next

	./make.sh

	./make.sh install

	cd bindings/python

	make install
else
	echo "Capstone is up-to-date."
fi

# update pefile

pip install --upgrade pefile
