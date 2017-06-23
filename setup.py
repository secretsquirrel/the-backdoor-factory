#!/usr/bin/python
#
# Authors:
#   Philippe Thierry <phil@reseau-libre.net>

import os
import os.path

from distutils.core import setup


setup(
    name="backdoor-factory",
    #version=version.VERSION_STRING,
    author="secretsquirrel",
    description="Patch PE, ELF, Mach-O binaries with shellcode",
    license="BSD-3-clause",
    url="https://github.com/secretsquirrel/the-backdoor-factory",
    packages=['bdfactory','bdfactory.intel','bdfactory.arm','bdfactory.winapi','bdfactory.onionduke','bdfactory.preprocessor'],
    package_dir = {'bdfactory': ''},
    py_modules=['bdfactory.pebin','bdfactory.elfbin','bdfactory.machobin'],
    scripts=[
        os.path.join("./", "backdoor.py"),
    ],
)
