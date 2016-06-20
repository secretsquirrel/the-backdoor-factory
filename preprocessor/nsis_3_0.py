#!/usr/bin/env python

# settings
# Complete these as you need
#############################################

# ENABLE preprocessor
enabled = False 

# If you want the temp file used in the preprocessor saved
# THE NAME is self.tmp_file
keep_temp = False

# check if file is modified beyond patching support
recheck_support = True

# file format that this is for (PE, ELF, MACHO, ALL)
# if not specified the processor will run against all
file_format = "PE"

#############################################

# add your imports here
import re

class preprocessor:

    # REQUIRED
    def __init__(self, BDF):
        
        # REQUIRED
        self.BDF = BDF

        # Other 
        self.nsis_binary = False

    # REQUIRED
    def run(self):
        # call your program main here
        self.nsis30()

    def nsis30(self):
        print '\tNSIS 3.0 CRC32 Check | Patch Out Preprocessor'
        with open(self.BDF.tmp_file.name, 'r+b') as self.f:
            self.check_NSIS()
            if self.nsis_binary is True:
                print "\t[*] NSIS 3.0 Binary loaded"
                self.patch_crc32_check()
            else:
                print "\t[*] NSIS 3.0 Binary NOT loaded"

    def check_NSIS(self):
        check_one = False
        check_two = False
        check_three = False
        
        filecontents = self.f.read()
        
        if 'NSIS Error'in filecontents:
            check_one = True
        
        if 'Installer integrity check has failed.' in filecontents:
            check_two = True
        
        if 'http://nsis.sf.net/NSIS_Error' in filecontents:
            check_three = True
        
        if check_one is True and check_two is True and check_three is True:
            self.nsis_binary = True

        
    def patch_crc32_check(self):
        p = re.compile("\x3B\x45\x08\x0F\x85\x9C\x00\x00\x00")
        self.f.seek(0)
        locations = []
        match_loc = 0
        for m in p.finditer(self.f.read()):
            locations.append(m.start())
         
        if len(locations) > 1:
            print "\t[*] More than one binary match, picking first"
            match_loc = locations[0]
        else:
            match_loc = locations[0]

        print "\t[*] Patch location", hex(match_loc)
        
        self.f.seek(match_loc + 4)
        self.f.write("\x84")

        


