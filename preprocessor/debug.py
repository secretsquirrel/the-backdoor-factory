#!/usr/bin/env python

# settings
# Complete these as you need
#############################################

# ENABLE preprocessor
enabled = True 

# If you want to keep the temp file for inspection - pre-patch state.
# THE NAME is self.tmp_file
keep_temp = False

# Recheck the file before patching or the next preprocessor
recheck_support = False

# file format that this is for (PE, ELF, MACHO, ALL)
# if not specified the processor will run against all
file_format = "ALL"

#############################################


class preprocessor:

    # REQUIRED
    def __init__(self, BDF):
        
        # REQUIRED -- exposes BDF objects to the preprocessor environment
        self.BDF = BDF
        # You can set a return, just add a check that returns False
        # 'None' does not flag
        self.result = True

    # REQUIRED
    def run(self):
        # call your program main here, we're calling print_debug()
        self.print_debug()

        return self.result

    def print_debug(self):
        print "*"*25, "DEBUG INFO", "*"*25

        try:
            for item, data in vars(self.BDF).iteritems():
                #  file Items (flItms) will be printed later
                if item == 'flItms':
                    continue
                # This will give ARGS info
                print item, ":" ,data
            
            # BDF functions are exposed | print PE flItms (PE only)
            if 'flItms' in vars(self.BDF):
                self.BDF.print_flItms(self.BDF.flItms)

        except Exception, e:
            print "!" * 50
            print "\t[!] Exception:", str(e)
            print "!" * 50

            self.result = False

        print "*"*25, "END DEBUG INFO", "*"*25

