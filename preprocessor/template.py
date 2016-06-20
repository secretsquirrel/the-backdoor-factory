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
recheck_support = False 

# file format that this is for (PE, ELF, MACHO, ALL)
# if not specified the processor will run against all
file_format = "ALL"

#############################################


class preprocessor:

    # REQUIRED
    def __init__(self, BDF):
        
        # REQUIRED
        self.BDF = BDF
        # if you want to return a result set it to True
        #  and check for failures
        self.result = True

    # REQUIRED
    def run(self):
        # call your program main here
        self.hello()

        # return a result here, if you want
        return self.result

    def hello(self):
        # add a tab for readability
        try:

            print '\t[*] Default Template test complete'

        #  Of course this doesn't fail
        except Exception, e:
            print "Why fail?", str(e)
            self.result = False
