#!/usr/bin/env python
'''

Copyright (c) 2013-2017, Joshua Pitts
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


def xor_file(input_file, output_file, xorkey):
    number_added = 0
    while True:

        some_bytes = input_file.read(4)
        if len(some_bytes) == 0:
            break
        if len(some_bytes) % 4 != 0:
            number_added = 4 - len(some_bytes)
            some_bytes = some_bytes + "\x00" * (number_added)

        writable_bytes = struct.pack("<I", (struct.unpack("<I", some_bytes)[0]) ^ xorkey)
        output_file.write(writable_bytes)

    if number_added != 0:
        number_added = 0 - number_added
        output_file.seek(number_added, os.SEEK_END)
        output_file.truncate()


def write_rsrc(f, oldrva, newRva):
    '''
    This parses a .rsrc section and will adjust the RVA attributes
    for patching on to the OnionDuke Stub
    '''
    rsrc_structure = {}

    def parse_header(f):
        return {"Characteristics": struct.unpack("<I", f.read(4))[0],
                "TimeDataStamp": struct.unpack("<I", f.read(4))[0],
                "MajorVersion": struct.unpack("<H", f.read(2))[0],
                "MinorVersion": struct.unpack("<H", f.read(2))[0],
                "NumberOfNamedEntries": struct.unpack("<H", f.read(2))[0],
                "NumberofIDEntries": struct.unpack("<H", f.read(2))[0],
                }

    def merge_two_dicts(x, y):
        '''Given two dicts, merge them into a new dict as a shallow copy.'''
        z = x.copy()
        z.update(y)
        return z

    def parse_data_entry(f):
        return {"WriteME": f.tell(),
                "RVA of Data": struct.unpack("<I", f.read(4))[0],
                "Size": struct.unpack("<I", f.read(4))[0],
                "CodePage": struct.unpack("<I", f.read(4))[0],
                "Reserved": struct.unpack("<I", f.read(4))[0]
                }

    def parse_ID(f, number):
        temp = {}
        for i in range(0, number):
            _tempid = struct.unpack("<I", f.read(4))[0]
            temp[_tempid] = struct.unpack("<I", f.read(4))[0]
        return temp

    #parse initial header
    rsrc_structure['Typeheader'] = parse_header(f)
    rsrc_structure['Typeheader']['NameEntries'] = {}
    rsrc_structure['Typeheader']["IDentries"] = {}

    if rsrc_structure['Typeheader']["NumberofIDEntries"]:
        rsrc_structure['Typeheader']["IDentries"] = parse_ID(f, rsrc_structure['Typeheader']["NumberofIDEntries"])
    if rsrc_structure['Typeheader']["NumberOfNamedEntries"]:
        rsrc_structure['Typeheader']['NameEntries'] = parse_ID(f, rsrc_structure['Typeheader']['NumberOfNamedEntries'])

    #merge, flatten
    rsrc_structure['Typeheader']['Entries'] = merge_two_dicts(rsrc_structure['Typeheader']["IDentries"],
                                                              rsrc_structure['Typeheader']['NameEntries'])
    for entry, value in rsrc_structure['Typeheader']["Entries"].iteritems():

        #jump to location in PE adjusted for RVA
        f.seek((value & 0xffffff), 0)

        rsrc_structure[entry] = parse_header(f)
        rsrc_structure[entry]["IDs"] = {}
        rsrc_structure[entry]["Names"] = {}

        if rsrc_structure[entry]["NumberofIDEntries"]:
            rsrc_structure[entry]["IDs"] = parse_ID(f, rsrc_structure[entry]["NumberofIDEntries"])

        if rsrc_structure[entry]["NumberOfNamedEntries"]:
            rsrc_structure[entry]["Names"] = parse_ID(f, rsrc_structure[entry]["NumberOfNamedEntries"])

        rsrc_structure[entry]["NameIDs"] = merge_two_dicts(rsrc_structure[entry]["IDs"],
                                                           rsrc_structure[entry]["Names"])

        #Now get language
        for name_id, offset in rsrc_structure[entry]["NameIDs"].iteritems():
            f.seek((offset & 0xffffff), 0)
            rsrc_structure[name_id] = parse_header(f)
            rsrc_structure[name_id]["IDs"] = {}
            rsrc_structure[name_id]["Names"] = {}

            if rsrc_structure[name_id]["NumberofIDEntries"]:
                rsrc_structure[name_id]["IDs"] = parse_ID(f, rsrc_structure[name_id]["NumberofIDEntries"])

            if rsrc_structure[name_id]["NumberOfNamedEntries"]:
                rsrc_structure[name_id]["Names"] = parse_ID(f, rsrc_structure[name_id]["NumberOfNamedEntries"])

            rsrc_structure[name_id]["language"] = merge_two_dicts(rsrc_structure[name_id]["IDs"],
                                                                  rsrc_structure[name_id]["Names"])

            #now get Data Entry Details and write
            for lanID, offsetDataEntry in rsrc_structure[name_id]["language"].iteritems():
                f.seek((offsetDataEntry & 0xffffff), 0)
                rsrc_structure[lanID] = parse_data_entry(f)
                #write to location
                f.seek(rsrc_structure[lanID]["WriteME"], 0)
                f.write(struct.pack("<I", rsrc_structure[lanID]["RVA of Data"] - oldrva + newRva))
