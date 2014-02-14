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

def eat_code_caves(flItms, caveone, cavetwo):
    try:
        if flItms['CavesPicked'][cavetwo][0] == flItms['CavesPicked'][caveone][0]:
            return int(flItms['CavesPicked'][cavetwo][1], 16) - int(flItms['CavesPicked'][caveone][1], 16)
        else:
            caveone_found = False
            cavetwo_found = False
            forward = True
            windows_memoffset_holder = 0
            for section in flItms['Sections']:
                if flItms['CavesPicked'][caveone][0] == section[0] and caveone_found is False:
                    caveone_found = True
                    if cavetwo_found is False:
                        windows_memoffset_holder += section[1] + 4096 - section[1] % 4096 - section[3]
                        forward = True
                        continue
                    if section[1] % 4096 == 0:
                        continue
                    break

                if flItms['CavesPicked'][cavetwo][0] == section[0] and cavetwo_found is False:
                    cavetwo_found = True
                    if caveone_found is False:
                        windows_memoffset_holder += -(section[1] + 4096 - section[1] % 4096 - section[3])
                        forward = False
                        continue
                    if section[1] % 4096 == 0:
                        continue
                    break

                if caveone_found is True or cavetwo_found is True:
                    if section[1] % 4096 == 0:
                            continue
                    if forward is True:
                        windows_memoffset_holder += section[1] + 4096 - section[1] % 4096 - section[3]
                    if forward is False:
                        windows_memoffset_holder += -(section[1] + 4096 - section[1] % 4096 - section[3])
                    continue

                #Need a way to catch all the sections in between other sections

            return int(flItms['CavesPicked'][cavetwo][1], 16) - int(flItms['CavesPicked'][caveone][1], 16) + windows_memoffset_holder

    except Exception as e:
        #print "EAT CODE CAVE", str(e)
        return 0