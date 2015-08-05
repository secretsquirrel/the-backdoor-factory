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


def eat_code_caves(flItms, caveone, cavetwo):
    """
    Return the difference between caves RVA positions
    """

    try:
        if flItms['CavesPicked'][cavetwo][0] == flItms['CavesPicked'][caveone][0]:
            return int(flItms['CavesPicked'][cavetwo][1], 16) - int(flItms['CavesPicked'][caveone][1], 16)

        else:
            caveone_found = False
            cavetwo_found = False
            for section in flItms['Sections']:
                if flItms['CavesPicked'][caveone][0] == section[0] and caveone_found is False:
                    rva_one = int(flItms['CavesPicked'][caveone][1], 16) - int(flItms['CavesPicked'][caveone][4], 16) + flItms['CavesPicked'][caveone][8]
                    caveone_found = True

                if flItms['CavesPicked'][cavetwo][0] == section[0] and cavetwo_found is False:
                    rva_two = int(flItms['CavesPicked'][cavetwo][1], 16) - int(flItms['CavesPicked'][cavetwo][4], 16) + flItms['CavesPicked'][cavetwo][8]
                    cavetwo_found = True

                if caveone_found is True and cavetwo_found is True:
                    if flItms['CavesPicked'][caveone][1] < flItms['CavesPicked'][cavetwo][1]:
                        return -(rva_one - rva_two)
                    else:
                        return rva_two - rva_one

    except Exception:
        return 0
