; #########################################################################

;   aPPack is a test piece for MASM programmers using Joergen Ibsen's
;   MASM version of "aPLib". It is an implementation of the LZ77 algorithm
;   that has the characteristics of reasonable compression speed and very
;   high decompression speed.

;   This makes it highly suitable for installations and other similar
;   applications where decompression speed is critical. The compression
;   ratio averages slightly better than PKZIP.

;   aPLib is included in MASM32 because it is available from the author
;   for personal use as freeware. Commercial applications should contact
;   the author for licence of the software.

;   This example uses the 'safe function wrappers' for the compression and
;   decompression functions, which maintain a header in front of the packed
;   data that is used for crc checking and to determine the length of the
;   decompressed data so that the decompression algorithm knows the correct
;   buffer size to allocate.

;   This example uses OLE string memory which is implemented in 2 macros
;   for convenience of use. The macros are "stralloc" and "strfree".

;   Note that the toolbar bitmap is the single largest component in the
;   assembled program.

; #########################################################################

      .386
      .model flat, stdcall  ; 32 bit memory model
      option casemap :none  ; case sensitive

      include aPPack.inc     ; local includes for this file

; #########################################################################

.code

start:
      invoke GetModuleHandle, NULL
      mov hInstance, eax

      invoke GetCommandLine
      mov CommandLine, eax

      invoke InitCommonControls

      invoke WinMain,hInstance,NULL,CommandLine,SW_SHOWDEFAULT
      invoke ExitProcess,eax

; #########################################################################

WinMain proc hInst     :DWORD,
             hPrevInst :DWORD,
             CmdLine   :DWORD,
             CmdShow   :DWORD

      ;====================
      ; Put LOCALs on stack
      ;====================

      LOCAL wc   :WNDCLASSEX
      LOCAL msg  :MSG
      LOCAL Wwd  :DWORD
      LOCAL Wht  :DWORD
      LOCAL Wtx  :DWORD
      LOCAL Wty  :DWORD

      ;==================================================
      ; Fill WNDCLASSEX structure with required variables
      ;==================================================

      invoke LoadIcon,hInst,500    ; icon ID
      mov hIcon, eax

      szText szClassName,"aPLib_Class"

      mov wc.cbSize,         sizeof WNDCLASSEX
      mov wc.style,          CS_HREDRAW or CS_VREDRAW \
                             or CS_BYTEALIGNWINDOW
      mov wc.lpfnWndProc,    offset WndProc
      mov wc.cbClsExtra,     NULL
      mov wc.cbWndExtra,     NULL
      m2m wc.hInstance,      hInst
      mov wc.hbrBackground,  COLOR_BTNFACE+1
      mov wc.lpszMenuName,   NULL
      mov wc.lpszClassName,  offset szClassName
      m2m wc.hIcon,          hIcon
        invoke LoadCursor,NULL,IDC_ARROW
      mov wc.hCursor,        eax
      m2m wc.hIconSm,        hIcon

      invoke RegisterClassEx, ADDR wc

      ;================================
      ; Centre window at following size
      ;================================

      mov Wwd, 334
      mov Wht, 191

      invoke GetSystemMetrics,SM_CXSCREEN
      invoke TopXY,Wwd,eax
      mov Wtx, eax

      invoke GetSystemMetrics,SM_CYSCREEN
      invoke TopXY,Wht,eax
      mov Wty, eax

      invoke CreateWindowEx,WS_EX_LEFT,
                            ADDR szClassName,
                            ADDR szDisplayName,
                            WS_OVERLAPPED or WS_SYSMENU,
                            Wtx,Wty,Wwd,Wht,
                            NULL,NULL,
                            hInst,NULL
      mov   hWnd,eax

      invoke LoadMenu,hInst,600  ; menu ID
      invoke SetMenu,hWnd,eax

      invoke ShowWindow,hWnd,SW_SHOWNORMAL
      invoke UpdateWindow,hWnd

      ;===================================
      ; Loop until PostQuitMessage is sent
      ;===================================

    StartLoop:
      invoke GetMessage,ADDR msg,NULL,0,0
      cmp eax, 0
      je ExitLoop
      invoke TranslateMessage, ADDR msg
      invoke DispatchMessage,  ADDR msg
      jmp StartLoop
    ExitLoop:

      return msg.wParam

WinMain endp

; #########################################################################

WndProc proc hWin   :DWORD,
             uMsg   :DWORD,
             wParam :DWORD,
             lParam :DWORD

    LOCAL var    :DWORD
    LOCAL caW    :DWORD
    LOCAL caH    :DWORD
    LOCAL hFont  :DWORD
    LOCAL Rct    :RECT
    LOCAL hDC    :DWORD
    LOCAL Ps     :PAINTSTRUCT
    LOCAL tbab   :TBADDBITMAP
    LOCAL tbb    :TBBUTTON
    LOCAL buffer1[128]:BYTE  ; these are two spare buffers
    LOCAL buffer2[128]:BYTE  ; for text manipulation etc..

    .if uMsg == WM_COMMAND

    ; ********************************************************
    ; first check commands that are not allowed while packing
    ; ********************************************************
      .if Packing == 0

        .if wParam == 50
            .data
              ThreadID dd 0
            .code

            ; start compressing in a thread
            mov eax, OFFSET PackFile
            invoke CreateThread,NULL,NULL,eax,
                                NULL,0,ADDR ThreadID
            invoke CloseHandle,eax

        .elseif wParam == 51
            invoke UnpackFile

        .elseif wParam == 53
            invoke SendMessage,hWin,WM_SYSCOMMAND,SC_CLOSE,NULL

        .elseif wParam == 54

            .data
              SelectFile db "Select File",0
              fPattern   db "*.*",0,0
            .code

            mov szFileName[0], 0

            invoke GetFileName,hWin,ADDR SelectFile,ADDR fPattern

            .if szFileName[0] != 0
              invoke lcase,ADDR szFileName
              invoke SetWindowText,hEdit1,ADDR szFileName
            .endif

        .endif

      .endif

    ; **************************************
    ; then commands that are always allowed
    ; **************************************
      .if wParam == 52

          .data
          AboutTtl db "aPLib Pack",0
          AboutMsg db "Joergen Ibsen's aPLib example",13,10,\
                      "Copyright © MASM32 2001",0
          .code

          invoke ShellAbout,hWin,ADDR AboutTtl,ADDR AboutMsg,hIcon

      .elseif wParam == 55
          mov ContPack, 0

      .elseif wParam == 56
          mov killFlag, 1

      .endif

    .elseif uMsg == WM_SYSCOLORCHANGE
        invoke Do_ToolBar,hWin

    .elseif uMsg == WM_CREATE
        invoke Do_ToolBar,hWin

      .data
        align 4
        caption  db "...",0
        abortbt  db "Stop",0
        nullbyte db 0
      .code

        invoke EditSl,ADDR nullbyte,20,100,253,22,hWin,700
        mov hEdit1, eax
        invoke PushButton,ADDR caption,hWin,283,100,25,22,54
        mov hButn1, eax
        invoke Static,ADDR nullbyte,hWin,20,127,240,20,500
        mov hStat1, eax
        invoke PushButton,ADDR abortbt,hWin,270,127,38,21,55
        mov hButn2, eax

        invoke GetStockObject,ANSI_VAR_FONT
        mov hFont, eax

        invoke SendMessage,hEdit1,WM_SETFONT,hFont,0
        invoke SendMessage,hButn1,WM_SETFONT,hFont,0
        invoke SendMessage,hStat1,WM_SETFONT,hFont,0
        invoke SendMessage,hButn2,WM_SETFONT,hFont,0

    .elseif uMsg == WM_SIZE
        invoke SendMessage,hToolBar,TB_AUTOSIZE,0,0

    .elseif uMsg == WM_PAINT
        invoke BeginPaint,hWin,ADDR Ps
          mov hDC, eax
          invoke Paint_Proc,hWin,hDC
        invoke EndPaint,hWin,ADDR Ps
        return 0

    .elseif uMsg == WM_CLOSE

    .elseif uMsg == WM_DESTROY
        invoke PostQuitMessage,NULL
        return 0
    .endif

    invoke DefWindowProc,hWin,uMsg,wParam,lParam

    ret

WndProc endp

; ########################################################################

TopXY proc wDim:DWORD, sDim:DWORD

    shr sDim, 1      ; divide screen dimension by 2
    shr wDim, 1      ; divide window dimension by 2
    mov eax, wDim    ; copy window dimension into eax
    sub sDim, eax    ; sub half win dimension from half screen dimension

    return sDim

TopXY endp

; #########################################################################

Paint_Proc proc hWin:DWORD, hDC:DWORD

    LOCAL btn_hi   :DWORD
    LOCAL btn_lo   :DWORD
    LOCAL Rct      :RECT

    invoke GetSysColor,COLOR_BTNHIGHLIGHT
    mov btn_hi, eax

    invoke GetSysColor,COLOR_BTNSHADOW
    mov btn_lo, eax

    invoke FrameGrp,hEdit1,hButn2,4,1,0
    invoke FrameGrp,hEdit1,hButn2,5,1,1
    invoke FrameGrp,hEdit1,hButn2,14,1,0

    return 0

Paint_Proc endp

; ########################################################################

PackFile proc Param:DWORD

    LOCAL hFile   :DWORD
    LOCAL ln      :DWORD
    LOCAL br      :DWORD
    LOCAL source$ :DWORD
    LOCAL dest$   :DWORD
    LOCAL working$:DWORD
    LOCAL clenth  :DWORD
    LOCAL szNameFile[128]:BYTE

    push esi
    push edi

    invoke GetWindowText,hEdit1,ADDR szNameFile,128

    cmp szNameFile[0], 0
    jne @F
    invoke MessageBox,hWnd,ADDR plSelect,
                      ADDR szDisplayName,MB_OK
    mov eax, 0
    pop edi
    pop esi
    ret
  @@:

    invoke CreateFile,ADDR szNameFile,
                      GENERIC_READ,
                      FILE_SHARE_READ,
                      NULL,OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL
    mov hFile, eax

    invoke GetFileSize,hFile,NULL
    mov ln, eax

    stralloc ln
    mov source$, eax

    invoke ReadFile,hFile,source$,ln,ADDR br,NULL

    invoke CloseHandle,hFile

    mov esi, source$
    lodsd
    cmp eax, "23PA"     ; test for "AP32" signature
    jne @F
      .data
        beendone db "This file has already been compressed by aPPack",0
      .code
      invoke MessageBox,hWnd,ADDR beendone,
                        ADDR szDisplayName,MB_OK
      strfree source$
      pop edi
      pop esi
      ret
  @@:

    invoke aP_max_packed_size,ln

    stralloc eax
    mov dest$, eax

    invoke aP_workmem_size,ln

    stralloc eax
    mov working$, eax

  ; ---------------------------------------
  ; compress source$ and write it to dest$
  ; ---------------------------------------

    mov Packing, 1
    mov ContPack, 1

    invoke aPsafe_pack,source$,dest$,ln,working$,ADDR cbProc,NULL
    mov clenth, eax

    .if eax == 0
      .data
        aborted db "Packing aborted",0
      .code
      invoke SendMessage,hStat1,WM_SETTEXT,0,ADDR aborted
      jmp Abort
    .endif

    .data
      Patn1     db "*.*",0,0
      SaveFile1 db "Save File As",0
    .code

    mov szFileName[0], 0
    invoke SaveFileName,hWnd,ADDR SaveFile1,ADDR Patn1

    .if szFileName[0] != 0
    ; -----------------------------------------
    ; truncate file to zero length if it exists
    ; -----------------------------------------
      invoke CreateFile,ADDR szFileName,  ; pointer to name of the file
              GENERIC_WRITE,              ; access (read-write) mode
              NULL,                       ; share mode
              NULL,                       ; pointer to security attributes
              CREATE_ALWAYS,              ; how to create
              FILE_ATTRIBUTE_NORMAL,      ; file attributes
              NULL
      mov hFile, eax

      invoke WriteFile,hFile,dest$,clenth,ADDR br,NULL
      invoke CloseHandle,hFile

    .endif

  Abort:

    strfree source$
    strfree dest$
    strfree working$

    mov Packing, 0

    pop edi
    pop esi

    ret

PackFile endp

; ########################################################################

UnpackFile proc

    LOCAL hFile          :DWORD
    LOCAL ln             :DWORD
    LOCAL br             :DWORD
    LOCAL dsize          :DWORD
    LOCAL source$        :DWORD
    LOCAL dest$          :DWORD
    LOCAL szNameFile[128]:BYTE

    push esi

    invoke GetWindowText,hEdit1,ADDR szNameFile,128

    cmp szNameFile[0], 0
    jne @F
    invoke MessageBox,hWnd,ADDR plSelect,
                      ADDR szDisplayName,MB_OK
    mov eax, 0
    pop esi
    ret
  @@:

    invoke CreateFile,ADDR szNameFile,
                      GENERIC_READ,
                      FILE_SHARE_READ,
                      NULL,OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL
    mov hFile, eax

    invoke GetFileSize,hFile,NULL
    mov ln, eax

    stralloc ln
    mov source$, eax

    invoke ReadFile,hFile,source$,ln,ADDR br,NULL

    invoke CloseHandle,hFile

    invoke aPsafe_get_orig_size,source$
    mov dsize, eax

    test eax,eax
    jnz @F
      .data
        noap db "This file has not been compressed by aPPack",0
      .code
      invoke MessageBox,hWnd,ADDR noap,
                        ADDR szDisplayName,MB_OK
      strfree source$
      pop esi
      ret
  @@:
    stralloc dsize
    mov dest$, eax

    invoke aPsafe_depack,source$,ln,dest$,dsize

    .data
      Patn2     db "*.*",0,0
      SaveFile2 db "Save File As",0
    .code

    mov szFileName[0], 0
    invoke SaveFileName,hWnd,ADDR SaveFile2,ADDR Patn2

    .if szFileName[0] != 0
    ; -----------------------------------------
    ; truncate file to zero length if it exists
    ; -----------------------------------------
      invoke CreateFile,ADDR szFileName,  ; pointer to name of the file
              GENERIC_WRITE,              ; access (read-write) mode
              NULL,                       ; share mode
              NULL,                       ; pointer to security attributes
              CREATE_ALWAYS,              ; how to create
              FILE_ATTRIBUTE_NORMAL,      ; file attributes
              NULL

      mov hFile, eax
      invoke WriteFile,hFile,dest$,dsize,ADDR br,NULL
      invoke CloseHandle,hFile
    .endif

    strfree source$
    strfree dest$

    pop esi

    ret

UnpackFile endp

; ########################################################################

cbProc proc C orglen:DWORD,len1:DWORD,len2:DWORD,cbparam:DWORD

  ; ------------------------------------------------------
  ; This is an application defined callback that receives
  ; 2 parameters from the "aP_pack" procedure during the
  ; compression process. Note the "C" calling convention.
  ; ------------------------------------------------------

    LOCAL buff[32]:BYTE
    LOCAL buf2[16]:BYTE

    invoke dwtoa,len1,ADDR buff
    invoke dwtoa,len2,ADDR buf2

    .data
      arrow db " => ",0
    .code

    invoke lstrcat,ADDR buff,ADDR arrow
    invoke lstrcat,ADDR buff,ADDR buf2

    invoke SendMessage,hStat1,WM_SETTEXT,0,ADDR buff

    mov eax, ContPack
    ret

cbProc endp

; ########################################################################

end start
