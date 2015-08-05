; #########################################################################

;     include files
;     ~~~~~~~~~~~~~
      include \MASM32\INCLUDE\windows.inc
      include \MASM32\INCLUDE\masm32.inc
      include \MASM32\INCLUDE\gdi32.inc
      include \MASM32\INCLUDE\user32.inc
      include \MASM32\INCLUDE\kernel32.inc
      include \MASM32\INCLUDE\Comctl32.inc
      include \MASM32\INCLUDE\comdlg32.inc
      include \MASM32\INCLUDE\shell32.inc
      include \MASM32\include\oleaut32.inc
      include aplib.inc

;     libraries
;     ~~~~~~~~~
      includelib \MASM32\LIB\masm32.lib

      includelib \MASM32\LIB\gdi32.lib
      includelib \MASM32\LIB\user32.lib
      includelib \MASM32\LIB\kernel32.lib
      includelib \MASM32\LIB\Comctl32.lib
      includelib \MASM32\LIB\comdlg32.lib
      includelib \MASM32\LIB\shell32.lib
      includelib \MASM32\LIB\oleaut32.lib
      includelib ..\..\lib\coff\aplib.lib

; #########################################################################

        ;=================
        ; Local prototypes
        ;=================
        WinMain PROTO :DWORD,:DWORD,:DWORD,:DWORD
        WndProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
        TopXY PROTO   :DWORD,:DWORD
        Paint_Proc   PROTO :DWORD,:DWORD
        PackFile     PROTO :DWORD
        UnpackFile   PROTO
        cbProc PROTO C :DWORD,:DWORD,:DWORD,:DWORD

        wsprintfA PROTO C :DWORD,:VARARG
        wsprintf equ <wsprintfA>

      ;=============
      ; Local macros
      ;=============

      szText MACRO Name, Text:VARARG
        LOCAL lbl
          jmp lbl
            Name db Text,0
          lbl:
        ENDM

      m2m MACRO M1, M2
        push M2
        pop  M1
      ENDM

      return MACRO arg
        mov eax, arg
        ret
      ENDM

      stralloc MACRO ln
        invoke SysAllocStringByteLen,0,ln
      ENDM

      strfree MACRO strhandle
        invoke SysFreeString,strhandle
      ENDM

    .data
        CommandLine   dd 0
        hWnd          dd 0
        hInstance     dd 0
        hIcon         dd 0
        hEdit1        dd 0
        hButn1        dd 0
        hButn2        dd 0
        hStat1        dd 0
        Packing       dd 0
        ContPack      dd 1
        killFlag      dd 0
        szDisplayName db "aPLib Pack",0
        plSelect      db "Please Select File First",0

; ########################### Inserted modules ############################

    include toolbar.asm
    include filedlgs.asm
    include ctrls.asm

; #########################################################################
