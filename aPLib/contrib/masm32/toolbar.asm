; ########################################################################

    Do_ToolBar  PROTO :DWORD
    SetBmpColor PROTO :DWORD

    include tbmacros.asm

    .data
        hTbBmp        dd 0
        hToolBar      dd 0

    .code

; ########################################################################

Do_ToolBar proc hWin :DWORD

    ; ---------------------------------------
    ; This proc works by using macros so that 
    ; the code is easier to read and modify
    ; ---------------------------------------

    LOCAL bSize :DWORD
    LOCAL tbab  :TBADDBITMAP
    LOCAL tbb   :TBBUTTON

    ; ------------------
    ; The toolbar bitmap
    ; ~~~~~~~~~~~~~~~~~~
    ; You must supply a bitmap for the toolbar that has the 
    ; correct number of the required images, each of the same
    ; size and in the following strip bitmap form.
    
    ;  -------------------------------------
    ;  |  1  |  2  |  3  |  4  |  5  |  6  |
    ;  -------------------------------------

    ; ------------------------
    ; Uncomment following when
    ; bitmap has been created
    ; ------------------------
    invoke LoadBitmap,hInstance,750
    mov hTbBmp,eax

    ; --------------------------------------------------
    ; Set toolbar button dimensions here, width & height
    ; --------------------------------------------------
    Create_Tool_Bar 75, 75

    TBextraData     ; additional data for TBBUTTON structure

    ; -----------------------------------
    ; Add toolbar buttons and spaces here
    ; Syntax for the macro TBbutton is
    ; TBbutton bmpID number, WM_COMMAND ID number
    ; WM_COMMAND ID numbers start at 50
    ; -----------------------------------
    TBbutton  0,  50
    TBbutton  1,  51
    TBbutton  2,  52
    TBbutton  3,  53

    ret

Do_ToolBar endp

; ########################################################################

SetBmpColor proc hBitmap:DWORD

    LOCAL mDC       :DWORD
    LOCAL hBrush    :DWORD
    LOCAL hOldBmp   :DWORD
    LOCAL hReturn   :DWORD
    LOCAL hOldBrush :DWORD

      invoke CreateCompatibleDC,NULL
      mov mDC,eax

      invoke SelectObject,mDC,hBitmap
      mov hOldBmp,eax

      invoke GetSysColor,COLOR_BTNFACE
      invoke CreateSolidBrush,eax
      mov hBrush,eax

      invoke SelectObject,mDC,hBrush
      mov hOldBrush,eax

      invoke GetPixel,mDC,1,1
      invoke ExtFloodFill,mDC,1,1,eax,FLOODFILLSURFACE

      invoke SelectObject,mDC,hOldBrush
      invoke DeleteObject,hBrush

      invoke SelectObject,mDC,hBitmap
      mov hReturn,eax
      invoke DeleteDC,mDC

      mov eax,hReturn

    ret

SetBmpColor endp

; #########################################################################
