      ; ---------------------------
      ; macros for creating toolbar
      ; ---------------------------

      TBextraData MACRO
        mov tbb.fsState,   TBSTATE_ENABLED
        mov tbb.dwData,    0
        mov tbb.iString,   0
      ENDM

      ; ------------------------------

      TBbutton MACRO bID, cID
        mov tbb.iBitmap,   bID  ;; button  ID number
        mov tbb.idCommand, cID  ;; command ID number
        mov tbb.fsStyle,   TBSTYLE_BUTTON
        invoke SendMessage,hToolBar,TB_ADDBUTTONS,1,ADDR tbb
      ENDM

      ; ------------------------------

      TBblank MACRO
        mov tbb.iBitmap,   0
        mov tbb.idCommand, 0
        mov tbb.fsStyle,   TBSTYLE_SEP
        invoke SendMessage,hToolBar,TB_ADDBUTTONS,1,ADDR tbb
      ENDM

      ; ------------------------------

      Create_Tool_Bar MACRO Wd, Ht

        szText tbClass,"ToolbarWindow32"

        invoke CreateWindowEx,0,
                              ADDR tbClass,
                              ADDR szDisplayName,
                              WS_CHILD or WS_VISIBLE or CCS_NODIVIDER or TBSTYLE_FLAT,
                              0,0,500,40,
                              hWin,NULL,
                              hInstance,NULL

                              ;; or TBSTYLE_FLAT

        mov hToolBar, eax
    
        invoke SendMessage,hToolBar,TB_BUTTONSTRUCTSIZE,sizeof TBBUTTON,0
    
        ;; ---------------------------------------
        ;; Put width & height of bitmap into DWORD
        ;; ---------------------------------------
        mov  ecx,Wd  ;; loword = bitmap Width
        mov  eax,Ht  ;; hiword = bitmap Height
        shl  eax,16
        mov  ax, cx

        mov bSize, eax
    
        invoke SendMessage,hToolBar,TB_SETBITMAPSIZE,0,bSize
    
        invoke SetBmpColor,hTbBmp
        mov hTbBmp,eax
    
        mov tbab.hInst, 0
        m2m tbab.nID,   hTbBmp
        invoke SendMessage,hToolBar,TB_ADDBITMAP,12,ADDR tbab
    
        invoke SendMessage,hToolBar,TB_SETBUTTONSIZE,0,bSize
      ENDM

