; ########################################################################

    PushButton PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
    EditSl     PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
    Static     PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

    .data
      btnClass  db "BUTTON",0
      EditClass db "EDIT",0
      statClass db "STATIC",0

    .code

; ########################################################################

PushButton proc lpText:DWORD,hParent:DWORD,
                a:DWORD,b:DWORD,wd:DWORD,ht:DWORD,ID:DWORD

; invoke PushButton,ADDR szText,hWnd,20,20,100,25,500

    invoke CreateWindowEx,0,
            ADDR btnClass,lpText,
            WS_CHILD or WS_VISIBLE,
            a,b,wd,ht,hParent,ID,
            hInstance,NULL

    ret

PushButton endp

; #########################################################################

EditSl proc szMsg:DWORD,a:DWORD,b:DWORD,
               wd:DWORD,ht:DWORD,hParent:DWORD,ID:DWORD

; invoke EditSl,ADDR adrTxt,200,10,150,25,hWnd,700


    invoke CreateWindowEx,WS_EX_CLIENTEDGE,ADDR EditClass,szMsg,
                WS_VISIBLE or WS_CHILDWINDOW or \
                ES_AUTOHSCROLL or ES_NOHIDESEL,
              a,b,wd,ht,hParent,ID,hInstance,NULL

    ret

EditSl endp

; ########################################################################

Static proc lpText:DWORD,hParent:DWORD,
                 a:DWORD,b:DWORD,wd:DWORD,ht:DWORD,ID:DWORD

; invoke Static,ADDR szText,hWnd,20,20,100,25,500

    invoke CreateWindowEx,WS_EX_STATICEDGE,
            ADDR statClass,lpText,
            WS_CHILD or WS_VISIBLE or SS_CENTER,
            a,b,wd,ht,hParent,ID,
            hInstance,NULL

    ret

Static endp

; ########################################################################

