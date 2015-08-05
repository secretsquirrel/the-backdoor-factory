; ########################################################################

    GetFileName  PROTO :DWORD, :DWORD, :DWORD
    SaveFileName PROTO :DWORD, :DWORD, :DWORD
    FillBuffer   PROTO :DWORD, :DWORD, :BYTE

    .data
      szFileName    db 260 dup(0)
      ofn           OPENFILENAME <>  ; structure

    .code

; ########################################################################

GetFileName proc hParent:DWORD,lpTitle:DWORD,lpFilter:DWORD

    mov ofn.lStructSize,        sizeof OPENFILENAME
    m2m ofn.hWndOwner,          hParent
    m2m ofn.hInstance,          hInstance
    m2m ofn.lpstrFilter,        lpFilter
    m2m ofn.lpstrFile,          offset szFileName
    mov ofn.nMaxFile,           sizeof szFileName
    m2m ofn.lpstrTitle,         lpTitle
    mov ofn.Flags,              OFN_EXPLORER or OFN_FILEMUSTEXIST or \
                                OFN_LONGNAMES

    invoke GetOpenFileName,ADDR ofn

    ret

GetFileName endp

; #########################################################################

SaveFileName proc hParent:DWORD,lpTitle:DWORD,lpFilter:DWORD

    mov ofn.lStructSize,        sizeof OPENFILENAME
    m2m ofn.hWndOwner,          hParent
    m2m ofn.hInstance,          hInstance
    m2m ofn.lpstrFilter,        lpFilter
    m2m ofn.lpstrFile,          offset szFileName
    mov ofn.nMaxFile,           sizeof szFileName
    m2m ofn.lpstrTitle,         lpTitle
    mov ofn.Flags,              OFN_EXPLORER or OFN_LONGNAMES or OFN_OVERWRITEPROMPT
                                
    invoke GetSaveFileName,ADDR ofn

    ret

SaveFileName endp

; ########################################################################
