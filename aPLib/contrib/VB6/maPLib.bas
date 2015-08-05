Attribute VB_Name = "maPLib"
'---------------------------------------------------------------------------------------
' Name      : maPLib (Module)
'---------------------------------------------------------------------------------------
' Project   : aPLib Compression Library Visual Basic 6 Wrapper
' Author    : Jon Johnson
' Date      : 7/15/2005
' Email     : jjohnson@sherwoodpolice.org
' Version   : 1.0
' Purpose   : Wraps the functions in 'aplib.dll' for use in Visual Basic 6
' Notes     : The two functions (CompressFile, DecompressFile) have very limited error
'           : checking.  There is much room for improvement.
'---------------------------------------------------------------------------------------
Option Explicit

'---------------------------------------------------------------------------------------
' API Constants
'---------------------------------------------------------------------------------------
Const APLIB_ERROR = -1

'---------------------------------------------------------------------------------------
' API Compression Functions
'---------------------------------------------------------------------------------------
'---------------------------------------------------------------------------------------
' Declare   : aP_Pack
' Inputs    : source = Pointer to the data to be compressed.
'           : destination = Pointer to where the compressed data should be stored.
'           : length = The length of the uncompressed data in bytes.
'           : workmem = Pointer to the work memory which is used during compression.
'           : callback = Pointer to the callback function (or NULL).
'           : cbparam = Callback argument.
' Returns   : The length of the compressed data, or APLIB_ERROR on error.
' Purpose   : Compresses 'length' bytes of data from 'source()' into 'destination()',
'           : using 'workmem()' for temporary storage.
'---------------------------------------------------------------------------------------
Public Declare Function aP_Pack Lib "aplib.dll" Alias "_aP_pack" (source As Byte, destination As Byte, ByVal length As Long, workmem As Byte, Optional ByVal callback As Long = &H0, Optional ByVal cbparam As Long = &H0) As Long
'---------------------------------------------------------------------------------------
' Declare   : aP_workmem_size
' Inputs    : input_size = The length of the uncompressed data in bytes.
' Returns   : The required length of the work buffer.
' Purpose   : Computes the required size of the 'workmem()' buffer used by 'aP_pack' for
'           : compressing 'input_size' bytes of data.
'---------------------------------------------------------------------------------------
Public Declare Function aP_workmem_size Lib "aplib.dll" Alias "_aP_workmem_size" (ByVal input_size As Long) As Long
'---------------------------------------------------------------------------------------
' Declare   : aP_max_packed_size
' Inputs    : input_size = The length of the uncompressed data in bytes.
' Returns   : The maximum possible size of the compressed data.
' Purpose   : Computes the maximum possible compressed size possible when compressing
'           : 'input_size' bytes of incompressible data.
'---------------------------------------------------------------------------------------
Public Declare Function aP_max_packed_size Lib "aplib.dll" Alias "_aP_max_packed_size" (ByVal input_size As Long) As Long
'---------------------------------------------------------------------------------------
' Declare   : aPsafe_pack
' Inputs    : source = Pointer to the data to be compressed.
'           : destination = Pointer to where the compressed data should be stored.
'           : length = The length of the uncompressed data in bytes.
'           : workmem = Pointer to the work memory which is used during compression.
'           : callback = Pointer to the callback function (or NULL).
'           : cbparam = Callback argument.
' Returns   : The length of the compressed data, or APLIB_ERROR on error.
' Purpose   : Wrapper function for 'aP_pack', which adds a header to the compressed data
'           : containing the length of the original data, and CRC32 checksums of the
'           : original and compressed data.
'---------------------------------------------------------------------------------------
Public Declare Function aPsafe_pack Lib "aplib.dll" Alias "_aPsafe_pack" (source As Byte, destination As Byte, ByVal length As Long, workmem As Byte, Optional ByVal callback As Long = &H0, Optional ByVal cbparam As Long = &H0) As Long


'---------------------------------------------------------------------------------------
' API Decompression Functions
'---------------------------------------------------------------------------------------
'---------------------------------------------------------------------------------------
' Declare   : aP_depack
' Inputs    : source = Pointer to the compressed data.
'           : destination = Pointer to where the decompressed data should be stored.
' Returns   : The length of the decompressed data, or APLIB_ERROR on error.
' Purpose   : Decompresses the compressed data from 'source()' into 'destination()'.
'---------------------------------------------------------------------------------------
Public Declare Function aP_depack Lib "aplib.dll" Alias "_aP_depack_asm_fast" (source As Byte, destination As Byte) As Long
'---------------------------------------------------------------------------------------
' Declare   : aP_depack_safe
' Inputs    : source = Pointer to the compressed data.
'           : srclen = The size of the source buffer in bytes.
'           : destination = Pointer to where the decompressed data should be stored.
'           : dstlen = The size of the destination buffer in bytes.
' Returns   : The length of the decompressed data, or APLIB_ERROR on error.
' Purpose   : Decompresses the compressed data from 'source()' into 'destination()'.
'---------------------------------------------------------------------------------------
Public Declare Function aP_depack_safe Lib "aplib.dll" Alias "_aP_depack_asm_safe" (source As Byte, ByVal srclen As Long, destination As Byte, ByVal dstlen As Long) As Long
'---------------------------------------------------------------------------------------
' Declare   : aP_depack_asm
' Inputs    : source = Pointer to the compressed data.
'           : destination = Pointer to where the decompressed data should be stored.
' Returns   : The length of the decompressed data, or APLIB_ERROR on error.
' Purpose   : Decompresses the compressed data from 'source()' into 'destination()'.
'---------------------------------------------------------------------------------------
Public Declare Function aP_depack_asm Lib "aplib.dll" Alias "_aP_depack_asm" (source As Byte, destination As Byte) As Long
'---------------------------------------------------------------------------------------
' Declare   : aP_depack_asm_fast
' Inputs    : source = Pointer to the compressed data.
'           : destination = Pointer to where the decompressed data should be stored.
' Returns   : The length of the decompressed data, or APLIB_ERROR on error.
' Purpose   : Decompresses the compressed data from 'source()' into 'destination()'.
'---------------------------------------------------------------------------------------
Public Declare Function aP_depack_asm_fast Lib "aplib.dll" Alias "_aP_depack_asm_fast" (source As Byte, destination As Byte) As Long
'---------------------------------------------------------------------------------------
' Declare   : aP_depack_asm_safe
' Inputs    : source = Pointer to the compressed data.
'           : srclen = The size of the source buffer in bytes.
'           : destination = Pointer to where the decompressed data should be stored.
'           : dstlen = The size of the destination buffer in bytes.
' Returns   : The length of the decompressed data, or APLIB_ERROR on error.
' Purpose   : Decompresses the compressed data from 'source()' into 'destination()'.
'---------------------------------------------------------------------------------------
Public Declare Function aP_depack_asm_safe Lib "aplib.dll" Alias "_aP_depack_asm_safe" (source As Byte, ByVal srclen As Long, destination As Byte, ByVal dstlen As Long) As Long
'---------------------------------------------------------------------------------------
' Declare   : aP_crc32
' Inputs    : source = Pointer to the data to process.
'           : length = The size in bytes of the data.
' Returns   : The CRC32 value.
' Purpose   : Computes the CRC32 value of 'length' bytes of data from 'source()'.
'---------------------------------------------------------------------------------------
Public Declare Function aP_crc32 Lib "aplib.dll" Alias "_aP_crc32" (source As Byte, ByVal length As Long) As Long
'---------------------------------------------------------------------------------------
' Declare   : aPsafe_check
' Inputs    : source = The compressed data to process.
' Returns   : The length of the decompressed data, or APLIB_ERROR on error.
' Purpose   : Computes the CRC32 of the compressed data in 'source()' and checks it
'           : against the value in the header.  Returns the length of the decompressed
'           : data stored in the header.
'---------------------------------------------------------------------------------------
Public Declare Function aPsafe_check Lib "aplib.dll" Alias "_aPsafe_check" (source As Byte) As Long
'---------------------------------------------------------------------------------------
' Declare   : aPsafe_get_orig_size
' Inputs    : source = The compressed data to process.
' Returns   : The length of the decompressed data, or APLIB_ERROR on error.
' Purpose   : Returns the length of the decompressed data stored in the header of the
'           : compressed data in 'source()'.
'---------------------------------------------------------------------------------------
Public Declare Function aPsafe_get_orig_size Lib "aplib.dll" Alias "_aPsafe_get_orig_size" (source As Byte) As Long
'---------------------------------------------------------------------------------------
' Declare   : aPsafe_depack
' Inputs    : source = Pointer to the compressed data.
'           : srclen = The size of the source buffer in bytes.
'           : destination = Pointer to where the decompressed data should be stored.
'           : dstlen = The size of the destination buffer in bytes.
' Returns   : The length of the decompressed data, or APLIB_ERROR on error.
' Purpose   : Wrapper function for 'aP_depack_asm_safe', which checks the CRC32 of the
'           : compressed data, decompresses, and checks the CRC32 of the decompressed
'           : data.
'---------------------------------------------------------------------------------------
Public Declare Function aPsafe_depack Lib "aplib.dll" Alias "_aPsafe_depack" (source As Byte, ByVal srclen As Long, destination As Byte, ByVal dstlen As Long) As Long

'---------------------------------------------------------------------------------------
' Procedure : CompressFile
' Returns   : Boolean (True if succesful, False if not)
' DateTime  : 7/15/2005
' Author    : Jon Johnson <jjohnson@sherwoodpolice.org>
' Purpose   : Example of using aPLib to compress a file
'---------------------------------------------------------------------------------------
Public Function CompressFile(sInFile As String, Optional sOutFile As String) As Boolean
    Dim lCompressedSize As Long     'Length of compressed data
    Dim bInBuffer() As Byte         'Input buffer
    Dim bOutBuffer() As Byte        'Output buffer
    Dim bWorkBuffer() As Byte       'Work buffer
    Dim iFileO As Integer           'File I/O
    
    'If no input file specified, return False and exit
    If sInFile = "" Then
        CompressFile = False
        Exit Function
    End If
    'If no output file specified, create one using the .ap file extension
    If sOutFile = "" Then
        sOutFile = FileParsePath(sInFile, False, False) & FileParsePath(sInFile, True, False) & ".ap"
    End If
    'Move the data to compress into a buffer
    iFileO = FreeFile
    Open sInFile For Binary As #iFileO
        ReDim bInBuffer(0 To LOF(iFileO) - 1)
        Get #iFileO, , bInBuffer()
    Close #iFileO
    'Compute the size of the work buffer
    ReDim bWorkBuffer(0 To aP_workmem_size(UBound(bInBuffer) + 1))
    'Compute the size of the output buffer
    ReDim bOutBuffer(0 To aP_max_packed_size(UBound(bInBuffer) + 1))
    'Compress the data using the 'safe' pack method
    lCompressedSize = aPsafe_pack(bInBuffer(0), bOutBuffer(0), (UBound(bInBuffer) + 1), bWorkBuffer(0))
    'If an error encountered in compressing, then return False and exit
    If lCompressedSize = APLIB_ERROR Then
        CompressFile = False
        Exit Function
    End If
    'Resize the output buffer to the proper size
    'The rtlMoveMemory API could also be used here
    ReDim Preserve bOutBuffer(0 To (lCompressedSize - 1))
    'Put the compressed data into the output file
    If (FileExist(sOutFile)) Then Kill sOutFile
    iFileO = FreeFile
    Open sOutFile For Binary As #iFileO
        Put #iFileO, , bOutBuffer()
    Close #iFileO
    'Everything went OK, return True
    CompressFile = True
End Function

'---------------------------------------------------------------------------------------
' Procedure : DecompressFile
' Returns   : Boolean (True if succesful, False if not)
' DateTime  : 7/15/2005
' Author    : Jon Johnson <jjohnson@sherwoodpolice.org>
' Purpose   : Example of using aPLib to decompress a file
'---------------------------------------------------------------------------------------
Public Function DecompressFile(sInFile As String, Optional sOutFile As String) As Boolean
    Dim lDecompressedSize As Long       'Length of decompressed data
    Dim bInBuffer() As Byte             'Input buffer
    Dim lInBufferLen As Long            'Input buffer size
    Dim bOutBuffer() As Byte            'Output buffer
    Dim lOutBufferLen As Long           'Output buffer size
    Dim iFileO As Integer               'File I/O
    
    'If no input file specified, return False and exit
    If sInFile = "" Then
        DecompressFile = False
        Exit Function
    End If
    'If no output file specified, create one using the .dec file extension
    If sOutFile = "" Then
        sOutFile = FileParsePath(sInFile, False, False) & FileParsePath(sInFile, True, False) & ".dec"
    End If
    'Move the data to decompress into a buffer
    iFileO = FreeFile
    Open sInFile For Binary As #iFileO
        ReDim bInBuffer(0 To LOF(iFileO) - 1)
        Get #iFileO, , bInBuffer()
    Close #iFileO
    'Compute the sizes of the buffers
    lInBufferLen = (UBound(bInBuffer) + 1)
    lOutBufferLen = aPsafe_get_orig_size(bInBuffer(0))
    'Set the output buffer to the proper size
    ReDim bOutBuffer(0 To (lOutBufferLen - 1))
    'Decompress the data using the 'safe' depack method
    lDecompressedSize = aPsafe_depack(bInBuffer(0), lInBufferLen, bOutBuffer(0), lOutBufferLen)
    'If an error encountered in decompressing, then return False and exit
    If lDecompressedSize = APLIB_ERROR Then
        DecompressFile = False
        Exit Function
    End If
    'Put the decompressed data into the output file
    If (FileExist(sOutFile)) Then Kill sOutFile
    iFileO = FreeFile
    Open sOutFile For Binary As #iFileO
        Put #iFileO, , bOutBuffer()
    Close #iFileO
    'Everything went OK, return True
    DecompressFile = True
End Function

'---------------------------------------------------------------------------------------
' Utility Functions
'---------------------------------------------------------------------------------------
Private Function FileParsePath(sPathname As String, bRetFile As Boolean, bExtension As Boolean) As String
    Dim sEditArray() As String
    sEditArray = Split(sPathname, "\", -1)
    If bRetFile = True Then
        Dim sFileName As String
        sFileName = sEditArray(UBound(sEditArray))
        If bExtension = True Then
            FileParsePath = sFileName
        Else
            sEditArray = Split(sFileName, ".", -1)
            FileParsePath = sEditArray(LBound(sEditArray))
        End If
    Else
        Dim sPathnameA As String
        Dim i As Integer
        For i = 0 To UBound(sEditArray) - 1
            sPathnameA = sPathnameA & sEditArray(i) & "\"
        Next
        FileParsePath = sPathnameA
    End If
    On Error GoTo 0
End Function

Private Function FileExist(sFilePath As String) As Boolean
    On Error GoTo ErrorHandler
    Call FileLen(sFilePath)
    FileExist = True
    Exit Function
ErrorHandler:
    FileExist = False
End Function
