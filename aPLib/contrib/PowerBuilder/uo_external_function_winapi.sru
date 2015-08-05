$PBExportHeader$uo_external_function_winapi.sru
$PBExportComments$Window api external functions
forward
global type uo_external_function_winapi from uo_external_function
end type
type str_memorystatus from structure within uo_external_function_winapi
end type
end forward

type str_memorystatus from structure
	unsignedlong		sul_dwlength
	unsignedlong		sul_dwmemoryload
	unsignedlong		sul_dwtotalphys
	unsignedlong		sul_dwavailphys
	unsignedlong		sul_dwtotalpagefile
	unsignedlong		sul_dwavailpagefile
	unsignedlong		sul_dwtotalvirtual
	unsignedlong		sul_dwavailvirtual
end type

global type uo_external_function_winapi from uo_external_function
end type
global uo_external_function_winapi uo_external_function_winapi

type prototypes
//playsound
Function boolean sndPlaySoundA (string SoundName, uint Flags) Library "WINMM.DLL"
Function uint waveOutGetNumDevs () Library "WINMM.DLL"

//getsyscolor
Function ulong GetSysColor (int index) Library "USER32.DLL"

//getsystemmetrics
Function int GetSystemMetrics (int index) Library "USER32.DLL"

//getfreememory
Subroutine GlobalMemoryStatus (ref str_memorystatus memorystatus ) Library "KERNEL32.DLL"

//set and kill timer
Function Boolean KillTimer (long handle, uint id ) library "USER32.DLL"
Function uint SetTimer (long handle, uint id, uint time, long addr ) library "USER32.DLL"

//GetModuleHandle
Function long GetModuleHandleA(string modname) Library "KERNEL32.DLL"
Function ulong FindWindowA (ulong classname, string windowname) Library "USER32.DLL"
Function integer FindExecutable ( string FileName, &
      REF string Directory, REF string Result ) Library "shellapi32"

Function boolean FlashWindow (long handle, boolean flash) Library "USER32.DLL"
Function uint GetWindow (long handle,uint relationship) Library "USER32.DLL"
Function int GetWindowTextA(long handle, ref string wintext, int length) Library "USER32.DLL"
Function int GetWindowTextLengthA(long handle) Library "USER32.DLL"
Function boolean IsWindowVisible (long handle) Library "USER32.DLL"
Function uint GetWindowsDirectoryA (ref string dirtext, uint textlen) library "KERNEL32.DLL"
Function uint GetSystemDirectoryA (ref string dirtext, uint textlen) library "KERNEL32.DLL"
Function uint GetDriveTypeA (string drive) library "KERNEL32.DLL"
Function ulong GetCurrentDirectoryA (ulong textlen, ref string dirtext) library "KERNEL32.DLL"
Function boolean SetFileAttributesA(ref string lpfilename, ulong dwFileAttributes) library "KERNEL32.DLL"

// Close application
Function boolean DestroyWindow(ulong handle) Library "USER32.DLL"

Function boolean GetUserNameA (ref string name, ref ulong len) library "ADVAPI32.DLL"
Function ulong GetTickCount ( ) Library "KERNEL32.DLL"
Function Long LZCopy (Uint hfSourcet, Uint hfDes  ) library "user32.exe"
function uint OpenFile(String lpszFileName, str_ofstruct lpOpenBuff, Uint fuMode) library "kernel32.DLL"
FUNCTION boolean SetCurrentDirectoryA(ref string cdir) LIBRARY "kernel32.dll"
FUNCTION Long WNetAddConnection2A(ref str_netresource lpNetResource, ref string lpPassword, &
			ref string lpUsername, Long dwFlags) LIBRARY "mpr.dll"
FUNCTION ULong WNetCancelConnectionA(string lpName,  BOOLEAN fForce) LIBRARY "mpr.dll"
FUNCTION ULong WNetGetLastErrorA(REF ULong lpError, Ref String lpErrorBuf, Ulong nErrorBufSize, &
			Ref string lpNameBuf, ULONG nNameBufSize) LIBRARY "mpr.dll"
Function Boolean CloseHandle(ULong hObject)  library "kernel32.DLL"
Function ULong CreateFileA(Ref String lpFileName, ULong dwDesiredAccess, ULong dwShareMode, &
			str_security_attibutes lpSecurityAttributes,  ULong dwCreationDisposition, &
			ULong dwFlagsAndAttributes, ULong hTemplateFile) library "kernel32.DLL"
Function Boolean WriteFile(UnsignedLong hFile, Ref String lpBuffer, ULong nNumberOfBytesToWrite, &
		  Ref ULong lpNumberOfBytesWritten, Ref str_overlapped lpOverlapped) library "kernel32.DLL"
Function Boolean ReadFile(UnsignedLong hFile, Ref String lpBuffer, ULong nNumberOfBytesToRead, &
		  Ref ULong lpNumberOfBytesRead,  Ref str_overlapped lpOverlapped) library "kernel32.DLL"

Function String GetLastError() library "kernel32.DLL"
								
	
end prototypes

type variables
str_ofstruct istr_ofstruct
end variables

forward prototypes
public function integer uf_playsound (string as_filename, integer ai_option)
public function unsignedlong uf_getsyscolor (integer ai_index)
public function int uf_getscreenwidth ()
public function int uf_getscreenheight ()
public function unsignedinteger uf_getsystemdirectory (ref string as_dir, unsignedinteger aui_size)
public function unsignedinteger uf_getwindowsdirectory (ref string as_dir, unsignedinteger aui_size)
public function ulong uf_get_logon_time ()
public function boolean uf_killtimer (long aui_handle, unsignedinteger aui_id)
public function unsignedinteger uf_settimer (long aui_handle, unsignedinteger aui_id, unsignedinteger aui_time)
public function boolean uf_flash_window (long aui_handle, boolean ab_flash)
public function unsignedinteger uf_getwindow (long aui_handle, unsignedinteger aui_relationship)
public function boolean uf_iswindowvisible (long aui_handle)
public function unsignedinteger uf_openfile (string as_filename, ref str_ofstruct astr_ptr_str, unsignedinteger aui_fileaccess)
public function unsignedinteger uf_getdrivetype (string as_drive)
public function integer uf_get_logon_name (ref string as_name)
public function long uf_getmodulehandle (string as_modname)
public function unsignedlong uf_getfreememory (long ai_type)
public function boolean uf_destroywindow (unsignedlong aul_whnd)
public function integer uf_findexecutable (ref string as_filename, ref string as_directory, ref string as_executable)
public function unsignedlong uf_findwindow (unsignedlong aul_classname, string as_windowname)
public function integer uf_getwindowtext (long aui_handle, ref string as_text, integer ai_max)
public function long uf_copyfile (unsignedinteger aui_sourcehandle, unsignedinteger aui_desthandle)
public function integer uf_getwindowtextlength (unsignedlong aul_hwnd)
public function integer uf_getsystemmetrics (integer ai_index)
public function integer uf_setcurrentdirectory ()
public function integer uf_netaddconnection2 (ref string as_drive, string as_path)
public function integer uf_cancelconnection (string as_drive)
public function integer uf_setfileattributes (ref string as_filename, unsignedlong aul_attribute)
public function unsignedinteger uf_create_file (string as_filename, unsignedlong aul_desiredaccess, unsignedlong aul_sharemode, unsignedlong aul_creationdisposition, unsignedlong ul_flagsandattributes)
public function boolean uf_close_file (unsignedinteger aui_file_handle)
public function integer uf_netgetlasterror ()
public function string uf_getlasterror ()
public function boolean uf_write_file (long al_file_handle, ref string as_buffer, unsignedlong aul_byte_to_write)
public function boolean uf_read_file (long al_file_handle, ref string as_buffer, ref unsignedlong aul_bytes_to_read, ref unsignedlong aul_bytes_read)
end prototypes

public function integer uf_playsound (string as_filename, integer ai_option);//Options as defined in mmystem.h These may be or'd together.

//#define SND_SYNC            0x0000  /* play synchronously (default) */
//#define SND_ASYNC           0x0001  /* play asynchronously */
//#define SND_NODEFAULT       0x0002  /* don't use default sound */
//#define SND_MEMORY          0x0004  /* lpszSoundName points to a memory file */
//#define SND_LOOP            0x0008  /* loop the sound until next sndPlaySound */
//#define SND_NOSTOP          0x0010  /* don't stop any currently playing sound */    

uint lui_numdevs


lui_numdevs = WaveOutGetNumDevs() 
If lui_numdevs > 0 Then 
	sndPlaySoundA(as_filename,ai_option)
	return 1
Else
	return -1
End If
end function

public function unsignedlong uf_getsyscolor (integer ai_index);//GetsysColor in win32
Return GetSysColor (ai_index)
end function

public function int uf_getscreenwidth ();Return GetSystemMetrics(0)
end function

public function int uf_getscreenheight ();return getSystemMetrics(1)
end function

public function unsignedinteger uf_getsystemdirectory (ref string as_dir, unsignedinteger aui_size);Return GetSystemDirectoryA(as_dir,aui_size)
end function

public function unsignedinteger uf_getwindowsdirectory (ref string as_dir, unsignedinteger aui_size);Return GetWindowsDirectoryA(as_dir,aui_size)
end function

public function ulong uf_get_logon_time ();//user gettickcount to find total logon time
Return GetTickCount()

end function

public function boolean uf_killtimer (long aui_handle, unsignedinteger aui_id);//win api call to kill timer
Return KillTimer(aui_handle,aui_id)
end function

public function unsignedinteger uf_settimer (long aui_handle, unsignedinteger aui_id, unsignedinteger aui_time);//win api to create timer
Return(SetTimer(aui_handle,aui_id,aui_time,0))
end function

public function boolean uf_flash_window (long aui_handle, boolean ab_flash);//function not found in descendent
Return FlashWindow(aui_handle, ab_flash)
end function

public function unsignedinteger uf_getwindow (long aui_handle, unsignedinteger aui_relationship);//function not found
Return GetWindow(aui_handle,aui_relationship)
end function

public function boolean uf_iswindowvisible (long aui_handle);Return IsWindowVisible(aui_handle)
end function

public function unsignedinteger uf_openfile (string as_filename, ref str_ofstruct astr_ptr_str, unsignedinteger aui_fileaccess);Return OpenFile(as_filename, astr_ptr_str, aui_fileaccess)
end function

public function unsignedinteger uf_getdrivetype (string as_drive);//drive types
Return GetDriveTypeA(as_drive)
end function

public function integer uf_get_logon_name (ref string as_name);//use windows function wnetgetuser

ulong lul_value
Boolean lb_rc
string ls_temp

lul_value =255
ls_temp = space(255)

lb_rc = GetUserNameA(ls_temp, lul_value)

If lb_rc Then
	as_name = ls_temp
	Return 1
Else
	Return -1
End If



end function

public function long uf_getmodulehandle (string as_modname);
//use sdk getmodule handle
Long ll_return
ll_return = GetModuleHandleA (as_modname)
Return ll_return
end function

public function unsignedlong uf_getfreememory (long ai_type);//win api to get free memory
str_memorystatus lstr_memorystatus

lstr_memorystatus.sul_dwlength = 32

GlobalMemoryStatus(lstr_memorystatus)

If ai_type = 1 Then
	Return(lstr_memorystatus.sul_dwmemoryload)
ElseIf ai_type = 2 Then
	Return(lstr_memorystatus.sul_dwavailphys)	
ElseIf ai_type = 3 Then
	Return(lstr_memorystatus.sul_dwavailvirtual)	
End If
end function

public function boolean uf_destroywindow (unsignedlong aul_whnd);
Return DestroyWindow(aul_whnd)
end function

public function integer uf_findexecutable (ref string as_filename, ref string as_directory, ref string as_executable);Return FindExecutable ( as_filename, as_directory, as_executable )
end function

public function unsignedlong uf_findwindow (unsignedlong aul_classname, string as_windowname);//use win 32 getmodulehandle function
Return FindWindowA(aul_classname,as_windowname)
end function

public function integer uf_getwindowtext (long aui_handle, ref string as_text, integer ai_max);//function not found
Return GetWindowTextA (aui_handle,as_text,ai_max)
end function

public function long uf_copyfile (unsignedinteger aui_sourcehandle, unsignedinteger aui_desthandle);Return LZCopy(aui_sourcehandle, aui_desthandle)


end function

public function integer uf_getwindowtextlength (unsignedlong aul_hwnd);
Return GetWindowTextLengthA(aul_hwnd) + 1
end function

public function integer uf_getsystemmetrics (integer ai_index);Return GetSystemMetrics(ai_index)
end function

public function integer uf_setcurrentdirectory ();boolean rtn 
string ls_dir


ls_dir = "c:\ems" 
rtn = SetCurrentDirectoryA(ls_dir) 
//MessageBox("SetCurrentDirectory", string(rtn))

if rtn then
	return 1
else
	return -1
end if

end function

public function integer uf_netaddconnection2 (ref string as_drive, string as_path);Ulong		lul_value
Long 		ll_flags
Long 		ll_return
String 	ls_password
String 	ls_username

str_netresource lstr_netresource
	
lstr_netresource.dwScope       = 2
lstr_netresource.dwType        = 1
lstr_netresource.dwDisplayType = 3
lstr_netresource.dwUsage       = 1
lstr_netresource.lpLocalName   = as_drive
lstr_netresource.lpRemoteName  = as_path

lul_value = 255
ls_username = space(lul_value)

GetUserNameA(ls_username, lul_value)

SetNull(ls_password)

ll_return = WNetAddConnection2A(lstr_netresource, ls_password, ls_username, ll_flags)

Return ll_return
end function

public function integer uf_cancelconnection (string as_drive);

Long 		ll_return

ll_return = WNetCancelConnectionA(as_drive,  TRUE)
Return ll_return
end function

public function integer uf_setfileattributes (ref string as_filename, unsignedlong aul_attribute);// Change file attributes  
// aul_attribute values:
// 	FILE_ATTRIBUTE_ARCHIVE => 0x20 => 32,
//  	FILE_ATTRIBUTE_ATOMIC_WRITE => 0x200 => 512,
//		FILE_ATTRIBUTE_COMPRESSED => 0x800 => 2048,
//		FILE_ATTRIBUTE_DIRECTORY => 0x10 => 16,
//		FILE_ATTRIBUTE_HIDDEN => 0x2 => 2,
//		FILE_ATTRIBUTE_NORMAL => 0x80 => 128,
//		FILE_ATTRIBUTE_READONLY => 0x1 => 1,
//		FILE_ATTRIBUTE_SYSTEM => 0x4 => 4,
//		FILE_ATTRIBUTE_TEMPORARY => 0x100 => 256,
//		FILE_FLAG_BACKUP_SEMANTICS => 0x2000000 => 33554432,
//		FILE_FLAG_DELETE_ON_CLOSE => 0x4000000 => 67108864, 
//		FILE_FLAG_NO_BUFFERING => 0x20000000 => 536870912,
//		FILE_FLAG_OVERLAPPED => 0x40000000 => 1073741824,
//		FILE_FLAG_POSIX_SEMANTICS => 0x1000000 => 16777216,
//		FILE_FLAG_RANDOM_ACCESS => 0x10000000 => 268435456,
//		FILE_FLAG_SEQUENTIAL_SCAN => 0x8000000 => 134217728,
//		FILE_FLAG_WRITE_THROUGH => 0x80000000 => 2147483648
//
// (Note:  FILE_ATTRIBUTE_NORMAL - The file has no other attributes
// This value is valid only if used alone.)

boolean ib_rtn

ib_rtn = SetFileAttributesA(as_filename, aul_attribute)

if ib_rtn then
	return 1
else
	return -1
end if
end function

public function unsignedinteger uf_create_file (string as_filename, unsignedlong aul_desiredaccess, unsignedlong aul_sharemode, unsignedlong aul_creationdisposition, unsignedlong ul_flagsandattributes);
// Values for aul_DesiredAccess
//
// FILE_LIST_DIRECTORY               0x00000001
// FILE_READ_DATA                    0x00000001
// FILE_ADD_FILE                     0x00000002
// FILE_WRITE_DATA                   0x00000002
// FILE_ADD_SUBDIRECTORY             0x00000004
// FILE_APPEND_DATA                  0x00000004
// FILE_CREATE_PIPE_INSTANCE         0x00000004
// FILE_READ_EA                      0x00000008
// FILE_WRITE_EA                     0x00000010
// FILE_EXECUTE                      0x00000020
// FILE_TRAVERSE                     0x00000020
// FILE_DELETE_CHILD                 0x00000040
// FILE_READ_ATTRIBUTES              0x00000080
// FILE_WRITE_ATTRIBUTES             0x00000100

// Values for aul_ShareMode
//
// FILE_SHARE_READ                   0x00000001
// FILE_SHARE_WRITE                  0x00000002
// FILE_SHARE_DELETE                 0x00000004
// FILE_SHARE_VALID_FLAGS            0x00000007

// Values for aul_CreationDisposition
//
// CREATE_NEW		   					0x00000001
// CREATE_ALWAYS							0x00000002
// OPEN_EXISTING							0x00000003
// OPEN_ALWAYS		   					0x00000004
// TRUNCATE_EXISTING						0x00000005

// Values for aul_FlagsAndAttributes
//
// FILE_ATTRIBUTE_READONLY					0x00000001
// FILE_ATTRIBUTE_HIDDEN					0x00000002
// FILE_ATTRIBUTE_SYSTEM					0x00000004
// FILE_ATTRIBUTE_DIRECTORY				0x00000010
// FILE_ATTRIBUTE_ARCHIVE					0x00000020
// FILE_ATTRIBUTE_ENCRYPTED				0x00000040
// FILE_ATTRIBUTE_NORMAL					0x00000080
// FILE_ATTRIBUTE_TEMPORARY				0x00000100
// FILE_ATTRIBUTE_SPARSE_FILE				0x00000200
// FILE_ATTRIBUTE_REPARSE_POINT			0x00000400
// FILE_ATTRIBUTE_COMPRESSED				0x00000800
// FILE_ATTRIBUTE_OFFLINE					0x00001000
// FILE_ATTRIBUTE_NOT_CONTENT_INDEXED	0x00002000

uint lui_ret, lui_null
str_security_attibutes lstr_security_attibutes

lstr_security_attibutes.lpsecuritydescriptor = 0

SetNull(lui_null)

lui_ret = CreateFileA(as_filename, aul_desiredaccess, aul_sharemode, lstr_security_attibutes, &
                      aul_creationdisposition, ul_flagsandattributes, lui_null)

//uf_getlasterror()

return lui_ret
end function

public function boolean uf_close_file (unsignedinteger aui_file_handle);Boolean lb_ret

lb_ret = CloseHandle(aui_file_handle)

Return (lb_ret)
end function

public function integer uf_netgetlasterror ();
char   lca_error[256]
char   lca_name[256]
Long 		ll_return
String ls_error
String ls_name
ULong lpError
Ulong nErrorBufSize
ULONG nNameBufSize

//ls_error    = lca_error
//nErrorBufSize = 256
//ls_name     = lca_name
//nNameBufSize  = 256

ll_return = WNetGetLastErrorA(lpError, ls_error, nErrorBufSize, ls_name, nNameBufSize)

Return ll_return
end function

public function string uf_getlasterror ();
Char lca_error[80]

String ls_error

ls_error = GetLastError()

return ls_error
end function

public function boolean uf_write_file (long al_file_handle, ref string as_buffer, unsignedlong aul_byte_to_write);//Function Boolean WriteFile(Long hFile, Ref String lpBuffer, ULong nNumberOfBytesToWrite,
//  Ref ULong lpNumberOfBytesWritten, Long lpOverlapped) library "kernel32.DLL"
//
Long ll_null = 0
ULong lul_bytes_written
Boolean lb_ret

str_overlapped lstr_overlapped

lb_ret = WriteFile(al_file_handle, as_buffer, aul_byte_to_write, lul_bytes_written, lstr_overlapped)

//uf_getlasterror()

Return lb_ret
end function

public function boolean uf_read_file (long al_file_handle, ref string as_buffer, ref unsignedlong aul_bytes_to_read, ref unsignedlong aul_bytes_read);
//Function Boolean WriteFile(Long hFile, Ref String lpBuffer, ULong nNumberOfBytesToWrite,
//  Ref ULong lpNumberOfBytesWritten, Long lpOverlapped) library "kernel32.DLL"
//
Long ll_null = 0
Boolean lb_ret

str_overlapped lstr_overlapped

as_buffer = Space(aul_bytes_to_read)

lb_ret = ReadFile(al_file_handle, as_buffer, aul_bytes_to_read, aul_bytes_read, lstr_overlapped)

//uf_getlasterror()

Return lb_ret

return true
end function

on uo_external_function_winapi.create
call super::create
end on

on uo_external_function_winapi.destroy
call super::destroy
end on

