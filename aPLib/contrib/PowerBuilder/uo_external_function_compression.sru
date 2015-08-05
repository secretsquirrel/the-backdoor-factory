$PBExportHeader$uo_external_function_compression.sru
forward
global type uo_external_function_compression from nonvisualobject
end type
end forward

global type uo_external_function_compression from nonvisualobject
end type
global uo_external_function_compression uo_external_function_compression

type prototypes

Function ULong _aPsafe_pack(Ref String source, Ref String destination, ULong length,   &
                      Ref String workmen, Long callback,  Long cbparam) Library "C:\ems\aplib.dll"
Function ULong _aPsafe_depack(Ref String source, ULong srclen, Ref String destination, &
                      ULong dstlen) Library "C:\ems\aplib.dll"
Function ULong _aPsafe_get_orig_size(Ref String source) Library "C:\ems\aplib.dll"
Function ULong _aP_workmem_size(Ulong length) Library "C:\ems\aplib.dll"
Function ULong _aP_max_packed_size(Ulong input_size) Library "C:\ems\aplib.dll"

end prototypes

forward prototypes
public function unsignedlong uof_workmem_size (ref unsignedlong aul_size)
public function unsignedlong uof_max_packed_size (ref unsignedlong aul_size)
public function integer uof_num_of_loops (long al_length)
public function long uof_get_orig_size (ref string as_source)
public function string uof_alloc_memory (unsignedlong aul_size)
public function integer uof_compress (string as_source, string as_dest, ref string as_message)
public function integer uof_decompress (string as_source, string as_dest, ref string as_message)
public function string uof_compressed_name (string as_file)
public function string uof_decompressed_name (string as_file)
end prototypes

public function unsignedlong uof_workmem_size (ref unsignedlong aul_size);
UnsignedLong lul_ret

lul_ret = _aP_workmem_size(aul_size)
If lul_ret = 0 then lul_ret = 655360
	
Return lul_ret 
end function

public function unsignedlong uof_max_packed_size (ref unsignedlong aul_size);
UnsignedLong lul_ret

lul_ret = _aP_max_packed_size(aul_size)
If lul_ret = 0 then lul_ret = 36925

Return lul_ret 
end function

public function integer uof_num_of_loops (long al_length);Integer li_loop

Choose Case al_length
Case 1
	li_loop = 1
	
Case -1
	li_loop = -1
	
Case Else
	If Mod(al_length, 32765) = 0 Then
		li_loop = al_length/32765
	Else
		li_loop = (al_length/32765) + 1
	End If	
End Choose

Return li_loop
end function

public function long uof_get_orig_size (ref string as_source);
Long ll_ret

ll_ret = _aPsafe_get_orig_size(as_source)

Return ll_ret
end function

public function string uof_alloc_memory (unsignedlong aul_size);
String ls_string

Choose Case aul_size
Case is < 1
	SetNull(ls_string)
	
Case is > 2147483647 
	SetNull(ls_string)
	
Case Else
	ls_string = Space(aul_size)
End Choose

Return ls_string
end function

public function integer uof_compress (string as_source, string as_dest, ref string as_message);
Boolean lb_ret

Long ll_null = 0
Long ll_ret 
Long ll_source
Long ll_dest  

ULong lul_size
ULong lul_bytes_read 
ULong lul_bytes_to_read 

String ls_work_mem
String ls_source
String ls_dest

uo_external_function_winapi api_func

api_func = Create uo_external_function_winapi

SetNull(as_message)

ll_source = api_func.uf_create_file(as_source, 1, 1, 3, 128)
If ll_source = -1 Then 
	as_message = 'Error opening file ' + as_source + '.'
	Return -1
End If

lul_bytes_to_read = FileLength(as_source)
ls_source = uof_alloc_memory(lul_bytes_to_read)
If IsNull(ls_source) Then 
	as_message = 'Unable to allocate memory to read source file ' + as_source + '.'
	Return -1
End If

lb_ret  = api_func.uf_read_file(ll_source, ls_source, lul_bytes_to_read, lul_bytes_read)
lb_ret  = api_func.uf_close_file(ll_source)

lul_size = uof_max_packed_size(lul_bytes_read)
ls_dest = uof_alloc_memory(lul_size)
If IsNull(ls_dest) Then 
	as_message = 'Unable to allocate packed memory size ' + String(lul_size)
	Return -1
End If

lul_size = uof_workmem_size(lul_bytes_read)
ls_work_mem = uof_alloc_memory(lul_size)
If IsNull(ls_work_mem) Then 
	as_message = 'Unable to allocate working memory size ' + String(lul_size)
	Return -1
End If

ll_ret = _aPsafe_pack(ls_source, ls_dest, lul_bytes_read, ls_work_mem, ll_null, ll_null)
If ll_ret = -1 Then
	as_message = 'Error compressing file ' + as_source + '.'
	Return -1
End If

If FileExists(as_dest) Then FileDelete(as_dest)

ll_dest = api_func.uf_create_file(as_dest, 4, 2, 4, 128)
If ll_dest = -1 Then 
	as_message = 'Error creating file ' + as_dest + '.'
	Return -1
End If

lb_ret  = api_func.uf_write_file(ll_dest, ls_dest, ll_ret)
lb_ret  = api_func.uf_close_file(ll_dest)
	
Destroy api_func
	
Return 1
end function

public function integer uof_decompress (string as_source, string as_dest, ref string as_message);Boolean lb_ret

Long ll_null = 0
Long ll_ret 
Long ll_source
Long ll_dest  

ULong lul_size
ULong lul_bytes_read 
ULong lul_bytes_to_read 

String ls_source
String ls_dest

uo_external_function_winapi api_func

api_func = Create uo_external_function_winapi

SetNull(as_message)

ll_source = api_func.uf_create_file(as_source, 1, 1, 3, 128)
If ll_source = -1 Then 
	as_message = 'Error opening file ' + as_source + '.'
	Return -1
End If

lul_bytes_to_read = FileLength(as_source)
ls_source = uof_alloc_memory(lul_bytes_to_read)
If ll_source = -1 Then 
	as_message = 'Unable to allocate memory to read source file ' + as_source + '.'
	Return -1
End If

lb_ret  = api_func.uf_read_file(ll_source, ls_source, lul_bytes_to_read, lul_bytes_read)
lb_ret  = api_func.uf_close_file(ll_source)

If FileExists(as_dest) Then FileDelete(as_dest)

lul_size = uof_get_orig_size(ls_source)
ls_dest = uof_alloc_memory(lul_size)
If ll_source = -1 Then 
	as_message = 'Error opening file ' + as_source + '.'
	Return -1
End If

ll_ret = _aPsafe_depack(ls_source, lul_bytes_read, ls_dest, lul_size)
If ll_source = -1 Then 
	as_message = 'Error decompressing file ' + as_source + '.'
	Return -1
End If
	
ll_dest = api_func.uf_create_file(as_dest, 4, 2, 4, 128)
If ll_source = -1 Then 
	as_message = 'Error creating file ' + as_dest + '.'
	Return -1
End If

lb_ret  = api_func.uf_write_file(ll_dest, ls_dest, ll_ret)
lb_ret  = api_func.uf_close_file(ll_dest)

Destroy api_func

Return 1

end function

public function string uof_compressed_name (string as_file);
String ls_temp

ls_temp = Left(as_file, (Len(as_file) - 1)) + '_'

Return ls_temp
end function

public function string uof_decompressed_name (string as_file);
String ls_ext1
String ls_ext2
String ls_file
Long ll_pos

ls_file = as_file

ls_ext1 = Right(ls_file, 3)
Choose Case Lower(ls_ext1)
Case 'pb_'
	ls_ext2 = 'pbd'

Case 'ex_'
	ls_ext2 = 'exe'
	
Case 'dl_'
	ls_ext2 = 'dll'
		
Case Else 
	SetNull(ls_ext2)
	
End Choose

ll_pos = Pos(ls_file, ls_ext1)
ls_file = Replace(ls_file, ll_pos, 3, ls_ext2)

Return ls_file
end function

on uo_external_function_compression.create
call super::create
TriggerEvent( this, "constructor" )
end on

on uo_external_function_compression.destroy
TriggerEvent( this, "destructor" )
call super::destroy
end on

