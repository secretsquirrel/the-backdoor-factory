;;
;; aPLib compression library  -  the smaller the better :)
;;
;; MASM32 include file
;;

aP_pack                proto c, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
aP_workmem_size        proto c, :DWORD
aP_max_packed_size     proto c, :DWORD
aP_depack_asm          proto c, :DWORD, :DWORD
aP_depack_asm_fast     proto c, :DWORD, :DWORD
aP_depack_asm_safe     proto c, :DWORD, :DWORD, :DWORD, :DWORD
aP_crc32               proto c, :DWORD, :DWORD

aPsafe_pack            proto c, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
aPsafe_check           proto c, :DWORD
aPsafe_get_orig_size   proto c, :DWORD
aPsafe_depack          proto c, :DWORD, :DWORD, :DWORD, :DWORD
