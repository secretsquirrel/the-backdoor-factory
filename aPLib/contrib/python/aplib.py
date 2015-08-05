################################################################################
# quick hack for using aplib (http://www.ibsensoftware.com/products_aPLib.html)
# put aplib.dll in %PATH% or same dir as this script
# on *nix it might require LD_LIBRARY_PATH set depending on where libaplib.so is

import os
from ctypes import *

################################################################################

__all__ = [ 'pack', 'pack_safe', 'depack', 'depack_safe', 'CB_COMPRESS']

################################################################################

if os.name == 'nt':
    CB_COMPRESS = WINFUNCTYPE(c_uint, c_uint, c_uint, c_uint, c_void_p)
    _aplib = windll.aplib
else:
    CB_COMPRESS = CFUNCTYPE(c_uint, c_uint, c_uint, c_uint, c_void_p)
    # might require LD_LIBRARY_PATH set
    _aplib = CDLL("libaplib.so")    

def _ratio(inpos, insize):
    return (inpos * 100) / insize

def _cbCompress(insize, inpos, outpos, cbparam):
    print "compressed %u -> %u bytes (%u%% done)" % \
        ( inpos, outpos, _ratio(inpos, insize))
    return 1

_cbCompressFunc = CB_COMPRESS(_cbCompress)

################################################################################

def pack(src, cb=None):

    srclen = len(src)
    if srclen <= 0:
        raise ValueError('Invalid input.')

    dstlen = _aplib.aP_max_packed_size(srclen)
    dst = create_string_buffer(dstlen)
    wrkmem = create_string_buffer(_aplib.aP_workmem_size(srclen))

    dstlen = _aplib.aP_pack(src, dst, srclen, wrkmem, cb, 0)

    if dstlen == -1:
        raise ValueError('Compression error.')
        
    return buffer(dst, 0, dstlen)

def pack_safe(src, cb=None):

    srclen = len(src)
    if srclen <= 0:
        raise ValueError('Invalid input.')

    dstlen = _aplib.aP_max_packed_size(srclen)
    dst = create_string_buffer(dstlen)
    wrkmem = create_string_buffer(_aplib.aP_workmem_size(srclen))

    dstlen = _aplib.aPsafe_pack(src, dst, srclen, wrkmem, cb, 0)

    if dstlen == -1:
        raise ValueError('Compression error.')
        
    return buffer(dst, 0, dstlen)

################################################################################

def depack(src, dstlen):

    srclen = len(src)
    if srclen <= 0 or dstlen <= 0:
        raise ValueError('Invalid input.')
    
    dst = create_string_buffer(dstlen)

    dstlen = _aplib.aP_depack_asm_safe(src, srclen, dst, dstlen)
       
    if dstlen == -1:
        raise ValueError('Decompression error.')
    
    return buffer(dst, 0, dstlen)

def depack_safe(src):

    srclen = len(src)
    if srclen <= 0:
        raise ValueError('Invalid input.')
    
    dstlen = _aplib.aPsafe_get_orig_size(src)
    dst = create_string_buffer(dstlen)

    dstlen = _aplib.aPsafe_depack(src, srclen, dst, dstlen)
       
    if dstlen == -1:
        raise ValueError('Decompression error.')
    
    return buffer(dst, 0, dstlen)

################################################################################

if __name__ == "__main__":
    import optparse

    parser = optparse.OptionParser(
        usage='%prog [-h] [-v] -m c|d infile outfile'
        )
    parser.add_option(
        '-m', '--mode',
        action="store",
        type="string", 
        dest='mode',
        help='c for compress, d for decompress')
    parser.add_option(
        '-v', '--verbose',
        action="store_true",
        dest='verbose')

    options, args = parser.parse_args()
    if not options.mode in ['c', 'd']:
        parser.error('You must give a valid --mode')
    if not len(args) == 2:
        parser.error('You must give in- and outfile')

    infile = args[0]
    outfile = args[1]

    src = open(infile, 'rb').read()

    if options.mode == 'c':
        print "Compressing '%s' to '%s'" % (infile, outfile)
        if options.verbose:
            dst = pack_safe(src, _cbCompressFunc)
        else:
            dst = pack_safe(src)
        open(outfile, 'wb').write(dst)
        print "Compressed '%s' from %u to %u bytes (%u%%)" \
                % (infile, len(src), len(dst), _ratio(len(dst), len(src)))
    elif options.mode == 'd':
        print "Decompressing '%s' to '%s'" % (infile, outfile)
        dst = depack_safe(src)
        open(outfile, 'wb').write(dst)
        print "Decompressed '%s' from %u to %u bytes (%u%%)" \
                % (infile, len(src), len(dst), _ratio(len(dst), len(src)))
    

################################################################################
