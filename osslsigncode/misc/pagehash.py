#!/usr/bin/python

import struct
import sys
import hashlib
from pyasn1.type import univ
from pyasn1.codec.ber import encoder, decoder

f = open(sys.argv[1], 'rb')
filehdr = f.read(1024)
if filehdr[0:2] != 'MZ':
    print "Not a DOS file."
    sys.exit(0)
pepos = struct.unpack('<I', filehdr[60:64])[0]
if filehdr[pepos:pepos+4] != 'PE\0\0':
    print "Not a PE file."
    sys.exit(0)
pepos += 4

nsections = struct.unpack('<H', filehdr[pepos+2:pepos+4])[0]
print "#sections", nsections

magic = struct.unpack('<H', filehdr[pepos+20:pepos+22])[0]
pe32plus = 0
if magic == 0x20b:
    pe32plus = 1
elif magic == 0x10b:
    pe32plus = 0
else:
    print "Unknown magic", magic
    sys.exit(0)

sectoralign = struct.unpack('<I', filehdr[pepos+52:pepos+56])[0]
print "Sector alignment", sectoralign

pos = pepos + 112 + pe32plus*16
nrvas = struct.unpack('<I', filehdr[pos:pos+4])[0]
print "#rvas", nrvas

pos += 4
tpos = pos
rvas = []
for i in range(0, nrvas):
    (p1,p2) = struct.unpack('<II', filehdr[pos:pos+8])
    rvas.append((p1,p2))
    pos += 8

sections = []
for i in range(0, nsections):
    (vsize,vaddr,rsize,raddr) = struct.unpack('<IIII', filehdr[pos+8:pos+24])
    pos += 40
    sections.append((vsize,vaddr,rsize,raddr))

hdrend = pos
print "End of headers", pos
print rvas
print sections

sigpos,siglen = rvas[4]
if sigpos == 0:
    print "No signature found"
    sys.exit(0)

f.seek(sigpos)
sigblob = f.read(siglen)
cid_page_hash = "\xa6\xb5\x86\xd5\xb4\xa1\x24\x66\xae\x05\xa2\x17\xda\x8e\x60\xd6"
oid_ph_v1 = "\x06\x01\x04\x01\x82\x37\x02\x03\x01"
oid_ph_v2 = "\x06\x01\x04\x01\x82\x37\x02\x03\x02"
p = sigblob.find(cid_page_hash)
if p == -1:
    print "No page hash present"
    sys.exit(0)

p += len(cid_page_hash)
sha1 = True
i = sigblob.find(oid_ph_v1)
if i == -1:
    i = sigblob.find(oid_ph_v2)
    if i == -1:
        print "No page hash found"
        sys.exit(0)
    sha1 = False
p = i + len(oid_ph_v1)

blob = str(decoder.decode(sigblob[p:])[0].getComponentByPosition(0))
ph = []
i = 0
hashlen = 20
if not sha1:
    hashlen = 24
while i < len(blob):
    offset = struct.unpack('<I', blob[i:i+4])[0]
    i += 4
    data = blob[i:i+hashlen]
    ph.append((offset,data.encode("hex")))
    i += hashlen

if sha1:
    md = hashlib.sha1()
else:
    md = hashlib.sha256()
b = filehdr[0:pepos+84]
b += filehdr[pepos+88:tpos+4*8]
b += filehdr[tpos+5*8:1024]
b += '\0'*(4096-1024)
md.update(b)
digest = md.hexdigest()

print ""
print "Checking page hash..."
print ""

nph = [(0,digest)]
lastpos = 0
pagesize = sectoralign # ???
for vs,vo,rs,ro in sections:
    l = 0
    while l < rs:
        f.seek(ro+l)
        howmuch = pagesize
        if rs - l < pagesize:
            howmuch = rs - l
        b = f.read(howmuch)
        if howmuch < pagesize:
            b = b + '\0' * (pagesize - (rs - l))
        if sha1:
            d = hashlib.sha1(b).hexdigest()
        else:
            d = hashlib.sha256(b).hexdigest()
        nph.append((ro+l, d))
        l += pagesize
    lastpos = ro + rs

nph.append((lastpos,'0'*(2*hashlen)))
for i in range(0,len(nph)):
    x=ph[i]
    y=nph[i]
    if x[0] != y[0] or x[1] != y[1]:
        print "Not matching:", x, "!=", y
