aPLib data decompressor for the Apple II by Peter Ferrie.
Two versions, depending on your unpacking needs.
apdstsrc.s is for when the unpacked address is lower in memory than the packed address (for example, if you load the packed data to the top of memory and want to unpack to the bottom of memory).
apsrcdst.s is for when the unpacked address is higher in memory than the packed address (for example, if you load the packed data to the bottom of memory and want to unpack to the top of memory).

Both versions support an option called "init".  You can use this if you know both addresses and unpacked entrypoint at assemble-time.  Sample initialisation code will be generated for you.

apdstsrc.s has more options:
hiunp: unpacker will be relocated to high memory ($d000 or higher) and run from there.  It allows the unpacker code in low memory to be overwritten.
hipak: packed data will also be relocated to high memory.  It allows the entire low memory to be used for unpacked data.

apsrcdst.s unpacks backwards in memory to maximise the amount that can be unpacked.  Packed data must be stored backwards for this to work.

The src and dst can overlap up to the point of the last byte fetched by getbit.

appack.exe can be used to pack data on a PC, just remove the AP32 header (24 bytes), the rest is the packed data.

http://pferrie.host22.com
