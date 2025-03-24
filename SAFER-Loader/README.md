## Modified Loader ##
  
### Important files ###
1. elf/rtld.c
2. elf/dl-load.c
3. elf/dl-reloc.c
4. elf/elf.h
5. sysdeps/generic/ldsodefs.h
6. include/link.h
7. elf/dl-open.c
9. elf/do-rel.h
10. elf/dynamic-link.h
11. sysdeps/x86_64/dl-machine.h
12. sysdeps/nptl/libc-lockP.h


### Changes made to the loader ###
1. ldsodefs.h - A new struct called gtt_sbi is defined, this struct is a node
   for the linked list of gtt nodes.
2. rtld.c - A function called gtf (global translation function) is added.  It's
   job is to check if a given pointer falls in the range of a particular
   module, and if so dispatch the call the the corresponding ATF (address
   translation function).
   A loop for traversing over GTT is also added for debugging purposes.
3. dl-load.c - Function used for filling the GTT (global tranlation table)
   are added.  It fills in the node struct gtt_sbi with the data like start
   and end addr.  The addr of ATF is taken from a newly added segment called
   PT_SBI_ATT.  This segments also points to a table of ptrs to be encoded.
   These are code pointers.  We currently calculate a checksum of the ptrs and
   store it in the 8 bits after the first bit (linux currently uses 48-bit
   addressing). The MSB is set to 1 so that this cannot be used directly as a
   code ptr without decoding.
4. dl-machine.h - A new relocation type called R_X86_64_SBIENC0 is handled
   and processed similar to that of R_X86_64_RELATIVE.

### How to build ###
1. cd bui
2. ../glibc-2.27/configure --prefix=/usr
3. make

### Replacing the system loader ###
1. In case the system is using a previous version of ld-2.31_sbi.so, then go
   back to the original loader:
   cd /lib64;
   sudo ln -sf /lib/x86_64-linux-gnu/ld-2.31.so ld-linux-x86-64.so.2;
   reboot;
2. cp ~/SBI-Loader/glibc-build/elf/ld.so /lib/x86_64-linux-gnu/ld-2.31_sbi.so
3. cd /lib64;
   sudo ln -sf /lib/x86_64-linux-gnu/ld-2.31.so ld-linux-x86-64_sbi.so.2;

### Encoding schemes ###
1. Global + Local index
64-bit pointer on x86-64 architecture.

64 63 62 61 ... 48 47 46 ... 1
First 4 bits are for marking the encoding scheme used. We will mark this scheme
as scheme #1.
0  0  0  1
64 63 62 61

48 47 46 ... 35
12-bits starting from the bit number 48 will give us the gtt-index.

36 35 34 ... 1
The last 36 bits will give us att-index. 

