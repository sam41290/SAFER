### What loader instrumentation is needed ###
All the indirect jumps in the loader need to be instrumented as there might be
a pointer from an external module being used and that pointer needs to be
translated properly. We can do this by locating all the indirect jumps and then
passing the pointer to gtf() to get the translated pointer.

### How to find the indirect jumps ###
We can use objdump on the compiled binary for the loader to find all the
indirect calls.
```
objdump -d ld.so | grep 'callq' | grep '*'
```
This will give us all 95 indirect calls made by the loader.
As we are trying to instrument the loader at source code level, next we need to
find a way of mapping these indirect calls to the place where they are happening
in the code.
We can do that using the following command -
```
 readelf --debug-dump=decodedline ld.so | grep -v "name\|section\|CU:"
```
This will give us a mapping of basic block to the source line in a particular
C file. And since the indirect call instruction should follow a basic block
start, we can map the indirect calls with the corresponding line in the source
code.

To facilitate the mapping we, would filter out the addresses of the indirect
call instructions, using -
```
objdump -d ld.so | grep 'callq' | grep '*' | awk '{ print $1 }' | sed 's/.$//' > calls.txt
```
Now we will filter out the file to basic block mapping -
```
readelf --debug-dump=decodedline ld.so | grep -v "name\|section\|CU:" | awk '{print $1, $2, $3}' > source.txt
```

The finally you we run the script -
```
python3 get\_mapping.py
```

