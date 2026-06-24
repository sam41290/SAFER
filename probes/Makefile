all:
	gcc -std=gnu11 -ggdb -fPIC -nostdlib -I/usr/include -I./lib -c instrument.c
	gcc -std=gnu11 -ggdb -nostdlib -I/usr/include -I./lib -o libinstrument.so dummy_start.s lib/instrumentation_lib.c instrument.o -lseccomp
clean:
	rm -f libinstrument.so *.o
