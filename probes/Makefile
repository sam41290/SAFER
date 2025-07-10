all:
	gcc -ggdb -fPIC -nostdlib -I./lib -c instrument.c
	gcc -ggdb -shared -nostdlib -I./lib -o libinstrument.so lib/sa_restorer.s instrument.o lib/instrumentation_lib.c
clean:
	rm -f libinstrument.so *.o
