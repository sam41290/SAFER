all:
	gcc -g -I/usr/include -I./lib -nostdlib -fno-stack-protector -fPIC -c instrument.c
	gcc -g -I/usr/include -I./lib -nostdlib -o tutorial dummy_start.s lib/sa_restorer.s instrument.o lib/instrumentation_lib.c
clean:
	rm -f tutorial *.o
