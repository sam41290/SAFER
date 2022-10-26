GCCDIR = /usr/lib/gcc/x86_64-linux-gnu/10/

CXX = /usr/bin/g++
LDFLAGS = -std=c++11
CXXFLAGS = $(LDFLAGS) -Wall -fno-rtti -Wno-literal-suffix
CXXFLAGS += -I$(GCCDIR)/plugin/include -I/usr/include/x86_64-linux-gnu/ -I$(GCCDIR)/include -I.

all: my_plugin.so

my_plugin.so: my_plugin.o
	$(CXX) $(LDFLAGS) -shared -o $@ $<

my_plugin.o : my_plugin.cpp
	$(CXX) $(CXXFLAGS) -fPIC -c -o $@ $<

clean:
	rm -f my_plugin.o my_plugin.so

.PHONY: all clean