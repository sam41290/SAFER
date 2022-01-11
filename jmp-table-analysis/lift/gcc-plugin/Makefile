GCCDIR = /home/nhuhuan/gcc-build

CXX = $(GCCDIR)/bin/g++
LDFLAGS = -std=c++11
CXXFLAGS = $(LDFLAGS) -Wall -fno-rtti -Wno-literal-suffix

PLUGINDIR=$(shell $(CXX) -print-file-name=plugin)
CXXFLAGS += -I$(PLUGINDIR)/include -I$(GCCDIR)/gmp -I$(GCCDIR)/gcc

all: my_plugin.so

my_plugin.so: my_plugin.o
	$(CXX) $(LDFLAGS) -shared -o $@ $<

my_plugin.o : my_plugin.cc
	$(CXX) $(CXXFLAGS) -fPIC -c -o $@ $<

clean:
	rm -f my_plugin.o my_plugin.so test.o

check: my_plugin.so test.cc
	$(CXX) -fplugin=./my_plugin.so -c -dP test.cc

.PHONY: all clean check
