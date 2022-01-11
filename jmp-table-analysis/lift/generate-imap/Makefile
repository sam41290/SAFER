CXX = g++
CXX_FLAG = -I.
CC_FLAG = -c -I.

main.o:
	mkdir -p bin;
	$(CXX) $(CC_FLAG) format_asm.cpp -o bin/format_asm.o;
	$(CXX) $(CC_FLAG) format_rtl.cpp -o bin/format_rtl.o;
	$(CXX) $(CC_FLAG) x64.cpp -o bin/x64.o;
	$(CXX) $(CXX_FLAG) main.cpp -o bin/main.o bin/format_rtl.o bin/format_asm.o bin/x64.o;

clean:
	rm -rf bin/