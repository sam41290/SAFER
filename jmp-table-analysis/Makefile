export LD_LIBRARY_PATH=/usr/lib/ocaml

CXX = g++ -std=gnu++11 -g
CXX_FLAG = -I.
CC_FLAG = -c -I.

main.o:
	mkdir -p bin;
	$(CXX) $(CC_FLAG) -fPIC expr.cpp -o bin/expr.o;
	$(CXX) $(CC_FLAG) -fPIC mathexpr.cpp -o bin/mathexpr.o;
	$(CXX) $(CC_FLAG) -fPIC basicblock.cpp -o bin/basicblock.o;
	$(CXX) $(CC_FLAG) -fPIC interface.cpp -o bin/interface.o;
	$(CXX) $(CXX_FLAG) jmp_tbl.cpp bin/expr.o bin/mathexpr.o bin/basicblock.o bin/interface.o lift/lift-code/ocaml_interface.o -L/usr/lib/ocaml -lm -ldl -lasmrun_shared -lcamlstr -o jmp_tbl;

clean:
	rm -rf bin/
	rm -f jmp_tbl
