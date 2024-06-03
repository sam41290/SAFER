#include <stdio.h>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "Binary.h"

using namespace std;

extern bool disasm_only;
extern bool dump_cfg;

int
main (int argc, char *args[]) {
  string binary_path ("");
  binary_path += args[1];
  string disasm = "";
  if(argc > 2)
    disasm = args[2];

  if(disasm.find("disasmonly") != string::npos)
    disasm_only = true;
  string dump = "";
  if(argc > 3)
    dump = args[3];

  if(dump.find("dumpcfg") != string::npos)
    dump_cfg = true;

  cout << binary_path << endl;
  Binary b (binary_path);
  vector<InstArg> arglst;
  arglst.push_back(InstArg::REG_RAX);
  arglst.push_back(InstArg::RIP);
  arglst.push_back(InstArg::EXENAME);
  b.registerInstrumentation(InstPoint::BASIC_BLOCK,InstPos::PRE,"LOG",arglst);
  SHSTK(b)
  b.rewrite();
  return 0;
}
