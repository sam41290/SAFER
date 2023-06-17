#include <stdio.h>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "Binary.h"

using namespace std;
int
main (int argc, char *args[]) {
  string binary_path ("");
  binary_path += args[1];
  cout << binary_path << endl;
  Binary b (binary_path);

  vector<InstArg> arglst2;
  arglst2.push_back(InstArg::INDIRECT_TARGET);
  arglst2.push_back(InstArg::RIP);
  b.registerInstrumentation(InstPoint::ADDRS_TRANS,"GTF_reg",arglst2);

  vector<InstArg> arglst4;
  arglst4.push_back(InstArg::REG_RAX);
  b.registerInstrumentation(InstPoint::SYSCALL_CHECK,"SYSCHK",arglst4);

  if(RA_OPT == false) {
    vector<InstArg> arglst4;
    b.registerInstrumentation(InstPoint::RET_CHK,"GTF_stack",arglst4);
  }
  //vector<InstArg> arglst5;
  //b.registerInstrumentation(InstPoint::LEGACY_SHADOW_STACK,"GTF_stack",arglst5);
  SHSTK(b);
  b.rewrite();
  return 0;
}
