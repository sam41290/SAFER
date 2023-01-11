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

  //vector<InstArg> arglst;
  //arglst.push_back(InstArg::EXENAME);
  //arglst.push_back(InstArg::RIP);
  //arglst.push_back(InstArg::INDIRECT_TARGET);
  //b.registerInstrumentation(InstPoint::INDIRECT_CF,"LOG",arglst);
  //

  vector<InstArg> arglst2;
  arglst2.push_back(InstArg::INDIRECT_TARGET);
  arglst2.push_back(InstArg::RIP);
  b.registerInstrumentation(InstPoint::ADDRS_TRANS,"GTF",arglst2);

  vector<InstArg> arglst3;
  arglst3.push_back(InstArg::REG_RAX);
  b.registerInstrumentation(InstPoint::SYSCALL_CHECK,"SYSCHK",arglst3);
  //
  //vector<InstArg> arglst2;
  //arglst2.push_back(InstArg::EXENAME);
  //arglst2.push_back(InstArg::RIP);
  //arglst2.push_back(InstArg::LEA_VAL);
  //b.registerInstrumentation(InstPoint::LEA_INS_POST,"LOG2",arglst2);



  b.rewrite();
  return 0;
}
