#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
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
extern bool no_custom_loader;

vector <int> read_syscall_list() {
    std::ifstream file("./syscalls.csv");
    if (!file.is_open()) {
        std::cerr << "Error: could not open file  "<<"./tmp/syscalls.csv"<<"\n";
	exit(1);
    }

    std::vector<int> syscalls;
    std::string line;

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string token;

        while (std::getline(ss, token, ',')) {
            try {
                int num = std::stoi(token);
                syscalls.push_back(num);
            } catch (const std::invalid_argument&) {
                std::cerr << "Warning: skipping invalid token '" << token << "'\n";
            }
        }
    }

    file.close();

    // Print result
    std::cout << "Read " << syscalls.size() << " syscalls:\n";
    for (int num : syscalls) {
        std::cout << num << " ";
    }
    std::cout << "\n";


    return syscalls;
}


int
main (int argc, char *args[]) {

  no_custom_loader = true;
  string binary_path ("");
  binary_path += args[1];

  cout << binary_path << endl;
  Binary b (binary_path);

  auto syscalls = read_syscall_list();
  int len = syscalls.size();

  int *syscall_array = new int[len];
  
  for (size_t i = 0; i < syscalls.size(); ++i) {
      syscall_array[i] = syscalls[i];
  }
  
  //char s[] = "Say hello!! main function starting...\n";

  auto arg = b.addInstrumentationData((void *)syscall_array, len * sizeof(int)); 
  auto arg2 = b.addInstrumentationData((void *)&len, sizeof(int)); 

  vector<InstArg> arglst = {arg,arg2};
  b.registerInstrumentation("main","install_syscall_filter",arglst);

  //vector<InstArg> arglst = {InstArg::RIP};
  //b.registerInstrumentation(InstPoint::BASIC_BLOCK, InstPos::PRE,"LOG",arglst);
  SHSTK(b)
  b.rewrite();
  return 0;
}
