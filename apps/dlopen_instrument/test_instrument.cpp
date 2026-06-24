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
#include <filesystem>
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

  //string key("/");
  //size_t found = binary_path.rfind(key);
  //string exe_name = binary_path.substr(found + 1);
  //

  //filesystem::path abs_path(binary_path);
  //filesystem::path dir_path = abs_path.parent_path();
  string dir_str = "/tmp/safer_profile_data";//dir_path.string();


  auto logfile = dir_str + "/dlopen";
  cout<<"log file: "<<logfile<<endl;
  int len = logfile.length();

  auto logfile_cstr = logfile.c_str();

  auto arg = b.addInstrumentationData((void *)logfile_cstr, len + 1); 
  vector<InstArg> arglst = {arg, InstArg::REG_RDI};
  b.registerInstrumentation("dlopen","write_string",arglst);
  
  auto logfile2 = dir_str + "/dlsym";
  cout<<"log file: "<<logfile2<<endl;
  auto len2 = logfile2.length();
  auto logfile_cstr2 = logfile2.c_str();
  auto arg2 = b.addInstrumentationData((void *)logfile_cstr2, len2 + 1); 
  vector<InstArg> arglst2 = {arg2, InstArg::REG_RSI};
  b.registerInstrumentation("dlsym","write_string",arglst2);

  auto logfile3 = dir_str + "/execve";
  cout<<"log file: "<<logfile3<<endl;
  auto len3 = logfile3.length();
  auto logfile_cstr3 = logfile3.c_str();
  auto arg3 = b.addInstrumentationData((void *)logfile_cstr3, len3 + 1); 
  vector<InstArg> arglst3 = {arg3, InstArg::REG_RDI};

  b.registerInstrumentation("execve","write_string",arglst3);
  b.registerInstrumentation("execv","write_string",arglst3);
  b.registerInstrumentation("execl","write_string",arglst3);
  b.registerInstrumentation("system","write_string",arglst3);
  b.registerInstrumentation("execvpe","write_string",arglst3);
  b.registerInstrumentation("execveat","write_string",arglst3);
  b.registerInstrumentation("execvp","write_string",arglst3);
  b.registerInstrumentation("fexecve","write_string",arglst3);

  //vector<InstArg> arglst = {InstArg::RIP};
  //b.registerInstrumentation(InstPoint::BASIC_BLOCK, InstPos::PRE,"LOG",arglst);
  SHSTK(b)
  b.rewrite();
  return 0;
}
