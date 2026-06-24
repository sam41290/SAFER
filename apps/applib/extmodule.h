#ifndef EXT_MODULE_H
#define EXT_MODULE_H


#include <stdio.h>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "Binary.h"

using namespace std;


#include <nlohmann/json.hpp>

using json = nlohmann::json;

using namespace std;

struct json_ins {
  uint64_t location;
  string mne;
  string op;
  bool plt_jump;
  string plt_target;
  int size;
  vector <uint8_t> bytes;

};

//struct json_ins_list {
//  vector <json_ins> ins_list;
//};

struct json_bb {
  uint64_t start;
  uint64_t end;
  uint64_t target;
  uint64_t fall;
  bool is_call;
  uint64_t function;
  int call_type;
  vector <uint64_t> indirect_tgts;
};

struct json_fn {
  uint64_t start;
  uint64_t end;
  vector<uint64_t> definite_entries;
  vector<uint64_t> psbl_entries;
};

struct json_pointer {
  uint64_t val;
  int type;
  int source;
  int root_source;
};


struct Module {
  string path_;
  Cfg *cfg_;
};

class ExtDeps {
  vector <Module> modules_;
  string binPath_;

public:

  ExtDeps(string exe) { binPath_ = exe; }

  vector<string> sharedLibPaths();
  void addModule(string path);
  Cfg *getModule(string path) {
    for(auto & mod : modules_) {
      if(mod.path_ == path)
	return mod.cfg_;
    }
    return NULL;
  }
  void addExtModule(string mod_path);

private:
  Cfg * blankCfg(string mod_path);
  void populateCfg(
       Cfg *cfg, 
       vector <json_ins> &json_ins_list, vector <json_bb> &json_bb_list,
       vector <json_bb> &json_psbl_bb_list, vector <json_fn> &json_fn_list,
       vector <json_pointer> &json_ptr_list
  );

};


#endif
