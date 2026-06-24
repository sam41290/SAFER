#include <stdio.h>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "Binary.h"
#include "Function.h"
#include "Frame.h"
#include "extmodule.h"

using namespace std;


#include <nlohmann/json.hpp>

using json = nlohmann::json;

using namespace std;

void from_json(const json& j, json_ins &ins) {
  j.at("location").get_to(ins.location);
  j.at("mne").get_to(ins.mne);
  j.at("op").get_to(ins.op);
  j.at("plt_jump").get_to(ins.plt_jump);
  j.at("plt_target").get_to(ins.plt_target);
  j.at("size").get_to(ins.size);
  j.at("bytes").get_to(ins.bytes);
};

void from_json(const json& j, json_bb &bb) {
  j.at("start").get_to(bb.start);
  j.at("end").get_to(bb.end);
  j.at("target").get_to(bb.target);
  j.at("fall").get_to(bb.fall);
  j.at("is_call").get_to(bb.is_call);
  j.at("function").get_to(bb.function);
  j.at("call_type").get_to(bb.call_type);
  j.at("indirect_tgts").get_to(bb.indirect_tgts);
};

void from_json(const json& j, json_fn &fn) {
  j.at("start").get_to(fn.start);
  j.at("end").get_to(fn.end);
  j.at("definite_entries").get_to(fn.definite_entries);
  j.at("psbl_entries").get_to(fn.psbl_entries);
};

void from_json(const json& j, json_pointer &ptr) {
  //cout<<"Reading pointer: "<<j.dump()<<endl;
  j.at("value").get_to(ptr.val);
  j.at("type").get_to(ptr.type);
  j.at("source").get_to(ptr.source);
  j.at("root_source").get_to(ptr.root_source);
};

vector <string>
ExtDeps::sharedLibPaths() {
  vector <string> lib_list;
  string command = "ldd " + binPath_;  
  array<char, 1024> buffer;
  unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);

  if(!pipe) {
    cout<<"popen() failed"<<endl;
    return lib_list;
  }

  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    string line(buffer.data());
    size_t arrow = line.find("=>");
    if (arrow != string::npos) {
      size_t path_start = line.find_first_not_of(" \t", arrow + 2);
      size_t path_end = line.find(' ', path_start);
      if (path_start != string::npos && path_end != string::npos) {
	string lib_path = line.substr(path_start, path_end - path_start);
	cout<<lib_path<<endl;
	lib_list.push_back(lib_path);
      }
    }
  }

  return lib_list;

}

Cfg * 
ExtDeps::blankCfg(string module_path) {
  auto exe_manager = new binary_class(module_path);
  auto range = exe_manager->progMemRange();

  auto rxSections_ = exe_manager->sections(section_types::RorX);
  auto roSections_ = exe_manager->sections(section_types::RONLY);
  auto rwSections_ = exe_manager->sections(section_types::RW);

  //get trampoline addresses for exit function calls.

  auto exitCallPlt_ = exe_manager->exitPlts();
  auto mayExitPlt_ = exe_manager->mayExitPlts();
  auto allPltSlots_ = exe_manager->allJmpSlots();
  auto pltSlotSymbolMap_ = exe_manager->jmpSlotSymbolMap();
  auto symbolMap_ = exe_manager->symbolMap();
  //get trampoline address for __libc_Start_main function.

  auto libcStartMain_ = exe_manager->jmpSlot("__libc_start_main");
  auto codeSegmentEnd_ = 0;
  auto codeSegmentStart_ = 0;
  for(section & sec:rxSections_) {
    if(sec.sec_type == section_types::RX) {
      uint64_t sec_end = sec.vma + sec.size;
      if(sec_end > codeSegmentEnd_)
        codeSegmentEnd_ = sec.vma + sec.size;

      if(sec.vma < codeSegmentStart_)
        codeSegmentStart_ = sec.vma;
    }
  }

  auto entryPoint_ = exe_manager->entryPoint();
  auto cfg = new Cfg(range.first, range.second, module_path);
  cfg->codeSegEnd(codeSegmentEnd_);
  cfg->libcStartMain(libcStartMain_);
  cfg->exePath(module_path);
  cfg->type(exe_manager->type());
  cfg->dataSegmntStart(rwSections_[0].vma);
  cfg->rxSections(rxSections_);
  cfg->entryPoint(entryPoint_);
  cfg->roSection(roSections_);
  cfg->rwSections(rwSections_);
  cfg->pltSlotSymbolMap(pltSlotSymbolMap_);
  cfg->symbolMap(symbolMap_);
  return cfg;
}

template <typename T1>
void read_json(string json_file, vector <T1> &list) {
  ifstream in(json_file);

  string line;

  while(getline(in, line)) {
    json j = nlohmann::json::parse(line);
    T1 json_struct = j.get<T1>();
    list.push_back(json_struct);
  }

}


void 
ExtDeps::addExtModule(string module_path) {
  string tool_dir = TOOL_PATH"/apps";
  string command = "rm -rf " + tool_dir + "/disassembly/tmp/* " + tool_dir + "/disassembly/log/* " + tool_dir + "/disassembly/jmp_table/*";
  int status = system(command.c_str());
  if (status != 0) {
    cout<<"[add_external_module] disassembly directory clean up failed!! Check shell command "<<command<<endl;
    exit(-1);
  }

  command = tool_dir + "/disassembly/run " + module_path;
  status = system(command.c_str());
  if (status != 0) {
    cout<<"[add_external_module] disassembly failed!! "<<command<<endl;
    exit(-1);
  }

  auto cfg = blankCfg(module_path);

  vector <json_ins> json_ins_list;
  vector <json_bb> json_bb_list;
  vector <json_bb> json_psbl_bb_list;
  vector <json_fn> json_fn_list;
  vector <json_pointer> json_ptr_list;

  string ins_file = tool_dir + "/disassembly/tmp/cfg/assembly.json";
  read_json(ins_file, json_ins_list);
  //for(auto & ins : json_ins_list) {
  //}


  string def_bb_file = tool_dir + "/disassembly/tmp/cfg/definite_basicblocks.json";
  read_json(def_bb_file, json_bb_list);

  string fn_file = tool_dir + "/disassembly/tmp/cfg/functions.json";
  read_json(fn_file, json_fn_list);

  string ptr_file = tool_dir + "/disassembly/tmp/cfg/pointers.json";
  read_json(ptr_file, json_ptr_list);

  populateCfg(cfg, json_ins_list, json_bb_list, json_psbl_bb_list, json_fn_list, json_ptr_list);
}


void
ExtDeps::populateCfg(
	Cfg *cfg, 
        vector <json_ins> &json_ins_list, vector <json_bb> &json_bb_list,
	vector <json_bb> &json_psbl_bb_list, vector <json_fn> &json_fn_list,
	vector <json_pointer> &json_ptr_list) {

  // Create functions first

  map <uint64_t, Function *> fn_map; 
  for(auto & fn : json_fn_list) {
    auto safer_fn = new Function(fn.start, fn.end, false);    
    for(auto & e : fn.definite_entries)
      safer_fn->addEntryPoint(e);
    for(auto & e : fn.psbl_entries)
      safer_fn->addProbableEntry(e);

    fn_map[fn.start] = safer_fn;
  }

  // Create basic blocks

  int ins_ctr = 0;

  for (auto & bb : json_bb_list) {
    while (ins_ctr < json_ins_list.size() && json_ins_list[ins_ctr].location < bb.start) ins_ctr++;

    vector <Instruction *> ins_list; 

    cout<<"Creating BB: "<<bb.start<<"-"<<bb.end<<endl;

    while(ins_ctr < json_ins_list.size() && json_ins_list[ins_ctr].location <= bb.end) {
      auto ins_j = json_ins_list[ins_ctr];
      uint8_t byte_arr[ins_j.size];
      copy(ins_j.bytes.begin(), ins_j.bytes.end(), byte_arr);
      auto safer_ins = new Instruction(ins_j.location, ins_j.mne.c_str(), ins_j.op.c_str(), byte_arr, ins_j.size);
      ins_list.push_back(safer_ins);
      ins_ctr++;

      cout<<ins_j.location<<":"<<ins_j.mne<<" "<<ins_j.op<<" ";
      for(auto & b : ins_j.bytes)
        cout<<(int)b<<" ";
      cout<<endl;
    }

    auto safer_bb = new BasicBlock(bb.start, bb.end);
    safer_bb->target(bb.target);
    safer_bb->fallThrough(bb.fall);
    safer_bb->insList(ins_list);

    cout<<"Created BB"<<endl;

    auto safer_fn = fn_map[bb.function];
    safer_fn->addDefCodeBB(safer_bb);

    cout<<"Added BB to function"<<endl;
  }

  cout<<"Created definite BBs"<<endl;

  ins_ctr = 0;

  for (auto & bb : json_psbl_bb_list) {
    while (ins_ctr < json_ins_list.size() && json_ins_list[ins_ctr].location < bb.start) ins_ctr++;

    vector <Instruction *> ins_list;

    while(ins_ctr < json_ins_list.size() && json_ins_list[ins_ctr].location <= bb.end) {
      auto ins_j = json_ins_list[ins_ctr];
      uint8_t byte_arr[ins_j.size];
      copy(ins_j.bytes.begin(), ins_j.bytes.end(), byte_arr);
      auto safer_ins = new Instruction(ins_j.location, ins_j.mne.c_str(), ins_j.op.c_str(), byte_arr, ins_j.size);
      ins_list.push_back(safer_ins);
      ins_ctr++;
    }

    auto safer_bb = new BasicBlock(bb.start, bb.end);
    safer_bb->target(bb.target);
    safer_bb->fallThrough(bb.fall);
    safer_bb->insList(ins_list);

    auto safer_fn = fn_map[bb.function];
    safer_fn->addUnknwnCodeBB(safer_bb);
  }

  cout<<"Created psbl BB list"<<endl;

  cfg->functions(fn_map);

  for(auto & ptr : json_ptr_list) {
    cfg->newPointer(ptr.val, (PointerType)ptr.type, (PointerSource)ptr.source, (PointerSource)ptr.root_source, 0);
  }

  cout<<"Created pointers"<<endl;

  cfg->linkAllBBs();

}
