#include <stdio.h>
#include <fstream>
#include <iostream>
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "Binary.h"
#include <cstdlib>
#include "extmodule.h"
#include "dataflow.h"
#include "lifter.h"
#include "rtl.h"
#include <nlohmann/json.hpp>
#include <queue>

using json = nlohmann::json;

using namespace std;

extern bool disasm_only;
extern bool dump_cfg;
using namespace SBI;

/*
vector<uint64_t> get_call_targets(DataFlow *df, Cfg *cfg) {
  vector <uint64_t> fn_list;
  auto bb_list = df->getAllBBs();
  auto fn_map = cfg->funcMap();
  for(auto & bb : bb_list) {
    if(bb->isCall() && bb->target() != 0) fn_list.push_back(bb->target());
    else if(bb->lastIns()->isUnconditionalJmp() && 
            bb->target() != 0) { 
      auto fn = is_within(bb->target(),fn_map);
      if(fn != fn_map.end()) {
	if(fn->second->entryExists(bb->target()))
          fn_list.push_back(bb->target());
      }
    }
  }
  return fn_list;
}

void check_indirect_cf(DataFlow *df, Cfg *cfg) {
  auto fn_addr = df->entryAddress();
  cout<<"Checking indirect CF in function: "<<hex<<fn_addr<<endl;
  auto bb_list = df->getAllBBs();
  for(auto & bb : bb_list) {
    if(bb->lastIns()->sem()->isIndrctCf_) {
      if(bb->lastIns()->isPltJmp()) {
	auto plt_tgt = bb->lastIns()->pltTarget();
	fn_syscall_map[fn_addr].plt_target.insert(plt_tgt);
	if(plt_tgt == "syscall") {
	  cout<<"Detected PLT call to syscall..marking as syscall wrapper"<<endl;
	  fn_syscall_map[fn_addr].is_syscall_wrapper = true;
	  fn_syscall_map[fn_addr].syscall_reg = "di";
	}
      }
      else if(cfg->withinPltSec(bb->lastIns()->location()) == false && bb->indirectTgts().size() <= 0) {
	fn_syscall_map[fn_addr].unresolved_icf = true;
	auto cf_loc = bb->lastIns()->location();
	fn_syscall_map[fn_addr].cf_info_map[cf_loc] = df->indirectCFExpr(cf_loc);
      }
    }
  }
}
*/
struct fn_data {
  string name;
  uint64_t addr;
  bool address_taken = false;
  //bool unresolved_icf = false;
  //unordered_set <string> plt_target;
  //unordered_set <uint64_t> targets;
  //bool syscall_list_complete = false;
  bool is_syscall_wrapper = false;
  bool is_main = false;
  unordered_set <int> syscall_list;
  string syscall_reg = "";
  DataFlow *df;
  FuncInfo *fn_details;
};

unordered_map <uint64_t, fn_data> fn_syscall_map;

uint64_t main_addr = 0;


void check_syscall_in_function(DataFlow *df, Cfg *cfg) {
    auto syscall_ins_list = df->getInstructionLocations("syscall");
    fn_data f;
    f.addr = df->entryAddress();
    f.name = cfg->symbolName(f.addr);
    f.df = df;
    if(f.name.length() <= 0) f.name = "func_" + to_string(f.addr);
    else f.is_main = true; //Possibly exported function, mark them as main so that CFG traversal picks them up
    cout<<"Function name: "<<f.name<<endl;
    for(auto & syscall_ins : syscall_ins_list) {
      cout<<"Found syscall ins at: "<<hex<<syscall_ins<<endl;
      //auto rax_val_list = df->getRegValAtBackward(GPR::REG_RAX, syscall_ins);
      //for(auto & val : rax_val_list) {
      //  if(val.val == RegValType::CONSTANT) {
      //    cout<<"Found syscall: "<<dec<<val.addend<<endl;
      //    f.syscall_list.insert(val.addend);
      //  }
      //  else {
      //    f.is_syscall_wrapper = true;
      //    cout<<"Could not resolve RAX val. Dependant regs: "<<dec<<(int)val.val<<endl;
      //  }
      //}
      auto rax_val_list = df->getRegValAt("ax", syscall_ins);
      if (rax_val_list.size() <= 0) cout<<"Could not resolve RAX at: "<<hex<<syscall_ins<<endl;
      else {
        for(auto & val : rax_val_list) {
	  cout<<"Resolved syscall number: "<<dec<<(int)val<<endl;
          f.syscall_list.insert((int)val);
        }
      }
    }
    fn_syscall_map[f.addr] = f;
}

void check_syscall_wrapper_calls(Cfg *cfg) {
  for(auto & fn : fn_syscall_map) {
    auto fn_detail = fn.second.fn_details;
    auto cs_list = fn_detail->callSiteInfo_;
    for(auto & cs : cs_list) {
      if(cs->pltTarget == "syscall") {
	cout<<"Direct call to libc syscall wrapper -- analyze the di reg at: "<<hex<<cs->location<<"\n";
        auto df = fn.second.df;
	auto cl = cs->location;
        cout<<"Resolving syscall number for syscall wrapper call at: "<<hex<<cl<<endl;
        auto reg_val_list = df->getRegValAt("di", cl);
        if (reg_val_list.size() <= 0) cout<<"Could not resolve syscall at: "<<hex<<cl<<endl;
        else {
          for(auto & val : reg_val_list) {
            cout<<"Resolved syscall number: "<<dec<<(int)val<<endl;
            fn.second.syscall_list.insert((int)val);
          }
        }
	continue;
      }
      for(auto & call_tgt : cs->target) {
        if(fn_syscall_map.find(call_tgt) == fn_syscall_map.end()) {
          cout<<"Callee missing from function map..something wrong!! "<<fn.second.name<<" -> "<<hex<<call_tgt<<endl;
          continue;
        }
        auto callee = fn_syscall_map[call_tgt];
        if(callee.is_syscall_wrapper) {
          auto df = fn.second.df;
	  auto cl = cs->location;
          cout<<"Resolving syscall number for syscall wrapper call at: "<<hex<<cl<<endl;
          auto reg_val_list = df->getRegValAt(callee.syscall_reg, cl);
          if (reg_val_list.size() <= 0) cout<<"Could not resolve syscall at: "<<hex<<cl<<endl;
          else {
            for(auto & val : reg_val_list) {
              cout<<"Resolved syscall number: "<<dec<<(int)val<<endl;
              fn.second.syscall_list.insert((int)val);
            }
          }
        }
      }
    }
  }
}

void getFnInfo(DataFlow *df, Cfg *cfg) {
  auto fn_addr = df->entryAddress();
  fn_syscall_map[fn_addr].fn_details = df->getFuncInfo();
  auto fn_info = fn_syscall_map[fn_addr].fn_details;
  for(auto & cs : fn_info->callSiteInfo_) {
    if(cs->pltTarget == "syscall") {
      fn_syscall_map[fn_addr].is_syscall_wrapper = true;
      fn_syscall_map[fn_addr].syscall_reg = "di";
    }
  }
}

void gen_syscall_list(Cfg *cfg) {

  // Lift the program first
  auto fn_map = cfg->funcMap();
  unordered_set <int> entry_list;
  for(auto & fn : fn_map) {
    auto entries = fn.second->allEntries();
    cout<<"--------Function: "<<hex<<fn.first<<endl;

    for(auto & e : entries)
      cout<<"\tentry: "<<hex<<e<<endl;
    entry_list.insert(entries.begin(), entries.end());
  }

  auto lifted_prog = new LiftedProg(cfg, entry_list);
  lifted_prog->deeperDetails_ = false;
  unordered_set<uint64_t> processed_fns;
  
  queue<uint64_t> fn_to_analyze;  
  	
  auto ptrs = cfg->pointers();
  
  // Start from only definitely reachable code

  cout<<"Processing entry point and address taken functions"<<endl;


  for(auto & ptr : ptrs) {
    if(ptr.second->source() == PointerSource::KNOWN_CODE_PTR || 
       ptr.second->source() == PointerSource::PIC_RELOC ||
       ptr.second->source() == PointerSource::CONSTMEM ||
       ptr.second->source() == PointerSource::CONSTOP ||
       ptr.second->source() == PointerSource::RIP_RLTV ||
       ptr.second->source() == PointerSource::STOREDCONST ||
       ptr.second->source() == PointerSource::EH ||
       ptr.second->source() == PointerSource::EHFIRST) {
      
      auto bb = cfg->getBB(ptr.first);
      cout<<"Processing AT fn: "<<hex<<ptr.first<<endl;
      if (bb != NULL && PointerAnalysis::dataByProperty(bb) == false) {
	auto df = lifted_prog->getLiftedFn(ptr.first);//new DataFlow(bb, cfg);
	if(df == NULL) {
	  cout<<"No function entry..possibly EH only. Ignoring!!!"<<endl;
	  continue;
	}
        check_syscall_in_function(df, cfg);
	getFnInfo(df, cfg);
        processed_fns.insert(ptr.first); 
        if(ptr.second->addressTaken(false) && cfg->withinPltSec(ptr.first) == false)
          fn_syscall_map[ptr.first].address_taken = true;
	if(ptr.first == main_addr) {
	  cout<<"Pointer to main: "<<hex<<ptr.first<<endl;
	  fn_syscall_map[ptr.first].is_main = true;
	}
	auto fn_detail = fn_syscall_map[ptr.first].fn_details;
	auto cs_list = fn_detail->callSiteInfo_;
	for(auto & cs : cs_list) {
	  for(auto & tgt : cs->target) {
	    //cout<<"Adding call target: "<<hex<<ptr.first<<"->"<<hex<<tgt<<endl;
	    fn_to_analyze.push(tgt);
	  }
	}
      }
    }
  }
  
  cout<<"Processing direct call targets"<<endl;

  while(!fn_to_analyze.empty()) {

    auto fn_addr = fn_to_analyze.front();
    fn_to_analyze.pop();
    if(processed_fns.find(fn_addr) != processed_fns.end()) continue;

    processed_fns.insert(fn_addr);

    auto bb = cfg->getBB(fn_addr);

    if (bb != NULL) {
      auto df = lifted_prog->getLiftedFn(bb->start());//new DataFlow(bb, cfg);
      check_syscall_in_function(df, cfg);
      getFnInfo(df, cfg);
      auto fn_detail = fn_syscall_map[fn_addr].fn_details;
      auto cs_list = fn_detail->callSiteInfo_;
      for(auto & cs : cs_list) {
        for(auto & tgt : cs->target) {
	  //cout<<"Adding call target: "<<hex<<fn_addr<<"->"<<hex<<tgt<<endl;
          fn_to_analyze.push(tgt);
        }
      }
    }
  
  }
  cout<<"Syscall identification complete"<<endl;
}

bool addressed_referred_elsewhere (uint64_t addr, uint64_t local_fn) {
  for(auto & fn : fn_syscall_map) {
    auto fn_detail = fn.second.fn_details;
    if(fn.second.addr != local_fn && 
       fn_detail->loadsAddress_.find(addr) != fn_detail->loadsAddress_.end() &&
       fn_detail->memWrites_.find(addr) != fn_detail->memWrites_.end()) {
      cout<<"Found other ref of address: "<<hex<<addr<<" in function "<<hex<<fn.second.addr<<endl;
      return true;
    }
  }
  return false;
}

void post_analysis_indirect_cf_resolution(Cfg *cfg) {
  for(auto & fn : fn_syscall_map) {
    auto call_site_list = fn.second.fn_details->callSiteInfo_;
    for(auto & cs : call_site_list) {
      if(cs->isIndirect && cs->resolved == false) {
        auto ind_info = cs->ind;
        if (ind_info->table.size() > 0) {
          
	  for(auto & t : ind_info->table) {
	    if(t.kind == PtrTable::Kind::CodeTab) {
	      while(true) {
		auto ptr = cfg->ptr(t.location);
		if(ptr != NULL && fn_syscall_map.find(t.location) != fn_syscall_map.end()) {
	          cs->resolved = true;
		  cs->target.insert(t.location);
		}
		else break;
		if(t.stride == 0) break;
		t.location += t.stride;
	      }
	    }
	    else if(t.kind == PtrTable::Kind::DataTab) {
	      auto start = t.location;
              while(true) {
	        if(cfg->withinRWSection(start) || cfg->withinRoSection(start)) {
                  uint64_t tgt;
                  utils::READ_FROM_FILE(cfg->exePath_, (void *) &tgt, start,8);
                  if(tgt != 0 && cfg->ptr(tgt) != NULL && fn_syscall_map.find(tgt) != fn_syscall_map.end()) {
                    cs->target.insert(tgt);
	            cs->resolved = true;
                    cout<<"Adding indirect target: "<<hex<<tgt<<endl;
                  }
                  else break;
		  //if(t.stride == 0) break;
	          start += 8;
	        }
	        else break;
              }
	    }
	  }
        }
      }
    }
  }
}

map <string, string> reg_deps_to_string(vector <RegVal> & reg_states, unordered_set <string> &reg_set) {
  map<string,string> reg_val_map;
  int i = 0;
  for(auto & r : reg_states) {
    auto reg = utils::gpr[i];
    //cout<<"Reg: "<<reg<<endl;
    reg.replace(0,1,"");
    i++;
    if(reg_set.find(reg) == reg_set.end()) continue;
    string val = "";
    //cout<<"Reg val "<<reg<<" : "<<(int)r.val<<endl;
    if(r.val != RegValType::UNKNOWN && r.val != RegValType::UNDEFINED) {
      if (r.val == RegValType::CONSTANT) {
	int ctr = 0;
	for(auto & v : r.addend) {
	  if(ctr == 0)
            val = to_string(v);
	  else
	    val = val + "," + to_string(v);
	  ctr += 1;
	}
      }
      else if(r.val == RegValType::POINTER) {
	val = "pointer";
      }
      else if(r.val == RegValType::VARINT) {
	val = "integer";
      }
      else {
        val = utils::gpr[(int)r.val - 4];
	val.replace(0,1,"");
	if(r.addend.size() != 0) {
	  val = val + "_var";
	}
      }
    }
    else val = "unknown";
    reg_val_map[reg] = val;
  }
  return reg_val_map;
}

bool identifiedLocalPointerTbl(FuncInfo *info, uint64_t addr) {
  for(auto & cs : info->callSiteInfo_) {
    auto ind = cs->ind;
    if(ind != NULL) {
      for(auto & t : ind->table)
	if(t.location == addr) return true;
    }
  }
  return false;
}

struct DataObj {
  uint64_t start = 0;
  uint64_t end = 0;
  unordered_set <uint64_t> points_to;
};

bool compareRelocs(Reloc &A, Reloc &B) {
  return (A.storage < B.storage);
}

unordered_set <uint64_t>
relocated_ptr_tables(Cfg *cfg) {
  unordered_set <uint64_t> tables;
  auto relocs = cfg->picConstReloc();
  sort(relocs.begin(),relocs.end(),compareRelocs);
  bool table_started = false;
  uint64_t table_start = 0;
  int entry_cnt = 0;
  uint64_t prev_entry = 0;
  for(auto & r : relocs) {
    if(fn_syscall_map.find(r.ptr) != fn_syscall_map.end()) {
      if(table_started) {
	if((r.storage - prev_entry) == 8) entry_cnt += 1;
        else {
	  if(entry_cnt >= 2)
	    tables.insert(table_start);
	  table_start = r.storage;
	  entry_cnt = 1;
	}
      }
      else {
	table_started = true;
	table_start = r.storage;
	entry_cnt = 1;
      }
    }
    else if(table_started) {
      if(entry_cnt >= 2) tables.insert(table_start);
      table_started = false;
      entry_cnt = 0;
      table_start = 0;
    }
    prev_entry = r.storage;
  }
  if(table_started) {
    if(entry_cnt >= 2) tables.insert(table_start);
  }
  return tables;
}

bool
is_vtable(Cfg *cfg, uint64_t addr) {
  cout<<"Checking possible vtable at: "<<hex<<addr<<endl;
  bool first_entry_chk = false, second_entry_chk = false;
  int fptr_cnt = 0;
  auto start = addr;
  while(true) {
    if(first_entry_chk == false) {
      int64_t val;
      utils::READ_FROM_FILE(cfg->exePath_, (void *) &val, start,8);
       cout<<"First entry "<<val<<endl;
      if(val <= 100) {
        cout<<"First entry check pass..."<<endl;
        first_entry_chk = true;
      }
      else return false;
    }
    else if(second_entry_chk == false) {
      uint64_t val;
      utils::READ_FROM_FILE(cfg->exePath_, (void *) &val, start,8);
       cout<<"Second entry "<<hex<<val<<endl;
      if(cfg->withinRoSection(val) || cfg->withinRWSection(val)) {
        cout<<"Second entry check pass..."<<endl;
        second_entry_chk = true;
      }
      else return false;
    }
    else if(fptr_cnt >= 1) return true;
    else {
      uint64_t val;
      utils::READ_FROM_FILE(cfg->exePath_, (void *) &val, start,8);
       cout<<"ptr entry "<<hex<<val<<endl;
      if(cfg->ptr(val) != NULL && fn_syscall_map.find(val) != fn_syscall_map.end()) fptr_cnt += 1;
      else return false;
    } 
    start += 8;
  }
  return false;
}

unordered_set <uint64_t>
possible_vtables(Cfg *cfg) {
  unordered_set <uint64_t> vtables;
  for(auto & fn : fn_syscall_map) {
    if(fn.second.addr != 0) {
      auto fn_detail = fn.second.fn_details;
      auto psbl_vtables = fn_detail->escapedAddress_;
      //auto psbl_vtables = fn_detail->psblVtable_;
      for(auto & addr : psbl_vtables) {
	if(is_vtable(cfg, addr)) vtables.insert(addr);  
        else if(is_vtable(cfg, addr - 16)) vtables.insert(addr - 16);  
      }                                          
    }
  }
  return vtables;
}

map <uint64_t, DataObj *> estimateDataObjs(Cfg *cfg) {
  map<uint64_t, DataObj *> all_objs;
  auto all_jtables = cfg->jumpTables();
  // First add all identified jump tables
  unordered_set <uint64_t> added;
  for(auto & j : all_jtables) {
    if(added.find(j.location()) == added.end()) {
      auto d = new DataObj();
      d->start = j.location();
      d->end = j.end();
      all_objs[d->start] = d;
      added.insert(d->start);
      cout<<"Creating data obj JTABLE "<<d->start<<endl;
    }
  }
  // Next add all identified function pointer tables and escaped addresses
  for(auto & fn : fn_syscall_map) {
    if(fn.second.addr != 0) {
      auto fn_detail = fn.second.fn_details;
      auto call_sites_list = fn_detail->callSiteInfo_;
      for(auto & cs : call_sites_list) {
	auto ind = cs->ind;
	if(ind != NULL) {
	  auto tbl = ind->table;
	  for(auto & t : tbl) {
	    if(t.kind == PtrTable::Kind::DataTab &&
	      (cfg->withinCodeSec(t.location) == false)) {
              if(added.find(t.location) == added.end()) {
                auto d = new DataObj();
                d->start = t.location;
	        all_objs[d->start] = d;
		added.insert(d->start);
                cout<<"Creating data obj FPTR_TABLE "<<d->start<<endl;
	      }
	    }
	  }
	}
      }
      /*
      auto all_referred_addrs = fn_detail->loadsAddress_;
      all_referred_addrs.insert(fn_detail->readsAddress_.begin(), fn_detail->readsAddress_.end());
      for(auto & addr : all_referred_addrs) {
        if(cfg->withinCodeSec(addr) == false) {
          if(added.find(addr) == added.end() && fn_syscall_map.find(addr) == fn_syscall_map.end()) {
            DataObj d;
            d.start = addr; // keep end 0 as we do not know the end
            all_objs.push_back(d);
	    added.insert(d.start);
            cout<<"Creating data obj REFERRED_ADDR "<<d.start<<endl;
	  }
        }
      }
      */
    }
  }

  auto sym_map = cfg->symbolMap();

  for(auto & s : sym_map) {
    if(cfg->withinCodeSec(s.first) == false) {
      auto addr = s.first;
      if(added.find(addr) == added.end()) {
        auto d = new DataObj();
        d->start = addr;
        all_objs[d->start] = d;
        added.insert(d->start);
        cout<<"Creating data obj SYMBOL OBJ "<<d->start<<endl;
      }
    }
  }
  
  auto ptrs = cfg->pointers();
  for(auto & p : ptrs) {
    if(cfg->withinCodeSec(p.first) == false) {
      auto addr = p.first;
      if(added.find(addr) == added.end()) {
        auto d = new DataObj();
        d->start = addr;
        all_objs[d->start] = d;
        added.insert(d->start);
        cout<<"Creating data obj RELOCATED_PTR "<<d->start<<endl;
      }
    }
  }

  //auto ptr_tables = relocated_ptr_tables(cfg);
  //for(auto & v : ptr_tables) {
  //  auto addr = v;
  //  if(added.find(addr) == added.end()) {
  //    DataObj d;
  //    d.start = addr; // keep end 0 as we do not know the end
  //    all_objs.push_back(d);
  //    added.insert(d.start);
  //    cout<<"Creating data obj RELOC PTR TABLE "<<d.start<<endl;
  //  }
  //}

  auto vtables = possible_vtables(cfg);
  for(auto & v : vtables) {
    auto addr = v;
    if(added.find(addr) == added.end()) {
      auto d = new DataObj();
      d->start = addr;
      all_objs[d->start] = d;
      added.insert(d->start);
      cout<<"Creating data obj VTABLE "<<d->start<<endl;
    }
  }
  uint64_t prev_start = 0, prev_end = 0;
  vector <DataObj *> gap_objs;
  for(auto & d : all_objs) {
    if (prev_end != 0 && d.first > prev_end) {
      auto gd = new DataObj();
      gd->start = prev_end;
      gap_objs.push_back(gd);
    }
    prev_start = d.second->start;
    prev_end = d.second->end;
  }

  if(prev_end != 0 && prev_end < cfg->dataSegmntEnd_) {
    auto gd = new DataObj();
    gd->start = prev_end;
    gap_objs.push_back(gd);
  }
  
  for(auto & g : gap_objs) all_objs[g->start] = g;

  return all_objs;
}

bool compareDataObj(DataObj *A, DataObj *B) {
  return (A->start < B->start);
}

/*
DataObj get_mem_range(uint64_t addrs, Cfg *cfg, vector <DataObj> &data_objs) {
  uint64_t prev_end = 0;
  uint64_t end = 0;
  bool exact_addr_found = false;
  for(auto & d : data_objs) {
    //cout<<"Obj: "<<hex<<d.start<<" - "<<hex<<d.end<<endl;
    if(exact_addr_found) {
      end = d.start;
      break;
    }
    if(addrs == d.start) {
      exact_addr_found = true;
      continue;
    }
    else if(d.start > addrs) {
      end = d.start;
      break;
    }
    else if(d.end != 0 && d.end > addrs) {
      prev_end = d.start;
      end = d.end;
      break;
    }
    if(d.end != 0) prev_end = d.end;
    else prev_end = d.start;
  }
  DataObj d;
  if(prev_end != 0) d.start = prev_end;
  else d.start = addrs;
  if(end == 0) d.end = cfg->dataSegmntEnd_;
  d.end = end;
  return d;
}
*/

vector <DataObj *> get_mem_range(uint64_t addrs, Cfg *cfg, map <uint64_t, DataObj *> &data_objs) {
  vector <DataObj *> objs;
  auto it = data_objs.find(addrs);
  if(it != data_objs.end()) {
    objs.push_back(it->second);
    if(it != data_objs.begin()) {
      it = prev(it);
      objs.push_back(it->second);
    }
  }
  else {
    auto it = data_objs.lower_bound(addrs);
    if(it != data_objs.begin()) {
      it = prev(it);
      objs.push_back(it->second);
    }
  }
  return objs;
}

unordered_map <uint64_t, unordered_set<uint64_t>> points_to_cache;
map<uint64_t, uint64_t> pointer_storage;
unordered_set <uint64_t> data_seg_pointers;

void data_obj_points_to(map <uint64_t, DataObj *> &data_objs, Cfg *cfg) {
  auto ptrs = cfg->pointers();
  for(auto & p : ptrs) {
    auto holders = p.second->storages(SymbolType::CONSTANT);
    for(auto & h : holders) {
      pointer_storage[h] = p.first;
      if(fn_syscall_map.find(p.first) != fn_syscall_map.end() && fn_syscall_map[p.first].address_taken) {
        if(cfg->withinRWSection(h) || cfg->withinRoSection(h)) data_seg_pointers.insert(p.first);
      }
    }
  }
  auto it = pointer_storage.begin();
  auto dit = data_objs.begin();

  while(dit != data_objs.end()) {
    auto cur_start = dit->second->start;
    auto cur_end = dit->second->end;
    if(cur_end == 0) {
      auto next_dit = next(dit);
      if(next_dit != data_objs.end()) cur_end = next_dit->second->start;
      else cur_end = cfg->dataSegmntEnd_;
    }
    cout<<"Current obj: "<<hex<<cur_start<<" - "<<hex<<cur_end<<endl;
    while(it != pointer_storage.end() && it->first < cur_end) {
      if(it->first >= cur_start) {
        if(fn_syscall_map.find(it->second) != fn_syscall_map.end() && fn_syscall_map[it->second].address_taken) {
          dit->second->points_to.insert(it->second);
	  cout<<"Points to AT fn: "<<hex<<it->second<<endl;
	}
        else {
	  cout<<"Points to data pointer: "<<hex<<it->second<<endl;
          auto objs = get_mem_range(it->second, cfg, data_objs);
          for(auto & o : objs) {
            dit->second->points_to.insert(o->start);
	    cout<<"Points to: "<<hex<<o->start<<endl;
	  }
        }
      }
      it++;	
    }
    dit++;
  }
}
/*
unordered_set <uint64_t> pointsTo(DataObj &d, Cfg *cfg, 
		                  vector <DataObj> &data_objs, 
				  unordered_set<uint64_t> &checked_region) {
  unordered_set <uint64_t> points_to_set;
  if(checked_region.find(d.start) != checked_region.end()) return points_to_set;
  checked_region.insert(d.start);
  //cout<<"Getting points to set for region: "<<hex<<d.start<<"-"<<hex<<d.end<<endl;
  if(points_to_cache.find(d.start) != points_to_cache.end()) return points_to_cache[d.start];
  auto ptrs = cfg->pointers();
  for(auto & p : ptrs) {
     auto holders = p.second->storages(SymbolType::CONSTANT);
     for(auto & h : holders) {
       if(h >= d.start && h <= d.end) {
         if(fn_syscall_map.find(p.first) != fn_syscall_map.end()) { 
           if(fn_syscall_map[p.first].address_taken)
	     points_to_set.insert(p.first);
	 }
	 else if(cfg->withinCodeSec(p.first)) continue;
	 else {
	   auto child_data_obj = get_mem_range(p.first, cfg, data_objs);
	   auto child_points_to = pointsTo(child_data_obj, cfg, data_objs, checked_region);
	   for(auto & addr : child_points_to) points_to_set.insert(addr);
           //points_to_set.insert(child_points_to.begin(), child_points_to.end());
	 }
	 break;
       }
     }
  }
  points_to_cache[d.start] = points_to_set;
  return points_to_set;
}
*/

void recursive_points_to(DataObj *obj, map<uint64_t, DataObj *> &data_objs,
		         unordered_set<uint64_t> &res, unordered_set<uint64_t> &checked_region) {
  if(checked_region.find(obj->start) != checked_region.end()) return;
  cout<<"Getting points to for data object: "<<hex<<obj->start<<endl;
  checked_region.insert(obj->start);
  auto points_to = obj->points_to;
  for(auto & p : points_to) {
    if(data_objs.find(p) != data_objs.end()) recursive_points_to(data_objs[p], data_objs, res, checked_region);
    else res.insert(p);
  }
}

unordered_set<uint64_t> addrs_points_to(uint64_t addrs, Cfg *cfg, map<uint64_t, DataObj *> &data_objs) {
  unordered_set <uint64_t> res;
  auto obj_list = get_mem_range(addrs, cfg, data_objs);
  unordered_set <uint64_t> checked_region;
  for(auto & obj : obj_list) {
    cout<<"Data object: "<<hex<<obj->start<<endl;
    recursive_points_to(obj, data_objs, res, checked_region);
  }
  return res;
}

unordered_set <uint64_t> compute_at_list(FuncInfo *info, Cfg *cfg, map <uint64_t, DataObj *> &data_objs) {
  unordered_set <uint64_t> at_set;
  /* 
  unordered_set <uint64_t> all_referred_addrs = info->loadsAddress_;
  all_referred_addrs.insert(info->readsAddress_.begin(), info->readsAddress_.end());
  //auto all_referred_addrs = info->escapedAddress_;
  for (auto & addr : all_referred_addrs) {
    if(fn_syscall_map.find(addr) != fn_syscall_map.end()) {
      at_set.insert(addr);
    }
    else {
      cout<<"Escaped address: "<<hex<<addr<<endl;
      auto res = addrs_points_to(addr, cfg, data_objs);
      at_set.insert(res.begin(), res.end());
    }
  }
  //SYSFILER CONFIG
  at_set.insert(data_seg_pointers.begin(), data_seg_pointers.end());
  */
  return at_set;
}

json create_ind_cf_json(CallSite *cs) {
  json ind_cf_json = json::array();
  auto cf_loc = cs->location;
  auto ind = cs->ind;
  if(cs->resolved) return ind_cf_json;
  else if(ind != NULL) {
    cout<<"Exporting ind cf json: "<<hex<<cf_loc<<endl;
    string type = "";
    if(ind->kind == IndCFInfo::Kind::Memory) type = "memory";
    else if(ind->kind == IndCFInfo::Kind::Register) {
      type = "register";
      if (ind->rval.val == RegValType::CONSTANT) {
        cs->target.insert(ind->rval.addend.begin(), ind->rval.addend.end());
        cs->resolved = true;
        return ind_cf_json;
      }
    }
    else type = "unknown";
    string reg_val = "";
    if(ind->rval.val != RegValType::UNKNOWN && 
       ind->rval.val != RegValType::UNDEFINED) {
      reg_val = utils::gpr[(int)(ind->rval.val) - 4];
      reg_val.replace(0,1,"");
    }
    else reg_val = "unknown";
    cout<<hex<<cf_loc<<" Type: "<<type<<" reg val "<<(int)ind->rval.val<<" "<<reg_val<<endl;
    ind_cf_json.push_back(
      {
        {"site",cf_loc},
        {"type",type},
        {"reg_val",reg_val}
      }
    );
  }
  else {
    ind_cf_json.push_back(
      {
        {"site",cf_loc},
        {"type","unknown"},
        {"reg_val","unknown"}
      }
    );
  }

  return ind_cf_json;
}

void dump_call_graph(map <uint64_t, DataObj *> &data_objs) {
  //propagate_syscall_info();
  
    
  string file = "tmp/cfg/callgraph.json";
  ofstream ofile;
  ofile.open(file, ofstream::out | ofstream::app);
  unordered_set <string> args_reg_set = {"rdi","rsi","rdx","rcx","r8","r9"};

  for(auto & fn : fn_syscall_map) {
    if(fn.second.addr != 0) {
      cout<<"Exporting function: "<<hex<<fn.second.addr<<endl;
      auto fn_detail = fn.second.fn_details;
      auto call_sites_list = fn_detail->callSiteInfo_;
      //json call_sites_json = json::array();
      vector <json> call_sites_json;
      call_sites_json.reserve(call_sites_list.size());
      for (auto & call_site : call_sites_list) {
	uint64_t site = call_site->location;
	cout<<"Exporting call site json: "<<hex<<site<<endl;
	auto reg_vals = call_site->state.regState;
	auto reg_val_map = reg_deps_to_string(reg_vals, args_reg_set);
	auto ind_json = create_ind_cf_json(call_site);
	bool unresolved_icf = true;
	if(call_site->resolved) unresolved_icf = false;
	call_sites_json.push_back(
	  {
	    {"site",site},
	    {"expects_ret",call_site->expectsRetVal_},
	    {"args",reg_val_map},
	    {"targets",call_site->target},
	    {"plt_target",call_site->pltTarget},
	    {"unresolved_icf",unresolved_icf},
	    {"icf_details",ind_json}
	  }
	);
      }
      cout<<"Call sites exported"<<endl;
      auto at_set = compute_at_list(fn_detail, fn.second.df->cfg(), data_objs);
      json j = {
        {"address",fn.second.addr},
        {"name", fn.second.name},
	{"main",fn.second.is_main},
	{"address_taken", fn.second.address_taken},
	{"return_val", fn_detail->ret_},
	{"at_list",at_set},
        {"syscall", fn.second.syscall_list}, 
        {"args_use", fn_detail->argsUse_}, 
        {"call_sites", call_sites_json} 
      };
      ofile<<j.dump()<<endl;
    }
  }
  ofile.close();
  cout<<"Call graph dumping complete"<<endl;
}

int
main (int argc, char *args[]) {
  string binary_path ("");
  binary_path += args[1];
  disasm_only = true;
  dump_cfg = true;

  cout << binary_path << endl;
  Binary b(binary_path);
  b.disassemble();

  auto cfg = b.codeCfg();
  cout<<"Disassembly and CFG generation complete"<<endl;
  main_addr = cfg->symbolAddr("main");
  cout<<"Main function address: "<<hex<<main_addr<<endl;
  gen_syscall_list(cfg);
  //post_analysis_indirect_cf_resolution(cfg);
  check_syscall_wrapper_calls(cfg);
  auto data_objs = estimateDataObjs(cfg);
  data_obj_points_to(data_objs, cfg);
  dump_call_graph(data_objs);
  
  //auto deps = new ExtDeps(binary_path);

  //auto lib_list = deps->sharedLibPaths();
  //for(auto lib : lib_list)
  //  cout<<lib<<endl;

  //deps->addExtModule(lib_list[0]);

  //Binary b (binary_path);
  //SHSTK(b)
  //b.rewrite();
  return 0;
}
