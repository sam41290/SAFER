#include "PointerAnalysis.h"
#include "CfgElems.h"
#include "libutils.h"
#include "manager_constants.h"
#include "Function.h"
#include <unistd.h>
#include <fstream>

using namespace SBI;

long double propScore(vector <Property> &p_list) {
  long double score = 0;
  if(p_list.size() <= 0)
    return -1;
  for(auto & p : p_list) {
    switch(p) {
      case Property::VALID_CF:
        score += 0;
        break;
      case Property::SP_PRESERVED:
        score += 1;
        break;
      case Property::ABI_REG_PRESERVED:
        score += 2;
        break;
      case Property::VALIDINIT:
        score += 4;
        break;
      case Property::ABI_REG_PRESERVE_AND_VALID_INIT:
        score += 6;
        break;
      default:
        score += 0;
        break;
    }
  }
  return score;
}

PointerAnalysis::PointerAnalysis (uint64_t memstrt, uint64_t memend) :
                 CFValidity(memstrt,memend,INSVALIDITY),
                 JmpTblAnalysis(memstrt,memend) {
  propList_ = PROPERTIES;
  //allConstRelocs_.insert(allConstRelocs_.end(), picConstReloc().begin(), picConstReloc().end());
  //allConstRelocs_.insert(allConstRelocs_.end(), xtraConstReloc().begin(),xtraConstReloc().end());
  analysis::setup(TOOL_PATH"auto/itc.auto");
  analysis::set_init(INIT_TYPE);
}

void
setProperty(vector<BasicBlock *> &bb_list, int prop_val, uint64_t entry) {
  DEF_LOG("Setting property bb: "<<hex<<entry<<" property: "<<prop_val);
  Property p = Property::VALID_CF;
  bool pass = false;
  switch (prop_val) {
    case -1:
      break;
    case 0:
      p = Property::VALID_CF;
      pass = true;
      break;
    case 1:
      p = Property::SP_PRESERVED;
      pass = true;
      break;
    case 2:
      p = Property::ABI_REG_PRESERVED;
      pass = true;
      break;
    case 4:
      p = Property::VALIDINIT;
      pass = true;
      break;
    case 6:
      p = Property::ABI_REG_PRESERVE_AND_VALID_INIT;
      pass = true;
      break;
    default:
      pass = false;
      break;
  }
  for(auto & bb : bb_list) {
    if(pass) {
      //if(bb->start() == 0x402c20)
      //DEF_LOG("Pass property: "<<(int)p<<" bb: "<<hex<<bb->start()<<" "<<prop_val);
      bb->passedProp(p);
    }
    else {
      //if(bb->start() == 0x402c20)
      //  DEF_LOG("Fail property: "<<(int)p<<" bb: "<<hex<<bb->start()<<" "<<prop_val);
      bb->failedProp(p);
    }
    bb->contextProp(p, entry, pass);
  }
}


void
PointerAnalysis::symbolize() {
  LOG("Symbolizing pointers");
  map <uint64_t, Pointer *> ptrMap = pointers ();
#ifdef GROUND_TRUTH
  for(auto & r : allConstRelocs_) {
    auto ptr = ptrMap.find(r.ptr);
    if(ptr != ptrMap.end()) {
      uint64_t loc = insWithOperand(r.ptr,r.storage);
      if(loc > 0)
        ptr->second->symbolize(SymbolizeIf::IMMOP_LOC_MATCH,loc);
      if(ptr->second->type() == PointerType::CP) {
        LOG("Symbolizing const ptr: "<<hex<<ptr->first<<" at "<<hex<<r.storage);
        ptr->second->symbolize(SymbolizeIf::SYMLOCMATCH,r.storage);
      }
    }
  }
  for(auto & ptr : ptrMap) {
    if(ptr.second->type() == PointerType::CP)
      ptr.second->symbolize(SymbolizeIf::RLTV);
  }
#else
  for(auto & ptr : ptrMap) {
    LOG("Symbolizing: "<<hex<<ptr.second->address());
    if(ptr.second->type() != PointerType::DP && definiteCode(ptr.first)) {
      SYMBOLIZE(ptr.second);
    }
    else
      LOG("Pointer not CODE");
  }
#endif
  LOG("Symbolization complete");
}

void
PointerAnalysis::symbolizeAlignedConst(Pointer *ptr) {
  vector <uint64_t> storages = ptr->storages(SymbolType::CONSTANT);
  for(auto & loc : storages) {
    auto bb = withinBB(loc);
    if( (bb == NULL || bb->isCode() == false) && loc % 8 == 0)
      ptr->symbolize(SymbolizeIf::SYMLOCMATCH,loc);
  }
}

void
PointerAnalysis::symbolizeRelocatedConst(Pointer *ptr) {
  for(auto & r : allConstRelocs_) {
    if(r.ptr == ptr->address()) {
      ptr->symbolize(SymbolizeIf::SYMLOCMATCH,r.storage);
    }
  }
}

void
PointerAnalysis::symbolizeImmOp(Pointer *ptr) {
  ptr->symbolize(SymbolizeIf::IMMOPERAND);
}

void
PointerAnalysis::symbolizeRelocatedImm(Pointer *ptr) {
  for(auto & r : allConstRelocs_) {
    if(r.ptr == ptr->address()) {
      uint64_t loc = insWithOperand(r.ptr,r.storage);
      if(loc > 0)
        ptr->symbolize(SymbolizeIf::IMMOP_LOC_MATCH,loc);
    }
  }
}

bool
PointerAnalysis::aligned(Pointer *ptr) {
  vector <uint64_t> storages = ptr->storages(SymbolType::CONSTANT);
  for(auto & loc : storages) {
    if(isMetadata(loc) == false) {
      auto bb = withinBB(loc);
      if( (bb == NULL || bb->isCode() == false) && loc % 8 == 0)
        return true;
    }
  }
  return false;
}

bool
PointerAnalysis::immOperand(Pointer *ptr) {
  return ptr->symbolizable(SymbolizeIf::IMMOPERAND);
}

bool
PointerAnalysis::notString(Pointer *ptr) {
  LOG("Checking if its a string: "<<hex<<ptr->address());
  vector <uint64_t> storages = ptr->storages(SymbolType::CONSTANT);
  for (auto & loc : storages) {
    if(loc % 8 == 0) {
      if(isString(loc) == false)
        return true;
    }
  }
  return false;
}

void
PointerAnalysis::symbolizeNonString(Pointer *ptr) {
  LOG("Checking if its a string: "<<hex<<ptr->address());
  vector <uint64_t> storages = ptr->storages(SymbolType::CONSTANT);
  for (auto & loc : storages) {
    auto bb = withinBB(loc);
    if((bb == NULL || bb->isCode() == false) && isString(loc) == false)
      ptr->symbolize(SymbolizeIf::SYMLOCMATCH,loc);
  }
}


bool
PointerAnalysis::relocatedConst(Pointer *ptr) {
  for(auto & r : allConstRelocs_) {
    if(r.ptr == ptr->address()) {
      return ptr->symbolizable(SymbolizeIf::SYMLOCMATCH,r.storage);
    }
  }
  return false;
}

bool
PointerAnalysis::rltvPtr(Pointer *ptr) {
  return ptr->symbolizable(SymbolizeIf::RLTV);
}

bool
PointerAnalysis::jmpTblTgt(Pointer *ptr) {
  auto bb = getBB(ptr->address());
  if(bb != NULL && codeByProperty(bb))
    return ptr->symbolizable(SymbolizeIf::JMP_TBL_TGT);
  return false;
}

void
PointerAnalysis::symbolizeRltvPtr(Pointer *ptr) {
  return ptr->symbolize(SymbolizeIf::RLTV);
}


void
PointerAnalysis::symbolizeIfSymbolArray(Pointer *ptr) {
  vector <uint64_t> storages = ptr->storages(SymbolType::CONSTANT);
  for(auto & loc : storages) {
    auto bb = withinBB(loc);
    if((bb == NULL || bb->isCode() == false) && isString(loc) == false) {
      if(accessConflict(loc) == false || withinSymbolArray(loc)) 
        ptr->symbolize(SymbolizeIf::SYMLOCMATCH,loc);
    }
    else
      LOG("Storage conflicts with def code: "<<hex<<loc);
  }
}

void
PointerAnalysis::symbolizeIfValidAccess(Pointer *ptr) {
  vector <uint64_t> storages = ptr->storages(SymbolType::CONSTANT);
  for(auto & loc : storages) {
    auto bb = withinBB(loc);
    if((bb == NULL || bb->isCode() == false) && isString(loc) == false) {
      if(accessConflict(loc) == false) 
        ptr->symbolize(SymbolizeIf::SYMLOCMATCH,loc);
    }
    else
      LOG("Storage conflicts with def code: "<<hex<<loc);
  }
}

void
PointerAnalysis::symbolizeConst(Pointer *ptr) {
  vector <uint64_t> storages = ptr->storages(SymbolType::CONSTANT);
  for(auto & loc : storages) {
    auto bb = withinBB(loc);
    if(bb == NULL || bb->isCode() == false)
      ptr->symbolize(SymbolizeIf::SYMLOCMATCH,loc);
    else
      LOG("Storage conflicts with def code: "<<hex<<loc);
  }
}

uint64_t
PointerAnalysis::insWithOperand(uint64_t constop,uint64_t storage) {
  auto bb = withinBB(storage);
  if(bb != NULL) {
    vector <Instruction *> ins_list = bb->insList();
    bool ins_found = false;
    uint64_t ins_addr = 0;
    for(auto & ins : ins_list) {
      if(ins_found == false && ins->constOp() == constop) {
        ins_found = true;
        ins_addr = ins->location();
      }
      else if(ins_found && ins->location() > storage && ins_addr < storage)
        return ins_addr;
      else if(ins_found) {
        ins_found = false;
        ins_addr = 0;
      }
    }
    if(ins_found && bb->boundary() > storage && ins_addr < storage)
      return ins_addr;
  }
  return 0;
}

bool
PointerAnalysis::relocatedImm(Pointer *ptr) {
  for(auto & r : allConstRelocs_) {
    if(r.ptr == ptr->address()) {
      uint64_t loc = insWithOperand(r.ptr,r.storage);
      if(loc > 0)
        return true;
    }
  }
  return false;
}

bool
PointerAnalysis::isSymbolizable(uint64_t addrs) {
  map <uint64_t, Pointer *> ptrMap = pointers ();
  auto it = ptrMap.find(addrs);
  if(it == ptrMap.end())
    return false; 
  return SYMBOLIZING_COND(it->second);
}


//map <BasicBlock *, map <BasicBlock *,BasicBlock *>> dp;
map <uint64_t,bool> overlapVerified;

bool bbExists(uint64_t addr, vector <BasicBlock *> &bb_list) {
  for(auto & bb : bb_list)
    if(bb->start() == addr)
      return true;
  return false;
}


extern bool compareBB(BasicBlock *A, BasicBlock *B);

//unordered_set <uint64_t> SPPreserved;


int counter = 0;
/*
bool
bbInList(BasicBlock *bb, vector <BasicBlock *> &bb_list) {
  for(auto & b : bb_list)
    if(b->start() == bb->start())
      return true;
  return false;
}
*/
void
PointerAnalysis::checkIndTgts(unordered_map<int64_t, vector<int64_t>> & ind_tgts,
                              vector <BasicBlock *> & fin_bb_list) {
  for(auto & bb : fin_bb_list) {
    auto ind_tgt_set = bb->indirectTgts();
    for(auto & ind_bb : ind_tgt_set) {
      if(bbInList(ind_bb,fin_bb_list))
        ind_tgts[bb->end()].push_back(ind_bb->start());
    }
  }
}

unordered_map <uint64_t,int>
PointerAnalysis::regPreserved(vector <BasicBlock *> &entry_lst,
                              vector <BasicBlock *> &fin_bb_list,
                              const vector <string> &reg_list) {
  uint64_t entry = entry_lst[0]->start();
  unordered_map <uint64_t, int> valid;
  unordered_map<int64_t, vector<int64_t>> ind_tgts;
  checkIndTgts(ind_tgts,fin_bb_list);
  string dir = get_current_dir_name();
  dumpIndrctTgt(dir + "/tmp/" + to_string(entry)
      + ".ind",ind_tgts);
  string file_name =  dir + "/tmp/" + to_string(entry) + ".s";
  genFnFile(file_name,entry,fin_bb_list);
  unordered_map<int64_t,int64_t> ins_sz = insSizes(fin_bb_list);
  dumpInsSizes(dir + "/tmp/" + to_string(entry) + ".sz",ins_sz);
  /*
  vector <int64_t> all_entries;
  auto entry_bb = getBB(entry);
  auto bb = entry_bb;
  while (bb != NULL) {
    all_entries.push_back(bb->start());
    if(bb->fallThrough() == 0 || bb->isCall())
      break;
    bb = bb->fallThroughBB();
  }
  */
  vector <int64_t> all_entries;
  for(auto & bb : entry_lst)
    all_entries.push_back(bb->start());
  int e_cnt = all_entries.size();
  if(analysis::load(file_name,ins_sz,ind_tgts,all_entries)) {
    for (int func_index = 0; func_index < e_cnt; ++func_index) {
       auto bb = getBB(all_entries[func_index]);
       if(bb != NULL) {
         auto bb_lst = bbSeq(bb);
         /*
         if(codeByProperty(bb)) {
           valid[all_entries[func_index]] = nonCodeScore(all_entries[func_index]);
           continue;
         }
         */
         bool valid_func = analysis::analyze(func_index);
         if (valid_func) {
           if(analysis::preserved(reg_list)) {
             if(reg_list.size() == 1)
               valid[all_entries[func_index]] = 1;
             else
               valid[all_entries[func_index]] = 2;
           }
           else
             valid[all_entries[func_index]] = 0;
           setProperty(bb_lst, valid[all_entries[func_index]], bb->start());
         }
         else
           break;
       }
    }
  }
  return valid;
}

unordered_map <uint64_t,int>
PointerAnalysis::validInit(vector <BasicBlock *> &entry_lst, 
                           vector <BasicBlock *> &fin_bb_list) {
  uint64_t entry = entry_lst[0]->start();
  unordered_map <uint64_t, int> valid;
  unordered_map<int64_t, vector<int64_t>> ind_tgts;
  checkIndTgts(ind_tgts,fin_bb_list);
  string dir = get_current_dir_name();
  dumpIndrctTgt(dir + "/tmp/" + to_string(entry)
      + ".ind",ind_tgts);
  string file_name =  dir + "/tmp/" + to_string(entry) + ".s";
  genFnFile(file_name,entry,fin_bb_list);
  unordered_map<int64_t,int64_t> ins_sz = insSizes(fin_bb_list);
  dumpInsSizes(dir + "/tmp/" + to_string(entry) + ".sz",ins_sz);
  /*
  vector <int64_t> all_entries;
  auto entry_bb = getBB(entry);
  auto bb = entry_bb;
  while (bb != NULL) {
    all_entries.push_back(bb->start());
    if(bb->fallThrough() == 0 || bb->isCall())
      break;
    bb = bb->fallThroughBB();
  }
  */
  vector <int64_t> all_entries;
  for(auto & bb : entry_lst)
    all_entries.push_back(bb->start());
  int e_cnt = all_entries.size();
  if(analysis::load(file_name,ins_sz,ind_tgts,all_entries)) {
    for (int func_index = 0; func_index < e_cnt; ++func_index) {
       auto bb = getBB(all_entries[func_index]);
       if(bb != NULL) {
         auto bb_lst = bbSeq(bb);
         /*
         if(codeByProperty(bb)) {
           valid[all_entries[func_index]] = nonCodeScore(all_entries[func_index]);
           continue;
         }
         */
         bool valid_func = analysis::analyze(func_index);
         if (valid_func) {
           int score = 0;
            if(analysis::uninit() == 0) {
              score = 4;
            }
            else
              score = 0;
            valid[all_entries[func_index]] = score;
            setProperty(bb_lst, score, bb->start());
         }
         else
           break;
       }
    }
  }
  return valid;
}

unordered_map <uint64_t,int>
PointerAnalysis::validInitAndRegPreserve(vector <BasicBlock *> &entry_lst,
                                         vector <BasicBlock *> &fin_bb_list,
                                         const vector <string> &reg_list) {
  uint64_t entry = entry_lst[0]->start();
  unordered_map <uint64_t, int> valid;
  unordered_map<int64_t, vector<int64_t>> ind_tgts;
  checkIndTgts(ind_tgts,fin_bb_list);
  string dir = get_current_dir_name();
  dumpIndrctTgt(dir + "/tmp/" + to_string(entry)
      + ".ind",ind_tgts);
  string file_name =  dir + "/tmp/" + to_string(entry) + ".s";
  genFnFile(file_name,entry,fin_bb_list);
  unordered_map<int64_t,int64_t> ins_sz = insSizes(fin_bb_list);
  dumpInsSizes(dir + "/tmp/" + to_string(entry) + ".sz",ins_sz);
  /*
  vector <int64_t> all_entries;
  auto entry_bb = getBB(entry);
  auto bb = entry_bb;
  while (bb != NULL) {
    all_entries.push_back(bb->start());
    if(bb->fallThrough() == 0 || bb->isCall())
      break;
    bb = bb->fallThroughBB();
  }
  */
  vector <int64_t> all_entries;
  for(auto & bb : entry_lst) {
    all_entries.push_back(bb->start());
    valid[bb->start()] = 0;
  }
  int e_cnt = all_entries.size();
  if(analysis::load(file_name,ins_sz,ind_tgts,all_entries)) {
    for (int func_index = 0; func_index < e_cnt; ++func_index) {
       auto bb = getBB(all_entries[func_index]);
       if(bb != NULL) {
         auto bb_lst = bbSeq(bb);
         /*
         if(codeByProperty(bb)) {
           valid[all_entries[func_index]] = nonCodeScore(all_entries[func_index]);
           continue;
         }
         */
         bool valid_func = analysis::analyze(func_index);
         if (valid_func) {
           DEF_LOG("Analyzing entry: "<<hex<<all_entries[func_index]);
           if(analysis::uninit() == 0) {
             valid[all_entries[func_index]] += 4;
           }
           if(analysis::preserved(reg_list)) {
             valid[all_entries[func_index]] += 2;
           }
           setProperty(bb_lst, valid[all_entries[func_index]], bb->start());
         }
         else
           break;
       }
    }
  }
  return valid;
}

bool
PointerAnalysis::callsDefCode(vector <BasicBlock *> &bbList) {
  LOG("Analyzing call to def code");
  if(CFTODEFCODE > 0) {
    int cnt = 0;
    for(auto & bb : bbList) {
      if(bb->target() != 0 && definiteCode(bb->target())) {
        //LOG("call to defcode found. Calling "<<hex<<bb->target());
        cnt++;;
      }
    }
    if(cnt >= CFTODEFCODE)
      return true;
    return false;
  }
  else
    return true;
}

double
PointerAnalysis::CFTransferDensity(vector <BasicBlock *> &bbList) {
  int insCnt = 0;
  int CFTransferCount = 0;
  for(auto & bb : bbList) {
    insCnt += (bb->insList()).size();
    auto ins = bb->lastIns();
    if(ins->isJump() || ins->isCall())
      CFTransferCount++;
  }
  if(insCnt == 0)
    return 0;
  return CFTransferCount/insCnt;
}

bool
PointerAnalysis::CFDensityChk(vector <BasicBlock *> &bbList) {
  if(CFTRANSFERDENSITY > 0) {
    double density = CFTransferDensity(bbList);
    LOG("CF transfer density: "<<density);
    if(density < CFTRANSFERDENSITY)
      return false;
  }
  return true;
}

bool
PointerAnalysis::hasPossibleCode(vector <BasicBlock *> &bb_list) {
  for(auto & bb : bb_list) {
    if(bb->isCode() == false && codeByProperty(bb) == false) {
      return true;
    }
  }
  return false;
}


int
PointerAnalysis::cfCheck(vector <BasicBlock *> &bb_list) {
  if(validCF(bb_list)) {
    return 0;
  }
  return -1;
}

unordered_map <uint64_t, int>
PointerAnalysis::propertyCheck(vector <BasicBlock *> &entry_lst, 
                               vector<BasicBlock *> &bb_list) {
  unordered_map <uint64_t, int> valid;
  for(auto & p : propList_) {
    switch (p) {
      /*
      case Property::VALIDINS :
        setProperty(bb_list, cfCheck(bb_list), entry_bb->start());
        break;
      case Property::VALID_CF :
        setProperty(bb_list, cfCheck(bb_list), entry_bb->start());
        break;
      */
      case Property::VALIDINIT :
        valid = validInit(entry_lst, bb_list);
        break;
      case Property::SP_PRESERVED :
        valid = regPreserved(entry_lst, bb_list, vector<string>{"sp"});
        break;
      case Property::ABI_REG_PRESERVED :
        valid = regPreserved(entry_lst, bb_list, vector<string>{"sp","bx","bp","r12","r13","r14","r15"});
        break;
      case Property::ABI_REG_PRESERVE_AND_VALID_INIT :
        valid = validInitAndRegPreserve(entry_lst, bb_list, vector<string>{"sp","bx","bp","r12","r13","r14","r15"});
        break;
      default:
        break;
    }
  }
  return valid;
}

unordered_set <uint64_t> resolving_done;

void
PointerAnalysis::resolveNoRetCall(BasicBlock *entry) {
  DEF_LOG("Resolving psbly exit calls for entry: "<<hex<<entry->start());
  auto bb_lst = bbSeq(entry);
  if(hasPossibleCode(bb_lst) == false) {
    //DEF_LOG("Entry doesn't have possible code...avoiding resolution");
    return;
  }
  auto exitCalls = psblExitCalls(entry);
  bool resolved = false;
  while(exitCalls.empty() == false) {
    BasicBlock *call_bb = exitCalls.top();
    exitCalls.pop();
    if(resolved) {
      call_bb->callType(BBType::RETURNING);
      LOG("Marking returning as child resolved: "<<hex<<call_bb->start());
    }
    else if(call_bb->callType() == BBType::MAY_BE_RETURNING &&
       resolving_done.find(call_bb->start()) == resolving_done.end()) {
      DEF_LOG("Resolving possible exit call: "<<hex<<call_bb->start());
      if(entry->isCode()) {
        vector <BasicBlock *> entry_lst{entry};
        entry_lst.push_back(call_bb->fallThroughBB());
        entry->clearProps();
        analyzeEntries(entry_lst, true);
        if(codeByProperty(entry)/* && indTgtConsistency(entry)*/) {
          call_bb->callType(BBType::RETURNING);
          resolving_done.insert(call_bb->start());
          LOG("Code entry passed..Marking returning: "<<hex<<call_bb->start());
          resolved = true;
        }
        else if(call_bb->fallThroughBB()->isCode()) {
          DEF_LOG("Marking non-returning: "<<hex<<call_bb->start());
          possiblePtrs_.insert(call_bb->fallThrough());
          call_bb->callType(BBType::NON_RETURNING);
          call_bb->fallThrough(0);
          call_bb->fallThroughBB(NULL);
        }
        else {
          LOG("Checking if fall through is a valid function: "<<hex<<call_bb->fallThroughBB()->start());
          //analyzeEntry(call_bb->fallThroughBB(), true);
          if(dataByProperty(call_bb->fallThroughBB()) || 
             /*contextPreservesABI(call_bb->fallThroughBB()) ||*/
             contextPassed(call_bb->fallThroughBB(), call_bb->fallThroughBB())) {
            DEF_LOG("Marking non-returning: "<<hex<<call_bb->start());
            possiblePtrs_.insert(call_bb->fallThrough());
            call_bb->callType(BBType::NON_RETURNING);
            call_bb->fallThrough(0);
            call_bb->fallThroughBB(NULL);
          }
          else {
            LOG("Marking returning: "<<hex<<call_bb->start());
            call_bb->callType(BBType::RETURNING);
            resolving_done.insert(call_bb->start());
          }
        }
        resolving_done.insert(call_bb->start());
      }
      else {
        bool check_pass = true;
        auto all_entries = call_bb->entries();
        for(auto & e : all_entries) {
          if((ptr(e->start()) == NULL ||
             (ptr(e->start()) != NULL && 
              ptr(e->start())->source() != PointerSource::JUMPTABLE)) && 
             codeByProperty(e) == false) {
            analyzeEntry(e, true);
            if(codeByProperty(e) == false) {
              check_pass = false;
              break;
            }
          }
        }
        if(check_pass == false) {
          analyzeEntry(call_bb->fallThroughBB(), true);
          if(dataByProperty(call_bb->fallThroughBB()) ||
             /*contextPreservesABI(call_bb->fallThroughBB()) ||*/
             contextPassed(call_bb->fallThroughBB(), call_bb->fallThroughBB())) {
            DEF_LOG("Marking non-returning: "<<hex<<call_bb->start());
            possiblePtrs_.insert(call_bb->fallThrough());
            call_bb->callType(BBType::NON_RETURNING);
            call_bb->fallThrough(0);
            call_bb->fallThroughBB(NULL);
          }
          else {
            LOG("Marking returning: "<<hex<<call_bb->start());
            call_bb->callType(BBType::RETURNING);
          }
        }
        else {
          LOG("All entries passed..Marking returning: "<<hex<<call_bb->start());
          call_bb->callType(BBType::RETURNING);
          resolved = true;
        }
        resolving_done.insert(call_bb->start());
      }
    }
  }
}
/*

void
PointerAnalysis::resolveAllNoRetCalls() {
  LOG("Resolving no ret calls");
  map <uint64_t, Function *>funMap = funcMap();
  for(auto & fn : funMap) {
    set <uint64_t> defEntries = fn.second->entryPoints();
    for(auto & e : defEntries) {
      auto bb = getBB(e);
      if(bb != NULL) {
        resolveNoRetCall(bb);
      }
    }
  }

  for(auto & fn : funMap) {
    set <uint64_t> possibleEntries = fn.second->probableEntry();

    for(auto & e : possibleEntries) {
      auto bb = getBB(e);
      if(bb != NULL) {
        resolveNoRetCall(bb);
      }
    }
  }
  auto jmp_tbls = jumpTables();
  for(auto & j : jmp_tbls) {
    vector <BasicBlock *> targets = j.targetBBs();
    for(auto & tgt : targets) {
      resolveNoRetCall(tgt);
    }
  }
}
*/
bool
PointerAnalysis::contextPassed(BasicBlock *entry, BasicBlock *bb) {
  auto p_list = bb->contextPassedProps(entry->start());
  if(propScore(p_list) >= CODE_SCORE)
    return true;
  /*
  for(auto & p : p_list) {
    if(DEFCODE(p))
      return true;
  }
  */
  return false;
}
bool
PointerAnalysis::indTgtConsistency(BasicBlock *entry) {
  vector <BasicBlock *> next_entry;
  next_entry.push_back(entry);
  auto ind_set = allIndTgts(next_entry);
  int failed_tgts = 0;
  int passed_tgts = 0;
  if(ind_set.size() > 0) {
    for(auto & ind_bb : ind_set) {
      if(contextPassed(entry, ind_bb))
        passed_tgts++;
      else
        failed_tgts++;
    }
    if(failed_tgts <= 0)
      return true;
    return false;
  }
  return true;
}

bool 
PointerAnalysis::hasUnresolvedIndTgts(BasicBlock *entry) {
  //Return true only if none of the indirect targets are validated
  //DEF_LOG("Checking for unresolved inrct tgt: "<<hex<<entry->start());
  vector <BasicBlock *> next_entry;
  next_entry.push_back(entry);
  auto ind_set = allIndTgts(next_entry);
  if(ind_set.size() > 0) {
    /*
    auto first_tgt = *(ind_set.begin());
    if(codeByProperty(first_tgt))
      return false;
    return true;
    */
    int ctr = 0;
    for(auto & bb : ind_set) {
      if(codeByProperty(bb) == false) {
        return true;
      }
      ctr++;
      if(ctr == 5)
        break;
    }
    DEF_LOG("First 5 targets resolved - "<<hex<<entry->start());
    return false;
  }
  DEF_LOG("No indrct tgts for entry: "<<hex<<entry->start());
  return false;
}

uint64_t candidate_count = 0;

void
PointerAnalysis::analyzeEntries(vector <BasicBlock *> &entry_lst, bool force) {
  vector <BasicBlock *> fin_bb_lst;
  vector <BasicBlock *> fin_entry_lst;
  for(auto & entry : entry_lst) {
    vector <BasicBlock *> lst = bbSeq(entry, SEQTYPE::INTRAFN);
    DEF_LOG("Checking entry: "<<hex<<entry->start());
    vector <BasicBlock *> next_entry;
    next_entry.push_back(entry);
    auto ind_set = allIndTgts(next_entry);
    if(ind_set.size() > 0) {
      auto first_tgt = ind_set[0];
      auto ind_lst = bbSeq(first_tgt);
      lst.insert(lst.end(), ind_lst.begin(), ind_lst.end());
    }
    setProperty(lst, cfCheck(lst), entry->start());
    if(dataByProperty(entry) == false) {
      for(auto & bb : lst) {
        auto ins_list = bb->insList();
        candidate_count += ins_list.size();
      }
      if(force) {
        fin_bb_lst.insert(fin_bb_lst.end(), lst.begin(), lst.end());
        fin_entry_lst.push_back(entry);
      }
      else if(hasPossibleCode(lst)) {
        auto score = probScore(entry->start());
        if(score >= ACCEPT_THRESHOLD) {
          DEF_LOG("Avoiding analysis for: "<<hex<<entry->start()<<" score: "<<dec<<score);
          setProperty(lst, CODE_SCORE, entry->start());
        }
        else {
          fin_bb_lst.insert(fin_bb_lst.end(), lst.begin(), lst.end());
          fin_entry_lst.push_back(entry);
        }
      }
    }
  }
  if(fin_entry_lst.size() > 0) {
    propertyCheck(fin_entry_lst, fin_bb_lst);
  }
  /*
  for(auto & entry : entry_lst) {
    if(entry->isCode() || codeByProperty(entry)) {
      DEF_LOG("Validity check passed - "<<hex<<entry->start());
      if(hasUnresolvedIndTgts(entry))
        validateIndTgtsFrmEntry(entry);
    }
    else
      DEF_LOG("Property check failed: "<<hex<<entry->start());
  }
  */
}

void
PointerAnalysis::analyzeEntry(BasicBlock *entry, bool force) {
  vector <BasicBlock *> lst = bbSeq(entry, SEQTYPE::INTRAFN);
  vector <BasicBlock *> next_entry;
  next_entry.push_back(entry);
  auto ind_set = allIndTgts(next_entry);
  DEF_LOG("Checking property: "<<hex<<entry->start()<<" force: "<<force<<" ind tgt count: "<<dec<<ind_set.size());
  auto score = probScore(entry->start());
  if(ind_set.size() > 0) {
    auto first_tgt = ind_set[0];
    auto ind_lst = bbSeq(first_tgt);
    lst.insert(lst.end(), ind_lst.begin(), ind_lst.end());
  }
  setProperty(lst, cfCheck(lst), entry->start());
  if(dataByProperty(entry) == false) {
    for(auto & bb : lst) {
      auto ins_list = bb->insList();
      candidate_count += ins_list.size();
    }
    if(force) {
      propertyCheck(next_entry,lst);
    }
    else if(hasPossibleCode(lst)) {
      if(score >= ACCEPT_THRESHOLD) {
        DEF_LOG("Avoiding analysis for: "<<hex<<entry->start()<<" score: "<<dec<<score);
        auto bb_lst = bbSeq(entry);
        setProperty(bb_lst, CODE_SCORE, entry->start());
      }
      else
        propertyCheck(next_entry,lst);
    }
  }
  else
    DEF_LOG("CF check failed");
  /*
  if(codeByProperty(entry)) {
    DEF_LOG("Validity check passed!!");
    if(hasUnresolvedIndTgts(entry))
      validateIndTgtsFrmEntry(entry);
  }
  else if(entry->isCode() && hasUnresolvedIndTgts(entry)) {
    auto first_tgt = ind_set[0];
    //DEF_LOG("Evaluating with first ind tgt: "<<hex<<entry->start()<<"->"<<hex<<first_tgt->start());
    auto ind_lst = bbSeq(first_tgt);
    lst.insert(lst.end(), ind_lst.begin(), ind_lst.end());
    auto valid = propertyCheck(next_entry, lst);
    if(codeByProperty(entry))
      validateIndTgtsFrmEntry(entry);
  }
  else
    DEF_LOG("Property check failed: "<<hex<<entry->start());
  */
}

void
PointerAnalysis::validateIndTgtsFrmEntry(BasicBlock *entry) {
  DEF_LOG("Validating jmp tbl tgts for entry: "<<hex<<entry->start());
  queue <BasicBlock *> roots;
  unordered_set <uint64_t> valid_ind_path;
  valid_ind_path.insert(entry->start());

  vector <BasicBlock *> entry_lst;
  entry_lst.push_back(entry);
  auto ind_set = allIndTgts(entry_lst);

  for(auto & ind_bb : ind_set)
    roots.push(ind_bb);

  unordered_set <uint64_t> passed;

  while(roots.empty() == false) {
    auto bb = roots.front();
    roots.pop();
    if(passed.find(bb->start()) == passed.end()) {
      passed.insert(bb->start());
      DEF_LOG("Validating jump table target: "<<hex<<bb->start()<<" entry: "<<hex<<entry->start());
      auto ind_seq = bbSeq(bb);
      if(codeByProperty(bb)) {
        DEF_LOG("Pre-marked as code");
        //for(auto & bb2 : ind_seq)
        //  passed_.insert(bb2->start());
        vector <BasicBlock *> next_entry;
        next_entry.push_back(bb);
        auto nxt_ind_set = allIndTgts(next_entry);
        for(auto & ind_bb : nxt_ind_set)
          roots.push(ind_bb);
        continue;
      }
      /*
      if(bb->contextChecked(entry->start())) {
        DEF_LOG("Previously checked from this contest");
        continue;
      }
      */
      if(Conflicts_.find(bb->start()) != Conflicts_.end())
        continue;
      if(validCF(ind_seq) == false) {
        DEF_LOG("invalid control flow");
        setProperty(ind_seq, -1, bb->start());
        Conflicts_.insert(bb->start());
        continue;
      }
      auto exit_routes = allRoutes(entry, bb, valid_ind_path);
      if(validCF(exit_routes) == false) {
        DEF_LOG("Conflicts with entry");
        setProperty(exit_routes, -1, entry->start());
        continue;
      }
      setProperty(exit_routes, 0, entry->start());
      if(conflictsPriorityCode(bb)) {
        DEF_LOG("Conflicts with priority code");
        Conflicts_.insert(bb->start());
        continue;
      }
      for(auto & bb : ind_seq) {
        auto ins_list = bb->insList();
        candidate_count += ins_list.size();
      }
      auto score = probScore(bb->start());
      if(score >= ACCEPT_THRESHOLD)
        setProperty(ind_seq, CODE_SCORE, bb->start());
      else {
        auto valid = propertyCheck(entry_lst,exit_routes);
        for(auto & v : valid) {
          setProperty(exit_routes, v.second, v.first);
        }
      }
      if(codeByProperty(bb)) {
        //for(auto & bb2 : exit_routes)
        //  passed_.insert(bb2->start());
        valid_ind_path.insert(bb->start());
        vector <BasicBlock *> next_entry;
        next_entry.push_back(bb);
        auto nxt_ind_set = allIndTgts(next_entry);
        for(auto & ind_bb : nxt_ind_set)
          roots.push(ind_bb);
      }
      else
        DEF_LOG("property check failed");
    }
     
  }
  /*
   * Indirect target DFS

  LOG("Validating jmp tbl tgts for entry: "<<hex<<entry->start());
  unordered_set <uint64_t> valid_ind_path;
  valid_ind_path.insert(entry->start());
  vector <BasicBlock *> entry_lst;
  entry_lst.push_back(entry);
  auto ind_set = allIndTgts(entry_lst);

  auto bb_list = bbSeq(entry);
  for(auto & ind_bb : ind_set) {
    if(codeByProperty(ind_bb) == false) {
      unordered_set <BasicBlock *> prefix;
      prefix.insert(bb_list.begin(), bb_list.end());
      validateIndTgts(prefix, ind_bb, entry);
    }
  }

  */
}

bool
PointerAnalysis::callTargetRoot(BasicBlock *bb) {
  auto entries = bb->entries();
  for(auto e : entries) {
    auto parents = e->parents();
    for(auto & p : parents) {
      if(codeByProperty(p) == false)
        continue;
      if(p->isCall() && p->target() == e->start())
        return true;
    }
  }
  return false;
}

bool
PointerAnalysis::likelyTrueJmpTblTgt(BasicBlock *bb) {
  auto roots = bb->roots();
  for(auto & r : roots) {
    auto p = ptr(r->start());
    if(p != NULL && p->source() == PointerSource::JUMPTABLE &&
       p->symbolizable(SymbolizeIf::LINEAR_SCAN))
      return true;
  }
  return false;
}

bool
PointerAnalysis::likelyTrueFunction(BasicBlock *bb) {
  auto cnf_ptr = ptr(bb->start());
  auto sig_score = fnSigScore(bb);
  if(cnf_ptr != NULL && sig_score > 0 && 
     cnf_ptr->symbolizable(SymbolizeIf::LINEAR_SCAN))
    return true;
  return false;
}

bool
PointerAnalysis::trueConflict(BasicBlock *cnf_bb) {
  if(PRIORITIZED_REJECT) {
    if(cnf_bb->isCode() == false &&
      (codeByProperty(cnf_bb) == false || 
       Conflicts_.find(cnf_bb->start()) != Conflicts_.end()))
      return false;
    if(cnf_bb->isCode() || 
       passed_.find(cnf_bb->start()) != passed_.end() || 
       nonConflictingRoot(cnf_bb) ||
       callTargetRoot(cnf_bb) ||
       likelyTrueJmpTblTgt(cnf_bb) ||
       likelyTrueFunction(cnf_bb)) {
      return true;
    }
  }
  else if(cnf_bb->isCode())
    return true;
  return false;
}

bool
PointerAnalysis::conflictsPriorityCode(uint64_t addrs) {
  auto cnf_bbs = conflictingBBs(addrs);
  for(auto & cnf_bb : cnf_bbs) {
    if(trueConflict(cnf_bb)) { 
      DEF_LOG("BB conflicts priority code: "<<hex<<addrs<<"->"<<cnf_bb->start());
      return true;
    }
  }
  return false;
}

bool
PointerAnalysis::conflictsPriorityCode(BasicBlock *bb) {
/*
  auto bb_lst = bbSeq(bb);
  for(auto & bb : bb_lst) {
    if(Conflicts_.find(bb->start()) != Conflicts_.end())
      return true;
    if(conflictsPriorityCode(bb->start())) {
      Conflicts_.insert(bb->start());
      return true;
    }
  }

  return false;
  */

  return conflictsPriorityCode(bb->start());
}

void
PointerAnalysis::filterJmpTblTgts(Function *fn) {
  set <uint64_t> possibleEntries = fn->probableEntry();
  set <uint64_t> defEntries = fn->entryPoints();
  set <uint64_t> allEntries;
  allEntries.insert(defEntries.begin(),defEntries.end());
  allEntries.insert(possibleEntries.begin(), possibleEntries.end());
  
  vector <BasicBlock *> entry_bb_lst;
  for(auto & e : allEntries) {
    auto entry_bb = getBB(e);
    if(entry_bb != NULL && 
      (entry_bb->isCode() || codeByProperty(entry_bb))) {
      entry_bb_lst.push_back(entry_bb);
    }
  }

  
  for(auto & p : possiblePtrs_) {
    auto bb = fn->getBB(p);
    if(bb != NULL && (bb->isCode() || codeByProperty(bb))) {
      entry_bb_lst.push_back(bb);
    }
  }

  map <uint64_t, Pointer *> ptrMap = pointers ();
  for(auto & p : ptrMap) {
    if(p.second->source() == PointerSource::POSSIBLE_RA) {
      auto bb = fn->getBB(p.first);
      if(bb != NULL && (bb->isCode() || codeByProperty(bb))) {
        entry_bb_lst.push_back(bb);
      }
    }
  }
  for(auto & entry : entry_bb_lst)
    validateIndTgtsFrmEntry(entry);
  /*
   * Indirect target BFS
   */
  /*
  vector <BasicBlock *> unresolved;
  auto all_inds = allIndTgts(entry_bb_lst);
  unordered_set <uint64_t> valid_ind_path;
  unordered_set <uint64_t> checked;

  while (all_inds.size() > 0) {
    vector <BasicBlock *> next_entry;
    for(auto & bb : all_inds) {
      if(checked.find(bb->start()) == checked.end()) {
        if(codeByProperty(bb) == false) {
          unresolved.push_back(bb);
        }
        else
          valid_ind_path.insert(bb->start());
        next_entry.push_back(bb);
        checked.insert(bb->start());
      }
    }
    all_inds = allIndTgts(next_entry);
  }
  for(auto & ind_bb : unresolved) {
    //DEF_LOG("Validating jump table target: "<<hex<<ind_bb->start());
    if(conflictsPriorityCode(ind_bb)) {
      Conflicts_.insert(ind_bb->start());
      continue;
    }
    if(codeByProperty(ind_bb) == false) {
      auto ind_seq = bbSeq(ind_bb);
      if(validCF(ind_seq) == false)
        continue;
      for(auto & entry : entry_bb_lst) {
        auto valid_inds = valid_ind_path;
        valid_inds.insert(entry->start());
        if(ind_bb->contextChecked(entry->start()) == false) {
          if(contextPassed(entry, ind_bb) == false) {
            auto exit_routes = allRoutes(entry, ind_bb, valid_inds);
            if(exit_routes.size() > 0) {
              DEF_LOG("Validating jump table target: "<<hex<<ind_bb->start()<<" entry: "<<hex<<entry->start());
              propertyCheck(entry,exit_routes);
            }
            if(codeByProperty(ind_bb)) {
              valid_ind_path.insert(ind_bb->start());
              break;
            }
          }
        }
      }
    }
  }
  */
}

void
PointerAnalysis::jmpTblConsistency() {
  /*
  auto jmp_tbls = jumpTables();
  for(auto & j : jmp_tbls) {
    vector <BasicBlock *> targets = j.targetBBs();
    for(auto & tgt : targets) {
      if(conflictsPriorityCode(tgt))
        Conflicts_.insert(tgt->start());
    }
  }
  */
  map <uint64_t, Function *>funMap = funcMap();

  for(auto & fn : funMap) {
    //DEF_LOG("Filtering jump table targets for function: "<<hex<<fn.first);
    filterJmpTblTgts(fn.second);
  }
}


bool
PointerAnalysis::codeByProperty(BasicBlock *bb) {
  auto passed_props = bb->passedProps();
  if(propScore(passed_props) >= CODE_SCORE)
    return true;
  /*
  for(auto & p : passed_props) {
    if(DEFCODE(p)) {
      return true;
    }
  }
  */
  return false;
}

bool
PointerAnalysis::dataByProperty(BasicBlock *bb) {
  auto failed_props = bb->failedProps();
  for(auto & p : failed_props) {
    if(DEFDATA(p)) {
      //LOG("Definitely data by property: "<<(int)p<<" bb: "<<hex<<bb->start()<<" "<<bb);
      return true;
    }
  }
  return false;
}
/*
bool
PointerAnalysis::hasValidRoot(BasicBlock *bb) {
  auto roots = bb->roots();
  for(auto & r : roots)
    if(r->isCode() || codeByProperty(r))
      return true;
  return false
}
*/

void
PointerAnalysis::classifyEntry(uint64_t entry) {
  if(Conflicts_.find(entry) == Conflicts_.end()) {
    auto bb = getBB(entry);
    if(bb != NULL && dataByProperty(bb) == false) {
      vector <BasicBlock *> lst = bbSeq(bb,SEQTYPE::INTRAFN);
      DEF_LOG("Classifying entry: "<<hex<<entry);
      for(auto & bb2 : lst) {
        if(bb2->isCode() == false) {
          if(dataByProperty(bb2))
            markAsDefData(bb2->start());
          else if(Conflicts_.find(bb2->start()) == Conflicts_.end() && 
                  nonCodeScore(entry) >= CODE_SCORE) {
            //DEF_LOG("Marking as defcode BB: "<<hex<<bb2->start());
            markAsDefCode(bb2->start());
          }
        }
      }
    }
  }
  else
    LOG("Conflicting entry: "<<hex<<entry<<" ignoring code classification");
}

void
PointerAnalysis::classifyCode() {
  map <uint64_t, Function *>funMap = funcMap();
  for(auto & fn : funMap) {
    vector <uint64_t> entries = fn.second->allEntries();
    for(auto & e : entries) {
      classifyEntry(e);
    }
  }

}


void
PointerAnalysis::classify() {
  //DEF_LOG("Classifying function entries");
  classifyCode();
  auto jmp_tbls = jumpTables();
  //DEF_LOG("Classifying jump table targets");
  for(auto & j : jmp_tbls) {
    vector <BasicBlock *> targets = j.targetBBs();
    for(auto & tgt : targets) {
      classifyEntry(tgt->start());
    }
  }

  classifyPtrs();
}

void
PointerAnalysis::propagateDefCodeProperty() {
  map <uint64_t, Function *>funMap = funcMap();
  queue <uint64_t> to_check;
  for(auto & fn : funMap)
    to_check.push(fn.first);
  while(to_check.empty() == false) {
    auto fn_addr = to_check.front();
    auto fn = funMap[fn_addr];
    to_check.pop();
    auto def_code = fn->getDefCode();
    for(auto & bb : def_code) {
      //DEF_LOG("Propagating def code property for BB: "<<hex<<bb->start());
      if(bb->targetBB() != NULL) {
        auto tgt_bb = bb->targetBB();
        //DEF_LOG("Marking target as def code: "<<hex<<tgt_bb->start());
        if(tgt_bb->isCode() == false) {
          auto lst = bbSeq(tgt_bb);
          for(auto & bb2 : lst) {

            auto bb_fn = funMap[bb2->frame()];
            if(bb_fn != NULL) {
              bb_fn->markAsDefCode(bb2);
            }
            else
              markAsDefCode(bb2->start(), true);
          }
          auto changed_fn = is_within(tgt_bb->start(),funMap);
          to_check.push(changed_fn->first);
        }
      }
      if(bb->fallThroughBB() != NULL) {
        auto tgt_bb = bb->fallThroughBB();
        //DEF_LOG("Marking fall through as def code: "<<hex<<tgt_bb->start());
        if(tgt_bb->isCode() == false) {
          auto lst = bbSeq(tgt_bb);
          for(auto & bb2 : lst) {
            auto bb_fn = funMap[bb2->frame()];
            if(bb_fn != NULL) {
              bb_fn->markAsDefCode(bb2);
            }
            else
              markAsDefCode(bb2->start(), true);
          }
          auto changed_fn = is_within(tgt_bb->start(),funMap);
          to_check.push(changed_fn->first);
        }
      }
    }
  }
}


bool
PointerAnalysis::contextPreservesABI(BasicBlock *entry) {
  auto score = contextScore(entry, entry);
  if(score == 2 || score == 6)
    return true;
  return false;
}

long double
PointerAnalysis::contextScore(BasicBlock *entry, BasicBlock *bb) {
  auto p_list = bb->contextPassedProps(entry->start());
  return propScore(p_list);
  return -1;
}

long double
PointerAnalysis::nonCodeScore(uint64_t entry) {
  auto bb = getBB(entry);
  if(bb != NULL) {
    auto prop_list = bb->passedProps();
    return propScore(prop_list);
  }
  return -1;
}

bool
PointerAnalysis::nonConflictingRoot(BasicBlock *bb) {
  auto roots = bb->roots();
  for(auto & r : roots) {
    if(codeByProperty(r) == false || Conflicts_.find(r->start()) != Conflicts_.end())
      continue;
    if(passed_.find(r->start()) != passed_.end())
      return true;
    auto cnf_bbs = conflictingBBs(r->start());
    if(cnf_bbs.size() <= 0)
      return true;
  }
  return false;
}

bool
PointerAnalysis::codeParent(BasicBlock *bb) {
  auto parents = bb->parents();
  for(auto & p : parents) {
    if(p->isCode() || 
      (codeByProperty(p) && 
       Conflicts_.find(p->start()) == Conflicts_.end() &&
       p->target() == bb->start()))
      return true;
  }
  return false;
}

void
PointerAnalysis::passAllProps(BasicBlock *bb) {
  auto bb_lst = bbSeq(bb);
  if(validCF(bb_lst)) {
    setProperty(bb_lst, CODE_SCORE, bb->start());
    //for(auto & bb : bb_lst)
    //  DEF_LOG("Passing: "<<hex<<bb->start());
  }
  /*
  if(validCF(bb_lst)) {
    for(auto & bb : bb_lst) {
      DEF_LOG("Passing: "<<hex<<bb->start());
      for(auto & p : propList_) {
        bb->passedProp(p);
      }
    }
  }
  */
}

bool
PointerAnalysis::isNopPadding(BasicBlock *bb) {
  auto ins_list = bb->insList();
  if(ins_list.size() == 1 &&
     ins_list[0]->asmIns().find("nop") != string::npos &&
     bb->fallThroughBB() != NULL &&
     codeByProperty(bb->fallThroughBB()))
    return true;
  return false;
}

void
PointerAnalysis::createAnalysisQ(CandidateType t) {
  map <uint64_t, Function *>funMap = funcMap();
  map <uint64_t, Pointer *> ptrMap = pointers ();
  if(t == CandidateType::DEF_FN_ENTRY) {
    for(auto & fn : funMap) {
      DEF_LOG("Analyzing def entries for function: "<<hex<<fn.first);
      set <uint64_t> def_entries = fn.second->entryPoints();
      vector <BasicBlock *> all_entries;
      for(auto & e : def_entries) {
        auto bb = getBB(e);
        if(bb != NULL) {
          resolveNoRetCall(bb);
          all_entries.push_back(bb);
          validateIndTgtsFrmEntry(bb);
          //analyzeEntry(bb);
        }
      }
      //analyzeEntries(all_entries);
      for(auto & e : def_entries) {
        long double score = powl(2,44) * 40;
        DEF_LOG("Adding definite entry to Q: "<<hex<<e<<" score: "<<dec<<score);
        analysisQ_.push(AnalysisCandidate(e,score));
      }
    }
  }
  else if(t == CandidateType::PSBL_FN_ENTRY) {
    for(auto & fn : funMap) {
      DEF_LOG("Analyzing psbl entries for function: "<<hex<<fn.first);
      set <uint64_t> possibleEntries = fn.second->probableEntry();
      vector <BasicBlock *> all_entries;
      for(auto & e : possibleEntries) {
        if(checked_.find(e) != checked_.end())
          continue;
        checked_.insert(e);
        auto bb = getBB(e);
        if(bb == NULL)
          continue;
        if(bb != NULL && (bb->isCode() || codeByProperty(bb)))
          continue;
        if(isNopPadding(bb)) {
          passAllProps(bb);
        }
        if(bb != NULL && ptr(bb->start()) != NULL && 
           ptr(bb->start())->source() == PointerSource::JUMPTABLE)
          continue;
        resolveNoRetCall(bb);
        if(codeParent(bb))
          passAllProps(bb);
        all_entries.push_back(bb);
      }
      analyzeEntries(all_entries);
      for(auto & e : possibleEntries) {
        auto e_bb = getBB(e);
        auto p = ptr(e);
        if(e_bb != NULL) {
          if(codeByProperty(e_bb) &&
            (p == NULL || p->source() != PointerSource::JUMPTABLE))
            validateIndTgtsFrmEntry(e_bb);
        }
      }
      for(auto & e : possibleEntries) {
        auto e_bb = getBB(e);
        auto p = ptr(e);
        if(e_bb != NULL) {
          if(codeByProperty(e_bb) == false) {
            if(isNopPadding(e_bb))
              passAllProps(e_bb);
            else if(p != NULL && p->symbolizable(SymbolizeIf::LINEAR_SCAN) &&
                    e_bb->contextChecked(e_bb->start()) == false) {
              analyzeEntry(e_bb);
              validateIndTgtsFrmEntry(e_bb);
            }
          }
        }
      }
      for(auto & e : possibleEntries) {
        auto score = probScore(e) + nonCodeScore(e);
        if(score >= 0) {
          DEF_LOG("Adding possible entry to Q: "<<hex<<e<<" score: "<<dec<<score);
          analysisQ_.push(AnalysisCandidate(e, score));
        }
      }
    }
  }
  else if(t == CandidateType::PSBL_PTRS) {
    for(auto & p : ptrMap) {
      if(p.second->source() == PointerSource::POSSIBLE_RA || 
         p.second->source() == PointerSource::GAP_PTR
        /*|| (p.second->type() == PointerType::UNKNOWN && p.second->source() != PointerSource::JUMPTABLE)*/) {
        if(checked_.find(p.first) != checked_.end())
          continue;
        auto bb = getBB(p.second->address());
        if(bb == NULL)
          continue;
        checked_.insert(p.first);
        auto score = probScore(p.second->address());
        if(bb->isCode() == false && codeByProperty(bb) == false) {
          if(isNopPadding(bb))
            passAllProps(bb);
          else {
            resolveNoRetCall(bb);
            if(codeParent(bb))
              passAllProps(bb);
            analyzeEntry(bb);
          }
        }
        score += nonCodeScore(p.first);
        if(score >= 0) {
          if(codeByProperty(bb))
            validateIndTgtsFrmEntry(bb);
          else if(isNopPadding(bb)) {
            passAllProps(bb);
            score += nonCodeScore(bb->start());
          }
          DEF_LOG("Adding possible ptr(RA/Jmp tbl tgt) to Q: "<<hex<<p.second->address()<<" score: "<<dec<<score);
          analysisQ_.push(AnalysisCandidate(p.second->address(),score));
          possiblePtrs_.insert(p.second->address());
        }
      }
    }
    for(auto & fn : funMap) {
      auto psbl_code_lst = fn.second->getUnknwnCode();
      for(auto & bb : psbl_code_lst) {
        if(bb->source() == PointerSource::POSSIBLE_RA &&
           checked_.find(bb->start()) == checked_.end() &&
           bb->isCode() == false &&
           codeByProperty(bb) == false) {
          checked_.insert(bb->start());
          auto score = probScore(bb->start());
          resolveNoRetCall(bb);
          if(codeParent(bb))
            passAllProps(bb);
          analyzeEntry(bb);
          score += nonCodeScore(bb->start());
          if(score >= 0) {
            DEF_LOG("Adding possible BB (RA source) to Q: "<<hex<<bb->start()<<" score: "<<dec<<score);
            analysisQ_.push(AnalysisCandidate(bb->start(),score));
            possiblePtrs_.insert(bb->start());
            if(codeByProperty(bb))
              validateIndTgtsFrmEntry(bb);
          }
        }
      }
    }
  }
  else if(t == CandidateType::ADDITIONAL_PSBL_PTRS) {
    for(auto & p : possiblePtrs_) {
      if(checked_.find(p) != checked_.end())
        continue;
      checked_.insert(p);
      auto bb = getBB(p);
      if(bb == NULL)
        continue;
      auto score = probScore(p);
      if(bb->isCode() == false &&
         codeByProperty(bb) == false &&
         bb->contextChecked(bb->start()) == false) {
        resolveNoRetCall(bb);
        if(codeParent(bb))
          passAllProps(bb);
        analyzeEntry(bb);
      }
      score += nonCodeScore(bb->start());
      if(score >= 0) {
        DEF_LOG("Adding possible ptr(RA/Jmp tbl tgt) to Q: "<<hex<<p<<" score: "<<dec<<score);
        analysisQ_.push(AnalysisCandidate(p,score));
        if(codeByProperty(bb))
          validateIndTgtsFrmEntry(bb);
      }
    }
  }
  else if(t == CandidateType::JMP_TBL_TGTS) {
    auto jmp_tbls = jumpTables();
    for(auto & j : jmp_tbls) {
      vector <BasicBlock *> targets = j.targetBBs();
      for(auto & tgt : targets) {
        if(codeByProperty(tgt)) {
          auto score = probScore(tgt->start()) + nonCodeScore(tgt->start());
          analysisQ_.push(AnalysisCandidate(tgt->start(),score));
        }
      }
    }
  }
}

bool
PointerAnalysis::callTargetIntegrity(BasicBlock *entry, unordered_set <uint64_t> &checked) {
  //DEF_LOG("Checking call target integrity: "<<hex<<entry->start());
  checked.insert(entry->start());
  if(validInsAndCF_.find(entry->start()) != validInsAndCF_.end())
    return true;
  auto bb_lst = bbSeq(entry);
  if(validIns(bb_lst) == false || validCF(bb_lst) == false) {
    DEF_LOG("invalid code at: "<<hex<<entry->start());
    return false;
  }
  for(auto & bb : bb_lst) {
    if(bb->isCall() && bb->target() != 0) {
      if(bb->targetBB() == NULL)
        return false;
      else if(checked.find(bb->target()) == checked.end() &&
              callTargetIntegrity(bb->targetBB(), checked) == false)
        return false;
    }
  }
  validInsAndCF_.insert(entry->start());
  return true;
}

void
PointerAnalysis::analyzeCandidates() {
  DEF_LOG("Starting prioritized rejection");
  while (!analysisQ_.empty()) {
    auto candidate = analysisQ_.top();
    analysisQ_.pop();
    auto bb = getBB(candidate.address_);
    if(bb != NULL) {
      if(candidate.score_ < REJECT_THRESHOLD ||
         conflictsPriorityCode(bb)) {
        Conflicts_.insert(bb->start());
        continue;
      }
      if(bb->isCode() || nonCodeScore(bb->start()) >= CODE_SCORE) {
        unordered_set <uint64_t> checked;
        if(callTargetIntegrity(bb, checked) == false) {
          Conflicts_.insert(bb->start());
          DEF_LOG("Call target integrity failed: "<<hex<<bb->start());
          continue;
        }
        DEF_LOG("Entry passed: "<<hex<<bb->start());
        auto bb_list = bbSeq(bb);
        for(auto & bb2 : bb_list) {
          if(bb->start() == 0x1956f)
            DEF_LOG("Prioritizing bb: "<<hex<<bb2->start());
          passed_.insert(bb2->start());
        }
        //validateIndTgtsFrmEntry(bb);
        //classifyEntry(bb->start());
        //resolveNoRetCall(bb);
        //analyzeEntry(bb);
      }
      else {
        DEF_LOG("BB failed property check: "<<hex<<bb->start());
        Conflicts_.insert(bb->start());
        continue;
      }
    }
  }
}


void
PointerAnalysis::cfgConsistencyAnalysis() {
  LOG("Checking CF consistency");
  propagateAllRoots();
  updateBBTypes();
  phase1NonReturningCallResolution();
  createAnalysisQ(CandidateType::DEF_FN_ENTRY);
  analyzeCandidates();
  createAnalysisQ(CandidateType::PSBL_FN_ENTRY);
  createAnalysisQ(CandidateType::PSBL_PTRS);
  createAnalysisQ(CandidateType::ADDITIONAL_PSBL_PTRS);
  analyzeCandidates();
  createAnalysisQ(CandidateType::JMP_TBL_TGTS);
  analyzeCandidates();
  /*
  resolveAllNoRetCalls();
  map <uint64_t, Function *>funMap = funcMap();
  for(auto & fn : funMap)
    classifyPsblFn(fn.second);
  classifyPossiblePtrs(); 
  */
#ifdef EH_FRAME_DISASM_ROOT
  removeEHConflicts();
#endif
  //jmpTblConsistency();
  //disassembleGaps();
  //if(PRIORITIZED_REJECT)
  //  removeConflicts();
  //FNCorrection();
  classify();
  for(auto & p : possiblePtrs_) {
    classifyEntry(p);
  }
  propagateDefCodeProperty();
  DEF_LOG("Candidate count: "<<dec<<candidate_count);
}

int
PointerAnalysis::tgtCount(vector <BasicBlock *> &bb_list) {
  int ptr_tgt_cnt = 0;
  for(auto & bb : bb_list) {
    auto parents = bb->parents();
    for(auto & p : parents) {
      if(p->target() == bb->start()) {
        auto ins = p->lastIns();
        if(ins->insSize() >= 4)
          ptr_tgt_cnt++;
      }
    }
  }
  return ptr_tgt_cnt;
}

BasicBlock * 
PointerAnalysis::checkSignature(BasicBlock *bb) {
  auto orig_bb = bb;
  auto ins_list = orig_bb->insList();
  for(auto & ins : ins_list) {
    BasicBlock copy_bb = *orig_bb;
    auto new_bb = getBB(ins->location());
    bool add_bb = false;
    if(new_bb == NULL) {
      new_bb = copy_bb.split(ins->location());
      add_bb = true;
    }
    if(fnSigScore(new_bb) >= powl(2,14)) {
      if(add_bb)
        addBBtoFn(new_bb, PointerSource::VALIDITY_WINDOW);
      return new_bb;
    }
  }
  return NULL;
}

void
PointerAnalysis::markConflicting(vector <BasicBlock *> &bb_list) {
  for(auto & bb : bb_list) {
    Conflicts_.insert(bb->start());
  }
}

bool
PointerAnalysis::entryPointCorrection(BasicBlock *ptr_bb) {
  auto external_callers = externalCallers(ptr_bb, ptr_bb);
  if(external_callers.size() > 0) {
    for(auto & p : external_callers) {
      if(p->isCode() || codeByProperty(p)) {
        DEF_LOG("Avoiding entry point correction..ptr has callers: "<<hex<<ptr_bb->start());
        return false;
      }
    }
  }
  map <uint64_t, Pointer *> ptrMap = pointers ();
  auto ptr_it = ptrMap.find(ptr_bb->start());
  auto ptr = ptr_it->second;
  if(ptr_it == ptrMap.end() || ptr->source() != PointerSource::JUMPTABLE) {
    DEF_LOG("Entry point correction for: "<<hex<<ptr_bb->start());
    if(fnSigScore(ptr_bb) >= powl(2,14))
      return true;
    auto sig_start = checkSignature(ptr_bb);
    if(sig_start != NULL && sig_start->start() != ptr_bb->start()) {
      for(auto & p : propList_)
        sig_start->passedProp(p);
      Conflicts_.insert(ptr_bb->start());
      possiblePtrs_.insert(sig_start->start());
      DEF_LOG("Adding signature start as corrected entry: "<<hex<<ptr_bb->start()<<"->"<<sig_start->start());
      return true;
    }
    vector <BasicBlock *> region;
    region.push_back(ptr_bb);
    auto fall_through_bb = ptr_bb->fallThroughBB();
    uint64_t window = ptr_bb->validityWindow();
    if(window == 0) {
      auto fall_bb = fall_through_bb;
      auto last_ins = ptr_bb->lastIns();
      bool is_jmp = last_ins->isUnconditionalJmp();
      while (fall_bb != NULL && !is_jmp) {
        window = fall_bb->start();
        last_ins = fall_bb->lastIns();
        is_jmp = last_ins->isUnconditionalJmp();
        fall_bb = fall_bb->fallThroughBB();
      }
    }
    while(fall_through_bb != NULL && 
          fall_through_bb->start() <= window) {
      long double score = regionScore(region);
      if(score == 0) {
        DEF_LOG("Checking fall through: "<<hex<<fall_through_bb->start());
        auto sig_start = checkSignature(fall_through_bb);
        if(sig_start != NULL) {
          for(auto & p : propList_)
            sig_start->passedProp(p);
          DEF_LOG("Adding signature start as corrected entry: "<<hex<<ptr_bb->start()<<"->"<<sig_start->start());
          if(sig_start->start() != fall_through_bb->start())
            region.push_back(fall_through_bb);
          possiblePtrs_.insert(sig_start->start());
          markConflicting(region);
          return true;
        }
        if(fall_through_bb->isCode()) {
          DEF_LOG("Def code root found..correcting new entry point to: "<<hex<<fall_through_bb->start());
          possiblePtrs_.insert(fall_through_bb->start());
          markConflicting(region);
          return true;
        }
        auto external_callers = externalCallers(fall_through_bb, ptr_bb);
        if(external_callers.size() > 0) {
          DEF_LOG("External caller found..correcting new entry point to: "<<hex<<fall_through_bb->start()<<"<-"<<external_callers[0]->start());
          possiblePtrs_.insert(fall_through_bb->start());
          markConflicting(region);
          return true;
        }
        auto fall_ptr = ptrMap.find(fall_through_bb->start());
        if(fall_ptr != ptrMap.end() && 
          (fall_ptr->second->source() == PointerSource::RIP_RLTV)) {
          DEF_LOG("RLTV pointer found..correcting new entry point to: "<<hex<<fall_through_bb->start());
          possiblePtrs_.insert(fall_through_bb->start());
          markConflicting(region);
          return true;
        }
      }
      region.push_back(fall_through_bb);
      fall_through_bb = fall_through_bb->fallThroughBB();
    }

  }
  return false;
}

void
PointerAnalysis::FNEntryCorrection(BasicBlock *ptr_bb) {
  uint64_t window = 0;
  auto orig_bb = ptr_bb;
  while(orig_bb != NULL) {
    auto last_ins = orig_bb->lastIns();
    window = last_ins->location();
    if(last_ins->isUnconditionalJmp() || 
       last_ins->isCall() || last_ins->asmIns().find("ret") != string::npos)
      break;
    orig_bb = orig_bb->fallThroughBB();
  }
  auto entry_score = probScore(ptr_bb->start());
  DEF_LOG("Correcting false negative: "<<hex<<ptr_bb->start()<<" window: "<<hex<<window<<" score: "<<dec<<entry_score);
  for(auto i = ptr_bb->start() - 17; i < window; i++) {
    if(FNCorrectionDone_.find(i) != FNCorrectionDone_.end())
      continue;
    FNCorrectionDone_.insert(i);
    if(conflictsPriorityCode(i))
      continue;
    auto bb = getBB(i);
    if(bb == NULL) {
      addToCfg(i, PointerSource::GAP_PTR);
    }
    bb = getBB(i);
    if(bb != NULL) {
      vector <BasicBlock *> bb_check {bb};
      if(validIns(bb_check) == false)
        continue;
      linkAllBBs();
      auto bb_lst = bbSeq(bb);
      bool ignore = false;
      for(auto & bb : bb_lst) {
        if(bb->noConflict(window) == false) {
          ignore = true;
          break;
        }
      }
      if(ignore)
        continue;
      if(validCF(bb_lst)) {
        auto bb_score = probScore(i);
        if(bb_score < powl(2,10))
          continue;
        //double fn_sig_score = fnSigScore(bb);
        /*
        if(fn_sig_score > powl(2,14)) {
          for(auto & bb : bb_lst) {
            DEF_LOG("Passing: "<<hex<<bb->start());
            for(auto & p : propList_) {
              bb->passedProp(p);
            }
          }
        }
        */
        analyzeEntry(bb);
        possiblePtrs_.insert(bb->start());
        break;
      }
      //if(codeByProperty(bb)) {
      //  possiblePtrs_.insert(bb->start());
      //  entryPointCorrection(bb);
      //  break;
      //}
    }
  }
}

void
PointerAnalysis::FNCorrection() {
  map <uint64_t, Pointer *> ptrMap = pointers ();
  for(auto & ptr : ptrMap) {
    auto ptr_bb = getBB(ptr.first);
    if(ptr_bb != NULL && ptr.second->type() != PointerType::CP
       && (ptr.second->source() == PointerSource::GAP_PTR)
       && codeByProperty(ptr_bb) == false && ptr_bb->isCode() == false) {
      if(FNCorrectionDone_.find(ptr_bb->start()) != FNCorrectionDone_.end())
        continue;
      FNCorrectionDone_.insert(ptr_bb->start());
      auto cnf_bbs = conflictingBBs(ptr_bb->start());
      bool ignore = false;
      for(auto & cnf_bb : cnf_bbs) {
        if(cnf_bb->isCode() || codeByProperty(cnf_bb)) {
          ignore = true;
          break;
        }
      }
      if(ignore) {
        continue;
      }
      auto score = probScore(ptr_bb->start());
      if(score < ACCEPT_THRESHOLD) {
        continue;
      }
      if(Conflicts_.find(ptr.first) != Conflicts_.end())
        continue;
      DEF_LOG("Correcting false negative for: "<<hex<<ptr.first<<" score: "<<score);
      FNEntryCorrection(ptr_bb);
    }
  }
}


void
PointerAnalysis::removeConflicts() {
  map <uint64_t, Pointer *> ptrMap = pointers ();
  map <uint64_t, Function *>funMap = funcMap();
  
  for(auto & ptr : ptrMap) {
    auto ptr_bb = getBB(ptr.first);
    if(ptr_bb != NULL && ptr.second->type() != PointerType::CP
       && ptr.second->type() != PointerType::DP 
       && (ptr.second->source() == PointerSource::STOREDCONST 
           || ptr.second->source() == PointerSource::JUMPTABLE
           || ptr.second->source() == PointerSource::CONSTOP
           || ptr.second->source() == PointerSource::GAP_PTR
           || ptr.second->source() == PointerSource::RIP_RLTV)
       && passed_.find(ptr.first) != passed_.end()
       && Conflicts_.find(ptr.first) == Conflicts_.end()
       && ptr_bb->isCode() == false) {
      DEF_LOG("Checking for conflict: "<<hex<<ptr.first);
      unordered_set <uint64_t> checked;
      bool removed = false;
      auto score1 = probScore(ptr.first);
      auto cnf_bb_lst = conflictingBBs(ptr.first);
      for(auto & cnf_bb : cnf_bb_lst) {
        auto score2 = probScore(cnf_bb->start());
        if(passed_.find(cnf_bb->start()) != passed_.end() &&
           Conflicts_.find(cnf_bb->start()) == Conflicts_.end()) {
          if(ptr_bb->parents().size() == 0 && cnf_bb->parents().size() > 0) {
            DEF_LOG("Conflicting with directly called bb: "<<hex<<ptr_bb->start()<<"->"<<hex<<cnf_bb->start());
            Conflicts_.insert(ptr.first);
            removed = true;
            break;
          }
          else if(score2 > score1) {
            DEF_LOG("Conflicting with higher score bb: "<<hex<<ptr_bb->start()<<"->"<<hex<<cnf_bb->start());
            Conflicts_.insert(ptr.first);
            removed = true;
            break;
          }
          /*
          else if(ptr.second->source() == PointerSource::GAP_PTR) {
            auto p = ptrMap.find(cnf_bb->start());
            if(p != ptrMap.end() && p->second->source() != PointerSource::GAP_PTR) {
              DEF_LOG("Gap ptr conflicting with any other ptr: "<<hex<<ptr_bb->start()<<"->"<<hex<<cnf_bb->start());
              Conflicts_.insert(ptr.first);
              removed = true;
              break;
            }
          }
          else {
            auto p = ptrMap.find(cnf_bb->start());
            if(p != ptrMap.end() && 
              (p->second->source() == PointerSource::RIP_RLTV ||
               p->second->source() == PointerSource::PIC_RELOC) &&
               p->first > ptr.first) {
              DEF_LOG("Conflicting with RLTV ptr: "<<hex<<ptr_bb->start()<<"->"<<hex<<cnf_bb->start());
              Conflicts_.insert(ptr.first);
              removed = true;
              break;
            }
          }
          */
        }
      }
      /*
      if(removed)
        continue;
      if(removed == false) {
        removed = entryPointCorrection(ptr_bb);
      }
      if(removed == false && ptr.second->source() == PointerSource::GAP_PTR && score1 == 0) {
        DEF_LOG("Gap code with 0 score: "<<hex<<ptr_bb->start());
        Conflicts_.insert(ptr_bb->start());
        continue;
      }
      */
      //if(removed == false && ptr.second->source() == PointerSource::GAP_PTR) {
      //  //Remove all occluded BBs
      //  for(auto i = 1; i <= 4; i++) {
      //    Conflicts_.insert(ptr.first + i);
      //  }
      //}
    }
    //else {
    //  DEF_LOG("Avoiding resolution: "<<hex<<ptr.first<<" source: "<<(int)(ptr.second->source())<<" type: "<<(int)(ptr.second->type()));
    //  if(ptr_bb != NULL) {
    //    DEF_LOG("Ptr bb type: "<<ptr_bb->isCode()<<" property "<<codeByProperty(ptr_bb));
    //  }
    //}
  }
}

void
PointerAnalysis::removeEHConflicts() {
  map <uint64_t, Pointer *> ptrMap = pointers ();
  map <uint64_t, Function *>funMap = funcMap();
  for(auto & fn : funMap) {
    auto entries = fn.second->probableEntry();
    for(auto & entry1 : entries) {
      auto p1 = ptrMap.find(entry1);
      auto bb1 = getBB(entry1);
      if(p1 != ptrMap.end() && p1->second->source() == PointerSource::EHFIRST
         && bb1 != NULL && codeByProperty(bb1)) {
        LOG("Removing conflicts with EH ptr: "<<hex<<p1->first);
        auto seq1 = bbSeq(bb1);
        for(auto & entry2 : entries) {
          if(entry1 != entry2) {
            auto p2 = ptrMap.find(entry2);
            auto bb2 = getBB(entry2); 
            if(p2 != ptrMap.end() && p2->second->source() != PointerSource::EHFIRST
               && bb2 != NULL && codeByProperty(bb2)) {
              auto seq2 = bbSeq(bb2);
              LOG("Checking conflict with: "<<hex<<p2->first);
              if(conflictingSeqs(seq1, seq2)) {
                LOG("Conflicting ptr: "<<hex<<p2->first);
                Conflicts_.insert(entry2);
              }
            }
          }
        }
      }
    }
  }
}

bool
PointerAnalysis::conflictingSeqs(vector <BasicBlock *> &seq1,
                                 vector <BasicBlock *> &seq2) {
  for(auto & b1 : seq1) {
    for(auto & b2 : seq2)
      if(b1->noConflict(b2->start()) == false ||
         b2->noConflict(b1->start()) == false) {
        LOG("Conflicting bbs: "<<hex<<b1->start()<<" "<<b2->start());
        return true;
      }
  }
  return false;
}
