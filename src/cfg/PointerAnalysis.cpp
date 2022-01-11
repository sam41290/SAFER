#include "PointerAnalysis.h"
#include "libutils.h"
#include "manager_constants.h"
#include "Function.h"
#include <fstream>

using namespace SBI;

PointerAnalysis::PointerAnalysis (uint64_t memstrt, uint64_t memend) :
                 CFValidity(memstrt,memend,INSVALIDITY),
                 JmpTblAnalysis(memstrt,memend){}

set <string> calleeSaved{"%r12", "%r13", "%r14", "%r15", "%rbx", "%rsp",
       "%rbp"};


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
  return ptr->symbolizable(SymbolizeIf::ALIGNEDCONST);
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
    return true; //No Pointer means directly reached function. No need to check
                 //symbolizable criteria.

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

bool
PointerAnalysis::regPreserved(uint64_t entry,
    vector <BasicBlock *> fin_bb_list,
    const vector <string> &reg_list) {
  LOG("Checking SP preserved property for: "<<hex<<entry);
  if(validIns(fin_bb_list)) {
    unordered_map<int64_t, vector<int64_t>> ind_tgts;
    indTgts(fin_bb_list,ind_tgts);
    dumpIndrctTgt(TOOL_PATH"run/tmp/" + to_string(entry)
        + ".ind",ind_tgts);
    string file_name = TOOL_PATH"run/tmp/" + to_string(entry) + "_" + to_string(counter) + ".s";
    genFnFile(file_name,entry,fin_bb_list);
    unordered_map<int64_t,int64_t> ins_sz = insSizes(fin_bb_list);
    dumpInsSizes(TOOL_PATH"run/tmp/" + to_string(entry) + "_"
        + to_string(counter) + ".sz",ins_sz);
    vector <int64_t> all_entries;
    all_entries.push_back(entry);
    LOG("indirect targets size: "<<ind_tgts.size());
    //if(analysis::load(file_name,ins_sz,ind_tgts,all_entries)) {
    //  bool ret = analysis::preserved(reg_list);
    //  analysis::reset();
    //  return ret;
    //}
  }
  return false;
}

bool
PointerAnalysis::validInit(uint64_t entry, 
    vector <BasicBlock *> fin_bb_list) {
  if(validIns(fin_bb_list)) {
    unordered_map<int64_t, vector<int64_t>> ind_tgts;
    indTgts(fin_bb_list,ind_tgts);
    dumpIndrctTgt(TOOL_PATH"run/tmp/" + to_string(entry)
        + ".ind",ind_tgts);
    string file_name = TOOL_PATH"run/tmp/" + to_string(entry) + "_" + to_string(counter) + ".s";
    genFnFile(file_name,entry,fin_bb_list);
    unordered_map<int64_t,int64_t> ins_sz = insSizes(fin_bb_list);
    dumpInsSizes(TOOL_PATH"run/tmp/" + to_string(entry) + "_"
        + to_string(counter) + ".sz",ins_sz);
    vector <int64_t> all_entries;
    all_entries.push_back(entry);
    //if(analysis::load(file_name,ins_sz,ind_tgts,all_entries)) {
    //  unordered_set<string> invalid_init = analysis::invalid_regs();
    //  analysis::reset();
    //  if(invalid_init.size() > 0)
    //    return false;
    //  return true;
    //}
  }
  return false;
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
hasPossibleCode(vector <BasicBlock *> &bb_list) {
  for(auto & bb : bb_list) {
    if(bb->isCode() == false) {
      //LOG("Possible code found: "<<hex<<bb->start());
      return true;
    }
  }
  return false;
}

void
PointerAnalysis::resolvePossiblyExits(BasicBlock *bb) {
  LOG("Resolving possible exit calls for function entry: "<<hex<<bb->start());
  auto exitCalls = psblExitCalls(bb);
  LOG("Obtained all possible exit calls");
  map <uint64_t, Pointer *> ptr_map = pointers();
  while(exitCalls.empty() == false) {
    BasicBlock *call_bb = exitCalls.top();
    exitCalls.pop();
    LOG("Resolving possible exit call: "<<hex<<call_bb->start());
    vector <pair<uint64_t,vector <BasicBlock *>>> all_paths
      = allPathsTo(call_bb);
    LOG("Obtained all paths");
    vector <BasicBlock *> fall = bbSeq(call_bb,SEQTYPE::INTRAFN);
    LOG("Obtained all fall through paths");
    for(auto & lst : all_paths) {
      if(lst.second.size() > 0) {
        lst.second.insert(lst.second.end(),fall.begin(),fall.end());
        if(FNCHECK(getBB(lst.first),lst.second)) {
          call_bb->callType(BBType::RETURNING);
          break;
        }
      }
    }
    if(call_bb->callType() == BBType::MAY_BE_RETURNING) {
      //check if it has a jump table root

      auto roots = call_bb->roots();
      for(auto & r : roots) {
        if(if_exists(r->start(),ptr_map) &&
           ptr_map[r->start()]->symbolizable(SymbolizeIf::JMP_TBL_TGT)) {
          vector <BasicBlock *> bb_list = path(r,call_bb,SEQTYPE::INTRAFN);
          if(bb_list.size() > 0 && validCF(bb_list)) {
            call_bb->callType(BBType::RETURNING);
            break;
          }
        }
      }
      if(call_bb->callType() == BBType::MAY_BE_RETURNING) {
        LOG("Marking non-returning: "<<hex<<call_bb->start());
        call_bb->callType(BBType::NON_RETURNING);
        call_bb->fallThrough(0);
        call_bb->fallThroughBB(NULL);
      }
    }
  }

}

void
PointerAnalysis::classifyPsblFn(Function *fn) {
  set <uint64_t> possibleEntries = fn->probableEntry();
  set <uint64_t> defEntries = fn->entryPoints();
  set <uint64_t> allEntries;
  allEntries.insert(defEntries.begin(),defEntries.end());
  allEntries.insert(possibleEntries.begin(), possibleEntries.end());
  set <uint64_t> invalidPtrs = invalidPtr();
  for(auto & entry : allEntries) {
    LOG("Analyzing function entry: "<<hex<<entry);
    if(invalidPtrs.find(entry) == invalidPtrs.end() /*&& entry == 0xf6890*/) {
      auto bb = fn->getBB(entry);
      if(bb == NULL)
        LOG("No BB: "<<hex<<entry);
      else {
        if(bb->CFConsistency() != CFStatus::NOT_EXAMINED) {
          LOG("Function entry pre-validated");
          continue;
        }
        //resolvePossiblyExits(bb);
        vector <BasicBlock *> lst = bbSeq(bb,SEQTYPE::INTRAFN);
        counter = 0;
        if(hasPossibleCode(lst)) {
          if(FNCHECK(bb,lst)) {
            LOG("Validity check passed!!");
            fn->passedPropertyCheck(entry,true);
          }
          else {
            LOG("Valid code criteria certification failed: "<<hex<<entry);
            fn->passedPropertyCheck(entry,false);
          }
        }
      }
    }
    else
      LOG("Invalid entry point: "<<hex<<entry);
  }
}


void
PointerAnalysis::jmpTblConsistency() {
  map <uint64_t, Function *>funMap = funcMap();
  auto jmp_tbls = jumpTables();
  for(auto & j : jmp_tbls) {
    vector <BasicBlock *> targets = j.targetBBs();
    for(auto & tgt : targets) {
      LOG("Validating jump table target: "<<hex<<tgt->start());
      if(tgt->isCode()) {
        LOG("Target is pre-marked def code");
        continue;
      }
      if(tgt->jmpTblConsistency() == CFStatus::INCONSISTENT) {
        LOG("Target pre-marked inconsistent");
        continue;
      }
      auto tgt_fn = is_within(tgt->start(),funMap);
      if(tgt_fn->first != j.function()) {
        LOG("Jump table target: "<<hex<<tgt->start()<<" out of function "<<hex<<j.function());
        continue;
      }
      if(tgt->CFConsistency() != CFStatus::NOT_EXAMINED)
        continue;
      else {
        vector <BasicBlock *> lst = bbSeq(tgt,SEQTYPE::INTRAFN);
        if(validCF(lst)) {
          tgt->CFConsistency(CFStatus::CONSISTENT,TRANSITIVECF);
          tgt->jmpTblConsistency(CFStatus::CONSISTENT);
        }
        else {
          tgt->CFConsistency(CFStatus::INCONSISTENT,TRANSITIVECF);
          tgt->jmpTblConsistency(CFStatus::INCONSISTENT);
          LOG("Invalid jump table target: "<<hex<<tgt->start());
        }
      }
    }
  }
}

vector <pair<uint64_t,uint64_t>>
PointerAnalysis::conflicts(Function *fn1, Function *fn2) {
  vector <pair<uint64_t,uint64_t>> all_conflicts;
  vector <BasicBlock *> lst1 = fn1->getUnknwnCode();
  vector <BasicBlock *> lst2 = fn2->getUnknwnCode();
  for(auto & b1 : lst1) {
    for(auto & b2 : lst2) {
      if(b1->start() > b2->start() && b1->start() < b2->boundary()
         && b2->isValidIns(b1->start()) == false)
        all_conflicts.push_back(make_pair(b1->start(),b2->start()));
      else if(b2->start() > b1->start() && b2->start() < b1->boundary()
         && b1->isValidIns(b2->start()) == false)
        all_conflicts.push_back(make_pair(b1->start(),b2->start()));

    }
  }
  return all_conflicts;
}

void
PointerAnalysis::resolveConflict(uint64_t p1, uint64_t p2) {
  LOG("Resolving conflict: P1-"<<hex<<p1<<" P2-"<<hex<<p2);
  map <uint64_t, Function *>funMap = funcMap();
  map <uint64_t, Pointer *> ptr_map = pointers();
  auto bb1 = getBB(p1);
  auto bb2 = getBB(p2);

  auto roots1 = bb1->roots(); //getRoots(bb1);
  auto roots2 = bb2->roots(); //getRoots(bb2);;
  LOG("P1 roots count: "<<roots1.size());
  LOG("P2 roots count: "<<roots2.size());
  if(p1 < p2) {
    for(auto & r : roots2) {
      //LOG("Root: "<<hex<<r->start());
      if(if_exists(r->start(),ptr_map) 
         && ptr_map[r->start()]->type() == PointerType::DEF_PTR) {
        LOG("P2 has def ptr root "<<hex<<r->start()); 
        for(auto & r2 : roots1) {
          auto fn = is_within(r2->start(),funMap);
          LOG("Marking root invalid: "<<hex<<r2->start());
          fn->second->passedPropertyCheck(r2->start(),false);
          r2->jmpTblConsistency(CFStatus::INCONSISTENT);
        }
        break;
      }
    }
  }
  else if(p1 > p2) {
    for(auto & r : roots1) {
      //LOG("Root: "<<hex<<r->start());
      if(if_exists(r->start(),ptr_map) 
         && ptr_map[r->start()]->type() == PointerType::DEF_PTR) {
        LOG("P1 has def ptr root "<<hex<<r->start());
        for(auto & r2 : roots2) {
          LOG("Marking root invalid: "<<hex<<r2->start());
          auto fn = is_within(r2->start(),funMap);
          fn->second->passedPropertyCheck(r2->start(),false);
          r2->jmpTblConsistency(CFStatus::INCONSISTENT);
        }
        break;
      }
    }
  }

}

void
PointerAnalysis::spatialIntegrity() {
  map <uint64_t, Function *>funMap = funcMap();

  for(auto & fn : funMap) {
    vector <pair<uint64_t,uint64_t>> all_conflicts = conflicts(fn.second,fn.second);
    for(auto & c : all_conflicts)
      resolveConflict(c.first,c.second);
    auto fn_it = next_iterator(fn.first,funMap);
    if(fn_it != funMap.end()) {
      vector <pair<uint64_t,uint64_t>> all_conflicts = conflicts(fn.second,fn_it->second);
      for(auto & c : all_conflicts)
        resolveConflict(c.first,c.second);
    }
  }

}

void
PointerAnalysis::resolveAllPossibleExits() {
  map <uint64_t, Function *>funMap = funcMap();
//Resolve all possibly exiting calls
  for(auto & fn : funMap) {
    set <uint64_t> possibleEntries = fn.second->probableEntry();
    set <uint64_t> defEntries = fn.second->entryPoints();
    set <uint64_t> allEntries;
    allEntries.insert(defEntries.begin(),defEntries.end());
    allEntries.insert(possibleEntries.begin(), possibleEntries.end());
    for(auto & e : allEntries) {
      auto bb = getBB(e);
      if(bb != NULL) {
        vector <BasicBlock *> lst = bbSeq(bb,SEQTYPE::INTRAFN);
        if(hasPossibleCode(lst)) {
          resolvePossiblyExits(bb);
          if(bb->isCode())
            fn.second->passedPropertyCheck(e,true);
        }
      }
    }
  }
}

void
PointerAnalysis::classifyCode() {
  map <uint64_t, Function *>funMap = funcMap();
  for(auto & fn : funMap) {
    vector <uint64_t> valid_entries = fn.second->allValidEntries();
    for(auto & e : valid_entries) {
      if(fn.second->validEntry(e)) {
        vector <BasicBlock *> lst = bbSeq(getBB(e),SEQTYPE::INTRAFN);
        for(auto & bb2 : lst)
          markAsDefCode(bb2->start());
      }
    }
  }
}

void
PointerAnalysis::cfgConsistencyAnalysis() {
  LOG("Checking CF consistency");
  propagateAllRoots();
  resolveAllPossibleExits();

  //After resolving all possible exit calls, mark all code reachable from known
  //code pointers as definite code
  classifyCode(); 

  //re-classify pointers to get more definite pointers

  classifyPtrs();

  spatialIntegrity();
  map <uint64_t, Function *>funMap = funcMap();
  for(auto & fn : funMap)
    classifyPsblFn(fn.second);
  jmpTblConsistency();
  classifyCode();
  auto jmp_tbls = jumpTables();
  for(auto & j : jmp_tbls) {
    vector <BasicBlock *> targets = j.targetBBs();
    for(auto & tgt : targets) {
      if(tgt->CFConsistency() == CFStatus::CONSISTENT) {
        //LOG("Marking jump table target as def code: "<<hex<<tgt->start());
        vector <BasicBlock *> lst = bbSeq(tgt);
        for(auto & bb2 : lst) {
          //LOG("BB: "<<hex<<bb2->start());
          markAsDefCode(bb2->start());
        }
      }
    }
  }
}



