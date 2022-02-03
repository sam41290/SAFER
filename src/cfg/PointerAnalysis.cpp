#include "PointerAnalysis.h"
#include "libutils.h"
#include "manager_constants.h"
#include "Function.h"
#include <fstream>

using namespace SBI;

PointerAnalysis::PointerAnalysis (uint64_t memstrt, uint64_t memend) :
                 CFValidity(memstrt,memend,INSVALIDITY),
                 JmpTblAnalysis(memstrt,memend) {
  //analysis::setup();
}

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
  if(bb != NULL && bb->CFConsistency() == CFStatus::CONSISTENT)
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
    //  for (int func_index = 0; ; ++func_index) {
    //     bool valid_func = analysis::analyze(func_index);
    //     if (valid_func) {
    //        bool ret = analysis::preserved(reg_list);
    //        return ret;
    //     }
    //     else
    //        break;
    //  }
    //  //analysis::reset();
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
    //  //unordered_set<string> invalid_init = analysis::invalid_regs();
    //  ////analysis::reset();
    //  //if(invalid_init.size() > 0)
    //  //  return false;
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
  //set <uint64_t> defEntries = fn->entryPoints();
  set <uint64_t> allEntries;
  //allEntries.insert(defEntries.begin(),defEntries.end());
  allEntries.insert(possibleEntries.begin(), possibleEntries.end());
  set <uint64_t> invalidPtrs = invalidPtr();
  //bool resolved = true;
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
  //return resolved;
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

void
PointerAnalysis::filterJmpTblTgts(Function *fn) {
  auto bb_list = fn->getDefCode();
  auto bb_list2 = fn->getUnknwnCode();
  bb_list.insert(bb_list.end(),bb_list2.begin(),bb_list2.end());

  set <uint64_t> possibleEntries = fn->probableEntry();
  set <uint64_t> defEntries = fn->entryPoints();
  set <uint64_t> allEntries;
  allEntries.insert(defEntries.begin(),defEntries.end());
  allEntries.insert(possibleEntries.begin(), possibleEntries.end());
  for(auto & bb : bb_list) {
    auto ind_tgts = bb->indirectTgts();
    BasicBlock *prev_bb = NULL;
    for(auto & ind_bb : ind_tgts) { 
      auto ind_seq = bbSeq(ind_bb);
      LOG("Validating indirect target: "<<hex<<ind_bb->start());
      bool valid_entry = false;
      for (auto & e : allEntries) {
        LOG("Entry: "<<hex<<e);
        auto entry_bb = getBB(e);
        if(entry_bb != NULL) {
          auto entry_seq = bbSeq(entry_bb);
          if(conflictingSeqs(entry_seq,ind_seq) == false) {
            valid_entry = true;
            break;
          }
          else
            LOG("conflicts with entry");
        }
      }
      if(valid_entry == false) {
        LOG("Invalid jump table target (entry collision): "<<hex<<ind_bb->start());
        ind_bb->CFConsistency(CFStatus::INCONSISTENT,TRANSITIVECF);
        ind_bb->jmpTblConsistency(CFStatus::INCONSISTENT);
      }
      else if(prev_bb != NULL &&
             (prev_bb->noConflict(ind_bb->start()) == false || 
              ind_bb->noConflict(prev_bb->start()) == false)) {
        LOG("Invalid jump table target (prev tgt collision): "<<hex<<ind_bb->start());
        ind_bb->CFConsistency(CFStatus::INCONSISTENT,TRANSITIVECF);
        ind_bb->jmpTblConsistency(CFStatus::INCONSISTENT);
      }
      else
        prev_bb = ind_bb;

    }
  }
}

void
PointerAnalysis::jmpTblConsistency() {
  map <uint64_t, Function *>funMap = funcMap();

  for(auto & fn : funMap) {
    filterJmpTblTgts(fn.second);
  }

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
PointerAnalysis::getConflicts(uint64_t fn_start,Function *fn) {
  map <uint64_t, Function *>funMap = funcMap();
  vector <pair<uint64_t,uint64_t>> all_conflicts;
  auto bb_list = fn->getUnknwnCode();
  unsigned int bb_cnt = bb_list.size();
  LOG("Function: "<<hex<<fn_start);
  auto next_it = next_iterator(fn_start,funMap);
  for(unsigned int i = 0; i < bb_cnt; i++) {
    if(bb_list[i]->CFConsistency() != CFStatus::INCONSISTENT) {
      auto j = i + 1;
      while(j < bb_cnt && bb_list[i]->boundary() > bb_list[j]->start()) {
        if(bb_list[i]->noConflict(bb_list[j]->start()) == false) {
          if(bb_list[j]->CFConsistency() != CFStatus::INCONSISTENT)
            all_conflicts.push_back(make_pair(bb_list[i]->start(),bb_list[j]->start()));
          else
            bb_list[i]->conflict(ConflictStatus::NOCONFLICT,bb_list[j]->start());
        }
        j++;
      }
      auto it = next_it;
      while(it != funMap.end() && bb_list[i]->boundary() > it->first) {
        auto cnflcts = next_it->second->conflictingBBs(bb_list[i]->boundary());
        for(auto & cnf : cnflcts) {
          if(cnf->CFConsistency() != CFStatus::INCONSISTENT)
            all_conflicts.push_back(make_pair(bb_list[i]->start(),cnf->start()));
          else
            bb_list[i]->conflict(ConflictStatus::NOCONFLICT,cnf->start());
        }
        it++;
      }
    }
  }
  return all_conflicts;
}

void
PointerAnalysis::resolveConflict(ResolutionType t) {
  if(t == ResolutionType::NONE)
    return;
  map <uint64_t, Function *>funMap = funcMap();
  for(auto & fn : funMap) {
    LOG("Finding conflicts in function: "<<hex<<fn.first);
    vector <pair<uint64_t,uint64_t>> all_conflicts = getConflicts(fn.first,fn.second);
    for(auto & cf : all_conflicts) {
      LOG("Resolving conflict: "<<hex<<cf.first<<"-"<<cf.second);
      RESOLVE(t,getBB(cf.first),getBB(cf.second));
    }
  }
}

void
PointerAnalysis::spatialResolver(BasicBlock *b1, BasicBlock *b2) {
  map <uint64_t, Pointer *> ptr_map = pointers();
  if(b2->start() > b1->start() && if_exists(b2->start(),ptr_map)
     && ptr_map[b2->start()]->type() == PointerType::DEF_PTR) {
    conflictingBBs_.erase(b2->start());
    conflictingBBs_.insert(b1->start());
    b1->CFConsistency(CFStatus::INCONSISTENT,Update::TRANSITIVE);
    b1->conflict(ConflictStatus::CONFLICT,b2->start());
    b2->conflict(ConflictStatus::NOCONFLICT,b1->start());
  }
  else if(b1->start() > b2->start() && if_exists(b1->start(),ptr_map)
     && ptr_map[b1->start()]->type() == PointerType::DEF_PTR) {
    conflictingBBs_.erase(b1->start());
    conflictingBBs_.insert(b2->start());
    b2->CFConsistency(CFStatus::INCONSISTENT,Update::TRANSITIVE);
    b1->conflict(ConflictStatus::NOCONFLICT,b2->start());
    b2->conflict(ConflictStatus::CONFLICT,b1->start());
  }
  else {
    LOG("Cannot resolve spatial integrity: "<<hex<<b1->start()<<" "<<b2->start());
    conflictingBBs_.insert(b1->start());
    conflictingBBs_.insert(b2->start());
    b1->conflict(ConflictStatus::CONFLICT,b2->start());
    b2->conflict(ConflictStatus::CONFLICT,b1->start());
  }
}

bool
PointerAnalysis::hasSymbolizableRoot(BasicBlock *b) {
  auto roots = b->roots();
  for(auto & r : roots)
    if(SYMBOLIZABLE(r)) {
      LOG("BB: "<<hex<<b->start()<<" symbolizable root: "<<hex<<r->start());
      return true;
    }
  return false;
}

void
PointerAnalysis::symbolizabilityResolver(BasicBlock *b1, BasicBlock *b2) {
  if(hasSymbolizableRoot(b1) && !(hasSymbolizableRoot(b2))) {
    conflictingBBs_.erase(b1->start());
    conflictingBBs_.insert(b2->start());
    b2->CFConsistency(CFStatus::INCONSISTENT,Update::TRANSITIVE);
    b1->conflict(ConflictStatus::NOCONFLICT,b2->start());
    b2->conflict(ConflictStatus::CONFLICT,b1->start());
  }
  else if(hasSymbolizableRoot(b2) && !(hasSymbolizableRoot(b1))) {
    conflictingBBs_.erase(b2->start());
    conflictingBBs_.insert(b1->start());
    b1->CFConsistency(CFStatus::INCONSISTENT,Update::TRANSITIVE);
    b1->conflict(ConflictStatus::CONFLICT,b2->start());
    b2->conflict(ConflictStatus::NOCONFLICT,b1->start());
  }
  else {
    conflictingBBs_.insert(b1->start());
    conflictingBBs_.insert(b2->start());
    b1->conflict(ConflictStatus::CONFLICT,b2->start());
    b2->conflict(ConflictStatus::CONFLICT,b1->start());
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
        auto bb = getBB(e);
        if(bb != NULL && bb->conflict() != ConflictStatus::CONFLICT) {
          LOG("Marking entry as defcode: "<<hex<<e);
          vector <BasicBlock *> lst = bbSeq(bb,SEQTYPE::INTRAFN);
          for(auto & bb2 : lst)
            markAsDefCode(bb2->start());
        }
      }
    }
  }
}

void
PointerAnalysis::resolveAndClassify(ResolutionType t) {
  int ctr = 0;
  resolveConflict(t);
  while(true) {
    unsigned int sz = conflictingBBs_.size();
    LOG("Classifying code rep: "<<ctr<<" resolution: "<<(int)t<<" conflict count: "<<conflictingBBs_.size());
    classifyCode();
    auto jmp_tbls = jumpTables();
    for(auto & j : jmp_tbls) {
      vector <BasicBlock *> targets = j.targetBBs();
      for(auto & tgt : targets) {
        if(tgt->isCode() == false && tgt->CFConsistency() == CFStatus::CONSISTENT
           && tgt->conflict() != ConflictStatus::CONFLICT) {
          LOG("Marking jmp tbl tgt as defcode: "<<hex<<tgt->start());
          auto lst = bbSeq(tgt);
          for(auto & bb2 : lst) {
            markAsDefCode(bb2->start());
          }
        }
      }
    }
    classifyPtrs();
    resolveConflict(t);
    LOG("Conflicting BB count: "<<conflictingBBs_.size());
    if(sz == conflictingBBs_.size())
      break;
    ctr++;
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
  map <uint64_t, Function *>funMap = funcMap();
  for(auto & fn : funMap)
    classifyPsblFn(fn.second);
  jmpTblConsistency();
  resolveAndClassify(ResolutionType::SPATIAL);
  resolveAndClassify(ResolutionType::SYMBOLIZABILITY);
}



