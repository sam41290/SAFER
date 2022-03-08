#include "PointerAnalysis.h"
#include "libutils.h"
#include "manager_constants.h"
#include "Function.h"
#include <fstream>

using namespace SBI;

PointerAnalysis::PointerAnalysis (uint64_t memstrt, uint64_t memend) :
                 CFValidity(memstrt,memend,INSVALIDITY),
                 JmpTblAnalysis(memstrt,memend) {
  propList_ = PROPERTIES;
  //analysis::setup(TOOL_PATH"auto/output.auto");
  //analysis::set_init(1);
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

bool
PointerAnalysis::regPreserved(uint64_t entry,
    vector <BasicBlock *> &fin_bb_list,
    const vector <string> &reg_list) {
  LOG("Checking SP preserved property for: "<<hex<<entry);
  if(validIns(fin_bb_list)) {
    unordered_map<int64_t, vector<int64_t>> ind_tgts;
    checkIndTgts(ind_tgts,fin_bb_list);
    //indTgts(fin_bb_list,ind_tgts);
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
    /*
    if(analysis::load(file_name,ins_sz,ind_tgts,all_entries)) {
      for (int func_index = 0; ; ++func_index) {
         bool valid_func = analysis::analyze(func_index);
         if (valid_func) {
            bool ret = analysis::preserved(reg_list);
            return ret;
         }
         else
            break;
      }
    }
    */
  }
  return false;
}

bool
PointerAnalysis::validInit(uint64_t entry, 
    vector <BasicBlock *> &fin_bb_list) {
  if(validIns(fin_bb_list)) {
    unordered_map<int64_t, vector<int64_t>> ind_tgts;
    checkIndTgts(ind_tgts,fin_bb_list);
    //indTgts(fin_bb_list,ind_tgts);
    dumpIndrctTgt(TOOL_PATH"run/tmp/" + to_string(entry)
        + ".ind",ind_tgts);
    string file_name = TOOL_PATH"run/tmp/" + to_string(entry) + "_" + to_string(counter) + ".s";
    genFnFile(file_name,entry,fin_bb_list);
    unordered_map<int64_t,int64_t> ins_sz = insSizes(fin_bb_list);
    dumpInsSizes(TOOL_PATH"run/tmp/" + to_string(entry) + "_"
        + to_string(counter) + ".sz",ins_sz);
    vector <int64_t> all_entries;
    all_entries.push_back(entry);
    /*
    if(analysis::load(file_name,ins_sz,ind_tgts,all_entries)) {
      for (int func_index = 0; ; ++func_index) {
         bool valid_func = analysis::analyze(func_index);
         if (valid_func) {
            if(analysis::uninit() == 0)
              return true;
         }
         else
            break;
      }
    }
    */
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
setProperty(vector<BasicBlock *> &bb_list, Property p, bool pass) {
  for(auto & bb : bb_list) {
    if(pass) {
      //LOG("Pass property: "<<(int)p<<" bb: "<<hex<<bb->start()<<" "<<bb);
      bb->passedProp(p);
    }
    else {
      //LOG("Fail property: "<<(int)p<<" bb: "<<hex<<bb->start()<<" "<<bb);
      bb->failedProp(p);
    }
  }
}

void
PointerAnalysis::propertyCheck(BasicBlock *entry_bb, vector<BasicBlock *> &bb_list) {
  for(auto & p : propList_) {
    switch (p) {
      case Property::VALIDINS :
        setProperty(bb_list, Property::VALIDINS, validIns(bb_list));
        break;
      case Property::VALID_CF :
        setProperty(bb_list,Property::VALID_CF,validCF(bb_list));
        break;
      case Property::VALIDINIT :
        setProperty(bb_list,Property::VALIDINIT,validInit(entry_bb->start(),bb_list));
        break;
      case Property::SP_PRESERVED :
        setProperty(bb_list,Property::SP_PRESERVED,
                    regPreserved(entry_bb->start(),bb_list, vector<string>{"sp"}));
        break;
      case Property::ABI_REG_PRESERVED :
        setProperty(bb_list,Property::ABI_REG_PRESERVED,
                    regPreserved(entry_bb->start(),bb_list,vector<string>{"sp","bx","bp","r12","r13","r14","r15"}));
        break;
    }
  }
}

unordered_set <uint64_t> resolving_done;

void
PointerAnalysis::resolveNoRetCall(BasicBlock *entry) {
  auto exitCalls = psblExitCalls(entry);
  while(exitCalls.empty() == false) {
    BasicBlock *call_bb = exitCalls.top();
    exitCalls.pop();

    if(call_bb->callType() == BBType::MAY_BE_RETURNING &&
       resolving_done.find(call_bb->start()) == resolving_done.end()) {
      LOG("Resolving possible exit call: "<<hex<<call_bb->start());
      vector <BasicBlock *> fall = bbSeq(call_bb,SEQTYPE::INTRAFN);
      if(entry->isCode()) {
        auto paths_to_call  = pathsFromTo(entry,call_bb);
        paths_to_call.insert(paths_to_call.end(), fall.begin(), fall.end());
        propertyCheck(entry,paths_to_call);
        if(codeByProperty(call_bb)) {
          call_bb->callType(BBType::RETURNING);
          resolving_done.insert(call_bb->start());
        }
      }
      else {
        bool check_pass = true;
        auto all_paths = allPathsTo(call_bb);
        auto fall = bbSeq(call_bb, SEQTYPE::INTRAFN);
        for(auto & p : all_paths) {
          auto path = p.second;
          path.insert(path.end(), fall.begin(), fall.end());
          auto entry_bb = getBB(p.first);
          propertyCheck(entry_bb, path);
          if(codeByProperty(entry_bb) == false) {
            check_pass = false;
            for(auto & bb : path)
              bb->clearProps();
            break;
          }
          for(auto & bb : path)
            bb->clearProps();
        }
        if(check_pass == false) {
          auto fall_path = bbSeq(call_bb->fallThroughBB(),SEQTYPE::INTRAFN);
          propertyCheck(call_bb->fallThroughBB(), fall_path);
          if(dataByProperty(call_bb->fallThroughBB()) ||
             codeByProperty(call_bb->fallThroughBB())) {
            LOG("Marking non-returning: "<<hex<<call_bb->start());
            possibleRAs_.insert(call_bb->fallThrough());
            call_bb->callType(BBType::NON_RETURNING);
            call_bb->fallThrough(0);
            call_bb->fallThroughBB(NULL);
          }
          else
            call_bb->callType(BBType::RETURNING);
        }
        else
          call_bb->callType(BBType::RETURNING);
        resolving_done.insert(call_bb->start());
      }
    }
  }
}

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

void
PointerAnalysis::classifyPsblFn(Function *fn) {
  set <uint64_t> def_entries = fn->entryPoints();
  set <uint64_t> possibleEntries = fn->probableEntry();
  set <uint64_t> allEntries;
  allEntries.insert(possibleEntries.begin(), possibleEntries.end());
  allEntries.insert(def_entries.begin(), def_entries.end());
  set <uint64_t> invalidPtrs = invalidPtr();
  for(auto & entry : allEntries) {
    LOG("Analyzing function entry: "<<hex<<entry);
    if(invalidPtrs.find(entry) == invalidPtrs.end() /*&& entry == 0xf6890*/) {
      auto bb = fn->getBB(entry);
      if(bb == NULL)
        LOG("No BB: "<<hex<<entry);
      else {
        vector <BasicBlock *> lst = bbSeq(bb, SEQTYPE::INTRAFN);
        counter = 0;
        if(hasPossibleCode(lst)) {
          propertyCheck(bb,lst);
          if(codeByProperty(bb))
            LOG("Validity check passed!!");
          //else if(dataByProperty(bb) == false && resolvePossiblyExits(bb,bb))
          //  LOG("Validity check passed!!");
          else
            LOG("Property check failed: "<<hex<<entry);
        }
      }
    }
    else
      LOG("Invalid entry point: "<<hex<<entry);
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

void
PointerAnalysis::validateIndTgts(vector <BasicBlock *> &entry_lst, BasicBlock *entry_bb,
                                 BasicBlock *ind_bb) {
  LOG("Validating jump table target: "<<hex<<ind_bb->start());
  auto ind_seq = bbSeq(ind_bb);
  entry_lst.insert(entry_lst.end(), ind_seq.begin(), ind_seq.end());
  propertyCheck(entry_bb, entry_lst);
  if(codeByProperty(ind_bb)) {
    for(auto & bb : ind_seq) {
      auto inds = bb->indirectTgts();
      if(inds.size() > 0) {
        for(auto & ind_bb2 : inds) {
          if(codeByProperty(ind_bb2) == false) {
            vector <BasicBlock *> bb_list = entry_lst;
            validateIndTgts(bb_list, entry_bb, ind_bb2);
          }
        }
      }
    }
  }
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
    if(entry_bb != NULL && (entry_bb->isCode() || codeByProperty(entry_bb))) {
      entry_bb_lst.push_back(entry_bb);
    }
  }

  
  for(auto & p : possibleRAs_) {
    auto bb = fn->getBB(p);
    if(bb != NULL && codeByProperty(bb)) {
      entry_bb_lst.push_back(bb);
    }
  }

/*
  for(auto & e : entry_bb_lst) {
    LOG("Validating jump table target for entry: "<<hex<<e->start());
    auto bb_list = bbSeq(e);
    for(auto & bb : bb_list) {
      auto inds = bb->indirectTgts();
      if(inds.size() > 0) {
        for(auto & ind_bb : inds) {
          if(codeByProperty(ind_bb) == false) {
            vector <BasicBlock *> entry_lst = bb_list;
            validateIndTgts(entry_lst, e, ind_bb);
          }
        }
      }
    }
  }
*/
  auto ind_tgts = allIndTgts(entry_bb_lst);
  unordered_set <BasicBlock *> ind_set;
  ind_set.insert(ind_tgts.begin(),ind_tgts.end());

  for(auto & tgt : ind_set) {
    LOG("Validating jump table target: "<<hex<<tgt->start());
    auto bb_lst = bbSeq(tgt);
    if(validIns(bb_lst)) {
      if(codeByProperty(tgt) == false) {
        for(auto & e : entry_bb_lst) {
          auto exit_routes = allRoutes(e, tgt);
          if(exit_routes.size() > 0) {
            LOG("Validating with entry: "<<hex<<e->start());
            propertyCheck(e,exit_routes);
            if(codeByProperty(tgt))
              break;
          }
        }
      }
    }
    else
      setProperty(bb_lst, Property::VALIDINS, false);
  }

}

void
PointerAnalysis::jmpTblConsistency() {
  map <uint64_t, Function *>funMap = funcMap();

  for(auto & fn : funMap) {
    filterJmpTblTgts(fn.second);
  }
/*
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
*/
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
    if(codeByProperty(bb_list[i])) {
      auto j = i + 1;
      while(j < bb_cnt && bb_list[i]->boundary() > bb_list[j]->start()) {
        if(bb_list[i]->noConflict(bb_list[j]->start()) == false) {
          if(codeByProperty(bb_list[j]))
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
          if(codeByProperty(cnf))
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
    //b1->CFConsistency(CFStatus::INCONSISTENT,Update::TRANSITIVE);
    b1->conflict(ConflictStatus::CONFLICT,b2->start());
    b2->conflict(ConflictStatus::NOCONFLICT,b1->start());
  }
  else if(b1->start() > b2->start() && if_exists(b1->start(),ptr_map)
     && ptr_map[b1->start()]->type() == PointerType::DEF_PTR) {
    conflictingBBs_.erase(b1->start());
    conflictingBBs_.insert(b2->start());
    //b2->CFConsistency(CFStatus::INCONSISTENT,Update::TRANSITIVE);
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
    //b2->CFConsistency(CFStatus::INCONSISTENT,Update::TRANSITIVE);
    b1->conflict(ConflictStatus::NOCONFLICT,b2->start());
    b2->conflict(ConflictStatus::CONFLICT,b1->start());
  }
  else if(hasSymbolizableRoot(b2) && !(hasSymbolizableRoot(b1))) {
    conflictingBBs_.erase(b2->start());
    conflictingBBs_.insert(b1->start());
    //b1->CFConsistency(CFStatus::INCONSISTENT,Update::TRANSITIVE);
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
/*
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
*/

bool
PointerAnalysis::codeByProperty(BasicBlock *bb) {
  auto passed_props = bb->passedProps();
  for(auto & p : passed_props) {
    if(DEFCODE(p)) {
      return true;
    }
  }
  return false;
}

bool
PointerAnalysis::dataByProperty(BasicBlock *bb) {
  //LOG("Checking if data: "<<hex<<bb->start());
  auto failed_props = bb->failedProps();
  for(auto & p : failed_props) {
    if(DEFDATA(p)) {
      //LOG("Definitely data by property: "<<(int)p<<" bb: "<<hex<<bb->start()<<" "<<bb);
      return true;
    }
  }
  return false;
}

void
PointerAnalysis::classifyEntry(uint64_t entry) {
  auto bb = getBB(entry);
  if(bb != NULL) {
    vector <BasicBlock *> lst = bbSeq(bb,SEQTYPE::INTRAFN);
    for(auto & bb2 : lst) {
      if(bb2->isCode() == false) {
        if(dataByProperty(bb2))
          markAsDefData(bb2->start());
        else if(codeByProperty(bb2))
          markAsDefCode(bb2->start());
      }
    }
  }
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
        auto lst = bbSeq(tgt);
        for(auto & bb2 : lst) {
          classifyEntry(bb2->start());
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
PointerAnalysis::classifyPossibleRAs() {
  map <uint64_t, Pointer *> ptrMap = pointers ();
  map <uint64_t, Function *>funMap = funcMap();
  for(auto & p : ptrMap)
    if(p.second->source() == PointerSource::POSSIBLE_RA)
      possibleRAs_.insert(p.second->address());

  for(auto & p : possibleRAs_) {
    auto bb = getBB(p);
    if(bb != NULL) {
      auto bb_list = bbSeq(bb);
      propertyCheck(bb,bb_list);
    }
  }

  for(auto & fn : funMap) {
    auto psbl_code_lst = fn.second->getUnknwnCode();
    for(auto & bb : psbl_code_lst) {
      if(bb->source() == PointerSource::POSSIBLE_RA &&
         codeByProperty(bb) == false) {
        auto bb_list = bbSeq(bb);
        propertyCheck(bb,bb_list);
        possibleRAs_.insert(bb->start());
      }
    }
  }
}

void
PointerAnalysis::cfgConsistencyAnalysis() {
  LOG("Checking CF consistency");
  propagateAllRoots();
  updateBBTypes();

  resolveAllNoRetCalls();

  map <uint64_t, Function *>funMap = funcMap();
  for(auto & fn : funMap)
    classifyPsblFn(fn.second);
  classifyPossibleRAs(); 
  jmpTblConsistency();
  resolveAndClassify(ResolutionType::NONE);
  for(auto & p : possibleRAs_) {
    classifyEntry(p);
  }
}



