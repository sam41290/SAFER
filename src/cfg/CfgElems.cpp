#include "CfgElems.h"
#include "CFValidity.h"
#include "disasm.h"
#include <math.h>
#include "PointerAnalysis.h"
using namespace SBI;

//bool 
//CfgElems::rewritableJmpTbl(JumpTable &j) {
//
//  return true;
//}


vector <string>
CfgElems::allReturnSyms() {
  vector <string> ra_syms;
  unordered_set <uint64_t> added;
  for(auto & fn : funcMap_) {
    auto bb_list = fn.second->getDefCode();
    for(auto & bb : bb_list) {
      if(bb->lastIns()->isCall() && added.find(bb->start()) == added.end()) {
        ra_syms.push_back(bb->fallSym());
        added.insert(bb->start());
      }
    }
    bb_list = fn.second->getUnknwnCode();
    for(auto & bb : bb_list) {
      if(bb->lastIns()->isCall() && added.find(bb->start()) == added.end()) {
        ra_syms.push_back(bb->fallSym());
        added.insert(bb->start());
      }
    }
  }
  return ra_syms;
}

unordered_map <uint64_t,string>
CfgElems::allReturnAddresses() {
  unordered_map <uint64_t,string> ra_set;
  for(auto & fn : funcMap_) {
    auto fn_ra_set = fn.second->allReturnAddresses();
    for(auto & f : fn_ra_set) {
      ra_set[f.first] = f.second;
    }
  }
  return ra_set;
}

string
CfgElems::shStkTramps() {
  unordered_map <uint64_t, string> bb_tramp_map;
  string tramps = "";
  for(auto & fn : funcMap_) {
    auto bb_list = fn.second->getDefCode();
    for(auto & bb : bb_list) {
      if(bb->alreadyInstrumented(InstPoint::SHSTK_FUNCTION_TRAMP)) {
        tramps += bb->shStkTrampSym() + ":\n";
        tramps += bb->directCallShstkTramp();
        tramps += "jmp " + bb->label() + "\n";
      }
    }
    bb_list = fn.second->getUnknwnCode();
    for(auto & bb : bb_list) {
      if(bb->alreadyInstrumented(InstPoint::SHSTK_FUNCTION_TRAMP)) {
        tramps += bb->shStkTrampSym() + ":\n";
        tramps += bb->directCallShstkTramp();
        tramps += "jmp " + bb->label() + "\n";
      }
    }
  }
  return tramps;
}

bool
CfgElems::sameLocDiffBase(uint64_t loc, uint64_t base) {
  for(auto & j : jmpTables_)
    if(j.location() == loc && j.base() != base) {
      DEF_LOG("Same location different base: "<<hex<<j.location());
      return true;
    }
  return false;
}

bool
CfgElems::otherUseOfJmpTbl(JumpTable &j) {
  DEF_LOG("Checking other use for: "<<hex<<j.location());
  auto cf_loc = j.cfLoc();
  int cnt = 0;
  unordered_set <uint64_t> cf_set;
  for(auto c : cf_loc) {
    if(cf_set.find(c) == cf_set.end()) {
      cf_set.insert(c);
      cnt++;
    }
    if(cnt > 1)
      return true;
  }
  auto loc_ptr = ptr(j.location());
  if(loc_ptr != NULL) {
    auto sym_candidates = loc_ptr->symCandidate();
    for(auto & s : sym_candidates) {
      if(s.type() == SymbolType::RLTV) {
        auto loc = s.location();
        auto loc_bb = withinBB(loc);
        if(loc_bb != NULL) {
          auto cf_bbs = j.cfBBs();
          for(auto & bb : cf_bbs) {
            if(checkPath(loc_bb,bb)) {
              DEF_LOG("Path to cf bb found: "<<hex<<bb->start());
              return false;
            }
          }
          DEF_LOG("Other use for jump table: "<<hex<<j.location());
          return true;
        }
      }
    }
  }
  return false;
}

void
CfgElems::chkJmpTblRewritability() {
#ifdef STATIC_TRANS
  for(auto & j : jmpTables_) {
    auto loc_ptr = ptr(j.location());
    auto base_ptr = ptr(j.base());
    if(j.type() == 2 || j.type() == 3 || loc_ptr == NULL || 
       base_ptr == NULL || sameLocDiffBase(j.location(),j.base()) ||
      (type_ == exe_type::NOPIE && (loc_ptr->symbolizable(SymbolizeIf::IMMOPERAND) || 
                                    base_ptr->symbolizable(SymbolizeIf::IMMOPERAND)))) {
      DEF_LOG("Marking jump table non transformable: "<<hex<<j.location());
      j.rewritable(false);
    }
  }
#else
  unordered_set <uint64_t> unsafe_jumps;
  string dir = get_current_dir_name();
  ifstream ifile;
  ifile.open(dir+"/jmp_table/result.sjtable");
  string line;
  while(getline(ifile,line)) {
    uint64_t loc = stoull(line);
    unsafe_jumps.insert(loc);
  }
  for(auto & j : jmpTables_) {
    if(/*FULL_ADDR_TRANS || */SAFE_JTABLE == false) {
      j.rewritable(false);
      auto cf_ins = j.cfIns();
      for(auto & ins : cf_ins) {
        DEF_LOG("Marking cf for addr trans: "<<hex<<ins->location());
        //bb->addrTransMust(true);
        ins->atRequired(true);
      }
      continue;
    }
    auto loc_ptr = ptr(j.location());
    auto base_ptr = ptr(j.base());
    if(j.type() == 2 || j.type() == 3 || loc_ptr == NULL || 
       base_ptr == NULL || sameLocDiffBase(j.location(),j.base()) ||
      (type_ == exe_type::NOPIE && 
      (loc_ptr->symbolizable(SymbolizeIf::IMMOPERAND) || base_ptr->symbolizable(SymbolizeIf::IMMOPERAND))) ||
      (loc_ptr->symbolizable(SymbolizeIf::RLTV) && loc_ptr->type() == PointerType::CP) ||
      (base_ptr->symbolizable(SymbolizeIf::RLTV) && base_ptr->type() == PointerType::CP) ||
      otherUseOfJmpTbl(j) || isMetadata(j.location())) {
      DEF_LOG("Marking jump table non transformable: "<<hex<<j.location());
      j.rewritable(false);
      auto cf_ins = j.cfIns();
      for(auto & ins : cf_ins) {
        DEF_LOG("Marking cf for addr trans: "<<hex<<ins->location());
        //bb->addrTransMust(true);
        ins->atRequired(true);
      }
      //auto cf_bbs = j.cfBBs();
      //for(auto & bb : cf_bbs) {
      //  DEF_LOG("Marking cf for addr trans: "<<hex<<bb->start());
      //  bb->addrTransMust(true);
      //}
    }
    if(j.rewritable()) {
      auto cf_ins = j.cfIns();
      for(auto & ins : cf_ins) {
        if(unsafe_jumps.find(ins->location()) != unsafe_jumps.end()) {
          DEF_LOG("Marking cf for addr trans: "<<hex<<ins->location());
          ins->atRequired(true);
          j.rewritable(false);
        }
      }
    }
  }
  bool repeat = true;
  while(repeat) {
    repeat = false;
    for(auto & j : jmpTables_) {
      if(j.rewritable()) {
        //auto cf_bbs = j.cfBBs();
        bool addr_trans_must = false;
        auto cf_ins = j.cfIns();
        for(auto & ins : cf_ins) {
          if(ins->atRequired()) {
            addr_trans_must = true;
            break;
          }
        }
        //for(auto & bb : cf_bbs) {
        //  if(bb->addrTransMust()) {
        //    addr_trans_must = true;
        //    break;
        //  }
        //}
        if(addr_trans_must) {
          DEF_LOG("Marking jump table non transformable: "<<hex<<j.location());
          j.rewritable(false);
          for(auto & ins : cf_ins) {
            DEF_LOG("Marking cf for addr trans: "<<hex<<ins->location());
            //bb->addrTransMust(true);
            ins->atRequired(true);
            repeat = true;
          }
          //for(auto & bb : cf_bbs) {
          //  if(bb->addrTransMust() == false) {
          //    DEF_LOG("Marking cf for addr trans: "<<hex<<bb->start());
          //    bb->addrTransMust(true);
          //    repeat = true;
          //  }
          //}
        }
      }
    }
  }
  /*
  for(auto & j : jmpTables_) {
    if(j.rewritable()) {
      auto cf_bbs = j.cfBBs();
      for(auto & bb : cf_bbs) {
        bb->lastIns()->removeInstrumentation(InstPoint::ADDRS_TRANS);
      }
    }
  }
  */
#endif
}

bool
validJumpForScore(Instruction *ins) {
  if(ins->target() == 0)
    return false;
  uint64_t fall = ins->location() + ins->insSize();
  int32_t offt = (int32_t)(ins->target()) - (int32_t)(fall);
  //if(ins->insSize() >= 5 && abs(offt) <= 128)
  //  return false;
  //if(ins->insSize() == 2 && abs(offt) == 0)
  //  return false;
  if(abs(offt) == 0)
    return false;
  
  return true;
}

void
CfgElems::markCallTgtAsDefCode(BasicBlock *bb) {
  auto parents = bb->parents();
  if(parents.size() > 0) {
    auto cnf_bbs = conflictingBBs(bb->start());
    auto exitCalls = psblExitCalls(bb);
    if(cnf_bbs.size() > 0 || exitCalls.size() > 0)
      return;
    int call_cnt = 0;
    for(auto & parent : parents) {
      if(parent->target() == bb->start() &&
         parent->fallThrough() != bb->start() &&
         parent->isCall() && cnf_bbs.size() == 0 &&
         validJumpForScore(parent->lastIns())) {
        call_cnt++;
        if(call_cnt == 2)
          break;
      }
    }
    if(call_cnt >= 1) {
      DEF_LOG("Marking call target as def code: "<<hex<<bb->start());
      auto bb_list = bbSeq(bb);
      for(auto & bb2 : bb_list) {
        if(bb2->isCode() == false) {
          markAsDefCode(bb2->start());
        }
      }
    }
  }
}

void
CfgElems::markAllCallTgtsAsDefCode() {
  map <uint64_t, Pointer *> ptrMap = pointers ();
  map <uint64_t, Function *>funMap = funcMap();
  for(auto & p : ptrMap) {
    if(p.second->type() == PointerType::UNKNOWN) {
      auto bb = getBB(p.first);
      if(bb != NULL) {
        markCallTgtAsDefCode(bb);
      }
    }
  }
  for(auto & fn : funMap) {
    auto possibleEntries = fn.second->probableEntry();
    for(auto & e : possibleEntries) {
      auto bb = getBB(e);
      if(bb != NULL && bb->isCode() == false)
        markCallTgtAsDefCode(bb);
    }
  }
}
void
CfgElems::phase1NonReturningCallResolution() {
  auto fn_map = funcMap();
  unordered_set <uint64_t> entry_checked;
  unordered_set <uint64_t> call_checked;
  long double threshold = REJECT_THRESHOLD;
  for(auto & fn : fn_map) {
    auto entries = fn.second->allEntries();
    for(auto & e : entries) {
      if(entry_checked.find(e) != entry_checked.end())
        continue;
      auto entry_bb = getBB(e);
      auto bb_lst = bbSeq(entry_bb);
      for(auto & bb : bb_lst)
        entry_checked.insert(bb->start());
      if(entry_bb != NULL) {
        DEF_LOG("Resolving exit calls for function: "<<hex<<entry_bb->start());
        auto exitCalls = psblExitCalls(entry_bb);
        vector <BasicBlock *> terminate_at;
        while(exitCalls.empty() == false) {
          auto exit_call = exitCalls.top();
          exitCalls.pop();
          if(call_checked.find(exit_call->start()) != call_checked.end()) {
            terminate_at.push_back(exit_call);
            continue;
          }
          call_checked.insert(exit_call->start());
          DEF_LOG("Resolving exit call: "<<hex<<exit_call->start());
#ifdef EH_FRAME_DISASM_ROOT
          auto fall_bb = exit_call->fallThroughBB();
          if(withinFn(fall_bb->start())) {
            exit_call->callType(BBType::RETURNING);
          }
          else {
            DEF_LOG("Marking non-returning: "<<hex<<exit_call->start());
            newPointer(exit_call->fallThrough(), PointerType::UNKNOWN,
                       PointerSource::POSSIBLE_RA,PointerSource::POSSIBLE_RA,exit_call->end());
            exit_call->callType(BBType::NON_RETURNING);
            exit_call->fallThrough(0);
            exit_call->fallThroughBB(NULL);
          }
          continue;
#endif
          auto fall_through = exit_call->fallThroughBB();
          if(fall_through != NULL) {
            auto bb_list = bbSeq(fall_through);
            auto score = probScore(fall_through->start());
            //DEF_LOG("Fall through score: "<<dec<<score);
            if(CFValidity::validIns(bb_list) == false) {
              newPointer(exit_call->fallThrough(), PointerType::UNKNOWN,
                         PointerSource::POSSIBLE_RA,PointerSource::POSSIBLE_RA,exit_call->end());
              DEF_LOG("Marking BB non returning: "<<hex<<exit_call->start());
              exit_call->callType(BBType::NON_RETURNING);
              exit_call->type(BBType::NON_RETURNING);
              exit_call->fallThrough(0);
              exit_call->fallThroughBB(NULL);
            }
            else if(score >= threshold) {
              bool common_ancestor = false;
              //DEF_LOG("Checking for common ancestors");
              auto fall_graph_parents = subGraphParents(fall_through);
              for(auto & p : fall_graph_parents) {
                if(p->start() != exit_call->start() && 
                   p->isCall() == false && checkPath(p, exit_call)) {
                  //DEF_LOG("Common ancestor found: "<<hex<<p->start());
                  common_ancestor = true;
                  break;
                }
              }
              if(common_ancestor || checkPath(fall_through, exit_call)) { 
                DEF_LOG("Marking returning: "<<hex<<exit_call->start());
                exit_call->callType(BBType::RETURNING);
              }
              else
                terminate_at.push_back(exit_call);
            }
            else
              terminate_at.push_back(exit_call);
          }
          else {
            DEF_LOG("Marking BB non returning: "<<hex<<exit_call->start());
            exit_call->callType(BBType::NON_RETURNING);
            exit_call->type(BBType::NON_RETURNING);
            exit_call->fallThrough(0);
            exit_call->fallThroughBB(NULL);
          }
        }
      }
    }
  }
}

uint64_t
CfgElems::jumpTgt(uint8_t *bytes, int size, uint64_t ins_addrs) {
  uint64_t tgt = 0;
  if(size == 2) {
    int8_t offset = *((int8_t *)(bytes + 1));
    if(abs(offset) > 0)
      tgt = (int64_t)ins_addrs + size + offset;
  }
  else if(size == 5) {
    int32_t offset = *((int32_t *)(bytes + 1));
    if(abs(offset) > 128)
      tgt = (int64_t)ins_addrs + size + offset;
  }
  else if(size == 6) {
    int32_t offset = *((int32_t *)(bytes + 2));
    if(abs(offset) > 128)
      tgt = (int64_t)ins_addrs + size + offset;
  }
  if(tgt != 0 && withinCodeSec(tgt))
    return tgt;
  return 0;
}

unordered_set <string> calleeSaved{"%r12", "%r13", "%r14", "%r15", "%rbx",
       "%rbp"};

unordered_map <uint64_t, long double>
CfgElems::fnSigInGap(uint64_t g_start, uint64_t g_end) {
  //DEF_LOG("Getting function signatures for gap: "<<hex<<g_start);
  unordered_map <uint64_t, long double> sig_locs;
  uint64_t size = g_end - g_start;
  uint8_t *bytes = (uint8_t *)malloc(g_end - g_start);
  uint64_t start_offt = utils::GET_OFFSET(exePath_,g_start);
  if(start_offt == 0) {
    free(bytes);
    return sig_locs;
  }
  utils::READ_FROM_FILE(exePath_,(void *) bytes, start_offt, size);
  for(uint64_t i = 0; i < size;) {
    if(*(bytes + i) == 0x41 ||
       *(bytes + i) == 0x55 ||
       *(bytes + i) == 0x53 ||
       *(bytes + i) == 0x54 ||
       ((size - i) >=3  && *(bytes + i) == 0x48 && 
        *(bytes + i + 1) == 0x83 && *(bytes + i + 2) == 0xec)) {
      auto ins_list = disassembler_->getIns(g_start + i, 20);
      bool invalid = false;
      long double score = 0;
      unordered_set <string> saved_reg;
      for(auto & ins : ins_list) {
        if(CFValidity::validOpCode(ins) == false) {
          invalid = true;
          break;
        }
        if(ins->isJump() || ins->asmIns().find("ret") != string::npos)
          break;
        if(ins->asmIns().find("push") != string::npos) {
          string reg = ins->op1();
          if(saved_reg.find(reg) != saved_reg.end()) {
            //Repeated saves...invalid address
            invalid = true;
            break;
          }
          if(calleeSaved.find(ins->op1()) != calleeSaved.end()) {
            if(score == 0)
              score = powl(2,7);
            else
              score *= powl(2,7);
            saved_reg.insert(reg);
          }
        }
        else if(ins->asmIns().find("sub") != string::npos) {
          string operand = ins->op1();
          if(saved_reg.find("%rsp") == saved_reg.end() && operand.find(",%rsp") != string::npos) {
            if(score == 0)
              score = powl(2,7);
            else
              score *= powl(2,7);
            saved_reg.insert("%rsp");
          }
        }
        if(saved_reg.size() == 7)
          break;
      }
      if(invalid == false && score > 0) {
        sig_locs[g_start + i] = score;
        i+=20;
      }
      i++;
    }
    else
      break;
  }
  free(bytes);
  return sig_locs;
}

void
CfgElems::jumpTgtsInGap(uint64_t g_start, uint64_t g_end) {
  uint64_t size = g_end - g_start;
  uint8_t *bytes = (uint8_t *)malloc(g_end - g_start);
  uint64_t start_offt = utils::GET_OFFSET(exePath_,g_start);
  if(start_offt == 0) {
    free(bytes);
    return;
  }
  //DEF_LOG("reading file from: " <<hex<<start_offt <<" size " <<dec<<size);
  utils::READ_FROM_FILE(exePath_,(void *) bytes, start_offt, size);
  for(uint64_t i = 0; i < size; i++) {
    if(utils::isUnconditionalShortJmp(bytes + i, size - i)) {
      uint64_t tgt = jumpTgt(bytes + i, 2, g_start + i);
      if(tgt != 0) {
        if(cftTgtsInGaps_[tgt] == 0)
          cftTgtsInGaps_[tgt] = powl(2,8);
        else
          cftTgtsInGaps_[tgt] *= powl(2,8);
        cftsInGaps_[g_start + i] = JumpType::SUJ;
      }
    }
    else if(utils::isUnconditionalJmp(bytes + i, size - i) ||
            *(bytes + i) == 0xe8) {
      uint64_t tgt = jumpTgt(bytes + i, 5, g_start + i);
      if(tgt != 0) {
        if(cftTgtsInGaps_[tgt] == 0)
          cftTgtsInGaps_[tgt] = powl(2,15);
        else
          cftTgtsInGaps_[tgt] *= powl(2,15);
        cftsInGaps_[g_start + i] = JumpType::LUJ;
      }
    }
    else if(utils::isConditionalShortJmp(bytes + i, size - i)) {
      uint64_t tgt = jumpTgt(bytes + i, 2, g_start + i);
      if(tgt != 0) {
        if(cftTgtsInGaps_[tgt] == 0)
          cftTgtsInGaps_[tgt] = powl(2,4);
        else
          cftTgtsInGaps_[tgt] *= powl(2,4);
        cftsInGaps_[g_start + i] = JumpType::SCJ;
      }
    }
    else if(utils::isConditionalLongJmp(bytes + i, size - i)) {
      uint64_t tgt = jumpTgt(bytes + i, 6, g_start + i);
      if(tgt != 0) {
        if(cftTgtsInGaps_[tgt] == 0)
          cftTgtsInGaps_[tgt] = powl(2,44);
        else
          cftTgtsInGaps_[tgt] *= powl(2,44);
        cftsInGaps_[g_start + i] = JumpType::LCJ;
      }
    }
  }
  free(bytes);
}

vector <uint64_t>
CfgElems::crossingCftsInGap(uint64_t g_start, uint64_t g_end) {
  vector <uint64_t> crossing_cfts;
  for(uint64_t i = g_start; i < g_end; i++) {
    if(cftsInGaps_.find(i) != cftsInGaps_.end()) {
      uint64_t next_addr = i;
      if(cftsInGaps_[i] == JumpType::LUJ) {
        next_addr = i + 5;
      }
      else if(cftsInGaps_[i] == JumpType::SUJ) {
        next_addr = i + 2;
      }
      auto ins_list = disassembler_->getIns(next_addr,50);
      for(auto & ins : ins_list) {
        if(ins->asmIns().find("nop") == string::npos)
          break;
        next_addr = ins->location();
      }
      if(cftTgtsInGaps_.find(next_addr) != cftTgtsInGaps_.end())
        crossing_cfts.push_back(i);
    }
  }
  return crossing_cfts;
}

void
CfgElems::gapScore(Gap &g) {
  auto fn_sigs = fnSigInGap(g.start_, g.end_);
  for(auto & sig : fn_sigs) {
    Hint h(sig.first,sig.second);
    g.hintQ_.push(h);
    g.score_ += sig.second;
    if(g.minScore_ == 0)
      g.minScore_ = g.score_;
  }
  vector <uint64_t> def_code_cfts = defCodeCFTs(g.start_, g.end_);
  for(auto & c : def_code_cfts) {
    Hint h(c,powl(2,15));
    g.hintQ_.push(h);
    g.score_ += powl(2,15);
    if(g.minScore_ == 0)
      g.minScore_ = g.score_;
  }
  
  auto crossing_cfts = crossingCftsInGap(g.start_,g.end_);
  long double cft_score =  powl(2,12);
  for(auto & c : crossing_cfts) {
    Hint h(c,powl(2,cft_score));
    g.hintQ_.push(h);
    g.score_ += cft_score;
    if(g.minScore_ == 0)
      g.minScore_ = g.score_;
    else if(cft_score < g.minScore_)
      g.minScore_ = cft_score;
  }
  for(uint64_t i = g.start_; i < g.end_; i++) {
    if(cftTgtsInGaps_.find(i) != cftTgtsInGaps_.end()) {
      g.score_ += cftTgtsInGaps_[i];
      Hint h(i,cftTgtsInGaps_[i]);
      g.hintQ_.push(h);
      if(g.minScore_ == 0)
        g.minScore_ = cftTgtsInGaps_[i];
      else if(cftTgtsInGaps_[i] < g.minScore_)
        g.minScore_ = cftTgtsInGaps_[i];
    }
  }
}

vector <uint64_t>
CfgElems::defCodeCFTs(uint64_t g_start, uint64_t g_end) {
  uint64_t size = g_end - g_start;
  vector <uint64_t> cfts;
  uint8_t *bytes = (uint8_t *)malloc(g_end - g_start);
  uint64_t start_offt = utils::GET_OFFSET(exePath_,g_start);
  if(start_offt == 0) {
    free(bytes);
    return cfts;
  }
  utils::READ_FROM_FILE(exePath_,(void *) bytes, start_offt, size);
  for(uint64_t i = 0; i < size; i++) {
    if(utils::isUnconditionalShortJmp(bytes + i, size - i)) {
      uint64_t tgt = jumpTgt(bytes + i, 2, g_start + i);
      auto tgt_bb = getBB(tgt);
      if(tgt_bb != NULL && (tgt_bb->isCode() || PointerAnalysis::codeByProperty(tgt_bb)))
        cfts.push_back(g_start + i);
    }
    else if(utils::isUnconditionalJmp(bytes + i, size - i) ||
            *(bytes + i) == 0xe8) {
      uint64_t tgt = jumpTgt(bytes + i, 2, g_start + i);
      auto tgt_bb = getBB(tgt);
      if(tgt_bb != NULL && (tgt_bb->isCode() || PointerAnalysis::codeByProperty(tgt_bb)))
        cfts.push_back(g_start + i);
    }
  }
  free(bytes);
  return cfts;
}


bool
CfgElems::conflicts(uint64_t addrs) {
  auto fn = is_within(addrs, funcMap_);
  if(fn != funcMap_.end()) {
    auto cnf_bbs = fn->second->conflictingBBs(addrs);
    if(cnf_bbs.size() > 0)
      return true;
  }
  return false;
}

vector <BasicBlock *>
CfgElems::conflictingBBs(uint64_t addrs) {
  vector <BasicBlock *> conflict_bbs;
  auto fn = is_within(addrs, funcMap_);
  if(fn != funcMap_.end()) {
    auto cnf_bbs = fn->second->conflictingBBs(addrs);
    conflict_bbs.insert(conflict_bbs.end(), cnf_bbs.begin(), cnf_bbs.end());
  }
  auto bb = getBB(addrs);
  if(bb != NULL) {
    for(auto i = bb->start(); i < bb->boundary(); i++) {
      if(bb->noConflict(i) == false) {
        auto cnf_bb = getBB(i);
        if(cnf_bb != NULL)
          conflict_bbs.push_back(cnf_bb);
      }
    }
  }
  return conflict_bbs;
}

long double
CfgElems::crossingCft(vector <BasicBlock *> &bb_lst) {
  long double score = 0;
  for(auto & bb : bb_lst) {
    auto last_ins = bb->lastIns();
    if(last_ins->isJump() && last_ins->isCall() == false
       && last_ins->isUnconditionalJmp() && bb->target() != 0
       && last_ins->asmIns().find("ret") == string::npos &&
       validJumpForScore(last_ins)) {
      auto next_addr = last_ins->location() + last_ins->insSize();
      int ctr = 0;
      auto next_bb = getBB(next_addr);
      while(next_bb == NULL && ctr < 30) {
        next_addr++;
        next_bb = getBB(next_addr);
        ctr++;
      }
      if(next_bb != NULL) {
        auto parents = next_bb->parents();
        for (auto & p : parents) {
          if(p->target() == next_bb->start()) {
            auto p_last_ins = p->lastIns();
            if(p_last_ins->isCall() == false &&
               p_last_ins->isJump() && 
               p_last_ins->asmIns().find("ret") == string::npos && validJumpForScore(p_last_ins)) {
              score += powl(2,12);
              //////DEF_LOG("Crossing CFT: "<<hex<<bb->start()<<"->"<<next_bb->start());
              break;
            }
          }
        }
      }
    }
  }
  //DEF_LOG("Crossing CFT score: "<<dec<<score);
  return score;
}

long double
CfgElems::jumpScore(vector <BasicBlock *> &bb_lst) {
  long double score = 0;
  //long double bb_score_ceil = powl(2,50);
  unordered_map<uint64_t, long double> score_map;
  for(auto & bb : bb_lst) {
    auto last_ins = bb->lastIns();
    long double bb_score = 0;
    if(bb->target() != 0 && bb->target() != bb->fallThrough() && validJumpForScore(last_ins)) {
      if(last_ins->isUnconditionalJmp() && last_ins->insSize() == 2 && 
         last_ins->asmIns().find("ret") == string::npos && bb->target() != 0) {
        //DEF_LOG("Short unconditional jump target: "<<hex<<bb->start());
        /*
        if(bb_score == 0)
          bb_score = powl(2,8);
        else
          bb_score = bb_score * powl(2,8);
          */
        //score +=  powl(2,8);
        auto tgt = bb->target();
        if(score_map[tgt] == 0)
          score_map[tgt] = powl(2,8);
        else
          score_map[tgt] *=  powl(2,8);
      }
      else if(last_ins->isJump() && last_ins->insSize() == 2 &&
              last_ins->asmIns().find("ret") == string::npos) {
        //DEF_LOG("Short conditional jump target: "<<hex<<bb->start());
        /*
        if(bb_score == 0)
          bb_score = powl(2,4);
        else
          bb_score = bb_score * powl(2,4);
          */
        //score += powl(2,4);
        auto tgt = bb->target();
        if(score_map[tgt] == 0)
          score_map[tgt] = powl(2,4);
        else
          score_map[tgt] *=  powl(2,4);
      }
      else if(last_ins->isUnconditionalJmp() && last_ins->insSize() >= 5 && !last_ins->isCall()
              && bb->target() != 0) {
        //DEF_LOG("Long unconditional jump target: "<<hex<<bb->start());
        /*
        if(bb_score == 0)
          bb_score = powl(2,15);
        else
          bb_score = bb_score * powl(2,15);
          */
        //score += powl(2,15);
        auto tgt = bb->target();
        if(score_map[tgt] == 0)
          score_map[tgt] = powl(2,11);
        else
          score_map[tgt] *=  powl(2,11);
      }
      else if(last_ins->isJump() && last_ins->insSize() >= 6) {
        //DEF_LOG("Long conditional jump target: "<<hex<<bb->start());
        /*
        if(bb_score == 0)
          bb_score = powl(2,17);
        else
          bb_score = bb_score * powl(2,17);
          */
        //score += powl(2,20);
        auto tgt = bb->target();
        if(score_map[tgt] == 0)
          score_map[tgt] = powl(2,15);
        else
          score_map[tgt] *=  powl(2,15);
      }
    }
  }
  DEF_LOG("Jump target score: "<<dec<<score);
  for(auto & s : score_map)
    score += s.second;
  return score;
}

long double
CfgElems::fnSigScore(vector <Instruction *> &ins_list) {
  long double score = 0;
  unordered_set <string> saved_reg;
  int ctr = 0;
  for(auto & ins : ins_list) {
    if(CFValidity::validOpCode(ins) == false) {
      score = 0;
      break;
    }
    if(ins->isJump() || ins->asmIns().find("ret") != string::npos)
      break;
    if(ins->asmIns().find("push") != string::npos) {
      string reg = ins->op1();
      //DEF_LOG("Push found: "<<reg);
      if(saved_reg.find(reg) != saved_reg.end()) {
        //Repeated saves...invalid address
        //DEF_LOG("Repeated saves..making sig score 0");
        score = 0;
        break;
      }
      if(calleeSaved.find(ins->op1()) != calleeSaved.end()) {
        long double sig_score = 0;
        if(ins->insSize() == 2)
          sig_score = powl(2,14);
        else
          sig_score = powl(2,7);
        if(score == 0)
          score = sig_score;
        else
          score *= sig_score;
        saved_reg.insert(reg);
      }
    }
    else if(ins->asmIns().find("sub") != string::npos) {
      string operand = ins->op1();
      if(saved_reg.find("%rsp") == saved_reg.end() && operand.find("%rsp") != string::npos) {
        //DEF_LOG("Checking fn sig..mov sub");
        if(score == 0)
          score = powl(2,17);
        else
          score *= powl(2,17);
        saved_reg.insert("%rsp");
      }
    }
    else if(ins->asmIns().find("mov") != string::npos) {
      string operand = ins->op1();
      if(operand.find("%rbp") != string::npos && operand.find("%rsp") != string::npos) {
        //DEF_LOG("Checking fn sig..mov found");
        if(score == 0)
          score = powl(2,17);
        else
          score *= powl(2,17);
      }
    }
    else if(ins->asmIns().find("endbr") != string::npos)
      continue;
    else if(ctr >= 10)
      break;
    if(ctr == 0 && score == 0) {
      //DEF_LOG("First instruction not a valid sig start: "<<ins->asmIns());
      break;
    }
    if(saved_reg.size() == 7)
      break;
    ctr++;
  }
  
  return score;
}

long double
CfgElems::fnSigScore(BasicBlock *bb) {
  long double score = 0;
  auto ins_list = bb->insList();
  score = fnSigScore(ins_list);
  auto parents = bb->parents();
  long double call_score = 0;
  for(auto & p : parents) {
    auto last_ins = p->lastIns();
    if(p->target() == bb->start() &&
       last_ins->isCall() && validJumpForScore(last_ins)) {
      if(call_score == 0)
        call_score = powl(2,15);
      else
        call_score *= powl(2,15);
    }
  }
  score += call_score;
  //DEF_LOG("Fn sig score: "<<hex<<bb->start()<<"-"<<dec<<score);
  return score;
}

long double
CfgElems::defCodeCftScore(vector <BasicBlock *> &bb_lst) {
  long double score = 0;
  long double score_unit = powl(2,15);
  for(auto & bb : bb_lst) {
    if(bb->isCall() && bb->targetBB() != NULL && 
      (bb->targetBB()->isCode()))
      score += score_unit;
  }
  return score;
}

long double
outOfSnippetJumps(vector <BasicBlock *> &bb_lst) {
  unordered_map <uint64_t,long double> score_map;
  for(auto & bb : bb_lst) {
    score_map[bb->start()] = 0;
  }
  for(auto & bb : bb_lst) {
    auto parents = bb->parents();
    for(auto & p : parents) {
      if(score_map.find(p->start()) == score_map.end() && p->target() == bb->start()) {
        auto last_ins = p->lastIns();
        if(last_ins->isUnconditionalJmp() && last_ins->insSize() == 2 && 
           last_ins->asmIns().find("ret") == string::npos && bb->target() != 0) {
          if(score_map[bb->start()] == 0)
            score_map[bb->start()] = powl(2,8);
          else
            score_map[bb->start()] *=  powl(2,8);
        }
        else if(last_ins->isJump() && last_ins->insSize() == 2 &&
                last_ins->asmIns().find("ret") == string::npos) {
          if(score_map[bb->start()] == 0)
            score_map[bb->start()] = powl(2,4);
          else
            score_map[bb->start()] *=  powl(2,4);
        }
        else if(last_ins->isUnconditionalJmp() && last_ins->insSize() >= 5 && !last_ins->isCall()
                && bb->target() != 0) {
          if(score_map[bb->start()] == 0)
            score_map[bb->start()] = powl(2,11);
          else
            score_map[bb->start()] *=  powl(2,11);
        }
        else if(last_ins->isJump() && last_ins->insSize() >= 6) {
          if(score_map[bb->start()] == 0)
            score_map[bb->start()] = powl(2,15);
          else
            score_map[bb->start()] *=  powl(2,15);
        }

      }
    }
  }
  long double score = 0;
  for(auto & s : score_map)
    score += s.second;
  return score;
}

long double
CfgElems::probScore(uint64_t addrs) {

  //Calculates score of a function entry address.

  auto bb = getBB(addrs);
  if(bb != NULL) {
    auto bb_lst = bbSeq(bb);
    //DEF_LOG("bb seq size: "<<bb_lst.size());
    if(CFValidity::validIns(bb_lst)) {
      //return powl(2,4);
      double score = crossingCft(bb_lst);
      /*
       * Uncomment for original implementation
       */
      score += jumpScore(bb_lst);
      DEF_LOG("Jump score: "<<score);
      score += fnSigScore(bb);
      DEF_LOG("Sig score: "<<score);
      score += defCodeCftScore(bb_lst);

      //score *= jumpScore(bb_lst);
      //score *= fnSigScore(bb);
      //score *= defCodeCftScore(bb_lst);
      
      /*
       * Uncomment for original implementation
       */
      auto p = ptr(addrs);
      if(p != NULL) {
        if(p->source() == PointerSource::POSSIBLE_RA)
          score += powl(2,4);
        //score += outOfSnippetJumps(bb_lst);
      }
      //else {
      //  auto prev_reg = addrs - 1;
      //  auto prev_bb = withinBB(prev_reg);
      //  if(bb != NULL && bb->lastIns()->isCall()) {
      //    score += powl(2,4);
      //    score += outOfSnippetJumps(bb_lst);
      //  }
      //}

      DEF_LOG("Entry: "<<hex<<addrs<<" score: "<<dec<<score);

      return score;
    }
    else
      return -1;

  }

  return -1;
}

long double
CfgElems::regionScore(vector <BasicBlock *> &bb_lst) {
  //Gives score of a region defined by a set of consecutive basic blocks. the
  //basic blocks may or may not form a complete function

  double score = crossingCft(bb_lst);
  score += jumpScore(bb_lst);
  for(auto & bb : bb_lst)
    score += fnSigScore(bb);
  score += defCodeCftScore(bb_lst);
   
  return score;
}

uint64_t
CfgElems::sectionEnd(uint64_t addrs) {
  for(auto & sec : rxSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size)) {
      return sec.vma + sec.size;
    }
  }
  for(auto & sec : rwSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size)) {
      return sec.vma + sec.size;
    }
  }
  for(auto & sec : roSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size)) {
      return sec.vma + sec.size;
    }
  }
  return 0;
}

bool
CfgElems::isString(uint64_t addrs) {
  //First check within RX sections

  for(auto & sec : rxSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size)) {
      return utils::is_string(sec.vma,sec.vma + sec.size,addrs,exePath_);
    }
  }
  for(auto & sec : rwSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size)) {
      return utils::is_string(sec.vma,sec.vma + sec.size,addrs,exePath_);
    }
  }
  for(auto & sec : roSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size)) {
      return utils::is_string(sec.vma,sec.vma + sec.size,addrs,exePath_);
    }
  }
  return false;
}

bool
CfgElems::validRead(Pointer *ptr) {
  if(ptr->symbolizable(SymbolizeIf::RLTV)) {
    vector<uint64_t> access_points = ptr->storages(SymbolType::RLTV);
    for(auto p : access_points) {
      //LOG("Accessing ins: "<<hex<<p);
      auto bb = withinBB(p);
      if(bb != NULL && bb->isCode()) {
        auto ins = bb->getIns(p);
        if(ins != NULL) {
          string asm_ins = ins->asmIns();
          int rip_pos = asm_ins.find("(%rip)");
          if(rip_pos != string::npos) {
            //int comma_pos = asm_ins.rfind(",",rip_pos);
            //if(comma_pos == string::npos || comma_pos > rip_pos) {
              if(ins->isLea() || ins->isIndirectCf() || asm_ins.find("mov") != string::npos
                 || asm_ins.find("cmp") != string::npos)
                return true;
            //}
          }
        }
      }
    }
  }
  else if(ptr->symbolizable(SymbolizeIf::IMMOPERAND))
    return true;

  return false;
}

bool
CfgElems::validPtrToPtr(uint64_t ptr) {
  auto bb = withinBB(ptr);
  if(bb == NULL || bb->isCode() == false) {
    for(auto & p : pointerMap_) {
      if(p.second->type() == PointerType::CP &&
         p.second->symbolizable(SymbolizeIf::SYMLOCMATCH,ptr)) {
        LOG("Valid ptr to code ptr: "<<hex<<ptr);
        return true;
      }
    }
  }
  return false;
}

bool
CfgElems::validPtrToPtrArray(uint64_t ptr, uint64_t end) {
  LOG("Checking if pointer to symbol array: "<<hex<<ptr);
  uint64_t entry_sz = 8;
  if((end - ptr) % entry_sz == 0) {
    return true;
    ptr += entry_sz;
  }
  else {
    LOG("Entry size not aligned with end: "<<hex<<end);
    return false;
  }
  while(ptr < end) {
    if(validPtrToPtr(ptr) == false) {
      LOG("invalid symbol at: "<<hex<<ptr);
      return false;
    }
    ptr += entry_sz;
  }
  return true;
}

bool
CfgElems::withinSymbolArray(uint64_t addrs) {
  LOG("Checking if within symbol array: "<<hex<<addrs);
  auto it = pointerMap_.lower_bound(addrs);
  if(it != pointerMap_.end() && it->first != addrs &&
     abs(int((int)it->first - (int)addrs)) < 4)
    return false;
  if(validPtrToPtr(addrs - 8) && validPtrToPtr(addrs + 8))
    return true;
  if(validPtrToPtr(addrs - 8) && validPtrToPtr(addrs - 16))
    return true;
  if(validPtrToPtr(addrs + 8) && validPtrToPtr(addrs + 16))
    return true;
  return false;
}

bool
CfgElems::validPtrAccess(Pointer *ptr, uint64_t ptr_loc) {
  if((ptr->type() != PointerType::CP && conflictsDefCode(ptr->address()) == false)
     && (ptr_loc == ptr->address() || validPtrToPtrArray(ptr->address(),ptr_loc))
     && validRead(ptr))
    return true;
  return false;
}

bool
CfgElems::accessConflict(uint64_t addrs) {
  LOG("Checking access conflict for "<<hex<<addrs);
  auto it = pointerMap_.lower_bound(addrs);
  if(it == pointerMap_.end()) {
    it = prev(it);
    LOG("Possible access point: "<<hex<<it->first<<" "<<(int)it->second->type());
    if(validPtrAccess(it->second,addrs))
      return false;
    else
      return true;
  }
  else if(it->first != addrs) {
    if(abs(int((int)it->first - (int)addrs)) < 4) {
      LOG("Access to middle: "<<hex<<it->first);
      return true;
    }
    it = prev(it);
    LOG("Possible access point: "<<hex<<it->first<<" "<<(int)it->second->type());
    if(validPtrAccess(it->second,addrs))
      return false;
    else
      return true;;
  }
  else if(it->first == addrs) {
    LOG("Possible access point: "<<hex<<it->first<<" "<<(int)it->second->type());
    if(validPtrAccess(it->second,addrs))
      return false;
    else
      return true;
  }
  return false;
}

BasicBlock *
CfgElems::getDataBlock(uint64_t addrs) {
  auto fn = is_within(addrs,funcMap_);
  if(fn == funcMap_.end())
    return NULL;
  return fn->second->getDataBlock(addrs);
}

void
CfgElems::markAsDefCode(uint64_t addrs, bool force) {
  auto bb = getBB(addrs);
  if(bb == NULL) {
    LOG("No BB for address: "<<hex<<addrs);
    if(force) {
      bb = getDataBlock(addrs);
      if(bb == NULL) {
        LOG("No data BB for address: "<<hex<<addrs);
        exit(0);
      }
    }
    else
      exit(0);
  }
  auto frame = bb->frame();
  Function *fn = NULL;
  if(frame != 0)
    fn = funcMap_[frame];
  else {
    auto fn_it = is_within(bb->start(), funcMap_);
    if(fn_it == funcMap_.end()) {
      LOG("No function for BB: "<<hex<<addrs);
      return;
      //exit(0);
    }
    
    fn = fn_it->second;
  }
  
  fn->markAsDefCode(bb);
}

void
CfgElems::markAsDefData(uint64_t addrs) {
  auto bb = getBB(addrs);
  if(bb == NULL) {
    LOG("No BB for address: "<<hex<<addrs);
    return;
  }
  auto fn = is_within(bb->start(),funcMap_);
  if(fn == funcMap_.end()) {
    LOG("No function for BB: "<<hex<<addrs);
    return;
  }
  fn->second->markAsDefData(bb);

}

bool
CfgElems::conflictsDefCode(uint64_t addrs) {
  auto fn = is_within(addrs, funcMap_);
  if(fn == funcMap_.end())
    return false;
  return fn->second->conflictsCnsrvtvCode(addrs);
}

bool
CfgElems::zeroDefCodeConflict(vector <BasicBlock *> &bb_list) {
  for(auto & bb : bb_list) {
    //DEF_LOG("Checking def code conflict bb: "<<hex<<bb->start());
    if(bb->isCode() == false && (conflictsDefCode(bb->start()) ||
          conflictsDefCode(bb->boundary()))) {
      DEF_LOG("bb: "<<hex<<bb->start()<<" conflicts def code");
      return false;
    }
  }
  return true;
}


void
CfgElems::createFuncFrPtr(Pointer * ptr) {
  if(INVALID_CODE_PTR(ptr->address()) || ptr->source() == PointerSource::EH)
    return;
  uint64_t address = ptr->address();
  //LOG("Creating function for pointer "<<hex<<address);
  auto fn = is_within(address, funcMap_);
  LOG("Is within: "<<hex<<fn->first);
  if(fn == funcMap_.end() || 
    (address != fn->first && address >= fn->second->end() 
     && ptr->source() != PointerSource::EXTRA_RELOC_PCREL)) {
    
    LOG("Function doesn't exist..creating a new one");
    Function *f = new Function(address,0,true);
    if(ptr->type() == PointerType::CP)
      f->addEntryPoint(address);
    else
      f->addProbableEntry(address);

    funcMap_[address] = f;
  }
  else {
    if(ptr->type() == PointerType::CP)
      fn->second->addEntryPoint(address);
    else
      fn->second->addProbableEntry(address);
  }
}

bool
CfgElems::withinPltSec(uint64_t addrs) {
  for(auto & sec : rxSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size)) {

      if(sec.name.find("plt") != string::npos)
        return true;
      return false;
    }
  }
  return false;
}

bool
CfgElems::withinCodeSec(uint64_t addrs) {
  for(auto & sec : rxSections_) {
    if(addrs >= sec.vma && addrs < (sec.vma + sec.size) 
        && sec.sec_type == section_types::RX) {
      //DEF_LOG(hex<<addrs<<" Within code section: "<<hex<<sec.vma<<" - "<<sec.vma + sec.size);
      return true;
    }
  }
  return false;
}

bool
CfgElems::validEntry(uint64_t entry) {
  auto fn = is_within(entry,funcMap_);
  if(fn == funcMap_.end())
    return false;
  return fn->second->validEntry(entry);
}

BBType
CfgElems::getBBType(uint64_t bbAddrs) {
  //LOG("Getting bb type: "<<hex<<bbAddrs);
  auto fn = is_within(bbAddrs,funcMap_);
  BasicBlock *bb = fn->second->getBB(bbAddrs);
  if(bb != NULL)
    return bb->type();
  return BBType::NA;
}

BasicBlock *
CfgElems::getBB(uint64_t addrs) {
  //LOG("Getting BB: "<<hex<<addrs);
  if(bbCache_.find(addrs) != bbCache_.end())
    return bbCache_[addrs];
  auto fn = is_within(addrs,funcMap_);
  if(fn == funcMap_.end())
    return NULL;
  //LOG("Within function: "<<hex<<fn->first);
  auto bb = fn->second->getBB(addrs);
  if(bb != NULL)
    bbCache_[addrs] = bb;
  return bb;
}

BasicBlock *
CfgElems::withinBB(uint64_t addrs) {
  auto fn = is_within(addrs,funcMap_);
  if(fn == funcMap_.end())
    return NULL;
  auto bb = fn->second->withinBB(addrs);
  if(bb == NULL) {
    fn = prev(fn);
    if(fn == funcMap_.end())
      return NULL;
    return fn->second->withinBB(addrs);
  }
  return bb;
}

bool
CfgElems::isValidIns(uint64_t addrs) {
  auto bb = withinBB(addrs);
  if(bb != NULL) {
    if(bb->isValidIns(addrs))
      return true;
  }
  return false;
}

void
CfgElems::addBBtoFn(BasicBlock *bb, PointerSource t) {
  uint64_t addrs = bb->start();
  auto fn = is_within(addrs,funcMap_);
  Function *curFn = fn->second;
  fn++;
  if(fn != funcMap_.end()) {
    if(bb->boundary() >= fn->first) {
      vector <Instruction *> insLst = bb->insList();
      for(auto ins : insLst) {
        uint64_t loc = ins->location();
        if(loc >= fn->first) {
          BasicBlock *newbb = bb->split(loc);
          bb->fallThroughBB(NULL);
          delete(newbb);
          //bb->fallThrough(0);
          //ADDBBTOFN(newbb,fn->second,t);
          break;
        }
      }
    }
  }
  ADDBBTOFN(bb,curFn,t);
  LOG("BB "<<hex<<addrs<<" added to function "<<hex<<curFn->start()
      <<" Type: "<<(int)(bb->isCode())<<" "<<bb);
}

void
CfgElems::removeBB(BasicBlock *bb) {
  LOG("Removing BB: "<<hex<<bb->start()<<" "<<hex<<bb);
  auto fn = is_within(bb->start(),funcMap_);
  fn->second->removeBB(bb);
}

uint64_t 
CfgElems::isValidRoot(uint64_t addrs, code_type t) {

  /* Takes an address and returns a gap/undiscovered code region starting from
   * that address.
   * end of the gap can be next basic block start or next pointer.
   * returns a 0 if a basic block already exists or the address conflicts with
   * definite code.
   */
  auto fn = is_within(addrs,funcMap_);
  if(fn == funcMap_.end())
    return 0;
  //LOG("Within function: "<<hex<<fn->first);
  BasicBlock *bb = fn->second->getBB(addrs);
  if(bb == NULL) {
#ifdef GROUND_TRUTH
    if(fn->second->misaligned(addrs)) {
      LOG("Possibly invalid jump table target. Rejecting "<<hex<<addrs);
      return 0;
    }
#endif
    //if(t == code_type::GAP)
    //  return 1;
    if(t == code_type::CODE && fn->second->misaligned(addrs))
      return 0;
    else if(t == code_type::CODE || 
        fn->second->misaligned(addrs) == false) {

      //Try to split an existing BB
      BasicBlock *bb = fn->second->splitAndGet(addrs);

      if(bb != NULL) {
        LOG("returning splitted BB");
        return bb->start();
      }
      else {
        return 1; //No BB found, Disassemble.
      }
    }
    else
      return 1; //If misaligned and code type is unknown, Disassemble
  }
  else
    return bb->start();
 
  return 1;
}
/*
uint64_t CfgElems::nextPtr(uint64_t addrs) {
  //Returns the next pointer, given the address

  uint64_t chunk_end = 0;
  auto fn = funcMap_.lower_bound(addrs);
  if(fn->first == addrs)
    fn++;
  if(fn == funcMap_.end())
    chunk_end = codeSegEnd_;
  else
    chunk_end = fn->second->firstEntryPoint();
  if(chunk_end == 0) {
    auto it = pointerMap_.lower_bound(addrs);
    if(it->first == addrs)
      it++;
    if(it != pointerMap_.end() && it->first < codeSegEnd_)
      chunk_end = it->first;
    else
      chunk_end = codeSegEnd_;
  }
  return chunk_end;
}
*/
uint64_t 
CfgElems::nextCodeBlock(uint64_t addrs) {
  if(addrs > codeSegEnd_)
    return 0;
  auto fn = funcMap_.lower_bound(addrs);

  if(fn->first == addrs)
    fn++;
  while(fn != funcMap_.end()) {
    auto bbs = fn->second->getDefCode();
    if(bbs.size() == 0)
      fn++;
    else {
      return bbs[0]->start();
    }
  }
  if(fn == funcMap_.end())
    return codeSegEnd_;
  return codeSegEnd_;
}

void
CfgElems::createFn(bool is_call, uint64_t target_address,uint64_t ins_addrs,
    code_type t)
{
  if(INVALID_CODE_PTR(target_address))
    return;
  DEF_LOG("Creating function for address: " <<hex<<target_address);
  if(target_address != 0) {
    if(is_call) {
      auto f_it = is_within(target_address, funcMap_);
      if(f_it == funcMap_.end())
        return;
      uint64_t end = f_it->second->end();
      LOG("Previous function: " <<hex <<f_it->first <<" - " <<end);
      if(f_it->first == target_address) {
        LOG("Function exists");
        ADDENTRY(f_it->second,target_address,t);
        return;
      }
      else if(end > target_address) {
        //Multiple entry function.
        //Function already exists. Just add a new entry point.

        LOG("call target entry point added");
        ADDENTRY(f_it->second,target_address,t);
      }
      else {
        Function *f = f_it->second->splitFunction(target_address);
        ADDENTRY(f,target_address,t);
        funcMap_[target_address] = f;
        LOG("call target function created");
      }
    }
    else {
      //tail call handling
      //Check if the jump target goes out of current function's body. If
      //yes, create a new function.

      auto f_it = is_within(ins_addrs, funcMap_);
      if(f_it == funcMap_.end())
        return;
      LOG("Jmp ins function: "<<hex<<f_it->first);
      auto next_f_it = next_iterator(ins_addrs, funcMap_);
      if(next_f_it == funcMap_.end())
        return;
      LOG("Next function: "<<hex<<next_f_it->first);
      if(target_address <f_it->first || target_address>= next_f_it->first) {
        auto f_it2 = is_within(target_address, funcMap_);
        if(f_it2 == funcMap_.end())
          return;
        uint64_t end = f_it2->second->end();
        LOG("Previous function: " <<hex <<f_it2->first <<" - " <<end);
        if(f_it2->first == target_address) {
    	  LOG("Jump target function exists");
          ADDENTRY(f_it2->second,target_address,t);
    	  return;
    	}
        else if(end > target_address) {
    	  //Multiple entry function.
    	  //Function already exists. Just add a new entry point.

    	  LOG("jump target entry point added");
          ADDENTRY(f_it2->second,target_address,t);
    	}
        else {
    	  LOG("jump target function created");
    	  Function *f = f_it2->second->splitFunction(target_address);
          ADDENTRY(f,target_address,t);
    	  funcMap_[target_address] = f;
    	}

      }
    }
  }
  LOG("Function created");
  return;
}
/*
BasicBlock *
CfgElems::readBB(ifstream & ifile) {
  string str;
  uint64_t start = 0, end = 0, target = 0, fall = 0;
  BBType t = BBType::NA;
  BBType call_type = BBType::NA;
  code_type ctype = code_type::UNKNOWN;
  vector <Instruction *> ins_list;
  vector <uint64_t> ind_tgts;
  vector<uint64_t> jtable ;
  while(getline(ifile,str)) {
    vector<string> words = utils::split_string(str," ");
    if(words[0] == "start") {
      start = stoll(words[1]);
      end = stoll(words[2]);
      LOG("Reading BB: "<<hex<<start<<"-"<<hex<<end);
    }
    else if(words[0] == "type") {
      t = (BBType)(stoi(words[1]));
    }
    else if(words[0] == "calltype") {
      call_type = (BBType)(stoi(words[1]));
    }
    else if(words[0] == "codetype") {
      ctype = (code_type)(stoi(words[1]));
    }
    else if(words[0] == "JTable") {
      for(int i = 1; i < words.size(); i++) {
        auto j = stoi(words[1]);
        jtable.push_back(j);
      }
    }
    else if(words[0] == "target")
      target = stoll(words[1]);
    else if(words[0] == "fall")
      fall = stoll(words[1]);
    else if(words[0] == "indrc_tgt") {
      uint64_t addrs = stoll(words[1]);
      ind_tgts.push_back(addrs);
    }
    else if(words[0] == "ins") {
      uint64_t loc = stoll(words[1]);
      uint64_t size = stoll(words[2]);
      Instruction * in = new Instruction();
      string ins = "";
      string mne = "";
      string operand = "";
      set <string> cf_ins_set = utils::get_cf_ins_set();
      set <string> uncond_cf_ins_set = utils::get_uncond_cf_ins_set();
      bool mne_found = false;
      for(unsigned int i = 3; i < words.size(); i++) {
        ins += words[i] + " ";
        if(i >= 3 && utils::prefix_ops.find(words[i]) != utils::prefix_ops.end())
          continue;
        else if(i >= 3 && mne_found == false) {
          mne = words[i];
          mne_found = true;
          if(cf_ins_set.find(mne) != cf_ins_set.end()) {
            in->isJump(true);
          }
          if(uncond_cf_ins_set.find(mne) != uncond_cf_ins_set.end())
            in->isUnconditionalJmp(true);
        }
        else if(i >= 3)
          operand += words[i];
      }
      //for(unsigned int i = 4; i < words.size(); i++) {
      //  operand += words[i] + " ";
      //}
      //DEF_LOG("Reading ins: "<<hex<<loc<<": "<<mne<<" "<<operand);
      in->location(loc);
      in->label("." + to_string(loc));
      in->op1(operand);
      in->mnemonic(mne);
      in->insSize(size);
      in->chkConstOp();
      in->chkConstPtr();
      //in->isRltvAccess();
      int pos = operand.find("(%rip)");
      if(pos != string::npos) {
        in->setRltvAccess(true);
        int offset_pos = operand.rfind(".",pos);
        if(offset_pos != string::npos) {
          string off = operand.substr(offset_pos + 1, pos - offset_pos - 1);
          uint64_t rip_rltv_tgt = stoull(off,0,10);
          in->ripRltvOfft(rip_rltv_tgt);
        }
        if(mne.find("lea") != string::npos)
          in->isLea(true);
      }
      in->asmIns(ins);
      if(ins.find("call") != string::npos)
        in->isCall(true);

      if(ins.find("ret") != string::npos) {
        in->isFuncExit(true);
        in->isJump(true);
        in->isUnconditionalJmp(true);
      }
      else if(in->isJump() && operand.find("*") == string::npos) {
        LOG("Parsing jump target: "<<ins);
        long unsigned int dot_pos = operand.find(".");
        if(dot_pos != string::npos) {
          string tgt = operand.replace(dot_pos,1,"");
          in->target(stoll(tgt));
        }
      }

      ins_list.push_back(in);
      if(loc == end)
        break;
    }
  }
  BasicBlock *bb = new
    BasicBlock(start,end,PointerSource::NONE,PointerSource::NONE,ins_list);
  bb->target(target);
  bb->fallThrough(fall);
  bb->indTgtAddrs(ind_tgts);
  bb->type(t);
  bb->callType(call_type);
  bb->codeType(ctype);
  for(auto & j : jtable)
    bb->belongsToJumpTable(j);
  return bb;
}

void
CfgElems::readIndrctTgts(BasicBlock *bb, uint64_t fn_addrs) {
  JumpTable j;
  bool indrct_tgt = false;
  vector <uint64_t> ind_tgts = bb->indTgtAddrs();
  for(auto & addr : ind_tgts) {
    indrct_tgt = true;
    auto tgtbb = getBB(addr);
    if(tgtbb != NULL) {
      bb->addIndrctTgt(tgtbb);
      j.addTarget(addr);
      j.addTargetBB(tgtbb);
      ADDPOINTER(addr,PTRTYPE(tgtbb->codeType()),PointerSource::JUMPTABLE,bb->start());
    }
  }
  if(indrct_tgt) {
    j.function(fn_addrs);
    jumpTable(j);
  }
}

void
CfgElems::readCfg() {
  ifstream ifile;
  ifile.open("tmp/cfg/functions.lst");
  string str;
  while(getline(ifile,str)) {
    Function *cur_fn = NULL;
    ifstream fnfile;
    fnfile.open("tmp/cfg/" + str + ".fn");
    string fndata;
    while(getline(fnfile,fndata)) {
      vector<string> words = utils::split_string(fndata," ");
      if(words[0] == "start") {
        uint64_t start = stoll(words[1]);
        uint64_t end = stoll(words[2]);
        LOG("Reading function: "<<hex<<start);
        Function *f = new Function(start,end,true);
        funcMap_[start] = f;
        cur_fn = f;
      }
      else if(words[0] == "def_entry" && cur_fn != NULL) {
        uint64_t entry = stoll(words[1]);
        cur_fn->addEntryPoint(entry);
        LOG("Definite entry: "<<hex<<entry);
        //ADDPOINTERWITHROOT(entry, PointerType::CP,
        //    PointerSource::NONE,PointerSource::NONE);
      }
      else if(words[0] == "psbl_entry" && cur_fn != NULL) {
        uint64_t entry = stoll(words[1]);
        cur_fn->addProbableEntry(entry);
        LOG("Possible entry: "<<hex<<entry);
        //ADDPOINTERWITHROOT(entry, PointerType::UNKNOWN,
        //    PointerSource::NONE,PointerSource::NONE);
      }
      else if(words[0] == "def_bb" && cur_fn != NULL) {
        BasicBlock *bb = readBB(fnfile);
        //bb->isCode(true);
        if(bb != NULL)
          cur_fn->addDefCodeBB(bb);
      }
      else if(words[0] == "psbl_bb" && cur_fn != NULL) {
        BasicBlock *bb = readBB(fnfile);
        //bb->isCode(false);
        if(bb != NULL)
          cur_fn->addUnknwnCodeBB(bb);
      }
    }
    fnfile.close();
  }
  ifile.close();
  //Adding indirect targets
  for(auto & fn : funcMap_) {
    vector <BasicBlock *>defBB = fn.second->getDefCode();
    for(auto & bb : defBB)
      readIndrctTgts(bb,fn.first);
    vector <BasicBlock *>psblBB = fn.second->getUnknwnCode();
    for(auto & bb : psblBB)
      readIndrctTgts(bb,fn.first);
  }

  //Reading pointers
  LOG("Reading pointers");
  uint64_t val = 0;
  PointerSource src = PointerSource::NONE, rootsrc = PointerSource::NONE;
  PointerType type = PointerType::UNKNOWN;
  ifile.open("tmp/cfg/pointers.lst");
  while(getline(ifile,str)) {
    vector<string> words = utils::split_string(str," ");
    if(words[0] == "pointer") {
      LOG("Pointer: "<<str);
      val = stoull(words[1]);
      src = (PointerSource)stoi(words[2]);
      rootsrc = (PointerSource)stoi(words[3]);
      type = (PointerType)stoi(words[4]);
      ADDPOINTERWITHROOT(val,type,src,rootsrc,0);
    }
    else if(words[0] == "symcandidate") {
      LOG("Symbol: "<<str);
      uint64_t location = stoll(words[1]);
      SymbolType symtyp = (SymbolType)stoi(words[2]);
      bool symbolize = (bool)stoi(words[3]);
      Symbol s(location,symtyp);
      s.symbolize(symbolize);
      pointerMap_[val]->symCandidate(s);
    }
  }
  ifile.close();
}
*/
void 
CfgElems::dump() {
  ofstream ofile;
  ofile.open("tmp/cfg/functions.lst");
  for(auto & fn : funcMap_) {
    auto entries = fn.second->allEntries();
    for(auto & e : entries) {
      auto bb = getBB(e);
      if(bb != NULL) {
        if(bb->isCode()) {
          ofile<<dec<<"Definite entry: "<<fn.second->start()<<endl;
        }
        else if(bb->notData()) {
          ofile<<dec<<"Possible entry: "<<fn.second->start()<<endl;
        }
      }
    }
    fn.second->dump();
  }
  ofile.close();

  ofile.open("tmp/cfg/pointers.lst");
  for(auto & ptr : pointerMap_) {
    ptr.second->dump(ofile);
  }
  ofile.close();

  ofile.open("tmp/cfg/jmptables.lst");
  for(auto & j : jmpTables_) {
    j.dump(ofile);
  }
  ofile.close();
}

vector<Gap>
CfgElems::getGaps() {
  vector<Gap> all_gaps;
  for(auto & fn : funcMap_) {
    auto all_bbs = fn.second->allBBs();
    if(all_bbs.size() == 0) //If the function contains no basic blocks, then its already covered as gap from previous function
      continue;
    //DEF_LOG("Received all bbs");
    BasicBlock *prev_bb = NULL;
    for(auto & bb : all_bbs) {
      if(prev_bb != NULL) {
        if(bb->start() > prev_bb->boundary()) {
          uint64_t gap_end = bb->start();
          DEF_LOG("Intra fn gap: "<<hex<<prev_bb->boundary()<<" - "<<gap_end);
          Gap g(prev_bb->boundary(), gap_end);
          jumpTgtsInGap(g.start_,g.end_);
          all_gaps.push_back(g);
        }
      }
      prev_bb = bb;
    }
    auto fn_it = funcMap_.find(fn.first);
    uint64_t next_fn_start = 0;
    fn_it++;
    while(fn_it != funcMap_.end()) {
      auto bbs = fn_it->second->allBBs();
      if(bbs.size() == 0)
        fn_it++;
      else {
        next_fn_start = bbs[0]->start();
        break;
      }
    }
    auto sec_end = sectionEnd(fn.first);
    if(fn_it == funcMap_.end() || next_fn_start == 0 || next_fn_start >  sec_end)
      next_fn_start = sec_end;

    uint64_t fn_end = fn.first;
    if(prev_bb != NULL && prev_bb->boundary() > fn_end)
      fn_end = prev_bb->boundary();
    if(next_fn_start > fn_end /*&& (next_fn_start - fn_end) > 20*/) {
      DEF_LOG("Inter fn gap: "<<hex<<fn_end<<" - "<<next_fn_start);
      uint64_t gap_end = next_fn_start;
      Gap g(fn_end, gap_end);
      jumpTgtsInGap(g.start_,g.end_);
      all_gaps.push_back(g);
    }
  }
  //for(auto & g : all_gaps)
  //  gapScore(g);
  return all_gaps;
}

void
CfgElems::printDeadCode() {
  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1);
  string input_file_name = "tmp/" + file_name + "_deadcode.s";
  string psbl_jmp_tbl = "tmp/" + file_name + "_jmptbl.s";
  string dead_code_regions = "tmp/" + file_name + "_deadcode.data";
  ofstream ofile1, ofile2, ofile3;
  ofile1.open(input_file_name);
  ofile2.open(psbl_jmp_tbl);
  ofile3.open(dead_code_regions);
  for(auto fn : funcMap_) {
    vector <BasicBlock *> bbList = fn.second->getDefCode();
    bool deadcode = false;
    for(auto & bb : bbList) {
      if(bb->source() == PointerSource::SYMTABLE ||
         bb->rootSrc() == PointerSource::SYMTABLE || deadcode) {
        if(deadcode == false) {
          deadcode = true;
        }
        vector <string> all_orig_ins = bb->allAsm();
        for(string & asm_ins:all_orig_ins)
          ofile1 <<asm_ins <<endl;
        for(auto i = bb->start(); i < bb->boundary(); i++)
          ofile3<<dec<<i<<endl;
      }
      else if(bb->source() == PointerSource::JUMPTABLE ||
         bb->source() == PointerSource::EXTRA_RELOC_PCREL ||
         bb->rootSrc() == PointerSource::JUMPTABLE ||
         bb->rootSrc() == PointerSource::EXTRA_RELOC_PCREL) {
        
        vector <string> all_orig_ins = bb->allAsm();
        
        for(string & asm_ins:all_orig_ins) {
          ofile2 <<asm_ins <<endl;
        }
      }
      else if (bb->source() == PointerSource::DEBUGINFO ||
         bb->rootSrc() == PointerSource::DEBUGINFO) {
        vector <string> all_orig_ins = bb->allAsm();
        for(string & asm_ins:all_orig_ins)
          ofile1 <<asm_ins <<endl;
        for(auto i = bb->start(); i < bb->boundary(); i++)
          ofile3<<dec<<i<<endl;
      }
      if(deadcode == false) {
        auto ind_bbs = bb->indirectTgts();
        for(auto & ind_bb : ind_bbs) {
          //vector <BasicBlock *> lst = bbSeq(ind_bb);
          //for(auto & bb2 : lst) {
            vector <string> all_orig_ins = ind_bb->allAsm();

            for(string & asm_ins:all_orig_ins) {
              ofile2 <<asm_ins <<endl;
            }
         // }
          ofile2<<"----------------------------------------------\n";
        }
      }
    }
  }
  ofile1.close();
  ofile2.close();
  ofile3.close();
}

void
CfgElems::printOriginalAsm() {
  //To be used for debugging purpose
  string key("/");
  size_t found = exePath_.rfind(key);
  string file_name = exePath_.substr(found + 1);
  string input_file_name1 = "tmp/" + file_name + "_defcode.s";
  string input_file_name2 = "tmp/" + file_name + "_gap.s";
  string input_file_name3 = "tmp/" + file_name + "_data_in_code.s";
  string input_file_name4 = "tmp/" + file_name + "_gap_size.dat";

  ofstream ofile1, ofile2, ofile3, ofile4;
  ofile1.open(input_file_name1);
  ofile2.open(input_file_name2);
  ofile3.open(input_file_name3);
  ofile4.open(input_file_name4);


  for(auto & fn : funcMap_) {
    vector<BasicBlock *> defBBs = fn.second->getDefCode();
    for(auto & bb : defBBs) {
      vector <string> all_orig_ins = bb->allAsm();
      for(string asm_ins:all_orig_ins)
        ofile1 <<asm_ins <<endl;
    }
    vector<BasicBlock *>gapBB = fn.second->getUnknwnCode();
    for(auto & bb : gapBB) {
      vector <string> all_orig_ins = bb->allAsm();
      for(string asm_ins:all_orig_ins)
        ofile2 <<asm_ins <<endl;
    }
    vector<BasicBlock *> data_in_code = fn.second->getDataInCode();
    for(auto & bb : data_in_code) {
      vector <string> all_orig_ins = bb->allAsm();
      for(string asm_ins:all_orig_ins)
        ofile3 <<asm_ins <<endl;
    }
  }

  //auto all_gaps = getGaps();

  //for(auto & g : all_gaps)
  //  ofile4<<dec<<g.start_<<" "<<g.end_<<endl;

  ofile1.close();
  ofile2.close();
  ofile3.close();
  ofile4.close();

}

bool 
CfgElems::withinRoSection(uint64_t addrs) {
  for(section & sec : rxSections_) {
    if(sec.sec_type == section_types::RONLY && sec.vma <= addrs && 
        (sec.vma + sec.size) > addrs) {
      return true;
    }
  }
  return false;
}

bool 
CfgElems::readableMemory(uint64_t addrs) {
  for(section & sec : rxSections_) {
    if(sec.vma <= addrs && (sec.vma + sec.size) > addrs) {
      return true;
    }
  }
  if(withinRWSection(addrs))
    return true;
  return false;
}

bool 
CfgElems::isMetadata(uint64_t addrs) {
  for(section & sec : rxSections_) {
    if(sec.vma <= addrs && (sec.vma + sec.size) > addrs) {
      if(sec.is_metadata)
        return true;
      else
        return false;
    }
  }
  return true;
}

bool 
CfgElems::withinRWSection(uint64_t addrs) {
  for(section & sec : rwSections_) {
    if(sec.vma <= addrs && (sec.vma + sec.size) > addrs) {
      return true;
    }
  }
  return false;
}

bool
CfgElems::isDatainCode(uint64_t addrs) {
  auto fn = is_within(addrs,funcMap_);
  if(fn == funcMap_.end())
    return false;
  return fn->second->isDataInCode(addrs);
}

bool CfgElems::isDataPtr(Pointer * ptr) {
  /*Checks if a constant pointer lies within dats segment. If yes, marks it as
   * a data pointer.
   */
  
  uint64_t
    val = ptr->address();
  if(val >= codeSegEnd_ || isJmpTbl(val) == true 
     || withinRoSection(val) || withinRWSection(val)/* || isDatainCode(val)*/)
    return true;

  return false;

}

bool CfgElems::isValidAddress(uint64_t addrs) {
  if((addrs >= dataSegmntStart_ && addrs < dataSegmntEnd_)){
    return true;
  }
  else if(withinRoSection(addrs) ||
          withinCodeSec(addrs)) {
    return true;
  }
  return false;
}

void
CfgElems::classifyPtrs() {
  /*Iterates over the list of pointers and classifies them as CP/DP/UNKNOWN.
   */

  //if(type_ != code_type::CODE)
  //  return;


  for(auto ptr_it = pointerMap_.begin(); ptr_it != pointerMap_.end();
       ptr_it++) {
    LOG("Classifying pointer: "<<hex<<ptr_it->first);
    Pointer *ptr = ptr_it->second;
    if(ptr->type() == PointerType::UNKNOWN ||
       ptr->type() == PointerType::DEF_PTR) {
      if(isCodePtr(ptr)) {
#ifdef FN_PRLG_CHK
        auto bb = getBB(ptr_it->first);
        if(bb != NULL && fnSigScore(bb) > 0)
          ptr->type(PointerType::CP);
#else
          ptr->type(PointerType::CP);
#endif
      }
      else if(isDataPtr(ptr)) {
        ptr->type(PointerType::DP);
      }
      else {
        vector <Symbol> sym_candidates = ptr->symCandidate();
        for(auto & s : sym_candidates) {
          if(s.type() == SymbolType::RLTV && definiteCode(s.location())) {
            ptr->type(PointerType::DEF_PTR);
            break;
          }
          else if(s.type() == SymbolType::CONSTANT) {
            for(auto & r : picConstReloc_) {
              if(r.storage == s.location()) {
                ptr->type(PointerType::DEF_PTR);
                break;
              }
            }
            if(ptr->type() == PointerType::DEF_PTR)
              break;
          }
        }
      }
    }
  }
  //DEF_LOG("Classifying pointers complete");
}

bool CfgElems::isCodePtr(Pointer * ptr) {

  /*
   * Checks if a constant pointer is within EH frame boundary. If yes, marks
   * it as a code pointer.
   */
  uint64_t address = ptr->address();
  LOG("Checking if code ptr: "<<hex<<address);
  auto fn = is_within(address,funcMap_);
  if(fn != funcMap_.end()) {
    if(fn->second->isValidIns(address)) {
      return true;
    }
  }
  return false;
}


bool CfgElems::definiteCode(uint64_t addrs) {
  //LOG("Validating address: "<<hex<<addrs);
  auto it = is_within(addrs, funcMap_);
  if(it == funcMap_.end())
    return false;
  return it->second->definiteCode(addrs);
}


void
CfgElems::prntPtrStats() {
  //To be used for debugging purpose only.

  int unconfirmed_ptr = 0;
  int total_ptr = 0;
  for(auto ptr_it = pointerMap_.begin(); ptr_it != pointerMap_.end();
       ptr_it++) {
    LOG("Pointer value: " <<hex <<ptr_it->first);
    LOG(" source: " <<(int) ptr_it->second->source());
    LOG(" status: " <<(int) ptr_it->second->type());
    if(ptr_it->second->source() != PointerSource::EH) {
      Pointer *ptr = ptr_it->second;
      if(ptr->type() == PointerType::UNKNOWN) {
        unconfirmed_ptr++;
        LOG("Unconfirmed pointer: " <<hex <<ptr->address());
      }
      total_ptr++;
    }
  }
  LOG("Total pointers: " <<dec <<total_ptr);
  LOG("Total unconfirmed pointers: " <<unconfirmed_ptr);

  float fraction =(float) unconfirmed_ptr /(float) total_ptr;

  LOG("Fraction of unconfirmed pointers:" <<fraction);

}


void
CfgElems::functions(set <uint64_t> &function_list, uint64_t section_start,
		    uint64_t section_end) {
  /* Returns functions in the given range of addresses.
   */
  auto it = funcMap_.begin();
  while(it != funcMap_.end()) {
      if(it->first>= section_start && it->first <section_end)
	function_list.insert(it->first);
      it++;
    }
}

uint64_t CfgElems::dataBlkEnd() {
  uint64_t data_end = codeSegEnd_;
  if(rwSections_.size()> 0) {
      section
	sec = rwSections_[rwSections_.size() - 1];
      data_end = sec.offset + sec.size;
    }

  return data_end;
}
/*
bool CfgElems::assignLabeltoFn(string label, off_t func_addrs) {

  BasicBlock *bb = getBB(func_addrs);
  if(bb == NULL) {
      LOG("Function " <<hex <<func_addrs <<" doesn't exist in Cfg");
      return false;
    }

  bb->label(label);

  return true;
}
*/
void
CfgElems::populateRltvTgts() {
  LOG("Populating rltv tgts");
  for(auto & fn : funcMap_) {
    vector<BasicBlock *> defBBs = fn.second->getDefCode();
    for(auto & bb : defBBs) {
      vector <Instruction *> ins_list = bb->insList();
      for(auto & ins : ins_list) {
        uint64_t tgt = ins->ripRltvOfft();
        if(tgt != 0) {
          auto tgt_bb = getBB(tgt);
          if(tgt_bb != NULL) {
            //LOG("Adding rltv tgt: "<<hex<<tgt_bb->start());
            bb->rltvTgt(tgt_bb);
          }
        }
      }
    }
    vector<BasicBlock *> unknwnBBs = fn.second->getUnknwnCode();
    for(auto & bb : unknwnBBs) {
      //LOG("BB: "<<hex<<bb->start());
      vector <Instruction *> ins_list = bb->insList();
      for(auto & ins : ins_list) {
        uint64_t tgt = ins->ripRltvOfft();
        if(tgt != 0) {
          auto tgt_bb = getBB(tgt);
          if(tgt_bb != NULL) {
            //LOG("Adding rltv tgt: "<<hex<<tgt_bb->start());
            bb->rltvTgt(tgt_bb);
          }
        }
      }
    }
  }
  LOG("populating rltv tgts complete");
}

void
CfgElems::propagateEntries(set <uint64_t> &entries) {
  for(auto & e : entries) {
    if(entryPropagated_.find(e) != entryPropagated_.end())
      continue;
    entryPropagated_.insert(e);
    auto bb = getBB(e);
    if(bb != NULL) {
      auto bb_list = bbSeq(bb,SEQTYPE::INTRAFN);
      LOG("propagating entry: "<<hex<<e<<" bb count: "<<bb_list.size());
      for(auto & bb2 : bb_list)
        bb2->entries(bb);
    }
  }
}

void
CfgElems::propagateAllRoots() {
  for (auto & p : pointerMap_) {
    if(p.second->type() == PointerType::CP ||
       p.second->symbolizable(SymbolizeIf::CONST) ||
       p.second->symbolizable(SymbolizeIf::RLTV) ||
       p.second->symbolizable(SymbolizeIf::IMMOPERAND) ||
       p.second->symbolizable(SymbolizeIf::JMP_TBL_TGT)) {
      LOG("Propagating root: "<<hex<<p.first);
      auto bb = getBB(p.first);
      if(bb != NULL) {
        bb->roots(bb);
      }
    }
  }

  for(auto & fn : funcMap_) {
    auto e = fn.second->entryPoints();
    propagateEntries(e);
    e = fn.second->probableEntry();
    propagateEntries(e);
  }
}

void
CfgElems::linkBBs(vector <BasicBlock *> &bbs) {
  //LOG("Linking BBs");
  for(auto & bb : bbs) {
    if(bb->target() != 0 && bb->targetBB() == NULL) {
      auto tgtbb = getBB(bb->target());
      if(tgtbb == NULL) {
        //LOG("No BB for target address "<<hex<<bb->target());
        //exit(0);
      }
      else {
        bb->targetBB(tgtbb);
        if(tgtbb->start() == 0x1bcb10)
          DEF_LOG("Parent: "<<hex<<bb->start()<<"->Child: "<<hex<<tgtbb->start());
        if(tgtbb->start() != bb->start()) 
          tgtbb->parent(bb);
      }
    }
    if(bb->fallThrough() != 0 && bb->fallThroughBB() == NULL) {
      auto fallbb = getBB(bb->fallThrough());
      if(fallbb == NULL) {
        //LOG("No BB for fall-through address "<<hex<<bb->fallThrough()<<" bb "<<hex<<bb->start());
        //exit(0);
        //bb->fallThrough(0);
      }
      else {
        //LOG("Adding fall through: "<<hex<<bb->fallThrough()<<" bb "<<hex<<bb->start());
        bb->fallThroughBB(fallbb);
        fallbb->parent(bb);
      }
    }
  }
}

void
CfgElems::updateBBTypes() {
  for(auto & fn : funcMap_) {
    vector<BasicBlock *> defBBs = fn.second->getDefCode();
    for(auto & bb : defBBs) {
      //LOG("Updating bb type: "<<hex<<bb->start());
      bb->updateType();
      if(bb->isCall() && bb->callType() == BBType::NON_RETURNING) {
        auto fall = bb->boundary();
        newPointer(fall, PointerType::UNKNOWN,
            PointerSource::POSSIBLE_RA,PointerSource::POSSIBLE_RA,bb->end());
        createFn(true,fall,fall,code_type::UNKNOWN);
      }

    }
    vector<BasicBlock *> unknwnBBs = fn.second->getUnknwnCode();
    for(auto & bb : unknwnBBs) {
      //LOG("Updating bb type: "<<hex<<bb->start());
      bb->updateType();
      if(bb->isCall() && bb->callType() == BBType::NON_RETURNING) {
        auto fall = bb->boundary();
        newPointer(fall, PointerType::UNKNOWN,
            PointerSource::POSSIBLE_RA,PointerSource::POSSIBLE_RA,bb->end());
        createFn(true,fall,fall,code_type::UNKNOWN);
      }
    }
  }
}

void
CfgElems::linkAllBBs() {
  for(auto & fn : funcMap_) {
    fn.second->removeDuplicates();
    vector<BasicBlock *> defBBs = fn.second->getDefCode();
    linkBBs(defBBs);
    vector<BasicBlock *> unknwnBBs = fn.second->getUnknwnCode();
    linkBBs(unknwnBBs);
  }
}
/*
int
CfgElems::offsetFrmCanaryToRA(vector <BasicBlock *> &bb_list) {
  int offt = -1;
  for(auto & bb : bb_list) {
    auto ins_list = bb->insList();
    for(auto & ins : ins_list) {
      if(ins->asmIns().find("%fs:0x28") != string::npos && ins->asmIns().find("xor") != string::npos) {
        uint64_t ra_offset = peepHoleStackDecrement(ins->location(), bb);
        ins->raOffset(ra_offset);
        ins->canaryCheck(true);
        if(offt == -1)
          offt = ra_offset;
        else if(offt != (int)ra_offset)
          return -1;
      }
    }
  }
  return offt;
}
*/
int 
CfgElems::offsetFrmCanaryAddToRa(uint64_t add_loc, BasicBlock *bb) {
  auto ins_list = bb->insList();
  vector <Instruction *> ins_till_canary;
  for(auto & ins : ins_list) {
    if(ins->location() <= add_loc)
      ins_till_canary.push_back(ins);
  }
  int offt = stackDecrement(ins_till_canary);
  return offt;
}
/*
void
CfgElems::instrumentCanary() {
  for(auto fn : funcMap_) {

    auto all_entries = fn.second->allEntries();
    for(auto & e : all_entries) {
      auto bb = getBB(e);
      if(bb != NULL) {
        auto entry_ins_list = bb->insList();

        auto bb_list = bbSeq(bb);
        for(auto & bb : bb_list) {
          auto ins_list = bb->insList();
          for(auto & ins : ins_list) {
            if(ins->asmIns().find("%fs:0x28") != string::npos && ins->asmIns().find("mov") != string::npos) {
              ins->canaryAdd(true);
              auto canary_add_to_exit = bbSeq(bb);
              auto ra_offset = offsetFrmCanaryToRA(canary_add_to_exit);
              if(ra_offset != -1)
                ins->raOffset(ra_offset);
            }
          }
        }
      }
    }
  }
}
*/

void
CfgElems::shadowStackRetInst(BasicBlock *bb,pair<InstPoint,string> &x) {
  auto ins_list = bb->insList();
  //for(auto & ins : ins_list) {

  //}
  bool canary_found = false;
  if(x.first == InstPoint::SHADOW_STACK) {
    for(auto &ins : ins_list) {
      if(ins->asmIns().find("%fs:0x28") != string::npos &&
        (ins->asmIns().find("xor") != string::npos || ins->asmIns().find("sub") != string::npos)) {
        ins->canaryCheck(true);
        canary_found = true;
        ins->registerInstrumentation(InstPoint::SHSTK_CANARY_EPILOGUE,x.second,instArgs()[x.second]);
        DEF_LOG("Registering canary epilogue instrumentation: "<<hex<<ins->location());
        while (true) {
          auto last_ins = bb->lastIns();
          if(last_ins->isJump() || last_ins->isCall() || last_ins->asmIns().find("ret") != string::npos)
            break;
          bb = bb->fallThroughBB();
          if(bb == NULL)
            break;
        }
        auto fall_bb = bb->fallThroughBB();
        if(fall_bb != NULL) {
          auto list = canaryCheckWindow(fall_bb);
          auto last_ins = list[list.size() - 1];
          DEF_LOG("Canary window: "<<hex<<list[0]->location()<<"->"<<last_ins->location());
          if(last_ins->asmIns().find("ret") != string::npos) {
            DEF_LOG("Registering shadow stack return instrumentation: "<<hex<<last_ins->location());
            last_ins->registerInstrumentation(InstPoint::SHSTK_FUNCTION_RET,x.second,instArgs()[x.second]);
          }
        }
        auto tgt_bb = bb->targetBB();
        if(tgt_bb != NULL) {
          auto list = canaryCheckWindow(tgt_bb);
          auto last_ins = list[list.size() - 1];
          DEF_LOG("Canary window: "<<hex<<list[0]->location()<<"->"<<last_ins->location());
          if(last_ins->asmIns().find("ret") != string::npos) {
            //bb->lastIns()->mnemonic("jmp");
            DEF_LOG("Registering shadow stack return instrumentation: "<<hex<<last_ins->location());
            last_ins->registerInstrumentation(InstPoint::SHSTK_FUNCTION_RET,x.second,instArgs()[x.second]);
          }
        }
        break;
      }
    }
  }
  auto last_ins = bb->lastIns();
  if(last_ins->asmIns().find("ret") != string::npos) {
    if(last_ins->alreadyInstrumented(InstPoint::SHSTK_FUNCTION_RET) == false &&
       last_ins->alreadyInstrumented(InstPoint::LEGACY_SHADOW_STACK) == false) {
      last_ins->registerInstrumentation(InstPoint::LEGACY_SHADOW_STACK,x.second,instArgs()[x.second]);
      DEF_LOG("Registering legacy shadow stack return instrumentation: "<<hex<<last_ins->location());
    }
  }
  //else if(last_ins->isJump() && last_ins->isIndirectCf() && canary_found == false &&
  //        bb->indirectTgts().size() <= 0 &&
  //        last_ins->alreadyInstrumented(InstPoint::LEGACY_SHADOW_STACK) == false &&
  //        withinPltSec(last_ins->location()) == false) {
  //    last_ins->registerInstrumentation(InstPoint::LEGACY_SHADOW_STACK,x.second,instArgs()[x.second]);
  //    DEF_LOG("Registering legacy shadow stack return instrumentation for indirect jump: "<<hex<<last_ins->location());
  //}
  else if(canary_found == false && last_ins->isUnconditionalJmp() && last_ins->isCall() == false && bb->target() != 0 &&
          withinPltSec(bb->target()) && withinPltSec(last_ins->location()) == false &&
          last_ins->alreadyInstrumented(InstPoint::LEGACY_SHADOW_STACK) == false) {
      last_ins->registerInstrumentation(InstPoint::LEGACY_SHADOW_STACK,x.second,instArgs()[x.second]);
      DEF_LOG("Registering legacy shadow stack return instrumentation for direct jump: "<<hex<<last_ins->location());
  }
}

vector <Instruction *>
CfgElems::canaryCheckWindow(BasicBlock *bb) {
  auto ins_list = bb->insList();
  vector <Instruction *> window;
  window.insert(window.end(),ins_list.begin(),ins_list.end());
  while (true){
    auto last_ins = bb->lastIns();
    if(last_ins->isJump() || last_ins->isCall() || last_ins->asmIns().find("ret") != string::npos)
      break;
    bb = bb->fallThroughBB();
    if(bb != NULL) {
      auto list = bb->insList();
      window.insert(window.end(),list.begin(),list.end());
    }
    else
      break;
  }
  return window;
}


BasicBlock *canaryPrologueBB(BasicBlock *entry) {
  while(entry != NULL) {
    auto canary_ins = entry->canaryPrologue();
    if(canary_ins != NULL)
      return entry;
    auto last_ins = entry->lastIns();
    if(last_ins->isJump() || 
       last_ins->isCall() || 
       last_ins->asmIns().find("ret") != string::npos)
      break;
    entry = entry->fallThroughBB();
  }
  if(entry != NULL) {
    if(entry->isCall())
      return NULL;
    auto fall_bb = entry->fallThroughBB();
    auto tgt_bb = entry->targetBB();
    while(fall_bb != NULL) {
      auto canary_ins = fall_bb->canaryPrologue();
      if(canary_ins != NULL)
        return fall_bb;
      auto last_ins = fall_bb->lastIns();
      if(last_ins->isJump() || 
         last_ins->isCall() || 
         last_ins->asmIns().find("ret") != string::npos)
        break;
      fall_bb = fall_bb->fallThroughBB();
    }
    while(tgt_bb != NULL) {
      auto canary_ins = tgt_bb->canaryPrologue();
      if(canary_ins != NULL)
        return tgt_bb;
      auto last_ins = tgt_bb->lastIns();
      if(last_ins->isJump() || 
         last_ins->isCall() || 
         last_ins->asmIns().find("ret") != string::npos)
        break;
      tgt_bb = tgt_bb->fallThroughBB();
    }
  }
  return NULL;
}

bool
CfgElems::shstkForCanaryProlog(BasicBlock *canary_bb, pair<InstPoint,string> &x) {
  Instruction *canary_ins = NULL;
  Instruction *fall_ins = NULL;
  canary_ins = canary_bb->canaryPrologue();
  bool canary_found = false;
  if(canary_ins == NULL) {
    DEF_LOG("Canary bb is not null but canary ins is null: "<<hex<<canary_bb->start());
    return false;
  }
  auto canary_fall = canary_ins->fallThrough();
  auto tmp_bb = canary_bb;
  while(fall_ins == NULL && tmp_bb != NULL) {
    fall_ins = tmp_bb->getIns(canary_fall);
    tmp_bb = tmp_bb->fallThroughBB();
  }
  if(canary_ins != NULL && fall_ins != NULL) {
    canary_found = true;
    DEF_LOG("Canary ins: "<<hex<<canary_ins->location());
    DEF_LOG("Canary fall through: "<<hex<<fall_ins->location());
    if(canary_ins->alreadyInstrumented(InstPoint::SHSTK_CANARY_CHANGE) == false) {
      canary_ins->canaryAdd(true);
      canary_ins->registerInstrumentation(InstPoint::SHSTK_CANARY_CHANGE,x.second,instArgs()[x.second]);
      fall_ins->registerInstrumentation(InstPoint::SHSTK_CANARY_MOVE,x.second,instArgs()[x.second]);
    }
  }
  return canary_found;
}

bool
CfgElems::findAndInstrumentCanaryProlog(BasicBlock *bb, pair<InstPoint,string> &x) {
  auto canary_bb = canaryPrologueBB(bb);
  bool canary_found = false;
  if(canary_bb != NULL) {
     return shstkForCanaryProlog(canary_bb, x);
  }

  return canary_found;

}

void
CfgElems::shstkForIndrctTailCall(BasicBlock *entry, pair<InstPoint,string> &x) {
  auto ins_list = entry->insList();
  auto sig_score = fnSigScore(ins_list);
  DEF_LOG("Entry: "<<hex<<entry->start()<<" score: "<<sig_score);
  if(sig_score > 0) {
    //It means it is doing some stack change operation at beginning
    //Check and instrument tail calls only for this case.
    //If there is no stack change operation, it is hard to say if the indirect jump is a tail call. We do not instrument such cases

    auto bb_list = bbSeq(entry);
    for(auto & bb : bb_list) {
      auto last_ins = bb->lastIns();
      if(last_ins->isIndirectCf() && last_ins->isJump() && bb->indirectTgts().size() <= 0 && 
         last_ins->alreadyInstrumented(InstPoint::LEGACY_SHADOW_STACK) == false && 
         withinPltSec(last_ins->location()) == false) {
        //This means the basic block ends with an indirect jump that is not a jump table jump (intra functions) and not an intra module (plt) jump

        auto ins_path = insPath(entry, last_ins->location());
        auto ra_loc = getRA(ins_path);

        if(ra_loc.reg == "%rsp" && ra_loc.offt == 0) {

          //Instrument if the stack is preserved before indirect jump

          last_ins->registerInstrumentation(InstPoint::LEGACY_SHADOW_STACK,x.second,instArgs()[x.second]);
          DEF_LOG("Registering legacy shadow stack return instrumentation for indirect jump: "<<hex<<last_ins->location());
        }
      }
    }
  }
}

void
CfgElems::shstkForDefEntries(BasicBlock *bb, pair<InstPoint,string> &x) {
  DEF_LOG("Shadow stack instrumentation for entry point: "<<hex<<bb->start());
  if(withinPltSec(bb->start()) == false)
    bb->registerInstrumentation(InstPoint::SHSTK_FUNCTION_ENTRY,x.second,instArgs()[x.second]);
  bool canary_found = false;
  if(x.first == InstPoint::SHADOW_STACK) {
    canary_found = findAndInstrumentCanaryProlog(bb, x);
  }
  auto bb_list = bbSeq(bb);
  //Check for indirect tail calls if canary slot not found
  //1. Should not be a jump table
  //2. RSP must be preserved
  if(canary_found == false) {
  
    //We need to handle tail calls only of the canary prologue is not found.
    //Else the tail call handling will be taken care by the canary epilogue
    //handling routine...no need to do anything here
  
    shstkForIndrctTailCall(bb, x);
  }
}


extern long double propScore(vector <Property> &p_list);

void
CfgElems::shadowStackInstrumentV2(pair<InstPoint,string> &x) {

  //First instrument all direct call targets and known function pointers such as dynamic symbol table entries

  for(auto & fn : funcMap_) {
    auto all_entries = fn.second->allEntries();
    for(auto & e : all_entries) {
      auto bb = getBB(e);
      if(bb != NULL) {
        bool is_call_tgt = false;
        auto parents = bb->parents();
        for(auto & p : parents) {
          if(p->isCall() && p->target() == bb->start()) {
            is_call_tgt = true;
            break;
          }
        }

        if(is_call_tgt) {
          shstkForDefEntries(bb, x);
        }
      }
    }
    //Instrument all the returns and potential tail calls 
    vector<BasicBlock *> bbs = fn.second->getDefCode();
    for(auto & bb : bbs) {
      auto last_ins = bb->lastIns();
      if(last_ins->isCall())
        last_ins->registerInstrumentation(InstPoint::LEGACY_SHADOW_STACK,x.second,instArgs()[x.second]);
      shstkForCanaryProlog(bb, x);
      shadowStackRetInst(bb,x);
    }
    vector<BasicBlock *> bbs2 = fn.second->getUnknwnCode();
    for(auto & bb : bbs2) {
      auto last_ins = bb->lastIns();
      if(last_ins->isCall())
        last_ins->registerInstrumentation(InstPoint::LEGACY_SHADOW_STACK,x.second,instArgs()[x.second]);
      shstkForCanaryProlog(bb, x);
      shadowStackRetInst(bb,x);
    }
  }

  //Instrument address taken functions
  //Check all the stored constants and RIP relative targets. Instrument them if they preserve stack
  //To deal with false positives, add trampoline instrumentation instead of inlined instrumentation

  for(auto & ptr : pointerMap_) {
    if(ptr.second->source() == PointerSource::PIC_RELOC ||
       ptr.second->source() == PointerSource::KNOWN_CODE_PTR ||
       ptr.second->source() == PointerSource::STOREDCONST ||
       ptr.second->source() == PointerSource::RIP_RLTV ||
       ptr.second->source() == PointerSource::CONSTOP) {

      auto bb = getBB(ptr.first);
      if(bb != NULL &&
         bb->alreadyInstrumented(InstPoint::SHSTK_FUNCTION_ENTRY) == false) {
        auto p_list = bb->contextPassedProps(bb->start());
        auto code_score = propScore(p_list);
        if(bb->isCode() || code_score == 2 || code_score == 6) {
          if(ptr.second->source() == PointerSource::PIC_RELOC ||
             ptr.second->source() == PointerSource::KNOWN_CODE_PTR)
            shstkForDefEntries(bb, x);
          else if(withinPltSec(bb->start()) == false)
            bb->registerInstrumentation(InstPoint::SHSTK_FUNCTION_TRAMP,x.second,instArgs()[x.second]);
        }
      }
    }
  }
}

void
CfgElems::shadowStackInstrument(pair<InstPoint,string> &x) {

  for(auto & fn : funcMap_) {
    DEF_LOG("Checking function for canary prologue: "<<hex<<fn.first);
    auto all_entries = fn.second->allEntries();
    for(auto & e : all_entries) {
      DEF_LOG("Checking entry: "<<hex<<e);
      auto bb = getBB(e);
      if(bb != NULL) {
        bool drct_call_func = false;
        auto bb_parents = bb->parents(); 
        for (auto & p_bb : bb_parents) {
          DEF_LOG("Checking if parent is call: "<<hex<<p_bb->start());
          if ((p_bb->isCall()/* || p_bb->lastIns()->isUnconditionalJmp()*/) &&
              p_bb->target() == bb->start()) {
            drct_call_func = true;
            DEF_LOG("Entry is call target..parent:"<<hex<<p_bb->start());
            break;
          }
        }
        auto ins_list = bb->insList();
        if(drct_call_func || 
          (ins_list[0]->asmIns().find("endbr64") != string::npos &&
          (pointerMap_.find(e) != pointerMap_.end() && 
          (pointerMap_[e]->source() == PointerSource::PIC_RELOC ||
           pointerMap_[e]->source() == PointerSource::KNOWN_CODE_PTR ||
           pointerMap_[e]->source() == PointerSource::STOREDCONST ||
           pointerMap_[e]->source() == PointerSource::RIP_RLTV ||
           pointerMap_[e]->source() == PointerSource::CONSTOP))) ||
          (fn.first == e && fn.second->dummy() == false)) {

          //auto entry_ins = ins_list[0];
          //if(entry_ins->alreadyInstrumented(InstPoint::SHSTK_FUNCTION_ENTRY) == false) {
          //  entry_ins->registerInstrumentation(InstPoint::SHSTK_FUNCTION_ENTRY,x.second,instArgs()[x.second]);
          //}
          bool canary_found = false;
          if(withinPltSec(e) == false)
            bb->registerInstrumentation(InstPoint::SHSTK_FUNCTION_ENTRY,x.second,instArgs()[x.second]);
          if(x.first == InstPoint::SHADOW_STACK) {
            Instruction *canary_ins = NULL;
            Instruction *fall_ins = NULL;
            auto canary_bb = canaryPrologueBB(bb);
            if(canary_bb != NULL) {
              canary_ins = canary_bb->canaryPrologue();
              if(canary_ins == NULL) {
                DEF_LOG("Canary bb is not null but canary ins is null: "<<hex<<canary_bb->start());
                exit(0);
              }
              auto canary_fall = canary_ins->fallThrough();
              auto tmp_bb = canary_bb;
              while(fall_ins == NULL && tmp_bb != NULL) {
                fall_ins = tmp_bb->getIns(canary_fall);
                tmp_bb = tmp_bb->fallThroughBB();
              }
              if(canary_ins != NULL && fall_ins != NULL) {
                canary_found = true;
                DEF_LOG("Canary ins: "<<hex<<canary_ins->location());
                DEF_LOG("Canary fall through: "<<hex<<fall_ins->location());
                if(canary_ins->alreadyInstrumented(InstPoint::SHSTK_CANARY_CHANGE) == false) {
                  canary_ins->canaryAdd(true);
                  canary_ins->registerInstrumentation(InstPoint::SHSTK_CANARY_CHANGE,x.second,instArgs()[x.second]);
                  fall_ins->registerInstrumentation(InstPoint::SHSTK_CANARY_MOVE,x.second,instArgs()[x.second]);
                }
              }
            }
          }

          //auto ins_till_canary = insPath(bb,canary_ins->location());
          //auto ra_location = getRA(ins_till_canary);
          //if(ra_location.reg.length() <= 0) {
          //  DEF_LOG("Could not find frame register");
          //  if(canary_ins->alreadyInstrumented(InstPoint::SHSTK_CANARY_CHANGE) == false) {
          //    canary_ins->canaryAdd(true);
          //    canary_ins->registerInstrumentation(InstPoint::SHSTK_CANARY_CHANGE,x.second,instArgs()[x.second]);
          //    fall_ins->registerInstrumentation(InstPoint::SHSTK_CANARY_MOVE,x.second,instArgs()[x.second]);
          //    auto entry_ins = ins_list[0];
          //    entry_ins->registerInstrumentation(InstPoint::SHSTK_FUNCTION_ENTRY,x.second,instArgs()[x.second]);
          //  }
          //}
          //else if(canary_ins->alreadyInstrumented(InstPoint::SHSTK_CANARY_PROLOGUE) == false) {
          //  canary_ins->raOffset(ra_location.offt);
          //  canary_ins->frameReg(ra_location.reg);
          //  canary_ins->canaryAdd(true);
          //  canary_ins->registerInstrumentation(InstPoint::SHSTK_CANARY_PROLOGUE,x.second,instArgs()[x.second]);
          //  fall_ins->registerInstrumentation(InstPoint::SHSTK_CANARY_MOVE,x.second,instArgs()[x.second]);
          //}
        }
      }
    }
    vector<BasicBlock *> bbs = fn.second->getDefCode();
    for(auto & bb : bbs) {
      auto last_ins = bb->lastIns();
      if(last_ins->isCall())
        last_ins->registerInstrumentation(InstPoint::LEGACY_SHADOW_STACK,x.second,instArgs()[x.second]);
      shadowStackRetInst(bb,x);
    }
    vector<BasicBlock *> bbs2 = fn.second->getUnknwnCode();
    for(auto & bb : bbs2) {
      shadowStackRetInst(bb,x);
    }
  }
}

//void
//CfgElems::shadowStackInstrument(pair<InstPoint,string> &x) {
//  for(auto & fn : funcMap_) {
//    auto entryPoint = fn.second->allEntries();
//
//    //Add instrumentation code at each entry of a function.
//    //A function can have multiple entries.
//
//    bool canary_found = false;
//    for(auto & entry:entryPoint) {
//      DEF_LOG("Shadow stack instrumentation for entry: "<<hex<<entry);
//      auto bb = fn.second->getBB(entry);
//      if(bb != NULL) {
//        bool drct_call_func = false;
//        auto bb_parents = bb->parents(); 
//        for (auto &p_bb : bb_parents) {
//          if ((p_bb->isCall() || p_bb->lastIns()->isUnconditionalJmp()) &&
//              p_bb->target() == bb->start()) {
//            drct_call_func = true;
//            DEF_LOG("Entry is call target..parent:"<<hex<<p_bb->start());
//            break;
//          }
//        }
//        auto ins_list = canaryCheckWindow(bb);
//        if(ins_list[0]->asmIns().find("endbr64") != string::npos || 
//            drct_call_func) {
//          DEF_LOG("Entry is either call target or has endbr64..canary window:"<<hex<<
//                   ins_list[0]->location()<<"->"<<hex<<ins_list[ins_list.size() - 1]->location());
//          vector <Instruction *> ins_till_canary;
//          uint64_t canary_fall = 0;
//          for(auto & ins : ins_list) {
//            ins_till_canary.push_back(ins);
//            if(ins->asmIns().find("%fs:0x28") != string::npos && 
//               ins->asmIns().find("mov") != string::npos &&
//               ins->alreadyInstrumented(InstPoint::SHSTK_CANARY_PROLOGUE) == false) {
//              DEF_LOG("Canary prologue instrumentation: "<<hex<<ins->location());
//              //int canary_offt = stackDecrement(ins_till_canary);//offsetFrmCanaryAddToRa(ins->location(), bb); 
//              auto ra_location = getRA(ins_till_canary);
//              if(ra_location.reg.length() > 0) {
//                ins->raOffset(ra_location.offt);
//                ins->frameReg(ra_location.reg);
//                ins->canaryAdd(true);
//                ins->registerInstrumentation(InstPoint::SHSTK_CANARY_PROLOGUE,x.second,instArgs()[x.second]);
//                canary_found = true;
//                canary_fall = ins->fallThrough();
//              }
//            }
//            if(ins->location() == canary_fall)
//              ins->registerInstrumentation(InstPoint::SHSTK_CANARY_MOVE,x.second,instArgs()[x.second]);
//          }
//          /*
//          if(canary_found) {
//            auto bb_list = bbSeq(bb);
//            for(auto & bb2 : bb_list)
//              shadowStackRetInst(bb2,x);
//          }
//          */
//        }
//      }
//    }
//    if(canary_found) {
//      vector<BasicBlock *> bbs = fn.second->getDefCode();
//      for(auto & bb : bbs) {
//        shadowStackRetInst(bb,x);
//      }
//      vector<BasicBlock *> bbs2 = fn.second->getUnknwnCode();
//      for(auto & bb : bbs2) {
//        shadowStackRetInst(bb,x);
//      }
//    }
//  }
//}

void
CfgElems::instrument() {
  DEF_LOG("Instrumenting CFG");
  vector<pair<uint64_t, string>> tgtAddrs = targetAddrs();
  for(auto tgt:tgtAddrs) {
    auto bb = getBB(tgt.first);
    if(bb != NULL) {
      vector<InstArg> args = instArgs()[tgt.second];
      bb->registerInstrumentation(tgt.first,tgt.second,args);
    }
  }
  vector<pair<InstPoint,string>> targetPos = targetPositions();
  for(auto & x : targetPos) {
    DEF_LOG("Adding instrumentation to CFG: "<<(int)x.first);
    if(x.first == InstPoint::BASIC_BLOCK) {
      for(auto fn : funcMap_) {
        vector<BasicBlock *> bbs = fn.second->getDefCode();
        for(auto & bb : bbs)
          bb->registerInstrumentation(bb->start(),x.second,instArgs()[x.second]);
        vector<BasicBlock *> bbs2 = fn.second->getUnknwnCode();
        for(auto & bb : bbs2)
          bb->registerInstrumentation(bb->start(),x.second,instArgs()[x.second]);
      }
    }
    else if(x.first == InstPoint::ALL_FUNCTIONS) {
      for(auto fn:funcMap_) {
        auto entryPoint = fn.second->entryPoints();

        //Add instrumentation code at each entry of a function.
        //A function can have multiple entries.

        for(auto & entry:entryPoint) {
          auto bb = fn.second->getBB(entry);
          bb->registerInstrumentation(entry,x.second,instArgs()[x.second]);
        }
      }
    }
    else if(x.first == InstPoint::SHADOW_STACK || x.first == InstPoint::LEGACY_SHADOW_STACK) {
      shadowStackInstrumentV2(x);
    }
    else {
      for(auto fn : funcMap_) {
        vector<BasicBlock *> bbs = fn.second->getDefCode();
        for(auto bb:bbs)
          bb->registerInstrumentation(x.first,x.second,instArgs()[x.second]);
        vector<BasicBlock *> bbs2 = fn.second->getUnknwnCode();
        for(auto bb:bbs2)
          bb->registerInstrumentation(x.first,x.second,instArgs()[x.second]);
      }
    }
  }
  for(auto fn : funcMap_) {
    vector<BasicBlock *> bbs = fn.second->getDefCode();
    for(auto bb:bbs)
      bb->instrument();
    vector<BasicBlock *> bbs2 = fn.second->getUnknwnCode();
    for(auto bb:bbs2)
      bb->instrument();
  }

}

void
CfgElems::instrument(uint64_t hook_point,string code) {
  auto bb = getBB(hook_point);
  if(bb != NULL) {
    bb->instrument(code);
  }
}

bool
CfgElems::rewritableJmpTblBase(uint64_t addrs) {
  for(unsigned int i = 0; i < jmpTables_.size (); i++) {
    if(jmpTables_[i].base () == addrs &&
       jmpTables_[i].rewritable())
      return true;
  }
  return false;
}

bool
CfgElems::rewritableJmpTblLoc(uint64_t addrs) {
  for(unsigned int i = 0; i < jmpTables_.size (); i++) {
    if(jmpTables_[i].location () == addrs &&
       jmpTables_[i].rewritable())
      return true;
  }
  return false;
}


JumpTable
CfgElems::jmpTbl(uint64_t loc, uint64_t base) {
  for(auto & j : jmpTables_) {
    if(j.location() == loc && j.base() == base) { 
      return j;
    }
  }
  JumpTable j;
  return j;
}

bool
CfgElems::jmpTblExists(JumpTable &new_j) {
  for(auto & j : jmpTables_) {
    if(j.location() == new_j.location() && j.base() == new_j.base()) { 
      //Add cf loc
      auto new_cf_loc = new_j.cfLoc();
      for(auto & new_cf : new_cf_loc)
        j.cfLoc(new_cf);
      return true;
    }
  }
  return false;
}


bool
CfgElems::isJmpTblLoc(uint64_t addrs) {
  for(auto & j : jmpTables_) {
    if(j.location () == addrs)
      return true;
  }
  return false;
}

bool
CfgElems::isJmpTbl(uint64_t addrs) {
  for(auto & j : jmpTables_) {
    if(j.location () == addrs && j.type() != 2)
      return true;
  }
  return false;
}

bool
CfgElems::isJmpTblBase(uint64_t addrs) {
  for(unsigned int i = 0; i < jmpTables_.size (); i++) {
    if(jmpTables_[i].base () == addrs)
      return true;
  }
  return false;
}

string 
CfgElems::getSymbol(uint64_t addrs) {
  string sym = "";
  auto bb = withinBB(addrs);
  if(bb != NULL && bb->isValidIns(addrs))
    sym = "." + to_string(addrs) + bb->lblSuffix();
  return sym;
}

void
CfgElems::addIndrctTgt(uint64_t ins_loc, BasicBlock *tgt) {
  auto fn = is_within(ins_loc, funcMap_);
  if(fn != funcMap_.end())
    fn->second->addIndrctTgt(ins_loc, tgt);
}
vector <BasicBlock *>
CfgElems::allIndrctTgt(uint64_t ins_loc) {
  vector <BasicBlock *> inds;
  auto fn = is_within(ins_loc, funcMap_);
  if(fn != funcMap_.end())
    return fn->second->allIndrctTgt(ins_loc);
  return inds;
}

void
CfgElems::linkCFToJumpTable(JumpTable *j, vector <uint64_t> &ins_loc) {
  for(auto & loc : ins_loc) {
    auto fn = is_within(loc, funcMap_);
    if(fn != funcMap_.end())
      fn->second->linkCFToJumpTable(j, loc);
  }
}

bool
CfgElems::isData(uint64_t addrs) {
  auto bb = withinBB(addrs);
  if(bb == NULL)
    return false; //If no BB found, it could possibly be code
  
  auto ins_list = bb->insList();
  bool loc_found = false;
  for(auto & ins : ins_list) {
    if(ins->location() == addrs)
      loc_found = true;
    if(loc_found && CFValidity::validOpCode(ins) == false)
      return true;
  }
  return false;
}

uint64_t
CfgElems::dataSegmntEnd (uint64_t addrs)
{
  //Takes an address  and returns the location of next pointer access.
  //The whole region starting from addrs to the next pointer access is
  //considered as one data blk.

  uint64_t next_code = nextCodeBlock(addrs);
  if(next_code != 0)
    return next_code;

  uint64_t ro_data_end = 0;
  map < uint64_t, Pointer * >&pointer_map = pointers ();

  auto ptr_it = pointer_map.lower_bound (addrs);
  ptr_it++;
  if (ptr_it != pointer_map.end ()) {
    if(ptr_it->second->source() == PointerSource::RIP_RLTV ||
       ptr_it->second->source() == PointerSource::CONSTMEM ||
       ptr_it->second->type() == PointerType::DP) {
      if(next_code == 0 ||
        (next_code != 0 && next_code > ptr_it->first))
        return ptr_it->first;
      else if(next_code != 0 && next_code < ptr_it->first)
        return next_code;
    }
  }
  //else if no subsequent pointer access is found, return the end of read-only
  //data section.

  if(next_code != 0)
    return next_code;

  vector < section > rodata_sections = roSections ();

  bool found = false;
  for (section & sec : rodata_sections)
  {
    if (found == true)
      return sec.vma;

    if (addrs >= sec.vma && addrs <= (sec.vma + sec.size))
      found = true;

    ro_data_end = sec.vma + sec.size;
  }

  return ro_data_end;
}
