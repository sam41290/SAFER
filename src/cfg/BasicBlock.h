#ifndef BASICBLK_H
#define BASICBLK_H

#include "Instruction.h"
#include "Pointer.h"
#include "config.h"
#include <set>

/* class basic block represents a basic block in the CFG with one entry and one
 * exit point.
 */

namespace SBI {
enum class BBType
{

  //These types help in identifying non-returning calls or exit calls during
  //disassembly

  RETURNING,
  NON_RETURNING,
  MAY_BE_RETURNING,
  NA
};

enum class CFStatus {
  CONSISTENT,
  INCONSISTENT,
  UNDER_EXAMINATION,
  NOT_EXAMINED
};

enum class Update {
  LOCAL,
  TRANSITIVE
};

class BasicBlock:public Instrument
{
private:
  uint64_t start_ = 0;
  uint64_t end_ = 0;
  BasicBlock *fallThroughBB_ = NULL;
  BasicBlock *targetBB_ = NULL;
  BasicBlock *tramp_ = NULL;
  uint64_t target_ = 0;
  uint64_t fallThrough_ = 0;
  bool isFuncExit_ = false;
  bool isLea_ = false;
  //bool isCode_ = false;
  code_type codeType_ = code_type::UNKNOWN;
  Instruction fallThroughIns_;
  vector <BasicBlock *> parents_;
  BBType type_ = BBType::NA;
  BBType callType_ = BBType::NA;
  vector <Instruction *> insList_;
  unordered_set <BasicBlock *> indirectTgts_;
  vector <BasicBlock *> rltvTgts_;
  vector <uint64_t> indTgtAddrs_;
  int traps_ = 0;
  bool isJmpTblBlk_ = false;
  string label_;
  PointerSource source_;
  PointerSource rootSrc_;
  bool isTramp_ = false;
  CFStatus inComingCall_ = CFStatus::NOT_EXAMINED;
  CFStatus outGoingCall_ = CFStatus::NOT_EXAMINED;
  CFStatus jmpTblConsistency_ = CFStatus::NOT_EXAMINED;
  CFStatus CFConsistency_ = CFStatus::NOT_EXAMINED;
  unordered_set <BasicBlock *> roots_;
  vector <BasicBlock *> entries_;
  bool rootsComputed_ = false;
public:
  //void CFConsistency(CFStatus c) { CFConsistency_ = c; }
  void inconsistentChild(BasicBlock *bb,CFStatus c, Update u) {
    if(bb->CFConsistency() != c) {
      auto p = bb->parents();
      if(p.size() > 1 || p[0]->start() != start_) //Child has other parents
        return;
      auto child_roots = bb->roots();
      for(auto & r : child_roots) //Child itself is a root
        if(r->start() == bb->start())
          return;
      bb->CFConsistency(c,u);
    }
  }
  void CFConsistency(CFStatus c, Update u) {
    LOG("Changing CF consistency: "<<hex<<start_<<" "<<(int)c);
    CFConsistency_ = c;
    if(u == Update::TRANSITIVE && c == CFStatus::INCONSISTENT) {
      for(auto & p : parents_)
        if(p->CFConsistency() != c)
          p->CFConsistency(c,Update::TRANSITIVE);
      if(targetBB_ != NULL)
        inconsistentChild(targetBB_,c,u);
      if(fallThroughBB_ != NULL)
        inconsistentChild(fallThroughBB_,c,u);
    }
  }
  CFStatus CFConsistency() { return CFConsistency_; }
  BasicBlock(uint64_t start, uint64_t end, PointerSource src,
		 PointerSource root,vector <Instruction *> &insList);

  BasicBlock(uint64_t start, uint64_t end, PointerSource src,
      PointerSource root);
  BasicBlock(uint64_t start, PointerSource src,PointerSource root) {
    start_ = start;
    source_ = src;
    rootSrc_ = root;
  }
  void roots(BasicBlock *b) { 
    roots_.insert(b); 
  }
  unordered_set <BasicBlock *> roots();
  void inheritRoots(unordered_set <uint64_t> &passed,
                    unordered_set <BasicBlock *> &roots);
  void entries(BasicBlock *b) { 
    entries_.push_back(b); 
  }
  vector <BasicBlock *> entries() { return entries_; }
  void jmpTblConsistency(CFStatus c) { jmpTblConsistency_ = c; }
  CFStatus jmpTblConsistency() { return jmpTblConsistency_; }
  void inComingCall(CFStatus c) { inComingCall_ = c; }
  CFStatus inComingCall() { return inComingCall_; }
  void outGoingCall(CFStatus c) { outGoingCall_ = c; }
  CFStatus outGoingCall() { return outGoingCall_; }
  void parent(BasicBlock * p) { parents_.push_back(p); }
  vector <BasicBlock *> parents() { return parents_; }
  void callType(BBType t) { callType_ = t; }
  BBType callType() { return callType_; }
  void rltvTgt(BasicBlock *bb) { rltvTgts_.push_back(bb); }
  void isTramp(bool t) { isTramp_ = t; }
  bool isTramp() { return isTramp_; }
  void indTgtAddrs(uint64_t addrs) { indTgtAddrs_.push_back(addrs); }
  vector <uint64_t> indTgtAddrs() { return indTgtAddrs_; }
  void indTgtAddrs(vector <uint64_t> &tgts) { indTgtAddrs_ = tgts; }
  void dump(string file) {
    ofstream ofile;
    ofile.open(file,ofstream::out | ofstream::app);
    ofile<<"start "<<dec<<start_<<" "<<dec<<end_<<endl;
    ofile<<"end "<<dec<<end_<<endl;
    ofile<<"type "<<dec<<(int)type_<<endl;
    ofile<<"calltype "<<dec<<(int)callType_<<endl;
    ofile<<"codetype "<<dec<<(int)codeType_<<endl;
    ofile<<"target "<<dec<<target_<<endl;
    ofile<<"fall "<<dec<<fallThrough_<<endl;
    for (auto & bb : indirectTgts_)
      ofile<<"indrc_tgt "<<dec<<bb->start()<<endl;
    for(auto ins : insList_) {
      ofile<<"ins "<<dec<<ins->location()<<" "<<ins->insSize()<<" "<<ins->asmIns()<<endl;
    }
    ofile.close();
  }
  void target(uint64_t tgt) { target_ = tgt; }
  uint64_t target() { return target_; };
  PointerSource source() { return source_; };
  PointerSource rootSrc() { return rootSrc_; };
  void fallThrough(uint64_t tgt) { fallThrough_ = tgt; }
  uint64_t fallThrough() { return fallThrough_; }

  void isJmpTblBlk(bool isIt) { isJmpTblBlk_ = isIt; };
  bool isJmpTblBlk() { return isJmpTblBlk_; };
  void codeType (code_type c) { codeType_ = c; }
  code_type codeType() { return codeType_; }
  bool isCode() { 
    if(codeType_ == code_type::CODE)
      return true;
    return false;
  }
  void targetBB(BasicBlock *tgt) { targetBB_ = tgt; }
  void fallThroughBB(BasicBlock *fall_through) { fallThroughBB_ = fall_through; }
  BasicBlock *fallThroughBB() { 
    //LOG("Fall through: "<<hex<<fallThrough_);
    return fallThroughBB_; 
  }
  uint64_t end() { return end_; }
  uint64_t start() { return start_; }
  void type(BBType t) { type_ = t; }
  BBType type() { return type_; }
  BasicBlock *targetBB() { return targetBB_; }
  void insList(vector <Instruction *> insLst) { insList_ = insLst; }
  vector <Instruction *> insList() { return insList_;}
  unordered_map <int64_t,int64_t> insSizes() {
    unordered_map <int64_t,int64_t> ins_sz;
    for(auto & ins :insList_) {
      ins_sz[ins->location()] = ins->insSize();
    }
    return ins_sz;
  }
  void fallThroughIns(Instruction ins) { fallThroughIns_ = ins;}
  bool isLea() { return isLea_; }
  void isLea(bool isIt) { isLea_ = isIt; }
  unordered_set <BasicBlock *> &indirectTgts() { return indirectTgts_;}
  void addIndrctTgt(BasicBlock *bb) { indirectTgts_.insert(bb);}
  void end(uint64_t p_end) { end_ = p_end;}
  void traps(int trap_cnt) { traps_ += trap_cnt;}
  void label(string lbl) { label_ = lbl; }
  string label() {
    if(tramp_ != NULL)
      return tramp_->label();
    else if(isCode() == false)
      return insList_[0]->label() + "_" + to_string(start_) + "_unknown_code";
    else
      return insList_[0]->label() + "_" + to_string(start_) + "_def_code";
  }

  string lblSuffix() {
    if(isCode())
      return  "_" + to_string(start_) + "_def_code";
    else
      return "_" + to_string(start_) + "_unknown_code";
  }

  Instruction *getIns(uint64_t address);
  bool isCall();
  Instruction *lastIns();
  bool isValidIns(uint64_t address);
  BasicBlock *split (uint64_t address);
  void deleteIns(uint64_t address);
  void addIns(Instruction *ins);
  bool indirectCFWithReg();
  vector <string> allAsm();
  void print (string file_name, map < uint64_t, Pointer * >&map_of_pointer);
  void adjustRipRltvIns (uint64_t data_segment_start,
      map < uint64_t, Pointer * >&map_of_pointer);
  long insCount();
  void printFallThroughJmp(string file_name);
  vector <uint64_t> allInsLoc();
  void instrument ();
  vector < string > get_all_original_asm_ins ();
  bool inRange(uint64_t addrs);
  void instrument(string code);
  uint64_t boundary();
  void addTramp(uint64_t tramp_start);
  BasicBlock *tramp() { return tramp_; }
};
}
#endif
