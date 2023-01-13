#ifndef BASICBLK_H
#define BASICBLK_H

#include "Instruction.h"
#include "Pointer.h"
#include "config.h"
//#include "JumpTable.h"
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

//enum class CFStatus {
//  CONSISTENT,
//  INCONSISTENT,
//  UNDER_EXAMINATION,
//  NOT_EXAMINED
//};

enum class Property {
  VALIDINS,
  VALID_CF,
  VALIDINIT,
  SP_PRESERVED,
  ABI_REG_PRESERVED,
  ABI_REG_PRESERVE_AND_VALID_INIT
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
  code_type codeType_ = code_type::UNKNOWN;
  Instruction fallThroughIns_;
  vector <BasicBlock *> parents_;
  BBType type_ = BBType::NA;
  BBType callType_ = BBType::NA;
  vector <Instruction *> insList_;
  vector <BasicBlock *> indirectTgts_;
  vector <BasicBlock *> rltvTgts_;
  vector <uint64_t> indTgtAddrs_;
  vector <uint64_t> psblIndTgts_;
  int traps_ = 0;
  bool isJmpTblBlk_ = false;
  string label_;
  PointerSource source_;
  PointerSource rootSrc_;
  bool isTramp_ = false;
  unordered_set <BasicBlock *> roots_;
  vector <BasicBlock *> entries_;
  bool rootsComputed_ = false;
  unordered_set <int> passedProps_;
  unordered_set <int> failedProps_;
  long double hintScore_ = 0;
  unordered_map <int, bool> props_;
  unordered_map <uint64_t, unordered_map <int, bool>> contextProps_;
  uint64_t validityWindow_ = 0;
  uint64_t frame_ = 0;
  vector <BasicBlock *> mergedBBs_;
  bool lockJump_ = false;
  string fallSym_ = "";
public:
  string fallSym() { return fallSym_; }
  void addrTransMust(bool val) { lastIns()->atRequired(val); }
  bool addrTransMust() { return lastIns()->atRequired(); }
  void lockJump(bool val) { lockJump_ = val; }
  bool lockJump() { return lockJump_; }
  void mergeBB(BasicBlock *bb) { mergedBBs_.push_back(bb); }
  uint64_t frame() { return frame_; }
  void frame(uint64_t f) { frame_ = f; }
  uint64_t validityWindow() { return validityWindow_; }
  void validityWindow(uint64_t v) { validityWindow_ = v; }
  void hintScore(long double s) { hintScore_ += s; }
  long double hintScore() { return hintScore_; }
  void clearProps() { props_.clear(); }
  bool somePropPassed() { 
    //if(passedProps_.size() > 0) return true; return false; 

    for(auto & p : props_)
      if(p.second == true)
        return true;
    return false;
  }
  vector <Property> failedProps() {
    vector <Property> p_list;
    for(auto & p : props_)
      if(p.second == false)
        p_list.push_back((Property)p.first);
    return p_list; 
  }
  vector <Property> passedProps() { 
    vector <Property> p_list;
    for(auto & p : props_)
      if(p.second == true)
        p_list.push_back((Property)p.first);
    return p_list; 
  }
  void passedProp(Property p) { 
    //passedProps_.insert((int)p);
    //if(failedProps_.find((int)p) != failedProps_.end())
    //  failedProps_.erase(failedProps_.find((int)p));
    props_[(int)p] = true;
  }
  void failedProp(Property p) { 
    if(props_.find((int)p) == props_.end()) 
      props_[(int)p] = false; 
  }

  void contextProp(Property p, uint64_t entry, bool pass) {
    contextProps_[entry][(int)p] = pass;
  }

  bool contextChecked(uint64_t entry) {
    if(contextProps_.find(entry) == contextProps_.end())
      return false;
    return true;
  }

  vector <Property> contextPassedProps(uint64_t entry) {
    vector <Property> p_list;
    auto props = contextProps_[entry];
    for(auto & p : props)
      if(p.second == true)
        p_list.push_back((Property)p.first);
    return p_list;
  }

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
    //LOG("Entry: "<<start_<<"-"<<hex<<b->start());
    entries_.push_back(b); 
  }
  vector <BasicBlock *> entries() { return entries_; }
  void parent(BasicBlock * p) { if(p != NULL) parents_.push_back(p); }
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
  void source(PointerSource src) { source_ = src; };
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
  vector <BasicBlock *> &indirectTgts() { return indirectTgts_;}
  void indirectTgts(vector <BasicBlock *> &lst) { indirectTgts_ = lst; }
  void addIndrctTgt(BasicBlock *bb) { 
    for(auto & b : indirectTgts_)
      if(b->start() == bb->start())
        return;
    indirectTgts_.push_back(bb);
  }
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
  void updateType();
  bool noConflict(uint64_t addrs);
  void addTrampToTgt();

private:
  void inferType(unordered_set <uint64_t> &passed);
};
}
#endif
