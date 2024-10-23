#ifndef FRAME_H
#define FRAME_H

#include <string>
#include <vector>
#include <bits/stdc++.h>
#include "BasicBlock.h"
#include "JumpTable.h"

/* class frame represents a contiguous memory region to which a function belongs. 
 * 1 frame for every function.
 * Obtained from EH frames.
 */

#define ADDBB(func,bb,isDefCode)  {\
    if(isDefCode) \
      func->addDefCodeBB(bb); \
    else \
      func->addUnknwnCodeBB(bb);\
}


using namespace std;
namespace SBI {
class Frame
{
  bool dummy_ = false;
  uint64_t start_;
  uint64_t end_;
  //Basic block starts that are a part of definite code.
  vector <BasicBlock *> cnsrvtvDefCode_;
  vector <BasicBlock *> defCodeBBs_ ;
  //Basic block starts that are not definite code.
  vector <BasicBlock *> unknwnCodeBBs_;	
  vector <BasicBlock *> defDataInCode_;
  unordered_map <uint64_t, bool> overlapping_;
  unordered_set <uint64_t> bbSet_;
public:
  Frame(){}
  Frame(uint64_t p_start, uint64_t p_end, bool p_dummy);
  
  void start(uint64_t p_start) { start_ = p_start;}
  void end (uint64_t p_end) { end_ = p_end; }
  uint64_t start() { return start_; };
  uint64_t end() { return end_; }
  bool dummy() { return dummy_; }
  bool hasUnknwnCode() { return (unknwnCodeBBs_.size() > 0); }
  void addDefCodeBB(BasicBlock *bb) { 
    if(bbExists(bb->start()) == false) {
      LOG("Adding bb: "<<hex<<bb->start()<<" "<<bb<<" Function: "<<start_);
      defCodeBBs_.push_back(bb);
      bb->frame(start_);
      bbSet_.insert(bb->start());
    }
    else
      LOG("BB exists...not adding again");
  }
  void saveCnsrvtvCode() { cnsrvtvDefCode_ =   defCodeBBs_; }
  void addUnknwnCodeBB (BasicBlock *bb) { 
    if(bbExists(bb->start()) == false) {
      LOG("Adding bb: "<<hex<<bb->start()<<" "<<bb<<" Function: "<<start_);
      unknwnCodeBBs_.push_back(bb);
      bb->frame(start_);
      bbSet_.insert(bb->start());
    }
    else
      LOG("BB exists...not adding again");
  }
  
  vector <BasicBlock *> getDefCode();
  vector <BasicBlock *> getUnknwnCode();
  vector <BasicBlock *> getDataInCode();
  bool isDataInCode(uint64_t addrs);
  bool isValidIns(uint64_t address); 
  bool bbExists(uint64_t addrs);
  BasicBlock *getBB(uint64_t addrs);
  void splitFrame(uint64_t addrs, Frame *f); 
  void splitBBs(uint64_t addrs, Frame *f, bool defCode, 
      vector <BasicBlock *> &bbs); 
  bool withinDefCode(uint64_t addrs);
  void removeDuplicates();
  void markAsDefCode(BasicBlock *bb);
  void markAsDefData(BasicBlock *bb);
  bool misaligned(uint64_t start);
  uint64_t nxtDefCode(uint64_t addrs);
  void removeBB(BasicBlock *bb);
  
  bool definiteCode(uint64_t addrs);
  BasicBlock *splitAndGet(uint64_t addrs);
  bool conflictsCnsrvtvCode(uint64_t addrs);
  BasicBlock *withinBB(uint64_t addrs);
  vector <BasicBlock *> leaBBs();
  vector <BasicBlock * > conflictingBBs(uint64_t addrs);
  void addIndrctTgt(uint64_t ins_loc, BasicBlock *tgt);
  vector <pair <uint64_t, uint64_t>> gaps();
  vector <BasicBlock *> allBBs();
  BasicBlock *getDataBlock(uint64_t addrs);
  void linkCFToJumpTable(JumpTable *j, uint64_t ins_loc);
  uint64_t firstCodeAddress();
  unordered_map <uint64_t,string> allReturnAddresses(); 
  vector <string> allReturnSyms();
  vector <BasicBlock *> allIndrctTgt(uint64_t ins_loc);
  virtual vector <uint64_t> allValidEntries() = 0;
private:
};
}
#endif
