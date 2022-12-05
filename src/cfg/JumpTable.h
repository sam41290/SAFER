#ifndef JUMPTABLE_H
#define JUMPTABLE_H

#include <vector>
#include<string>
#include "BasicBlock.h"
#include "stdint.h"
using namespace std;

/*
 * Represents a jump table.
 * Jump tables store a form of computed code pointers. 
 * We use static analysis to identify the location, size and set of pointers
 * they contain.
 */
namespace SBI {
class JumpTable
{
  uint64_t base_ = 0;
  uint64_t location_ = 0;
  uint64_t end_ = 0;
  uint64_t function_ = 0;
  int entrySize_ = 0;
  int type_;
  vector <BasicBlock *> targetBBs_;
  vector <uint64_t> targets_;
  BasicBlock *baseBB_ = NULL;
  vector <BasicBlock *> cfBBs_;
  uint64_t cfLoc_ = 0;
  bool rewritable_ = true;
public:
  JumpTable(){}
  void rewritable(bool val) { rewritable_ = val; }
  bool rewritable() { return rewritable_; }
  void cfLoc(uint64_t loc) { cfLoc_ = loc; }
  uint64_t cfLoc() { return cfLoc_; }
  void cfBB(BasicBlock *bb) { 
    for(auto & b : cfBBs_)
      if(b->end() == bb->end())
        return;
    cfBBs_.push_back(bb); 
  }
  vector <BasicBlock *> cfBBs() { return cfBBs_; }
  void function(uint64_t f) { function_ = f; }
  uint64_t function() { return function_; }

  int type() { return type_; }
  void type(int t) { type_ = t; }
  void base(uint64_t p_base) { base_ = p_base; }
  void location(uint64_t p_location) { location_ = p_location; }
  void end(uint64_t p_end) { end_ = p_end; }
  void entrySize (int sz) { entrySize_ = sz; }
  void addTargetBB (BasicBlock *p_target) { targetBBs_.push_back(p_target);}
  void addTarget(uint64_t tgt) { targets_.push_back(tgt); }
  vector<uint64_t> targets() { return targets_; }
  vector<BasicBlock *> targetBBs() { return targetBBs_; }
  uint64_t base() { return base_; }
  uint64_t location() { return location_; }
  uint64_t end() { return end_; }
  int entrySize() { return entrySize_; }
  bool isTarget(uint64_t address);
  void baseBB(BasicBlock *bb) { baseBB_ = bb; }

  string rewriteTgts();
  void displayTgts();
};
}
#endif
