#ifndef FUNCTION_H
#define FUNCTION_H

#include<vector>
#include<stdio.h>
#include <stdint.h>
#include "Frame.h"
#include "BasicBlock.h"
#include <set>
using namespace std;

/* Represents a function.
 * Inherits a frame.
 * Contains members that define the properties of a function - entry_points,
 * exits, etc.
 */

namespace SBI {
class Function:public Frame
{
  set <uint64_t> entryPoints_;
  set <uint64_t> probableEntry_;
  set <uint64_t> jmpTblAnalyzed_;
  vector <uint64_t> exitBlocks_;
  unordered_map <uint64_t, bool> passedPropertyCheck_;
  bool hasJmpTbl_ = false;
  bool isLeaf_ = false;
public:
  Function (){}
  Function (uint64_t frame_start, uint64_t frame_end, bool
      dummy):Frame(frame_start,frame_end,dummy){}
  void jmpTblAnalyzed(uint64_t entry) { jmpTblAnalyzed_.insert(entry); }
  set <uint64_t> jmpTblAnalyzed() { return jmpTblAnalyzed_; }

  bool passedPropertyCheck(uint64_t entry) { 
    if(passedPropertyCheck_.find(entry) != passedPropertyCheck_.end())
      return passedPropertyCheck_[entry];
    return false;
  }

  void passedPropertyCheck(uint64_t entry, bool val) {
    passedPropertyCheck_[entry] = val;
    auto bb = getBB(entry);
    if(val)
      bb->CFConsistency(CFStatus::CONSISTENT,TRANSITIVECF);
    else
      bb->CFConsistency(CFStatus::INCONSISTENT,TRANSITIVECF);
  }

  bool propertyChecked(uint64_t entry) {
    if(passedPropertyCheck_.find(entry) != passedPropertyCheck_.end())
      return true;
    return false;
  }
  
  vector <uint64_t> allValidEntries() {
    vector <uint64_t> entries;
    for(auto & e : passedPropertyCheck_)
      if(e.second == true)
        entries.push_back(e.first);
    return entries;
  }

  bool validEntry(uint64_t entry) {
    if(isValidIns(entry))
      return true;
    else if(propertyChecked(entry))
      return passedPropertyCheck_[entry];
    return false;
  }

  bool entryExists(uint64_t entry) {
    if(entryPoints_.find(entry) != entryPoints_.end() ||
       probableEntry_.find(entry) != probableEntry_.end())
      return true;
    return false;
  }
  void addEntryPoint(uint64_t entry) { 
    LOG("Adding definite entry point: "<<hex<<entry);
    if(probableEntry_.find(entry) != probableEntry_.end())
      probableEntry_.erase(entry);
    entryPoints_.insert(entry);
  }
  void addProbableEntry(uint64_t entry) { 
    if(entryExists(entry) == false) {
      LOG("Adding probable entry: "<<hex<<entry);
      probableEntry_.insert(entry); 
    }
  }

  set <uint64_t> entryPoints() { return entryPoints_; };
  bool isLeaf() { return isLeaf_; }
  void isLeaf(bool leaf) { isLeaf_ = leaf; }
  void hasJmpTbl(bool b) { hasJmpTbl_ = b; }
  bool hasJmpTbl() { return hasJmpTbl_; }
  set <uint64_t> probableEntry() { return probableEntry_; }
  Function *splitFunction(uint64_t addrs) { 
    Function *f = new Function(addrs,0,true);
    splitFrame(addrs, (Frame *)f); 
    return f;
  }
  uint64_t firstEntryPoint() {
    uint64_t entry1 = 0,entry2 = 0;
    uint64_t firstEntry = INT_MAX;
    if(entryPoints_.size() > 0) {
      entry1 = *(entryPoints_.begin());
      if(entry1 < firstEntry)
        firstEntry = entry1;
    }
    if(probableEntry_.size() > 0) {
      entry2 = *(probableEntry_.begin());
      if(entry2 < firstEntry)
        firstEntry = entry2;
    }
    if (firstEntry == INT_MAX)
      return 0;
    return firstEntry;
  }

  void dump() {
    uint64_t st = start();
    uint64_t nd = end();
    vector <BasicBlock *> defBB = getDefCode();
    vector <BasicBlock *> psblBB = getUnknwnCode();
    ofstream ofile;
    string file = "tmp/cfg/" + to_string(st) + ".fn";
    ofile.open(file,ofstream::out | ofstream::app);
    ofile<<"start "<<dec<<st<<" "<<dec<<nd<<endl;
    for(auto entry : entryPoints_) {
      ofile<<"def_entry "<<dec<<entry<<endl;
    }
    for(auto entry : probableEntry_)
      ofile<<"psbl_entry "<<dec<<entry<<endl;
    ofile.close();
    for(auto & bb : defBB) {
      ofile.open(file,ofstream::out | ofstream::app);
      ofile<<"def_bb "<<dec<<bb->start()<<" "<<dec<<bb->end()<<endl;
      ofile.close();
      bb->dump(file);
    }
    for(auto & bb : psblBB) {
      ofile.open(file,ofstream::out | ofstream::app);
      ofile<<"psbl_bb "<<dec<<bb->start()<<" "<<dec<<bb->end()<<endl;
      ofile.close();
      bb->dump(file);
    }
    ofile.close();
  }

};
}
#endif
