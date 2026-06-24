#ifndef FUNCTION_H
#define FUNCTION_H

#include<vector>
#include<stdio.h>
#include <stdint.h>
#include "Frame.h"
#include "BasicBlock.h"
#include <set>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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
  
  unordered_map <uint64_t, vector <BasicBlock *>> nonReturningCalls_;

  bool hasJmpTbl_ = false;
  bool isLeaf_ = false;
public:
  Function (){}
  Function (uint64_t frame_start, uint64_t frame_end, bool
      dummy):Frame(frame_start,frame_end,dummy){}
  void jmpTblAnalyzed(uint64_t entry) { jmpTblAnalyzed_.insert(entry); }
  set <uint64_t> jmpTblAnalyzed() { return jmpTblAnalyzed_; }


  vector <BasicBlock *> nonReturningCalls(uint64_t entry) { return nonReturningCalls_[entry]; }
  void nonReturningCalls(uint64_t entry, vector <BasicBlock *> calls) { nonReturningCalls_[entry] = calls; }
 
  vector <uint64_t> allEntries() {
    vector <uint64_t> entries;
    entries.insert(entries.end(),entryPoints_.begin(),entryPoints_.end());
    entries.insert(entries.end(),probableEntry_.begin(),probableEntry_.end());
    return entries;
  }
  vector <uint64_t> allValidEntries() {
    vector <uint64_t> entries;
    entries.insert(entries.end(),entryPoints_.begin(),entryPoints_.end());
    for(auto & e : probableEntry_) {
      auto bb = getBB(e);
      if(bb != NULL && bb->somePropPassed())
        entries.push_back(e);
    }
    /*
    for(auto & e : passedPropertyCheck_)
      if(e.second == true)
        entries.push_back(e.first);
    */
    return entries;
  }

  bool validEntry(uint64_t entry) {
    if(isValidIns(entry))
      return true;
    else {
      auto bb = getBB(entry);
      if(bb != NULL && bb->somePropPassed())
        return true;
    }
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
  void dump() {
    vector <BasicBlock *> defBB = getDefCode();
    vector <BasicBlock *> psblBB = getUnknwnCode();
    string def_file = "tmp/cfg/definite_basicblocks.json";
    string psbl_file = "tmp/cfg/psbl_basicblocks.json";

    //json defj;
    //json psblj;

    ofstream ofile1, ofile2;
    ofile1.open(def_file,ofstream::out | ofstream::app);
    ofile2.open(psbl_file,ofstream::out | ofstream::app);

    for(auto & bb : defBB) {
      
      json bbj = { 
      //defj["bb_list"].push_back({
        {"function", start()},
        {"start", bb->start()},
        {"end", bb->end()},
        {"target",bb->target()},
        {"fall", bb->fallThrough()},	
	{"is_call", bb->isCall()},
	{"call_type",(int)bb->callType()},
	{"indirect_tgts",bb->indTgtAddrs()}
      };
      ofile1<<bbj.dump()<<endl;
     // });
      bb->dump();
    }
    for(auto & bb : psblBB) {
      if(bb->notData()) {
        json bbj = { 
        //psblj["psbl_bb_list"].push_back({
          {"function", start()},
          {"start", bb->start()},
          {"end", bb->end()},
          {"target",bb->target()},
          {"fall", bb->fallThrough()},	
	  {"is_call", bb->isCall()},
	  {"call_type",(int)bb->callType()},
	  {"indirect_tgts",bb->indTgtAddrs()}
       // });
        };
	ofile2<<bbj.dump()<<endl;
        bb->dump();
      }
    }
    //ofile1<<defj.dump(2);
    //ofile2<<psblj.dump(2);
    ofile1.close();
    ofile2.close();
  }

};
}
#endif
