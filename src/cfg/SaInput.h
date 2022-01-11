#ifndef _SAINPUT_H
#define _SAINPUT_H

#include "JumpTable.h"
#include "BasicBlock.h"
#include "config.h"
#include "Instruction.h"
#include "Pointer.h"
#include "Function.h"
#include "libutils.h"
#include "libanalysis.h"
#include "Dfs.h"
#include "CFValidity.h"

using namespace std;

#define FOLLOWTARGET(bb,s) \
  ((bb->isCall() && s == SEQTYPE::INTRAFN) ? false : true)

namespace SBI {
  class SaInput : public virtual Dfs {
  public:
    void genFnFile(string file_name,uint64_t entry,vector<BasicBlock *> &bbList);
    void indTgts(vector <BasicBlock *> & bb_list, unordered_map<int64_t,
        vector<int64_t>> & ind_tgts);
    unordered_map<int64_t,int64_t> insSizes(vector <BasicBlock *>bb_lst);
    void dumpIndrctTgt(string fname, unordered_map<int64_t, vector<int64_t>> ind_tgts);
    void dumpInsSizes(string file_name,unordered_map<int64_t,int64_t> &sizes);
  };
}

#endif
