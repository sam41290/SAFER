
#ifndef _DFS_H
#define _DFS_H

#include "JumpTable.h"
#include "BasicBlock.h"
#include "config.h"
#include "Instruction.h"
#include "Pointer.h"
#include "Function.h"
#include "libutils.h"
#include "libanalysis.h"

using namespace std;

#define FOLLOWTARGET(bb,s) \
  ((bb->isCall() && s == SEQTYPE::INTRAFN) ? false : true)

#define ADDBBTOLIST(bb,s,bblst) \
  if (bb->isCall() && bb->targetBB() != NULL && s == SEQTYPE::CALLGRAPH) \
    bblst.push_back(bb->targetBB()); \
  else if(s != SEQTYPE::CALLGRAPH) \
    bblst.push_back(bb);

namespace SBI {

  enum class SEQTYPE {
    INTRAFN,
    GLOBAL,
    CALLGRAPH
  };

  class Dfs {
    
    SEQTYPE traversal_ = SEQTYPE::INTRAFN;
    vector <BasicBlock *> bbList_;
  public:
    vector <BasicBlock *> &bbSeq(BasicBlock *bb, SEQTYPE s = SEQTYPE::INTRAFN);
    vector <pair<uint64_t, vector <BasicBlock *>>>allPathsTo(BasicBlock *bb,
        SEQTYPE s = SEQTYPE::INTRAFN);
    stack <BasicBlock *> psblExitCalls(BasicBlock *bb);
    vector <BasicBlock *> path(BasicBlock *start, BasicBlock *end, SEQTYPE s);
  private:
    void possibleExits(BasicBlock *bb,
                       stack <BasicBlock *> &calls,
                       unordered_set <uint64_t> &passed);
    void directlyReachableBBs(BasicBlock *bb,
                              unordered_set <uint64_t> &passed);
    bool pathExists(BasicBlock *start, BasicBlock *end,
               vector<BasicBlock *> &bbList,
               unordered_set<uint64_t> &passed);
  };
}

#endif
