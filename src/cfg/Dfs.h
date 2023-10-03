
#ifndef _DFS_H
#define _DFS_H

#include "JumpTable.h"
#include "BasicBlock.h"
#include "config.h"
#include "Instruction.h"
#include "Pointer.h"
#include "Function.h"
#include "libutils.h"
//#include "libanalysis.h"
#include <queue>

using namespace std;

#define FOLLOWTARGET(bb,s) \
  ((bb->isCall() && s == SEQTYPE::INTRAFN) ? false : true)

#define ADDBBTOLIST(bb,s,bblst) \
  if (bb->isCall() && bb->targetBB() != NULL && s == SEQTYPE::CALLGRAPH) \
    bblst.push_back(bb->targetBB()); \
  else if(s != SEQTYPE::CALLGRAPH) \
    bblst.push_back(bb);

namespace SBI {

  //struct IndPath {
  //  uint64_t entry_;
  //  uint64_t tgt_;
  //  vector <BasicBlock *> path_;
  //};

  enum class SEQTYPE {
    INTRAFN,
    GLOBAL,
    CALLGRAPH
  };

  class Dfs {
    
    SEQTYPE traversal_ = SEQTYPE::INTRAFN;
    vector <BasicBlock *> bbList_;
    vector <BasicBlock *> indbbList_;
    queue <BasicBlock *> BfsQ_;
    BasicBlock *curEntry_ = NULL;
    unordered_set <uint64_t> indRoots_;

    unordered_map <uint64_t, BasicBlock *> root_;
    //unordered_map <uint64_t, vector <BasicBlock *>> indPaths_;

  public:
    vector <BasicBlock *> bbSeq(BasicBlock *bb, SEQTYPE s = SEQTYPE::INTRAFN);
    vector <BasicBlock *> bbSeq(BasicBlock *bb, vector <BasicBlock *> &term_at, 
                                SEQTYPE s = SEQTYPE::INTRAFN);
    vector <pair<uint64_t, vector <BasicBlock *>>>allPathsTo(BasicBlock *bb,
        SEQTYPE s = SEQTYPE::INTRAFN);
    stack <BasicBlock *> psblExitCalls(BasicBlock *bb);
    vector <BasicBlock *> path(BasicBlock *start, BasicBlock *end, SEQTYPE s);
    vector <BasicBlock *> allRoutes(BasicBlock *entry, BasicBlock *through,
                                    unordered_set <uint64_t> &valid_ind_path);
    vector <BasicBlock *> allIndTgts(vector <BasicBlock *> &entry);
    bool bbInList(BasicBlock *bb, vector <BasicBlock *> &bb_list);
    vector <BasicBlock *> pathsFromTo(BasicBlock *from, BasicBlock *to);
    bool checkPath(BasicBlock *from, BasicBlock *to);
    vector <BasicBlock *> subGraphParents(BasicBlock *bb);
    vector <BasicBlock *> externalCallers(BasicBlock *bb, BasicBlock *entry);
    int peepHoleStackDecrement(uint64_t addrs, BasicBlock *bb);
    int stackDecrement(vector <Instruction *> &ins_list);
    unordered_set <uint64_t> indRoots() { return indRoots_; }
  private:
    void psblExitDFS(BasicBlock *bb, stack <BasicBlock *> &calls,
                       unordered_set <uint64_t> &passed);
    void directlyReachableBBs(BasicBlock *bb,
                              unordered_set <uint64_t> &passed);

    bool pathExists(BasicBlock *start, BasicBlock *end,
               vector<BasicBlock *> &bbList,
               unordered_set<uint64_t> &passed);
    void allRouteDfs(BasicBlock *through,
                     unordered_set <uint64_t> &passed,
                     unordered_set <BasicBlock *> &path,
                     unordered_set <uint64_t> &valid_ind_path);
    void indTgtsDfs(BasicBlock *entry, 
                                     unordered_set <uint64_t> &passed);
  };
}

#endif
