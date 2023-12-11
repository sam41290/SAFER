
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
  //


  struct RAlocation {
    string reg = "";
    int offt = 0;
  };

  enum class RegValType {
    UNDEFINED,
    UNKNOWN,
    CONSTANT,
    FRAME_PTR
  };

  struct RegVal {
    //GPR base = GPR::NONE;
    RegValType val = RegValType::UNDEFINED;
    int addend = 0;
  };


  struct State {
    unordered_map<int,RegVal> stackState;
    vector <RegVal> regState;
  };

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
    RAlocation getRA(vector <Instruction *> &ins_list);
    vector <Instruction *> insPath(BasicBlock *entry, uint64_t target);
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
    State analyzeRegState(vector <Instruction *> &ins_list);
    vector <Instruction *> insPathDfs(BasicBlock *entry, uint64_t target,
        unordered_set <uint64_t> &passed);
    RegVal updateState(RegVal &tgt, State &state, Operation &op, Instruction
        *ins, bool loop_upd);
    void loopUpdate(State &cur_state, vector <Instruction *> &ins_lst,
                    uint64_t loop_start, uint64_t loop_end);
  };
}

#endif
