#include "Dfs.h"

using namespace SBI;

void
Dfs::directlyReachableBBs(BasicBlock *bb,
    unordered_set <uint64_t> &passed) {
  if(bb != NULL && passed.find(bb->start()) == passed.end()) {
    passed.insert(bb->start());
    ADDBBTOLIST(bb,traversal_,bbList_);
    if(bb->targetBB() != NULL && FOLLOWTARGET(bb,traversal_))
      directlyReachableBBs(bb->targetBB(),passed);
    if(bb->fallThroughBB() != NULL) {
      directlyReachableBBs(bb->fallThroughBB(),passed);
    }
  }
}

vector <BasicBlock *> &
Dfs::bbSeq(BasicBlock *bb, SEQTYPE s) {
  traversal_ = s;
  bbList_.clear();
  unordered_set <uint64_t> passed;
  directlyReachableBBs(bb,passed);
  return bbList_;
}

bool
Dfs::pathExists(BasicBlock *start, BasicBlock *end,
             vector<BasicBlock *> &bbList,
             unordered_set<uint64_t> &passed) {
  if(start->start() == end->start()) {
    bbList.push_back(end);
    return true;
  }
  bool path_exists = false;
  passed.insert(start->start());
  if(start->fallThrough() != 0 &&
     passed.find(start->fallThrough()) == passed.end())
    if(pathExists(start->fallThroughBB(), end, bbList, passed))
      path_exists = true;
  if(start->target() != 0 && FOLLOWTARGET(start,traversal_) &&
     passed.find(start->target()) == passed.end())
    if(pathExists(start->targetBB(),end,bbList, passed))
      path_exists = true;

  if(path_exists) {
    bbList.push_back(start);
  }

  return path_exists;
}

void
Dfs::possibleExits(BasicBlock *bb,
    stack <BasicBlock *> &calls,
    unordered_set <uint64_t> &passed) {
  if(bb != NULL && passed.find(bb->start()) == passed.end()) {
    passed.insert(bb->start());
    if(bb->isCall() && bb->callType() == BBType::MAY_BE_RETURNING)
      calls.push(bb);
    if(bb->targetBB() != NULL && FOLLOWTARGET(bb,traversal_))
      possibleExits(bb->targetBB(),calls,passed);
    if(bb->fallThroughBB() != NULL) {
      possibleExits(bb->fallThroughBB(),calls,passed);
    }
  }
}


vector <pair<uint64_t, vector <BasicBlock *>>>
Dfs::allPathsTo(BasicBlock *bb, SEQTYPE s) {
  traversal_ = s;

  auto entries = bb->entries();

  vector <pair<uint64_t, vector <BasicBlock *>>> all_paths;
  for(auto & e : entries) {
    LOG("Entry: "<<hex<<e->start());
    vector <BasicBlock *> bb_list;
    unordered_set <uint64_t> passed;
    if(pathExists(e,bb,bb_list,passed)) {
      LOG("Path size: "<<hex<<bb_list.size());
      all_paths.push_back(make_pair(e->start(),bb_list));
    }
  }

  return all_paths;
}

stack <BasicBlock *> 
Dfs::psblExitCalls(BasicBlock *bb) {
  traversal_ = SEQTYPE::INTRAFN;
  stack <BasicBlock *> exitCalls;
  unordered_set <uint64_t> passed;
  possibleExits(bb,exitCalls,passed);
  return exitCalls;
}

vector <BasicBlock *> 
Dfs::path(BasicBlock *start, BasicBlock *end,SEQTYPE s) {

  traversal_ = s;
  vector <BasicBlock *> bb_list;
  unordered_set <uint64_t> passed;
  pathExists(start,end,bb_list,passed);
  return bb_list;
}
