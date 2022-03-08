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

vector <BasicBlock *> 
Dfs::bbSeq(BasicBlock *bb, SEQTYPE s) {
  traversal_ = s;
  bbList_.clear();
  unordered_set <uint64_t> passed;
  directlyReachableBBs(bb,passed);
  return bbList_;
}


vector <BasicBlock *> 
Dfs::bbSeq(BasicBlock *bb, vector <BasicBlock *> &term_at, SEQTYPE s) {
  traversal_ = s;
  bbList_.clear();
  unordered_set <uint64_t> passed;
  for(auto & term_bb : term_at) {
    if(term_bb->target() != 0)
      passed.insert(term_bb->target());
    if(term_bb->fallThrough() != 0)
      passed.insert(term_bb->fallThrough());
  }
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
Dfs::psblExitBFS(stack <BasicBlock *> &calls, 
                 unordered_set <uint64_t> &passed) {
  if (BfsQ_.empty())
    return;
  auto bb = BfsQ_.front();
  BfsQ_.pop();
  if(passed.find(bb->start()) == passed.end()) {
    //LOG("Bfs bb: "<<hex<<bb->start());
    passed.insert(bb->start());
    if(bb->isCall() && bb->callType() == BBType::MAY_BE_RETURNING) {
      //LOG("Possibly exit call");
      calls.push(bb);
    }
    if(bb->targetBB() != NULL && FOLLOWTARGET(bb,traversal_))
      BfsQ_.push(bb->targetBB());
    if(bb->fallThroughBB() != NULL)
      BfsQ_.push(bb->fallThroughBB());
  }
  psblExitBFS(calls, passed);
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

bool
Dfs::checkPath(BasicBlock *from, BasicBlock *to) {
    vector <BasicBlock *> bb_list;
    unordered_set <uint64_t> passed;
    return pathExists(from,to,bb_list,passed);
}

vector <BasicBlock *>
Dfs::pathsFromTo(BasicBlock *from, BasicBlock *to) {
  vector <BasicBlock *> bb_list;
  unordered_set <uint64_t> passed;
  pathExists(from,to,bb_list,passed);
  return bb_list;
}

vector <BasicBlock *>
Dfs::indTgtsDfs(BasicBlock *entry, unordered_set <uint64_t> &passed) {
  vector <BasicBlock *> ind_tgts;
  auto bb_list = bbSeq(entry);
  for(auto & bb : bb_list) {
    passed.insert(bb->start());
    auto inds = bb->indirectTgts();
    if(inds.size() > 0) {
      //LOG("Entry: "<<hex<<entry->start());
      ind_tgts.insert(ind_tgts.end(),inds.begin(),inds.end());
      for(auto & ind_bb : inds) {
        if(passed.find(ind_bb->start()) == passed.end()) {
          //LOG("ind tgt: "<<hex<<ind_bb->start());
          auto second_layer = indTgtsDfs(ind_bb,passed);
          ind_tgts.insert(ind_tgts.end(),second_layer.begin(),second_layer.end());
        }
      }
    }
  }
  return ind_tgts;
}

vector <BasicBlock *> 
Dfs::allIndTgts(vector <BasicBlock *> &entry) {
  unordered_set <uint64_t> passed;
  vector <BasicBlock *> all_inds;
  for(auto & e : entry) {
    auto lst = indTgtsDfs(e,passed);
    all_inds.insert(all_inds.end(), lst.begin(), lst.end());
  }
  return all_inds;
}

bool 
Dfs::bbInList(BasicBlock *bb, vector <BasicBlock *> &bb_list) {
  for(auto & b : bb_list)
    if(b->start() == bb->start())
      return true;
  return false;
}

bool
Dfs::allRouteDfs(BasicBlock *entry, BasicBlock *through, 
                 unordered_set <uint64_t> &passed,
                 unordered_set <BasicBlock *> &path) {
  //LOG("ind path: "<<hex<<entry->start());
  if(checkPath(entry, through)) {
    auto bb_list = bbSeq(entry);
    path.insert(bb_list.begin(), bb_list.end());
    return true;
  }
  auto bb_list = bbSeq(entry);

  unordered_set <BasicBlock *> ind_paths;
  for(auto & bb : bb_list) {
    passed.insert(bb->start());
    auto inds = bb->indirectTgts();
    ind_paths.insert(inds.begin(), inds.end());

    for(auto & ind_bb : inds) {
      if(checkPath(ind_bb,through)) {
        auto ind_seq = bbSeq(ind_bb);
        path.insert(bb_list.begin(), bb_list.end());
        path.insert(ind_seq.begin(), ind_seq.end());
        return true;
      }
    }
  }

  for(auto & ind_bb : ind_paths) {
    if(passed.find(ind_bb->start()) == passed.end()) {
      if(allRouteDfs(ind_bb, through, passed, path)) {
        path.insert(bb_list.begin(),bb_list.end());
        return true;
      }
    }
  }
  return false;
}

vector <BasicBlock *> 
Dfs::allRoutes(BasicBlock *entry, BasicBlock *through) {
  unordered_set <uint64_t> passed;
  vector <BasicBlock *> path;
  unordered_set <BasicBlock *> path_set;
  allRouteDfs(entry,through,passed, path_set);
  path.insert(path.end(),path_set.begin(),path_set.end());
  return path;
}
/*
vector <BasicBlock *> 
Dfs::allRoutes(BasicBlock *entry, BasicBlock *through, vector <BasicBlock *> &term_at) {
  unordered_set <uint64_t> passed;
  vector <BasicBlock *> path;
  unordered_set <BasicBlock *> path_set;
  allRouteDfs(entry,through,passed, term_at,path_set);
  path.insert(path.end(),path_set.begin(),path_set.end());
  return path;
}
*/
stack <BasicBlock *> 
Dfs::psblExitCalls(BasicBlock *bb) {
  traversal_ = SEQTYPE::INTRAFN;
  stack <BasicBlock *> exitCalls;
  unordered_set <uint64_t> passed;
  BfsQ_.push(bb);
  psblExitBFS(exitCalls,passed);
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
