#include "Dfs.h"

using namespace SBI;

int
Dfs::stackDecrement(vector <Instruction *> &ins_list) {
  int offt = 0;
  for(auto & ins : ins_list) {
    if(ins->asmIns().find("pop") != string::npos)
      offt += 8;
    else if(ins->asmIns().find("push") != string::npos)
      offt -= 8;
    else if(ins->asmIns().find("add") != string::npos &&
            ins->asmIns().find("rsp") != string::npos &&
            ins->constOp() != 0) {
      offt += ins->constOp();
    }
    else if(ins->asmIns().find("sub") != string::npos &&
            ins->asmIns().find("rsp") != string::npos &&
            ins->constOp() != 0)
      offt -= ins->constOp();
  }
  return offt;
}

int
Dfs::peepHoleStackDecrement(uint64_t addrs, BasicBlock *bb) {
  traversal_ = SEQTYPE::INTRAFN;

  auto bb_ins_list = bb->insList();
  vector <Instruction *> ins_list;
  for(auto & ins : bb_ins_list)
    if(ins->location() >= addrs)
      ins_list.push_back(ins);

  auto offt = stackDecrement(ins_list);

  if(bb->fallThroughBB() != NULL) {
    auto fall_ins_list = bb->fallThroughBB()->insList(); 
    auto fall_offt = stackDecrement(fall_ins_list);
    if(fall_offt != 0)
      return offt + fall_offt;
  }
  if(bb->targetBB() != NULL) {
    auto tgt_ins_list = bb->targetBB()->insList();
    auto tgt_offt = stackDecrement(tgt_ins_list);
    if(tgt_offt != 0)
      return offt + tgt_offt;
  }

  return offt;

}

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
Dfs::subGraphParents(BasicBlock *bb) {
  traversal_ = SEQTYPE::INTRAFN;
  bbList_.clear();
  unordered_set <uint64_t> passed;
  directlyReachableBBs(bb,passed);

  vector <BasicBlock *> sub_graph_parents;
  for(auto & bb : bbList_) {
    auto parents = bb->parents();
    for(auto & p : parents)
      if(passed.find(p->start()) == passed.end())
        sub_graph_parents.push_back(p);
  }

  return sub_graph_parents;
}

vector <BasicBlock *>
Dfs::externalCallers(BasicBlock *bb, BasicBlock *entry) {
  traversal_ = SEQTYPE::INTRAFN;
  bbList_.clear();
  unordered_set <uint64_t> passed;
  directlyReachableBBs(entry,passed);

  vector <BasicBlock *> sub_graph_parents;
  auto parents = bb->parents();
  for(auto & p : parents) {
    auto last_ins = p->lastIns();
    if(passed.find(p->start()) == passed.end() && p->target() == bb->start() 
       && last_ins->isCall() && p->target() != p->fallThrough())
      sub_graph_parents.push_back(p);
  }

  return sub_graph_parents;
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
    //DEF_LOG("Node: "<<hex<<start->start());
  if(start->fallThroughBB() != NULL &&
     passed.find(start->fallThrough()) == passed.end())
    if(pathExists(start->fallThroughBB(), end, bbList, passed))
      path_exists = true;
  if(start->targetBB() != NULL && FOLLOWTARGET(start,traversal_) &&
     passed.find(start->target()) == passed.end())
    if(pathExists(start->targetBB(),end,bbList, passed))
      path_exists = true;

  if(path_exists) {
    bbList.push_back(start);
  }

  return path_exists;
}

void
Dfs::psblExitDFS(BasicBlock *bb, stack <BasicBlock *> &calls, 
                 unordered_set <uint64_t> &passed) {
  if(passed.find(bb->start()) == passed.end()) {
    passed.insert(bb->start());
    if(bb->targetBB() != NULL && FOLLOWTARGET(bb,traversal_))
      psblExitDFS(bb->targetBB(), calls, passed);
    if(bb->fallThroughBB() != NULL)
      psblExitDFS(bb->fallThroughBB(), calls, passed);
    if(bb->isCall() && bb->callType() == BBType::MAY_BE_RETURNING) {
      calls.push(bb);
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

bool
Dfs::checkPath(BasicBlock *from, BasicBlock *to) {
  //DEF_LOG("Checking if path exists from: "<<hex<<from->start()<<"->"<<hex<<to->start());
  traversal_ = SEQTYPE::INTRAFN;
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

void
Dfs::indTgtsDfs(BasicBlock *entry, unordered_set <uint64_t> &passed) {
  //LOG("Entry: "<<hex<<entry->start());
  //vector <BasicBlock *> ind_tgts;
  auto bb_list = bbSeq(entry);
  passed.insert(entry->start());
  for(auto & bb : bb_list) {
    auto inds = bb->indirectTgts();
    //if(entry->start() == 0x40f830)
    //  DEF_LOG("BB: "<<hex<<bb->start()<<" - "<<bb->end()<<" ind: "<<inds.size());
    if(inds.size() > 0) {
      //DEF_LOG("Entry: "<<hex<<entry->start()<<" cf bb: "<<hex<<bb->start()<<" ind tgt count: "<<inds.size());
      //for(auto & ind_bb : inds)
      //  DEF_LOG(hex<<ind_bb->start());
      indbbList_.insert(indbbList_.end(),inds.begin(),inds.end());
      //for(auto & ind_bb : inds) {
      //  if(passed.find(ind_bb->start()) == passed.end()) {
      //    //LOG("ind tgt: "<<hex<<ind_bb->start());
      //    auto second_layer = indTgtsDfs(ind_bb,passed);
      //    ind_tgts.insert(second_layer.begin(),second_layer.end());
      //  }
      //}
    }
  }
  //return ind_tgts;
}

vector <BasicBlock *> 
Dfs::allIndTgts(vector <BasicBlock *> &entry) {
  unordered_set <uint64_t> passed;
 // vector <BasicBlock *> all_inds;
  indbbList_.clear();
  for(auto & e : entry) {
    indTgtsDfs(e,passed);
    
  }
  LOG("Total inds: "<<bbList_.size());
  return indbbList_;
}

bool 
Dfs::bbInList(BasicBlock *bb, vector <BasicBlock *> &bb_list) {
  for(auto & b : bb_list)
    if(b->start() == bb->start())
      return true;
  return false;
}

void
Dfs::allRouteDfs(BasicBlock *through, 
                 unordered_set <uint64_t> &passed,
                 unordered_set <BasicBlock *> &path,
                 unordered_set <uint64_t> &valid_ind_path) {

  while(BfsQ_.empty() == false) {

    BasicBlock *entry = BfsQ_.front();
    BfsQ_.pop();

    if(passed.find(entry->start()) == passed.end()) {
      passed.insert(entry->start());
      //if(through->start() == 0x41af01)
      //  DEF_LOG("ind path: "<<hex<<entry->start());
      if(entry->start() == through->start() ||
         valid_ind_path.find(entry->start()) != valid_ind_path.end()) {
        auto bb_list = bbSeq(entry);
        if(bbInList(through, bb_list)) {
          //if(through->start() == 0x41af01)
          //  DEF_LOG("reachable from: "<<hex<<entry->start());
          path.insert(bb_list.begin(), bb_list.end());
          
          auto root = root_.find(entry->start());
          while(root != root_.end()) {
            //LOG("Root: "<<hex<<root->second->start());
            auto root_seq = bbSeq(root->second);
            path.insert(root_seq.begin(), root_seq.end());
            indRoots_.insert(root->second->start());
            if(root->second->start() == curEntry_->start())
              break;
            root = root_.find(root->second->start());
          }
          
          return;
        }
        else {
          for(auto & bb : bb_list) {
            //if(through->start() == 0x41af01)
            //  DEF_LOG("Checking bb for ind tgts: "<<hex<<bb->start());
            if(bb->lastIns()->isIndirectCf() /*&& passed.find(bb->start()) == passed.end()*/) {
              //if(through->start() == 0x41af01)
              //  DEF_LOG("Ind cf: "<<hex<<bb->start());
              auto inds = bb->indirectTgts();
              for(auto & ind_bb : inds) {
                if(passed.find(ind_bb->start()) == passed.end()) {
                  BfsQ_.push(ind_bb);
                  if(root_.find(ind_bb->start()) == root_.end()) {
                    root_[ind_bb->start()] = entry;
                    //if(through->start() == 0x41af01)
                    //  DEF_LOG("Adding root: "<<hex<<ind_bb->start()<<"->"<<hex<<entry->start());
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  //allRouteDfs(through, passed, path);
  return;
}

vector <BasicBlock *> 
Dfs::allRoutes(BasicBlock *entry, BasicBlock *through,
               unordered_set <uint64_t> &valid_ind_path) {
  unordered_set <uint64_t> passed;
  vector <BasicBlock *> path;
  unordered_set <BasicBlock *> path_set;
  curEntry_ = entry;
  BfsQ_.push(entry);
  indRoots_.clear();
  allRouteDfs(through,passed, path_set, valid_ind_path);
  path.insert(path.end(),path_set.begin(),path_set.end());
  LOG("path size: "<<path.size());
  while(BfsQ_.empty() == false)
    BfsQ_.pop();
  //indPaths_.clear();

  root_.clear();

  return path;
}

stack <BasicBlock *> 
Dfs::psblExitCalls(BasicBlock *bb) {
  traversal_ = SEQTYPE::INTRAFN;
  stack <BasicBlock *> exitCalls;
  unordered_set <uint64_t> passed;
  psblExitDFS(bb,exitCalls,passed);
  stack <BasicBlock *> reversed_stack;
  while(exitCalls.empty() == false) {
    auto bb = exitCalls.top();
    reversed_stack.push(bb);
    exitCalls.pop();
  }
  return reversed_stack;
}

vector <BasicBlock *> 
Dfs::path(BasicBlock *start, BasicBlock *end,SEQTYPE s) {

  traversal_ = s;
  vector <BasicBlock *> bb_list;
  unordered_set <uint64_t> passed;
  pathExists(start,end,bb_list,passed);
  return bb_list;
}
