#include "Dfs.h"

using namespace SBI;

vector <Instruction *> 
Dfs::insPath(BasicBlock *entry, uint64_t target) { 
  unordered_set <uint64_t> passed;
  return insPathDfs(entry,target,passed);
}

vector <Instruction *> 
Dfs::insPathDfs(BasicBlock *entry, uint64_t target, unordered_set <uint64_t> &passed) {
  vector <Instruction *> path;
  if(passed.find(entry->start()) == passed.end()) {
    passed.insert(entry->start());
    if(entry->isValidIns(target)) {
      auto ins_list = entry->insList();
      for(auto & ins : ins_list) {
        path.push_back(ins);
        if(ins->location() == target)
          break;
      }
      return path;
    }
    else {
      auto fall_bb = entry->fallThroughBB();
      if(fall_bb != NULL) {
        auto fall_path = insPathDfs(fall_bb, target,passed);
        if(fall_path.size() > 0) {
          path = entry->insList();
          path.insert(path.end(),fall_path.begin(),fall_path.end());
          return path;
        }
      }
      auto tgt_bb = entry->targetBB();
      if(tgt_bb != NULL) {
        auto tgt_path = insPathDfs(tgt_bb, target, passed);
        if(tgt_path.size() > 0) {
          path = entry->insList();
          path.insert(path.end(),tgt_path.begin(),tgt_path.end());
          return path;
        }
      }
    }
  }
  return path;
}

extern unordered_set <string> calleeSaved;

void
Dfs::savedRegAtPrologue(BasicBlock *prolog_bb) {

  //Must only be called for basic blocks that are the function entry points
  //For each instruction in the basic block, checks what registers 
  //(i) have been saved and
  //(ii) have not been defined for use.
  //
  //That is, it creates a list of free registers 

  unordered_map <uint64_t, vector <string>> saved_reg_map;
  auto ins_list = prolog_bb->insList();
  Instruction *prev_ins = NULL;
  for(auto & ins : ins_list) {

    auto sem = ins->sem();
    auto op_list = sem->OpList;
    unordered_set <string> defined_reg;
    for(auto & o : op_list) {
      if(o.target.type_ == OperandType::REG &&
         calleeSaved.find(o.target.reg_) != calleeSaved.end()) {
        //defined_reg.insert(o.target.reg_);
        return;
      }
    }
    vector<string> reg_list;
    if(prev_ins != NULL) {
      auto prev_ins_free_reg = prev_ins->prologFreeReg();
      for(auto & reg : prev_ins_free_reg) {
        if(defined_reg.find(reg) == defined_reg.end())
          reg_list.push_back(reg);
      }
    }
    ins->prologFreeReg(reg_list);
    for(auto & o : op_list) {
      if(o.op == OP::STORE && o.source1.type_ == OperandType::REG &&
         calleeSaved.find(o.source1.reg_) != calleeSaved.end())
        ins->prologFreeReg(o.source1.reg_);
    }
    prev_ins = ins;
  }
}

void
Dfs::restoredRegAtEpilogue(BasicBlock *epilog_bb) {

  //Must only be called for basic blocks that are the function exits (i.e., they
  //must end with a return)
  //For each instruction in the basic block, checks what registers are yet to be
  //restored
  //
  //That is, it creates a list of free registers for each instruction right
  //before the RET.

  unordered_map <uint64_t, vector <string>> saved_reg_map;
  auto ins_list = epilog_bb->insList();
  int cnt = ins_list.size() - 1;

  Instruction *prev_ins = NULL;
  unordered_set <string> used_reg;
  for(int i = cnt; i >= 0; i--) {
    auto ins = ins_list[i];
    if(ins->asmIns().find("ret") != string::npos)
      continue;
    auto sem = ins->sem();
    auto op_list = sem->OpList;
    for(auto & o : op_list) {
      if(o.source1.type_ == OperandType::REG &&
         calleeSaved.find(o.source1.reg_) != calleeSaved.end()) {
        used_reg.insert(o.source1.reg_);
        return;
      }
    }
    vector<string> reg_list;
    if(prev_ins != NULL) {
      auto prev_ins_free_reg = prev_ins->epilogFreeReg();
      for(auto & reg : prev_ins_free_reg) {
        if(used_reg.find(reg) == used_reg.end())
          reg_list.push_back(reg);
      }
    }
    //ins->epilogFreeReg(reg_list);
    bool restore_found = false;
    for(auto & o : op_list) {
      if(o.op == OP::STORE && o.target.type_ == OperandType::REG &&
         calleeSaved.find(o.target.reg_) != calleeSaved.end() &&
         used_reg.find(o.target.reg_) == used_reg.end()) {
        ins->epilogFreeReg(o.target.reg_);
        restore_found = true;
      }
    }
    if(restore_found == false) return;
    for(auto & r : reg_list)
      ins->epilogFreeReg(r);
    prev_ins = ins;
  }
}

RegVal
Dfs::updateState(RegVal &tgt, State &state, Operation &op,
                 Instruction *ins, bool loop_update) {
  if(op.op == OP::STORE) {
    if(op.source1.op_ == OP::DEREF)
       tgt.val = RegValType::UNKNOWN;
    else if(op.source1.type_ == OperandType::REG) {
      auto source_val = state.regState[(int)op.source1.regNum_];
      tgt.val = source_val.val;
      tgt.addend = source_val.addend;
     
    }
    else if(op.source1.type_ == OperandType::CONSTANT) {
      tgt.val = RegValType::CONSTANT;
      tgt.addend = op.source1.constant_;
    }
  }
  else if(op.op == OP::ADD) {
    if((int)tgt.val > (int)RegValType::UNKNOWN) {
      if(op.source1.op_ == OP::DEREF)
        tgt.val = RegValType::UNKNOWN;
      else if(loop_update)
        tgt.val = RegValType::UNKNOWN;
      else if(op.source1.type_ == OperandType::REG) {
        auto source_val = state.regState[(int)op.source1.regNum_];
        if((int)source_val.val >= (int)tgt.val)
          tgt.val = source_val.val;
        tgt.addend += source_val.addend;
      }
      else if(op.source1.type_ == OperandType::CONSTANT) {
        tgt.addend += op.source1.constant_;
      }
    }
  }
  else if(op.op == OP::SUB) {
    if((int)tgt.val > (int)RegValType::UNKNOWN) {
      if(op.source1.op_ == OP::DEREF)
         tgt.val = RegValType::UNKNOWN;
      else if(loop_update)
        tgt.val = RegValType::UNKNOWN;
      else if(op.source1.type_ == OperandType::REG) {
        auto source_val = state.regState[(int)op.source1.regNum_];
        if((int)source_val.val >= (int)tgt.val)
          tgt.val = source_val.val;
        tgt.addend += source_val.addend;
       
      }
      else if(op.source1.type_ == OperandType::CONSTANT) {
        tgt.addend += -1 * (op.source1.constant_);
      }
    }
  }
  else if(op.op == OP::LEA) {
    if(op.source1.type_ == OperandType::RLTV) {
      if(op.source1.ripRltv()) {
        tgt.val = RegValType::CONSTANT;
        tgt.addend = ins->ripRltvOfft();
      }
      else {
        auto source_val = state.regState[(int)op.source1.regNum_];
        tgt.addend = op.source1.constant_ + source_val.addend;
        tgt.val = source_val.val;
      }
    }
  }
  else if(op.op == OP::XOR) {
    if(op.source1.regNum_ == op.target.regNum_){
      tgt.val = RegValType::CONSTANT;
      tgt.addend = ins->ripRltvOfft();
    }
    else
      tgt.val = RegValType::UNKNOWN;
  }
  else if(op.op == OP::OR) {
    if(op.source1.type_ == OperandType::CONSTANT &&
       op.source1.constant_ == 1){
      tgt.val = RegValType::CONSTANT;
      tgt.addend = 1;
    }
    else
      tgt.val = RegValType::UNKNOWN;
  }
  else if(op.op == OP::AND) {
    if(op.source1.type_ == OperandType::CONSTANT &&
       op.source1.constant_ == 0){
      tgt.val = RegValType::CONSTANT;
      tgt.addend = 0;
    }
    else
      tgt.val = RegValType::UNKNOWN;
  }
  return tgt;
}

void
Dfs::loopUpdate(State &state, vector <Instruction *> &ins_lst,
                uint64_t loop_start, uint64_t loop_end) {
  for(auto & ins : ins_lst) {
    if(ins->location() == loop_end)
      return;
    else if(ins->location() >= loop_start) {
      auto sem = ins->sem();
      auto op_list = sem->OpList;
      for(auto & op : op_list) {
        if(op.target.type_ == OperandType::REG && op.target.regNum_ != GPR::NONE &&
           op.target.op_ != OP::DEREF) {
          auto v = state.regState[(int)op.target.regNum_];
          state.regState[(int)op.target.regNum_] = updateState(v, state, op, ins, true);
          if(state.regState[(int)GPR::REG_RSP].val == RegValType::UNKNOWN) {
            unordered_map<int,RegVal> new_stack;
            state.stackState = new_stack;
          }
        }
      }
    }
  }
}

State
Dfs::analyzeRegState(vector <Instruction *> &ins_list) {
  State state;
  unordered_set <uint64_t> processed_ins;
  for(auto i = 0; i <= 16; i++) {
    RegVal r;
    if((GPR)i == GPR::REG_RSP)
      r.val = RegValType::FRAME_PTR;
    state.regState.push_back(r);
  }
  for(auto & ins : ins_list){
    processed_ins.insert(ins->location());
    auto sem = ins->sem();
    auto op_list = sem->OpList;
    for(auto & op : op_list) {
      if(op.op == OP::UNKNOWN)
        continue;
      if(op.target.op_ == OP::DEREF && op.target.regNum_ == GPR::REG_RSP) {
        auto offt = op.target.constant_;
        RegVal v;
        if(state.stackState.find(offt) != state.stackState.end()) {
          v = state.stackState[offt];
        }
        state.stackState[offt] = updateState(v, state, op, ins, false);
      }
      else if(op.target.type_ == OperandType::REG && op.target.regNum_ != GPR::NONE &&
         op.target.op_ != OP::DEREF) {
        auto v = state.regState[(int)op.target.regNum_];
        state.regState[(int)op.target.regNum_] = updateState(v, state, op, ins, false);
        if(op.target.regNum_ == GPR::REG_RSP && op.source1.type_ == OperandType::CONSTANT &&
           (op.op == OP::ADD || op.op == OP::SUB)) {
          int addend = op.source1.constant_;
          if(op.op == OP::ADD)
            addend *= -1;
          unordered_map<int,RegVal> new_stack;
          for(auto & v : state.stackState) {
            new_stack[v.first + addend] = v.second;
          }
          state.stackState = new_stack;
        }
      }
      else if(op.op == OP::JUMP) {
        auto tgt = ins->target();
        if(tgt != 0 && processed_ins.find(tgt) != processed_ins.end())
          loopUpdate(state, ins_list, tgt, ins->location());
      }
      DEF_LOG("ins: "<<hex<<ins->location()<<": "<<ins->asmIns());
      DEF_LOG("GPR: "<<(int)op.target.regNum_<<" val: "<<(int)state.regState[(int)op.target.regNum_].val);
    }
  }
  return state;
}

RAlocation
Dfs::getRA(vector <Instruction *> &ins_list) {
  RAlocation r;
  auto state = analyzeRegState(ins_list);
  int ctr = 0;
  if(state.regState[(int)GPR::REG_RSP].val == RegValType::FRAME_PTR) {
    r.reg = "%rsp";
    r.offt = -1 * state.regState[(int)GPR::REG_RSP].addend;
    DEF_LOG("Frame reg: "<< r.reg<<" offset"<<dec<<r.offt);
    return r;
  }
  for(auto & rval : state.regState) {
    //if((GPR)ctr == GPR::NONE)
    //  continue;
    DEF_LOG("GPR: "<<(int)ctr<<" val: "<<(int)rval.val);
    if(rval.val == RegValType::FRAME_PTR && ctr < utils::gpr.size()) {
      r.reg = utils::gpr[ctr];
      r.offt = -1 * rval.addend;
      DEF_LOG("Frame reg: "<< r.reg<<" offset"<<dec<<r.offt);
      return r;
    }
    ctr++;
  }
  for(auto & v : state.stackState) {
    if(v.second.val == RegValType::FRAME_PTR) {
      r.reg = to_string(v.first) + "(%rsp)";
      r.offt = -1 * v.second.addend;
      DEF_LOG("Frame pointer stored on RSP: offset "<<v.first<<" frame pointer addend: "<<r.offt);
    }
  }
  return r;
}

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
