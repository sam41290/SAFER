#include "BasicBlock.h"
#include "disasm.h"
#include "libutils.h"

using namespace SBI;

bool
compareIns(Instruction *A, Instruction *B)
{
  return A->location() < B->location();
}


BasicBlock::
BasicBlock(uint64_t p_start, uint64_t p_end,PointerSource src,
			  PointerSource root,vector <Instruction *> &p_ins) {
  start_ = p_start;
  end_ = p_end;
  insList_ = p_ins;
  source_ = src;
  rootSrc_ = root;
}

BasicBlock::
BasicBlock(uint64_t start, uint64_t end, PointerSource src,
    PointerSource root) {
  start_ = start;
  end_ = end;
  source_ = src;
  rootSrc_ = root;
}


Instruction *
BasicBlock::getIns(uint64_t address) {
  for(auto ins : insList_)
    if(ins->location() == address)
      return ins;
  return NULL;
}


Instruction *
BasicBlock::lastIns() {
  return insList_[insList_.size() - 1];
}

uint64_t
BasicBlock::boundary() {
  Instruction *last_ins = lastIns();
  return last_ins->location() + last_ins->insSize();
}

void
BasicBlock::deleteIns(uint64_t address) {
  auto it = insList_.begin();
  while(it != insList_.end()) {
    if((*it)->location() == address) {
      insList_.erase(it);
    }
    it++;
  }
}


bool
BasicBlock::isValidIns(uint64_t addrs) {
  for(auto & ins : insList_) { 
    if(addrs == ins->location())
      return true;
    else if((addrs - ins->location()) == 1 
             && ins->insSize() > 1) {
      auto bin = ins->insBinary();
      if(utils::is_prefix(bin[0]))
        return true;
    }
  }
  return false;
}


bool
BasicBlock::indirectCFWithReg() {
  return(lastIns()->indirectCFWithReg() & !(isCall()));
}


void
BasicBlock::addIns(Instruction *ins) {
  isLea_ = ins->isLea();
  insList_.push_back(ins);
  sort(insList_.begin(), insList_.end(),compareIns);
}

BasicBlock *
BasicBlock::split(uint64_t address) {
  /* Breaks the basic block at the given address and returns a Pointer to the
   * newly created basic block.
   * The new basic block is marked as the fall through of the old one.
   */
  LOG("Splitting bb " <<hex <<start_ <<" at " <<hex <<address);
  if(address > end_ || address < start_)
    return NULL;
  if(isValidIns(address) == false) {
    LOG("Invalid instruction address");
    return NULL;
  }
  uint64_t new_bb_start = address;
  uint64_t new_bb_end = end_;

  vector<Instruction *> newInsList1, newInsList2;
  vector<Instruction *> :: iterator splitPoint;
  bool splitFound = false;
  bool isLea = false;
  isLea_ = false;
  //uint64_t end;
  for(auto ins : insList_) {
    if(ins->location() >= address) {
      newInsList2.push_back(ins);
      splitFound = true;
      if(isLea == false)
        isLea = ins->isLea();
    }
    else {
      newInsList1.push_back(ins);
      if(isLea_ == false)
        isLea_ = ins->isLea();
    }
  }
  if(splitFound) {
    BasicBlock *new_bb = new BasicBlock(new_bb_start, new_bb_end,
        source_,rootSrc_,newInsList2);
    new_bb->isLea(isLea);
    //LOG("Parent BB fall through: "<<hex<<fallThrough_<<" "
    //    <<fallThroughBB_);
    new_bb->fallThrough(fallThrough_);
    new_bb->fallThroughBB(fallThroughBB_);
    fallThrough_ = new_bb_start;
    fallThroughBB_ = new_bb;
    //LOG("Fall through set!!");
    new_bb->target(target_);
    new_bb->targetBB(targetBB_);
    new_bb->fallThroughIns(fallThroughIns_);
    //LOG("Target set!!!");
    fallThroughIns_.asmIns("");
    targetBB_ = NULL;
    target_ = 0;
    new_bb->codeType(codeType_);
    //LOG("is code set");
    insList_ = newInsList1;
    end_ = lastIns()->location();
    //LOG("End updated");
    LOG("In basic block split: " <<start_ <<"-" <<end_ <<
         " Fall through: " <<hex<<fallThrough_<<" target: "
         <<hex<<target_);
    LOG("New BB: "<<hex<<new_bb->start()<<"-"<<new_bb->end()
        <<"Fall Through: "<<hex<<new_bb->fallThrough());
    return new_bb;
  }
  return NULL;
}



bool
BasicBlock::isCall() {
  return lastIns()->isCall();
}

vector <string> BasicBlock::allAsm() {
  vector <string> orig_ins;
  for(auto ins:insList_) {
      string ins_str = ins->label();
      ins_str += ":";
      string origs = ins->asmIns();
      //for(string s: origs)
      //{
      ins_str += " " + origs;
      //}
      orig_ins.push_back(ins_str);
    }

  return orig_ins;
}

vector <string> BasicBlock::get_all_original_asm_ins() {
  vector <string> orig_ins;
  for(auto ins : insList_) {
      string ins_str = ins->label();
      ins_str += ":";
      vector <string> origs = ins->originalIns();
      for(string s:origs) {
	      ins_str += " " + s;
	    }
      orig_ins.push_back(ins_str);
    }

  return orig_ins;
}


void
BasicBlock::print(string file_name, map <uint64_t, Pointer *>&map_of_pointer) {

  /* Prints out the asm instructions within this basic block
   */

  string ins_lbl_sfx = "_" + to_string(start_) + "_def_code";

  if(isCode() == false) {
    ins_lbl_sfx = "_" + to_string(start_) + "_unknown_code";
  }
  for(auto & it:insList_) {
    it->isCode(isCode());
    uint64_t rip_rltv_offset = it->ripRltvOfft();
    if(ENCODE == 1 && rip_rltv_offset != 0 && 
        map_of_pointer[rip_rltv_offset]->type() == PointerType::CP 
        && map_of_pointer[rip_rltv_offset]->encodable() == true)
      it->set_encode(true);
    if(it->location() == end_ && isJmpTblBlk_ == true
        && ENCODE == 1) {
      it->asmIns(moveZeros(it->op1(),it->location(),file_name)
          + it->asmIns());
      it->set_decode(false);
    }
    if((it->isJump() || it->isCall()) && targetBB_ != NULL) {
      it->asmIns(it->mnemonic() + " " + targetBB_->label());
      it->op1(targetBB_->label());
    }
    it->print(file_name,ins_lbl_sfx);
  }
  printFallThroughJmp(file_name);
  ofstream ofile;
  ofile.open(file_name, ofstream::out | ofstream::app);
  for(int i = 0; i < traps_; i++)
    ofile <<".byte 0xcc\n";
  ofile.close();
}


void
BasicBlock::adjustRipRltvIns(uint64_t data_segment_start, 
    map<uint64_t, Pointer *> &ptr_map) {

  /* Adjusts the RIP relative instructions to point to new locations.
   * Done by replacing fixed constants with labels.
   */

  LOG("Adjusting RIP relative access");
  if(insList_.size() <= 0)
    LOG("No instructions in the bb!!");
  for(auto & it : insList_) {
    if(it->isRltvAccess() == 1 && it->rltvOfftAdjusted() == false) {
      uint64_t rip_rltv_offset = it->ripRltvOfft();
      LOG("Relative Pointer: " <<hex <<rip_rltv_offset);
      if(rip_rltv_offset >= data_segment_start) {

        string op = utils::symbolizeRltvAccess(it->op1(),
            ".datasegment_start + " + 
             to_string(rip_rltv_offset - data_segment_start)
             ,rip_rltv_offset,SymBind::FORCEBIND);
        it->asmIns(it->prefix() + it->mnemonic() + " " + op);
        it->op1(op);
      }
      else {
        auto p = ptr_map.find(rip_rltv_offset);
        if(p == ptr_map.end() || p->second->type() == PointerType::CP) {
          for (auto & bb : rltvTgts_) {
            if(bb->start() == rip_rltv_offset) {
              string op = utils::symbolizeRltvAccess(it->op1(),
                   bb->label(),rip_rltv_offset,SymBind::FORCEBIND);
              it->asmIns(it->prefix() + it->mnemonic() + " " + op);
              it->op1(op);
              break;
            }
          }
        }
        else {
          string op = utils::symbolizeRltvAccess(it->op1(),
                   "." + to_string(rip_rltv_offset),rip_rltv_offset,SymBind::FORCEBIND);
          it->asmIns(it->prefix() + it->mnemonic() + " " + op);
          it->op1(op);
        }
      }
      it->rltvOfftAdjusted(true);
    }
  }
}

long
BasicBlock::insCount() {
  return insList_.size();
}


void
BasicBlock::printFallThroughJmp(string file_name) {
  if(fallThroughIns_.asmIns().size()> 0) {
    ofstream ofile;
    ofile.open(file_name, ofstream::out | ofstream::app);
    ofile <<"\t" <<fallThroughIns_.asmIns() <<"\n";
    ofile.close();
  }
}

vector <uint64_t> BasicBlock::allInsLoc() {
  vector <uint64_t> all_ins;
  for(auto it:insList_)
    all_ins.push_back(it->location());

  return all_ins;
}


void
BasicBlock::instrument() {
  vector<pair<uint64_t,string>> tgtAddrs = targetAddrs();
  map<string,vector<InstArg>>allargs = instArgs();
  for(auto tgt:tgtAddrs) {
    for(auto ins_it:insList_) {
      if(ins_it->location() == tgt.first) {
        ins_it->registerInstrumentation(InstPoint::BASIC_BLOCK,
          tgt.second,allargs[tgt.second]);
      //ins_it->second.instrument();
      }
    }
  }
  vector<pair<InstPoint,string>> targetPos = targetPositions();
  for(auto p:targetPos) {
    if(p.first == InstPoint::INDIRECT_CF) {
      auto ins_it = lastIns();
      if(ins_it->isIndirectCf()) {
        ins_it->registerInstrumentation(p.first,p.second,allargs[p.second]);
        //ins_it->second.instrument();
      }
    }
    else if(p.first == InstPoint::LEA_INS_PRE ||
            p.first == InstPoint::LEA_INS_POST){
      for(auto it:insList_) {
        if(it->isLea()) {
          it->registerInstrumentation(p.first,p.second,allargs[p.second]);
          //ins.second.instrument();
        }
      }
    }
  }
}

bool 
BasicBlock::inRange(uint64_t addrs) {
  if(addrs < start_)
    return false;
  Instruction *last_ins = lastIns();
  if(addrs>=(last_ins->location() + last_ins->insSize()))  //Out of basic block boundary.
    return false;

  return true;

}

void
BasicBlock::instrument(string code) {
  insList_[0]->instAsmPre(code);
}

void 
BasicBlock::inheritRoots(unordered_set <uint64_t> &passed,
                         unordered_set <BasicBlock *> &rts) {
  passed.insert(start_);
  if(roots_.size() > 0) {
    rts.insert(roots_.begin(), roots_.end());
  }
  if(rootsComputed_)
    return;
  if(parents_.size() == 0) {
    rootsComputed_ = true;
    return;
  }
  for(auto & p : parents_) {
    if(passed.find(p->start()) == passed.end())
      p->inheritRoots(passed,rts);
  }
}

unordered_set <BasicBlock *>
BasicBlock::roots() {
  if(rootsComputed_)
    return roots_;
  unordered_set <uint64_t> passed;
  passed.insert(start_);
  for(auto & p : parents_) {
    if(passed.find(p->start()) == passed.end())
      p->inheritRoots(passed,roots_);
  }
  rootsComputed_ = true;
  return roots_;
}

void
BasicBlock::addTramp(uint64_t tramp_start) {
  tramp_ = new BasicBlock(tramp_start,tramp_start,source(),source());
  tramp_->isTramp(true);
  tramp_->codeType(codeType_);
  Instruction *ins = new Instruction();
  ins->label(insList_[0]->label());
  insList_[0]->label(insList_[0]->label() + "_tramp");
  ins->isJump(true);
  ins->mnemonic("jmp");
  ins->asmIns("jmp " + label());
  tramp_->addIns(ins);
}
