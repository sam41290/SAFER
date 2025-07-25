#include "BasicBlock.h"
#include "disasm.h"
#include "libutils.h"
#include "CFValidity.h"

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
  lastIns_ = insList_[insList_.size() - 1];
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
  for(auto & ins : insList_)
    if(ins->location() == address)
      return ins;
  return NULL;
}


Instruction *
BasicBlock::lastIns() {
  return lastIns_;//insList_[insList_.size() - 1];
}

uint64_t
BasicBlock::boundary() {
  Instruction *last_ins = lastIns();
  auto fall = last_ins->fallThrough();
  if(fall != 0)
    return fall;
  else
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
  if(lastIns_ != NULL && address == lastIns_->location())
    lastIns_ = insList_[insList_.size() - 1];
}


bool
BasicBlock::isValidIns(uint64_t addrs) {
  for(auto & ins : insList_) { 
    if(addrs == ins->location() && CFValidity::validOpCode(ins))
      return true;
  }
  return false;
}


bool
BasicBlock::indirectCFWithReg() {
  //DEF_LOG("Checking if indirect CF: "<<hex<<start());
  return(lastIns()->indirectCFWithReg() & !(isCall()));
}


void
BasicBlock::addIns(Instruction *ins) {
  isLea_ = ins->isLea();
  insList_.push_back(ins);
  //sort(insList_.begin(), insList_.end(),compareIns);
  lastIns_ = insList_[insList_.size() - 1];
}

void
BasicBlock::splitNoNew(uint64_t address) {
  /* Breaks the basic block at the given address and returns a Pointer to the
   * newly created basic block.
   * The new basic block is marked as the fall through of the old one.
   */
 LOG("Splitting bb " <<hex <<start_ <<" at " <<hex <<address);
  if(address > end_ || address < start_)
    return;
  if(isValidIns(address) == false) {
    LOG("Invalid instruction address");
    return;
  }
  uint64_t new_bb_start = address;
  //uint64_t new_bb_end = end_;

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
    fallThrough_ = new_bb_start;
    fallThroughIns_.asmIns("");
    targetBB_ = NULL;
    target_ = 0;
    mergedBBs_.clear();
    insList_ = newInsList1;
    lastIns_ = insList_[insList_.size() - 1];
    end_ = lastIns()->location();
    indirectTgts_.clear();
  }
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
    new_bb->lockJump(lockJump_);
    //LOG("Parent BB fall through: "<<hex<<fallThrough_<<" "
    //    <<fallThroughBB_);
    new_bb->fallThrough(fallThrough_);
    new_bb->fallThroughBB(fallThroughBB_);
    fallThrough_ = new_bb_start;
    fallThroughBB_ = new_bb;
    //LOG("Fall through set!!");
    new_bb->target(target_);
    new_bb->targetBB(targetBB_);
    if(targetBB_ != NULL)
      targetBB_->parent(new_bb);
    new_bb->fallThroughIns(fallThroughIns_);
    //LOG("Target set!!!");
    fallThroughIns_.asmIns("");
    targetBB_ = NULL;
    target_ = 0;
    new_bb->codeType(codeType_);
    new_bb->type(type_);
    new_bb->callType(callType_);
    new_bb->isJmpTblBlk(isJmpTblBlk());
    new_bb->indirectTgts(indirectTgts_);
    for(auto & m_bb : mergedBBs_)
      new_bb->mergeBB(m_bb);
    mergedBBs_.clear();
    //if(start() == 0x40f856) {
    //  DEF_LOG("Splitting bb : "<<hex<<start()<<" at "<<new_bb->start()<<" new bb indrct tgt cnt: "<<new_bb->indirectTgts().size());
    //}
    //LOG("is code set");
    insList_ = newInsList1;
    lastIns_ = insList_[insList_.size() - 1];
    end_ = lastIns()->location();
    indirectTgts_.clear();

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
  bool call_fall_thru = false;
  for(auto & p : parents_) {
    if(p->lastIns()->isCall() && p->lastIns()->fallThrough() == start()) {
      call_fall_thru = true;
      break;
    }
  }
  bool call_target = false;
  for(auto & p : parents_) {
    if(p->lastIns()->isCall() && p->target() == start()) {
      call_target = true;
      break;
    }
  }
  if(call_fall_thru == false && if_exists(start_, map_of_pointer)) {
    auto ptr = map_of_pointer[start_];
    if(ptr->source() != PointerSource::POSSIBLE_RA &&
      (ptr->symbolizable(SymbolizeIf::CONST) ||
       ptr->symbolizable(SymbolizeIf::IMMOPERAND) ||
       ptr->symbolizable(SymbolizeIf::RLTV))) {
      utils::printAlgn(16,file_name);
    }
    else if(call_target)
      utils::printAlgn(16,file_name);
  }
  else if(call_target)
    utils::printAlgn(16,file_name);


  uint64_t shadow_ret_inst_pt = 0, free_reg = 0;

  if(alreadyInstrumented(InstPoint::LEGACY_SHADOW_RET)) {
    int cnt = insList_.size() - 1;
    shadow_ret_inst_pt = insList_[cnt]->location();
    for(int i = cnt - 1; i >= 0; i--) {
      if(insList_[i]->epilogFreeReg().size() > free_reg) {
        shadow_ret_inst_pt = insList_[i]->location();
        free_reg = insList_[i]->epilogFreeReg().size();
      }
      if(free_reg == 2)
        break;
    }
  }

  for(auto & it:insList_) {
    it->isCode(isCode());
    if((it->isJump() || it->isCall())) {
      if(targetBB_ != NULL) {
        it->asmIns(it->mnemonic() + " " + targetBB_->label());
        it->op1(targetBB_->label());
        if(/*it->isCall() &&*/ 
           it->alreadyInstrumented(InstPoint::LEGACY_SHADOW_CALL) &&
           targetBB_->alreadyInstrumented(InstPoint::SHSTK_FUNCTION_ENTRY)) {
          it->asmIns(it->mnemonic() + " " + targetBB_->shStkTrampSym());
          it->op1(targetBB_->shStkTrampSym());
        }
      }
      else if(it->isIndirectCf() == false && lockJump_ && fallThroughBB_ != NULL) {
        it->asmIns(it->mnemonic() + " " + fallThroughBB_->label() + " + 1");
        it->op1(fallThroughBB_->label() + " + 1");
      }
    }
    if(it->isCall()) {
      it->fallSym(fallSym());
      auto fall_bb = fallThroughBB();
      if(fall_bb != NULL)
        it->fallBBSym(fall_bb->label());
      else {
        DEF_LOG("Call missing fall through: "<<hex<<it->location());
        it->fallBBSym(fallSym());
      }
    }
    if(it->location() == start_ && 
      (alreadyInstrumented(InstPoint::SHSTK_FUNCTION_ENTRY) ||
       alreadyInstrumented(InstPoint::SHSTK_FUNCTION_PTR))) {
      string shstk_tramp = directCallShstkTramp();
      string lbl = shStkTrampSym();
      utils::printAsm(shstk_tramp, start_, lbl, SymBind::FORCEBIND, file_name);
      it->isCode(false);
    }


    if(shadow_ret_inst_pt != 0 && it->location() == shadow_ret_inst_pt) {
      auto free_reg_list = it->epilogFreeReg();
      string shadow_ret_asm = "", reg1 = "", reg2 = "";
      DEF_LOG("Adding shadow ret check: "<<hex<<shadow_ret_inst_pt);
      DEF_LOG("free_reg: "<<free_reg<<"-"<<free_reg_list.size());
      if(free_reg == 1) {
        reg1 = free_reg_list[0];
      }
      else if(free_reg == 2) {
        reg1 = free_reg_list[0];
        reg2 = free_reg_list[1];
      }
      shadow_ret_asm = shadowRetInst(reg1, reg2, free_reg);
      it->instAsmPre(shadow_ret_asm);
      //utils::printAsm(shadow_ret_asm, shadow_ret_inst_pt, "", SymBind::NOBIND, file_name);
    }
    it->print(file_name,ins_lbl_sfx);
    //if(it->isCall()) {
    //  fallSym_ = it->label() + ins_lbl_sfx + "_fall";
    //  utils::printLbl(fallSym_,file_name);
    //}
  }
  printFallThroughJmp(file_name);
  for(auto & bb: mergedBBs_)
    bb->print(file_name, map_of_pointer);
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

  //DEF_LOG("Adjusting RIP relative access");
  if(insList_.size() <= 0) {
    LOG("No instructions in the bb!!");
    return;
  }
  //if(passed(Property::VALIDINS) == false)
  //  return;
  for(auto & it : insList_) {
    if(it->isRltvAccess() == true && it->rltvOfftAdjusted() == false) {
      uint64_t rip_rltv_offset = it->ripRltvOfft();
      //DEF_LOG("Relative Pointer: " <<hex <<rip_rltv_offset);

      if(CFValidity::validPrfx(it) == false ||
         CFValidity::validOpCode(it) == false) {
        it->setRltvAccess(false);
        it->asmIns("");
        continue;
      }

      if(rip_rltv_offset >= data_segment_start) {

        string op = utils::symbolizeRltvAccess(it->op1(),
            "(.datasegment_start + " + 
             to_string(rip_rltv_offset - data_segment_start) + ")"
             ,rip_rltv_offset,SymBind::FORCEBIND);
        it->asmIns(it->prefix() + it->mnemonic() + " " + op);
        it->op1(op);
      }
      else {
        auto p = ptr_map.find(rip_rltv_offset);
        if(FULL_ADDR_TRANS == false && NO_ENCODE_LEAPTRS == false && 
           it->asmIns().find("lea") != string::npos && p != ptr_map.end() && 
           p->second->type() == PointerType::CP && p->second->symbolized(SymbolizeIf::RLTV)) {
          //DEF_LOG("Symbolizing lea code access: "<<hex<<it->asmIns());
          if(it->encode()) {
            it->asmIns(encodeLea(it->op1(),rip_rltv_offset));
            //string op = it->op1();
            //size_t pos = op.find (",");
            //string reg = op.substr (pos + 1);
            //it->asmIns("mov ." + to_string(rip_rltv_offset) + "_enc_ptr(%rip)," + reg);
          }
          else {
            for (auto & bb : rltvTgts_) {
              if(bb->start() == rip_rltv_offset) {
                string lbl = bb->label();
                if(bb->alreadyInstrumented(InstPoint::SHSTK_FUNCTION_ENTRY) ||
                   bb->alreadyInstrumented(InstPoint::SHSTK_FUNCTION_TRAMP) ||
                   bb->alreadyInstrumented(InstPoint::SHSTK_FUNCTION_PTR))
                  lbl = bb->shStkTrampSym();
                string op = utils::symbolizeRltvAccess(it->op1(),
                     lbl,rip_rltv_offset,SymBind::FORCEBIND);
                it->asmIns(it->prefix() + it->mnemonic() + " " + op);
                it->op1(op);
                break;
              }
            }
          }
        }
        else {
          string op = utils::symbolizeRltvAccess(it->op1(),
                   "." + to_string(rip_rltv_offset),rip_rltv_offset,SymBind::NOBIND);
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
  for(auto & it : insList_) {
    if(it->location() != 0)
      all_ins.push_back(it->location());
  }

  return all_ins;
}


void
BasicBlock::instrument() {
  auto targetPos = targetPositions();
  for(auto & p : targetPos) {

    if(p.first == InstPoint::CUSTOM || p.first == InstPoint::BASIC_BLOCK) {
      if(p.second.pos_ == InstPos::PRE)
        insList_[0]->registerInstrumentation(InstPoint::CUSTOM,p.second);
      else {
        auto last_ins = lastIns();
        auto x = p.second;
        x.pos_ = InstPos::PRE;
        last_ins->registerInstrumentation(InstPoint::CUSTOM,x);
      }
    }
    else if(p.first == InstPoint::INDIRECT_CF) {
      auto ins_it = lastIns();
      if(CFValidity::validPrfx(ins_it) == false ||
         CFValidity::validOpCode(ins_it) == false) {
        continue;
      }
      if(ins_it->isIndirectCf()) {
        ins_it->registerInstrumentation(p.first,p.second);
      }
    }
    else if(p.first == InstPoint::ADDRS_TRANS) {
      for(auto & ins : insList_) {
        if(CFValidity::validPrfx(ins) == false ||
           CFValidity::validOpCode(ins) == false) {
          continue;
        }
        if(FULL_ADDR_TRANS == false && NO_ENCODE_LEAPTRS == false && 
           ins->isRltvAccess() && ins->isLea())
          ins->encode(true);
        if((ins->isIndirectCf() && ins->atRequired())) {
          DEF_LOG("Adding instrumentation to basic block: "<<hex<<ins->location()<<" "<<(int)p.first);
          ins->registerInstrumentation(p.first,p.second);
        }
      }
    }
    else if(p.first == InstPoint::RET_CHK) {
      for(auto & ins : insList_) {
        if(CFValidity::validPrfx(ins) == false ||
           CFValidity::validOpCode(ins) == false) {
          continue;
        }
        if(ins->asmIns().find("ret") != string::npos) {
          ins->registerInstrumentation(p.first,p.second);
        }
        else if(ins->isCall() && ins->asmIns().find("syscall") == string::npos) {
          ins->registerInstrumentation(p.first,p.second);
          ins->mnemonic("jmp");
          ins->asmIns(ins->mnemonic() + " " + ins->op1());
          ins->fallSym(ins->label() + lblSuffix() + "_fall");
        }
        else if(ins->isPltJmp())
          ins->registerInstrumentation(p.first,p.second);
      }
    }
    else if(p.first == InstPoint::SYSCALL_CHECK) {
      for(auto & ins : insList_) {
        if(CFValidity::validPrfx(ins) == false ||
           CFValidity::validOpCode(ins) == false) {
          continue;
        }
        if(ins->asmIns().find("syscall") != string::npos)
          ins->registerInstrumentation(p.first,p.second);
      }
    }
    else if(p.first == InstPoint::SHSTK_FUNCTION_RET) {
      for (auto &ins : insList_) {
        if(CFValidity::validPrfx(ins) == false ||
           CFValidity::validOpCode(ins) == false) {
          continue;
        }
        if (ins->asmIns().find("ret") != string::npos) {
          ins->registerInstrumentation(p.first, p.second);
          DEF_LOG("The ret asm inst is: " << ins->asmIns());
        }
      }
    }
    else if(p.first == InstPoint::SHSTK_CANARY_PROLOGUE) {
      for(auto &ins : insList_) {
        if(CFValidity::validPrfx(ins) == false ||
           CFValidity::validOpCode(ins) == false) {
          continue;
        }
        if (ins->asmIns().find("%fs:0x28") != string::npos &&
            ins->asmIns().find("mov") != string::npos) {
          ins->canaryAdd(true);
          ins->registerInstrumentation(p.first, p.second);
          DEF_LOG("The canary asm inst is: " << ins->asmIns());
        }
      }
    }
    else if(p.first == InstPoint::SHSTK_CANARY_EPILOGUE) {
      for(auto &ins : insList_) {
        if(CFValidity::validPrfx(ins) == false ||
           CFValidity::validOpCode(ins) == false) {
          continue;
        }
        if (ins->asmIns().find("%fs:0x28") != string::npos &&
            ins->asmIns().find("xor") != string::npos) {
          ins->canaryCheck(true);
          ins->registerInstrumentation(p.first, p.second);
          DEF_LOG("The canary asm inst is:" << ins->asmIns());
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
BasicBlock::inferType(unordered_set <uint64_t> &passed) {
  if(retTypeInferred_)
    return;
  if(type_ == BBType::NA || type_ == BBType::MAY_BE_RETURNING || 
     callType() == BBType::MAY_BE_RETURNING ||
     callType() == BBType::NA) {
    passed.insert(start_);
    if(targetBB_ != NULL && passed.find(target_) == passed.end()) {
      targetBB_->inferType(passed);
    }
    if(fallThroughBB_ != NULL && passed.find(fallThrough_) == passed.end())
      fallThroughBB_->inferType(passed);
    auto ins = lastIns();
    //if(start() == 0x21853 || start() == 0x21820 || start() == 0x21c50 || start() == 0xa5b7d || start() == 0x21c8c) {
    //  DEF_LOG("Infering return type BB: "<<hex<<start());
    //  if(targetBB_ != NULL)
    //    DEF_LOG("Target: "<<hex<<target()<<" type: "<<(int)targetBB_->type());
    //  if(fallThroughBB_ != NULL) {
    //    DEF_LOG("Fall: "<<hex<<fallThrough()<<" type: "<<(int)fallThroughBB_->type());
    //  }
    //}
    if(isCall()) {
      if(callType_ == BBType::NON_RETURNING) {
        type_ = BBType::NON_RETURNING;
        fallThrough_ = 0;
        fallThroughBB_ = NULL;
      }
      else {
        if(targetBB_ != NULL) {
          callType(targetBB_->type());
          if(targetBB_->type() == BBType::NON_RETURNING) {
            if(fallThroughBB_ != NULL)
              fallThroughBB_->source(PointerSource::POSSIBLE_RA);
            DEF_LOG("Marking BB non returning: "<<hex<<start_);
            type_ = BBType::NON_RETURNING;
            fallThrough_ = 0;
            fallThroughBB_ = NULL;
          }
          else if(targetBB_->type() == BBType::MAY_BE_RETURNING)
            type_ = BBType::MAY_BE_RETURNING;
        }
        if(fallThroughBB_ != NULL) {
          if(fallThroughBB_->type() == BBType::NON_RETURNING)
            type_ = BBType::NON_RETURNING;
          else if(fallThroughBB_->type() == BBType::MAY_BE_RETURNING &&
                  type_ != BBType::NON_RETURNING)
            type_ = BBType::MAY_BE_RETURNING;
        }
      }
    }
    else if(ins->isUnconditionalJmp()) {
      if(targetBB_ != NULL)
        type_ = targetBB_->type();
    }
    else if(targetBB_ != NULL && fallThroughBB_ != NULL) {
      auto tgt_type = targetBB_->type();
      auto fall_type = fallThroughBB_->type();
      if(tgt_type == BBType::NA && fall_type == BBType::NA)
        type(BBType::RETURNING);
      else if(tgt_type == BBType::NA)
        type(fall_type);
      else if(fall_type == BBType::NA)
        type(tgt_type);
      else if(fall_type != tgt_type)
        type(BBType::MAY_BE_RETURNING);
      else
        type(tgt_type);
    }
    else if(fallThroughBB_ != NULL) type(fallThroughBB_->type());
  }
  //LOG("BB Type: "<<hex<<start_<<"-"<<(int)type());
}

void
BasicBlock::updateType() {
  unordered_set <uint64_t> passed;
  inferType(passed);
  retTypeInferred_ = true;
}

void
BasicBlock::addTrampToTgt() {
  auto bb = new BasicBlock(target_,target_,source(),source());
  bb->codeType(codeType_);
  Instruction *ins = new Instruction();
  ins->label("." + to_string(target_) + "_" + to_string(start_));
  ins->isJump(true);
  ins->mnemonic("jmp");
  ins->location(0);
  ins->asmIns("jmp " + targetBB_->label());
  bb->addIns(ins);
  targetBB(bb);
  mergeBB(bb);

}

void
BasicBlock::addTramp(uint64_t tramp_start) {
  if(tramp_ == NULL) {
    auto bb = new BasicBlock(tramp_start,tramp_start,source(),source());
    bb->codeType(codeType_);
    Instruction *ins = new Instruction();
    ins->label(insList_[0]->label());
    insList_[0]->label(insList_[0]->label() + "_tramp");
    ins->isJump(true);
    ins->mnemonic("jmp");
    ins->asmIns("jmp " + label());
    bb->addIns(ins);
    tramp_ = bb;
    tramp_->isTramp(true);
  }
}

bool
BasicBlock::noConflict(uint64_t addrs) {
  if(addrs > start_ && addrs < boundary()) {
    for(auto & ins : insList_) {
      if(addrs == ins->location())
        return true;
      //else if((addrs - ins->location()) == 1
      //         && ins->insSize() > 1) {
      //  auto bin = ins->insBinary();
      //  if(bin.size() > 0 && utils::is_prefix(bin[0]))
      //    return true;
      //}
    }
    return false;
  }
  else
    return true;
}
