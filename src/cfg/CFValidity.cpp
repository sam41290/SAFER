#include "CFValidity.h"

using namespace SBI;

uint64_t CFValidity::memSpaceStart_;
uint64_t CFValidity::memSpaceEnd_;
bool (*CFValidity::InsValidators_[4])(Instruction *);
vector <InsValidityRules>  CFValidity::insRule_;
unordered_set <uint64_t> CFValidity::invalidIns_;
unordered_set <uint64_t> CFValidity::validIns_;

extern bool compareBB(BasicBlock *A, BasicBlock *B);

bool
CFValidity::validOpCode(Instruction *ins) {
  if(ins->asmIns().find("%riz") != string::npos)
    return false;
  if(ins->asmIns().find(".byte") != string::npos) {
    //LOG("Gap byte: "<<hex<<ins->location()<<": "<<ins->asmIns());
    return false;
  }
  if(ins->asmIns().find("lcalll") != string::npos) {
    //LOG("lcalll at: "<<hex<<ins->location()<<": "<<ins->asmIns());
    return false;
  }
  if(ins->mnemonic().find(",") != string::npos)
    return false;
  if((ins->isCall() || ins->isJump()) && ins->op1() == "*%rsp") {
    return false;
  }
  auto bin = ins->insBinary();
  if(bin.size() == 1 && utils::is_prefix(bin[0])) {
    //LOG("lone prefix byte: "<<ins->asmIns());
    return false;
  }
  return true;
}

bool
CFValidity::validMem(Instruction *ins) {
  if(ins->isRltvAccess()) {
    uint64_t offt = ins->ripRltvOfft();
    if(offt >= memSpaceStart_ && offt <= memSpaceEnd_)
      return true;
    return false;
  }
  else {
    int64_t offt = ins->constPtr();
    if(offt != 0 && offt > (int64_t)memSpaceEnd_) {
      //DEF_LOG("invalid const mem access at: "<<hex<<ins->location()<<": "<<ins->asmIns()<<" const ptr: "<<offt);
      return false;
    }
  }
  return true;
}

bool
CFValidity::validIns(vector <BasicBlock *> &bb_list) {
  for(auto & bb : bb_list) {
    //LOG("Checking ins validity for bb: "<<hex<<bb->start());
    if(validIns_.find(bb->start()) != validIns_.end())
      continue;
    if(invalidIns_.find(bb->start()) != invalidIns_.end())
      return false;
    vector<Instruction *> insList = bb->insList();
    for(auto & ins : insList) {
      for(auto & rule : insRule_) {
        if(InsValidators_[(int)rule](ins) == false) {
          bool hlt_nd_call = false;
          if(rule == InsValidityRules::VLD_USRMODE_INS &&
             ins->asmIns().find("hlt") != string::npos) {
            auto parents = bb->parents();
            for(auto & p : parents) {
              if(p->fallThrough() == ins->location() && p->isCall())
                hlt_nd_call = true;
            }
          }
          if(hlt_nd_call == false) {
            DEF_LOG("Invalid ins at: "<<hex<<ins->location()<<":"<<ins->asmIns()<<" type "<<(int)rule);
            invalidIns_.insert(bb->start());
            return false;
          }
        }
      }
    }
    validIns_.insert(bb->start());
  }
  return true;
}

bool 
CFValidity::validCFTransfer(vector <BasicBlock *> &bbList) {
  //DEF_LOG("Checking CF validity");
  sort(bbList.begin(),bbList.end(),compareBB);
  bool valid = true;
  int size = bbList.size();
  bool exit_point = false;
  //LOG("BB list size: "<<size);
  for(int i = 0; i < (size - 1); i++) {
    //DEF_LOG("BB: "<<hex<<bbList[i]->start()<<" - "<<bbList[i]->boundary());
    if(bbList[i]->boundary() > bbList[i + 1]->start()) {
      auto ins = bbList[i]->getIns(bbList[i + 1]->start());
      if(ins == NULL) {
        //DEF_LOG("Boundary exceeds: "<<hex<<bbList[i + 1]->start());
        valid = false;
        break;
      }
      //else if(ins->location() != bbList[i]->start()) {
      //  auto new_bb = bbList[i]->split(bbList[i + 1]->start());
      //  bbList[i]->fallThroughBB(bbList[i + 1]);
      //  delete(new_bb);
      //}
    }
  }
  if(valid) {
    for(auto & bb : bbList) {
      auto last_ins = bb->lastIns();
      if(bb->isCall() && bb->target() == 0 && bb->fallThroughBB() == NULL) { //Indirect call but no fall through.
        //DEF_LOG("Indirect call without fall through: "<<hex<<bb->start());
        return false;
      }
      else if(last_ins->isJump() && last_ins->isUnconditionalJmp() == false && bb->fallThroughBB() == NULL) {//conditional jump without fall through
        //DEF_LOG("Conditional jump without fall through: "<<hex<<bb->start());
        return false;
      }
      else if(last_ins->isJump() == false && last_ins->isCall() == false && bb->fallThroughBB() == NULL
              && last_ins->asmIns().find("ret") == string::npos 
              && last_ins->asmIns().find("ud2") == string::npos
              && last_ins->asmIns().find("hlt") == string::npos) {
        //DEF_LOG("No CFT BB without fall through: "<<hex<<bb->start()<<": "<<last_ins->asmIns());
        return false;
      }
      else if(last_ins->isJump() && bb->target() != 0 && bb->targetBB() == NULL) {
        //DEF_LOG("Jump without target: "<<hex<<bb->start());
        return false;
      }

      if(bb->isCall() || 
         last_ins->asmIns().find("ret") != string::npos ||
         last_ins->asmIns().find("ud2") != string::npos ||
        (last_ins->isJump() && bb->target() == 0))
        exit_point = true;

    }
    if(exit_point)
      return valid;
    else {
      //DEF_LOG("No exit point");
      return false;
    }
  }
  return valid;
}
