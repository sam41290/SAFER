#include "CFValidity.h"

using namespace SBI;

uint64_t CFValidity::memSpaceStart_;
uint64_t CFValidity::memSpaceEnd_;
bool (*CFValidity::InsValidators_[4])(Instruction *);
vector <InsValidityRules>  CFValidity::insRule_;

extern bool compareBB(BasicBlock *A, BasicBlock *B);

bool
CFValidity::validOpCode(Instruction *ins) {
  if(ins->asmIns().find(".byte") != string::npos)
    return false;
  auto bin = ins->insBinary();
  if(bin.size() == 1 && utils::is_prefix(bin[0]))
    return false;
  //string asm_ins = ins->asmIns();
  //vector <string> words = utils::split_string(asm_ins,' ');
  //if(words.size() == 1 && utils::is_prefix(words[0]))
  //  return false;
  return true;
}

bool
CFValidity::validMem(Instruction *ins) {
  if(ins->isRltvAccess()) {
    uint64_t offt = ins->ripRltvOfft();
    if(offt >= memSpaceStart_ && offt < memSpaceEnd_)
      return true;
    return false;
  }
  return true;
}

bool
CFValidity::validIns(vector <BasicBlock *> &bb_list) {
  for(auto & bb : bb_list) {
    vector<Instruction *> insList = bb->insList();
    for(auto & ins : insList) {
      for(auto & rule : insRule_) {
        if(InsValidators_[(int)rule](ins) == false) {
          LOG("Invalid ins at: "<<hex<<ins->location()<<" type "<<(int)rule);
          return false;
        }
      }
    }
  }
  return true;
}

bool 
CFValidity::validCFTransfer(vector <BasicBlock *> &bbList) {
  sort(bbList.begin(),bbList.end(),compareBB);
  bool valid = true;
  int size = bbList.size();
  //LOG("BB list size: "<<size);
  for(int i = 0; i < (size - 1); i++) {
    //LOG("BB: "<<hex<<bbList[i]->start());
    if(bbList[i]->boundary() > bbList[i + 1]->start()) {
      LOG("Boundary exceeds: "<<hex<<bbList[i + 1]->start());
      auto ins = bbList[i]->getIns(bbList[i + 1]->start());
      if(ins == NULL) {
        valid = false;
        break;
      }
      else if(ins->location() != bbList[i]->start()) {
        auto new_bb = bbList[i]->split(bbList[i + 1]->start());
        bbList[i]->fallThroughBB(bbList[i + 1]);
        delete(new_bb);
      }
    }
  }
  return valid;
}
