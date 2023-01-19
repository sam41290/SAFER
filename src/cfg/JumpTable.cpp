#include "JumpTable.h"
#include<bits/stdc++.h>
#include "libutils.h"

using namespace SBI;

bool
JumpTable::isTarget(uint64_t address) {
  for(auto bb : targets_)
    if(bb == address)
      return true;
  return false;
}

string
JumpTable::rewriteTgts() {
  //generates a set of assembler directives using labels, inorder to re-create
  //the jump table.

  string size;
  if(entrySize_ == 4)
    size = ".4byte";
  else
    size = ".8byte";
  string jmp_tbl = "";// = "." + to_string(location_) + ":\n";
  string baseLbl = "";
  if(rewritable_ == false)
    return jmp_tbl;
  if(baseBB_ != NULL)
    baseLbl = baseBB_->label();
  else
    baseLbl = "." + to_string(base_);
  for (auto & bb :targetBBs_) {
    if(type_ == 1) {
      string lbl;
      if(bb->isCode())
        lbl = utils::getLabel(bb->start());
      else
        lbl = bb->label();
      jmp_tbl += size + " " + lbl + " - " + baseLbl + "\n";
    }
    else if(type_ == 2) {
      bb->addTramp(bb->start());
      auto tramp_bb = bb->tramp();
      vector <Instruction *> ins_list = tramp_bb->insList();
      jmp_tbl += tramp_bb->label() + ": " + ins_list[0]->asmIns() 
              + "\n.skip " + to_string(entrySize_ - 5) + "\n";
    }
  }
  return jmp_tbl;
}

void 
JumpTable::displayTgts() {
  DEF_LOG("jump table start: "<<hex<<location_<<" end: "<<end_);
  //LOG("targets:");
  for(auto tgt : targets_)
    DEF_LOG("Jump table target: "<<hex<<tgt);
}
