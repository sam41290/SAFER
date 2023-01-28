/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "block.h"
#include "insn.h"
#include "state.h"
#include "expr.h"

using namespace SBA;
// ------------------------------ Basic Block ----------------------------------
Block::Block(const vector<Insn*>& insnList) {
   insnList_ = insnList;
   n_ = 0;
   succ_ind_ = nullptr;
}


COMPARE Block::cond(Block* u) const {
   return (succ((uint8_t)0)->offset() == u->offset())?
           cond((uint8_t)0): cond((uint8_t)1);
}


Expr* Block::indirect_target() const {
   return last_insn()->indirect_target();
}


IMM Block::offset() const {
   return first_insn()->offset();
}


void Block::succ_ind(Block* u) {
   if (succ_ind_ == nullptr)
      succ_ind_ = new IndirectTargetInfo();
   succ_ind_->push_back(u);
}


bool Block::execute(const array<AbsState*,DOMAIN_NUM>& s) const {
   /* refresh block b before execution */
   FOR_STATE(s, k, true, {
      s[k]->loc.block = (Block*)this;
      s[k]->refresh();
   });
   /* execute block */
   for (auto i: insn_list())
      i->execute(s);
   /* commit block channel to main channel, verify changes */
   bool change = false;
   FOR_STATE(s, k, true, {
      change |= s[k]->commit(CHANNEL::BLOCK);
   });
   LOG3("______________________________________________________________\n");
   return change;
}
