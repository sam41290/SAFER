/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "basicblock.h"
#include "insn.h"
#include "state.h"
#include "expr.h"
// ------------------------------ Basic Block ----------------------------------
BasicBlock::BasicBlock(const vector<Insn*>& insnList) {
   insnList_ = insnList;
}


COMPARE BasicBlock::edge_cond(BasicBlock* u) const {
   for (auto const& [t, cond]: succ_)
      if (t->offset() == u->offset())
         return cond;
   return COMPARE::NONE;
}


Expr* BasicBlock::indirect_target() const {
   return last_insn()->indirect_target();
}


int64_t BasicBlock::offset() const {
   return first_insn()->offset();
}


void BasicBlock::add_succ(BasicBlock* u, COMPARE cond) {
   succ_.push_back(make_pair(u, cond));
}


bool BasicBlock::execute(const array<State*,domainCnt>& s) const {
   /* set location */
   for (auto ss: s)
      ss->loc().block = (BasicBlock*)this;
   /* refresh block b before execution */
   for (auto ss: s)
      ss->refresh();
   /* execute block */
   for (auto i: insn_list())
      i->execute(s);
   /* commit block channel to main channel, verify changes */
   bool change = false;
   for (auto ss: s)
      change |= ss->commit(CHANNEL::BLOCK);
   LOG(3, "______________________________________\n");
   return change;
}


void BasicBlock::preset(const array<State*,domainCnt>& s) const {
   for (auto ss: s)
      ss->loc().block = (BasicBlock*)this;
   for (auto i: insn_list())
      i->preset(s);
   for (auto ss: s)
      ss->commit(CHANNEL::BLOCK);
}