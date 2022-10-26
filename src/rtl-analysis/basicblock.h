/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef BASICBLOCK_H
#define BASICBLOCK_H

#include "common.h"
// -----------------------------------------------------------------------------
class Insn;
class Expr;
class State;
// -----------------------------------------------------------------------------
class BasicBlock {
 private:
   vector<Insn*> insnList_;
   vector<pair<BasicBlock*,COMPARE>> succ_;

 public:
   BasicBlock(const vector<Insn*>& insnList);
   ~BasicBlock() {};

   /* Read accessors */
   Insn* first_insn() const {return insnList_.front();};
   Insn* last_insn() const {return insnList_.back();};
   const vector<Insn*>& insn_list() const {return insnList_;};
   const vector<pair<BasicBlock*,COMPARE>>& succ() const {return succ_;};
   COMPARE edge_cond(BasicBlock* u) const;
   Expr* indirect_target() const;
   int64_t offset() const;

   /* Write accessors */
   void add_succ(BasicBlock* u, COMPARE cond);

   /* Methods related to static analysis */
   bool execute(const array<State*,domainCnt>& s) const;
   void preset(const array<State*,domainCnt>& s) const;
};
// -----------------------------------------------------------------------------
#endif