/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef BLOCK_H
#define BLOCK_H

#include "utility.h"

namespace SBA {
   /* Forward declaration */
   class SCC;
   class Insn;
   class Expr;
   class AbsState;
   /* --------------------------------- Block ------------------------------- */
   class Block {
    public:
      /* context info */
      SCC* container;
      array<bool,2> ext_succ;

    private:
      vector<Insn*> insnList_;
      uint8_t n_;
      array<Block*,2> succ_;
      array<COMPARE,2> cond_;

    private:
      using IndirectTargetInfo = vector<Block*>;
      IndirectTargetInfo* succ_ind_;

    public:
      Block(const vector<Insn*>& insnList);
      ~Block() {if (succ_ind_ != nullptr) delete succ_ind_;};

      /* Read accessors */
      IMM offset() const;
      const vector<Insn*>& insn_list() const {return insnList_;};
      Insn* first_insn() const {return insnList_.front();};
      Insn* last_insn() const {return insnList_.back();};
      Expr* indirect_target() const;
      uint8_t num_succ() const {return n_;};
      Block* succ(uint8_t idx) const {return succ_[idx];};
      COMPARE cond(uint8_t idx) const {return cond_[idx];};
      COMPARE cond(Block* u) const;
      const IndirectTargetInfo* succ_ind() const {return succ_ind_;};

      /* Write accessors */
      void succ(Block* u, COMPARE c) {succ_[n_] = u; cond_[n_] = c; ++n_;};
      void succ_ind(Block* u);

      /* Methods related to static analysis */
      bool execute(const array<AbsState*,DOMAIN_NUM>& s) const;
      void preset(const array<AbsState*,DOMAIN_NUM>& s) const;
   };

}

#endif
