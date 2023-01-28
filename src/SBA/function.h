/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef FUNCTION_H
#define FUNCTION_H

#include "utility.h"

namespace SBA {
   /* Forward declaration */
   class SCC;
   class Block;
   class Insn;
   class JTable;
   class AbsState;
   class BaseDomain;
   /* ------------------------------- Function ------------------------------ */
   class Function {
    public:
      /* ---------------------------- *
       | 0x1: uninit mem address      |
       | 0x2: uninit control target   |
       | 0x4: uninit critical data    |
       | 0x8: uninit loop index/limit |
       * ---------------------------- */
      uint8_t uninit_error;
      /* ---------------------------- *
       | 0x0: store f(x) to memory    |
       | 0x1: dereference f(x)        |
       | 0x2: f(x) is callee's args   |
       | 0x3: f(x) is return value    |
       | 0x4: f(x) is cf targets      |
       * ---------------------------- */
      array<unordered_map<Insn*,unordered_set<Insn*>>,5> escaped_taint;

    private:
      Block* entry_;
      vector<Block*> exit_;
      vector<SCC*> scc_list_;
      array<AbsState*,DOMAIN_NUM> s_;

    public:
      Function(Block* entry);
      ~Function();

      /* Read accessors */
      IMM offset() const;
      Block* entry() const {return entry_;};
      const vector<Block*>& exit() const {return exit_;};
      const vector<SCC*>& scc_list() const {return scc_list_;};

      /* Methods related to static analysis */
      void init(const function<void(array<AbsState*,DOMAIN_NUM>&)>& init_func) {
         init_func(s_);
      };
      void forward_analysis();
      vector<BaseDomain*> track(TRACK trackType, int domainIndex, const UnitId& id,
                          const Loc& loc, const function<bool(Insn*)>& select);
      BaseDomain* track_subexpr(int domainIndex, Expr* expr, const Loc& loc);

      /* Methods related to pattern matching */
      vector<ExprLoc> find_def(ARCH::REG reg, const Loc& loc);
      vector<ExprLoc> find_use(ARCH::REG reg, const Loc& loc);
      vector<ExprLoc> find_reached(ARCH::REG reg, const Loc& loc);
      template<class RetType,class ExprType>
            vector<RetType> find_pattern(const ExprLoc& X,
            vector<RetType>(*recur)(const ExprLoc&),
            const function<void(vector<RetType>&,ExprType*,const Loc&)>& handler);

      /* Methods related to post-process */
      void clear();
 
    private:
      /* Methods related to CFG */
      void build_graph();
   };

}
#endif
