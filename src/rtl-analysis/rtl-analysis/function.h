/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef FUNCTION_H
#define FUNCTION_H

#include "common.h"
// -----------------------------------------------------------------------------
class BasicBlock;
class Insn;
class State;
class BaseDomain;
// -----------------------------------------------------------------------------
class SCC {
 private:
   vector<BasicBlock*> blockList_;
   unordered_map<BasicBlock*,vector<BasicBlock*>> succ_;
   unordered_map<BasicBlock*,vector<BasicBlock*>> pred_;
   unordered_map<BasicBlock*,vector<pair<BasicBlock*,SCC*>>> predScc_;
   int nExecute_;

 public:
   SCC(const vector<BasicBlock*>& blockList) {blockList_ = blockList;};
   ~SCC() {};

   /* Read accessors */
   const vector<BasicBlock*>& block_list() const {return blockList_;};
   const vector<BasicBlock*>& succ(BasicBlock* u) const {return succ_.at(u);};
   const vector<BasicBlock*>& pred(BasicBlock* u) const {return pred_.at(u);};
   vector<pair<BasicBlock*,SCC*>> pred_scc(BasicBlock* u) const;

   /* Methods related to CFG */
   void build_graph(BasicBlock* header, BasicBlock* pred);
   bool is_loop() const;

   /* Methods related to static analysis */
   void execute(const array<State*,domainCnt>& s) const;
};
// -----------------------------------------------------------------------------
class Function {
 private:
   BasicBlock* entry_;
   vector<SCC*> sccList_;

 private:
   /* ---------------------------- *
    | 0x1: uninit mem address      |
    | 0x2: uninit control target   |
    | 0x4: uninit critical data    |
    | 0x8: uninit loop index/limit |
    * ---------------------------- */
   int uninit_;

 public:
   Function(BasicBlock* entry);
   ~Function();
  
   array<State*,domainCnt> s_;
   /* Read accessors */
   BasicBlock* entry() const {return entry_;};
   int64_t offset() const;
   const vector<SCC*>& scc_list() const {return sccList_;};
   int uninit() const {return uninit_;};

   /* Methods related to static analysis */
   void forward_analysis(const function<void(array<State*,domainCnt>&)>& init);
   vector<BaseDomain*> track_before(int domainIndex, const UnitId& id,
                       const Loc& loc, const function<bool(Insn*)>& select);
   vector<BaseDomain*> track_after(int domainIndex, const UnitId& id,
                       const Loc& loc, const function<bool(Insn*)>& select);
   BaseDomain* track_subexpr(int domainIndex, const ExprLoc& subExpr);

   /* Methods related to pattern matching */
   vector<ExprLoc> find_def(const ExprLoc& reg);
   template<class RetType,class ExprType>
         vector<RetType> find_pattern(const ExprLoc& X,
         vector<RetType>(*recur)(const ExprLoc&),
         const function<void(vector<RetType>&,ExprType*,const Loc&)>& handler);

   /* Methods related to specific analyses */
   void uninit(int err) {uninit_ |= err;};
   analysis::JTable jump_table_analysis();

   /* Methods related to helper functions */
   void clear();

 private:
   /* Methods related to CFG */
   void build_graph();
};
// -----------------------------------------------------------------------------
#endif