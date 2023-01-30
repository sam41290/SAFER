/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "function.h"
#include "framework.h"
#include "scc.h"
#include "block.h"
#include "insn.h"
#include "jtable.h"
#include "state.h"
#include "domain.h"
#include "rtl.h"
#include "expr.h"
#include "arithmetic.h"

using namespace SBA;
/* -------------------------------- Function -------------------------------- */
Function::Function(Block* entry) {
   entry_ = entry;
   s_.fill(nullptr);
   clear();
   build_graph();
}


Function::~Function() {
   clear();
   for (auto scc: scc_list_)
      delete scc;
}


IMM Function::offset() const {
   return entry_->offset();
}


void Function::clear() {
   for (auto& ss: s_)
      if (ss != nullptr)
         delete ss;
   s_.fill(nullptr);
   escaped_taint.fill(unordered_map<Insn*,unordered_set<Insn*>>{});
   uninit_error = 0;
}


void Function::build_graph() {
   /* tarjan algorithm */
   int cnt = 0;
   unordered_map<Block*,int> num;
   unordered_map<Block*,int> low;
   stack<Block*> st;

   function<void(Block*)> tarjan = [&](Block* u) -> void {
      ++cnt;
      num[u] = cnt;
      low[u] = cnt;
      st.push(u);
      /* direct targets */
      for (uint8_t i = 0; i < u->num_succ(); ++i) {
         auto v = u->succ(i);
         /* if v is not visited */
         if (!num.contains(v)) {
            tarjan(v);
            low[u] = std::min(low[u], low[v]);
         }
         /* if v is visited */
         else if (num[v] > 0)
            low[u] = std::min(low[u], num[v]);
      }
      /* indirect targets */
      if (u->succ_ind() != nullptr)
         for (auto v: *(u->succ_ind())) {
            /* if v is not visited */
            if (!num.contains(v)) {
               tarjan(v);
               low[u] = std::min(low[u], low[v]);
            }
            /* if v is visited */
            else if (num[v] > 0)
               low[u] = std::min(low[u], num[v]);
         }

      /* found a new SCC */
      if (num[u] == low[u]) {
         vector<Block*> vec;

         while (true) {
            auto v = st.top();
            st.pop();
            vec.push_back(v);
            num[v] = -1;
            if (u == v)
               break;
         }

         auto scc = new SCC(vec);
         for (auto v: vec)
            v->container = scc;
      }
   };

   tarjan(entry_);

   /* reverse postorder for scc_list_ */
   function<void(Block*)> dfs = [&](Block* header) -> void {
      vector<Block*> ext_target;
      auto scc = header->container;
      scc->build_graph(header, ext_target);
      for (auto u: ext_target)
      if (!u->container->processed())
         dfs(u);
      scc_list_.push_back(scc);
   };

   dfs(entry_);
   entry_->container->set_as_entry();
   std::reverse(scc_list_.begin(), scc_list_.end());

   /* compute exit points */
   for (auto scc: scc_list_)
      for (auto b: scc->block_list())
         if (b->last_insn()->ret())
            exit_.push_back(b);
}


void Function::forward_analysis() {
   LOG3("############# analyzing ##############");
   TIME_START(start_t);

   /* set location */
   FOR_STATE(s_, k, true, {
      s_[k]->loc.func = this;
   });

   /* execute scc in reverse postorder */
   for (auto scc: scc_list())
      scc->execute(s_);

   TIME_STOP(Framework::t_analyse, start_t);
}


vector<BaseDomain*> Function::track(TRACK trackType, int domainIndex,
const UnitId& id, const Loc& loc, const function<bool(Insn*)>& select) {
   /* get list of insn to be tracked */
   vector<Insn*> insns;
   for (auto i: loc.block->insn_list())
      if (select(i))
         insns.push_back(i);
   if (insns.empty())
      return vector<BaseDomain*>{};

   LOG3("############## track " << id.to_string() << " ##############");
   TIME_START(start_t);

   /* initialize block channel */
   FOR_STATE(s_, k, true, {
      s_[k]->loc = loc;
      s_[k]->refresh();
   });

   /* execute instructions */
   vector<BaseDomain*> res;
   auto it = insns.begin();
   for (auto i: loc.block->insn_list()) {
      FOR_STATE(s_, k, true, {
         s_[k]->loc.insn = i;
      });
      if (trackType == TRACK::BEFORE && i == *it) {
         res.push_back(s_[domainIndex]->value_unit(id)->clone());
         if (++it == insns.end())
            break;
      }
      /* execute, but NOT commit to main channel */
      i->execute(s_);
      if (trackType == TRACK::AFTER && i == *it) {
         res.push_back(s_[domainIndex]->value_unit(id)->clone());
         if (++it == insns.end())
            break;
      }
   }

   /* clear block channel */
   FOR_STATE(s_, k, true, {
      s_[k]->clear();
   });

   TIME_STOP(Framework::t_track, start_t);

   return res;
}


BaseDomain* Function::track_subexpr(int domainIndex, Expr* expr, const Loc& loc)
{
   /* initialize block channel */
   FOR_STATE(s_, k, true, {
      s_[k]->loc = loc;
      s_[k]->refresh();
   });

   /* execute instructions */
   BaseDomain* res = BaseDomain::BOT;
   for (auto i: loc.block->insn_list()) {
      FOR_STATE(s_, k, true, {
         s_[k]->loc.insn = i;
      });
      if (i == loc.insn) {
         res = (i->stmt()->eval(s_, expr)[domainIndex])->clone();
         break;
      }
      i->execute(s_);
   }

   /* clear block channel */
   FOR_STATE(s_, k, true, {
      s_[k]->clear();
   });
   return res;
}


vector<ExprLoc> Function::find_def(ARCH::REG reg, const Loc& loc) {
   vector<ExprLoc> res;
   auto pattern = new Reg(Expr::EXPR_MODE::DI, reg);
   for (auto l: s_[0]->use_def(get_id(reg), loc)) {
      auto stmt = l.insn->stmt();
      auto vec = stmt->find(RTL_EQUAL::RELAXED, pattern);
      for (auto r: vec) {
         auto a = (Assign*)(stmt->find_container(r, [](const RTL* rtl)->bool {
            return (Assign*)(*rtl) != nullptr;
         }));
         /* ignore clobber, since we're looking for source expressions */
         if (a != nullptr) {
            auto src = a->src()->simplify();
            auto dst = a->dst()->simplify();
            if (dst->contains(r))
               res.push_back(ExprLoc{src, l});
         }
      }
   }
   delete pattern;
   return res;
}


vector<ExprLoc> Function::find_use(ARCH::REG reg, const Loc& loc) {
   vector<ExprLoc> res;
   auto pattern = new Reg(Expr::EXPR_MODE::DI, reg);
   for (auto l: s_[0]->def_use(get_id(reg), loc)) {
      auto stmt = l.insn->stmt();
      auto vec = stmt->find(RTL_EQUAL::RELAXED, pattern);
      for (auto r: vec) {
         auto a = (Assign*)(stmt->find_container(r, [](const RTL* rtl)->bool {
            return (Assign*)(*rtl) != nullptr;
         }));
         /* a use cannot be the destination of an assignment */
         if (a == nullptr || a->src()->contains(r))
            res.push_back(ExprLoc{(Expr*)r, l});
      }
   }
   delete pattern;
   return res;
}


vector<ExprLoc> Function::find_reached(ARCH::REG reg, const Loc& loc) {
   unordered_set<int> processed;
   processed.insert(ARCH::serial(reg, loc.insn->offset()));

   list<ExprLoc> lst;
   for (auto& u: find_use(reg, loc)) {
      lst.push_back(u);
      auto r = ((Reg*)(*(u.rtl())))->reg();
      auto serial = ARCH::serial(r, u.loc.insn->offset());
      processed.insert(serial);
   }

   for (auto v: lst) {
      auto stmt = v.loc.insn->stmt();
      auto a = (Assign*)(stmt->find_container(v.expr, [](const RTL* rtl)->bool {
         return (Assign*)(*rtl) != nullptr;
      }));
      if (a != nullptr) {
         auto src = a->src()->simplify();
         auto dst = a->dst()->simplify();
         auto dstr = (Reg*)(*dst);
         if (src->contains(v.expr) && dstr != nullptr) {
            for (auto v2: find_use(dstr->reg(), v.loc)) {
               auto r = ((Reg*)(*(v2.rtl())))->reg();
               auto serial = ARCH::serial(r, v2.loc.insn->offset());
               if (!processed.contains(serial)) {
                  lst.push_back(v2);
                  processed.insert(serial);
               }
            }
         }
      }
   }

   vector<ExprLoc> res(lst.begin(), lst.end());
   return res;
}


template<class RetType,class ExprType>
vector<RetType> Function::find_pattern(const ExprLoc& X,
vector<RetType>(*recur)(const ExprLoc&),
const function<void(vector<RetType>&,ExprType*,const Loc&)>& handler) {
   vector<ExprLoc> defs;
   auto r = (Reg*)(*(X.rtl()));
   if (r != nullptr)
      defs = find_def(r->reg(), X.loc);
   if ((ExprType*)(*(X.rtl())) != nullptr)
      defs.push_back(X);

   vector<RetType> res;
   if (!defs.empty())
      for (auto x: defs) {
         /* continue to unfold if x is register */
         auto r = (Reg*)(*(x.rtl()));
         if (r != nullptr) {
            auto vec = recur(x);
            res.insert(res.end(), vec.begin(), vec.end());
            continue;
         }
         /* otherwise, handle x */
         auto t = (ExprType*)(*(x.rtl()));
         if (t != nullptr) {
            handler(res, t, x.loc);
            continue;
         }
      }
   return res;
}
/* -------------------------------------------------------------------------- */
FIND_PATTERN_INSTANT(JTBase,Const);
FIND_PATTERN_INSTANT(JTBase,Binary);
FIND_PATTERN_INSTANT(JTRange,Binary);
FIND_PATTERN_INSTANT(JTAddr,Binary);
FIND_PATTERN_INSTANT(JTMem,Mem);
FIND_PATTERN_INSTANT(JTBaseMem,Binary);
