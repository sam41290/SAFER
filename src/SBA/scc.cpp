/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "scc.h"
#include "block.h"
#include "insn.h"
#include "rtl.h"
#include "state.h"

using namespace SBA;
/* --------------------- Strongly Connected Component ----------------------- */
vector<Block*> const SCC::empty_ = vector<Block*>{};

const vector<Block*>& SCC::pred(Block* u) const {
   auto it = pred_.find(u);
   return (it != pred_.end())? it->second: SCC::empty_;
};


const vector<Block*>& SCC::pred_ext(Block* u) const {
   auto it = pred_ext_.find(u);
   return (it != pred_ext_.end())? it->second: SCC::empty_;
};


void SCC::build_graph(Block* header, vector<Block*>& ext_target) {
   unordered_set<Block*> b_visited;
   unordered_set<Block*> b_all(b_list_.begin(), b_list_.end());

   function<void(Block*)> dfs = [&](Block* u) -> void {
      b_visited.insert(u);

      vector<Block*> succ;
      for (uint8_t i = 0; i < u->num_succ(); ++i) {
         auto v = u->succ(i);
         u->ext_succ[i] = !b_all.contains(v);
         succ.push_back(v);
      }
      if (u->succ_ind() != nullptr)
         succ.insert(succ.end(), u->succ_ind()->begin(), u->succ_ind()->end());

      for (auto v: succ)
         if (!b_all.contains(v)) {
            v->container->pred_ext_[v].push_back(u);
            ext_target.push_back(v);
         }
         else {
            pred_[v].push_back(u);
            if (!b_visited.contains(v))
               dfs(v);
         }

      b_list_.push_back(u);
   };

   /* reverse postorder for b_list_ */
   b_list_.clear();
   dfs(header);
   std::reverse(b_list_.begin(), b_list_.end());
   processed_ = true;
}


bool SCC::is_loop() const {
   if (b_list_.size() == 1) {
      auto u = b_list_.front();
      for (uint8_t i = 0; i < u->num_succ(); ++i)
         if (u->succ(i) == u)
            return true;
      return false;      
   }
   return true;
}


void SCC::execute(const array<AbsState*,DOMAIN_NUM>& s) const {
   /* set location */
   for (auto ss: s)
      ss->loc.scc = (SCC*)this;

   /* loop until fixpoint */
   bool change = false;
   bool loop = is_loop();

   /* if !fixpoint, preset all targets to TOP */
   if (loop) {
      unordered_set<ARCH::REG> rList;
      for (auto b: block_list())
         for (auto i: b->insn_list())
            if (i->stmt() != nullptr)
               i->stmt()->preset_list(rList);
      for (auto r: rList) {
         auto const& id = get_id(r);
         LOG3("preset " << id.to_string());
         FOR_STATE(s, k, !s[k]->enable_fixpoint(), {
            for (auto b: block_list()) {
               s[k]->loc.block = b; 
               s[k]->preset(id);
            }
         });
      }
   }
   do {
      change = false;
      for (auto b: block_list())
         change |= b->execute(s);
      break;
   }
   while (loop && change);
   LOG3("==============================================================\n");
}
