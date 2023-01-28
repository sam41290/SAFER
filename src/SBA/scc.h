/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef SCC_H
#define SCC_H

#include "utility.h"

namespace SBA {
   /* Forward declaration */
   class Block;
   class AbsState;
   /* ---------------------------------- SCC -------------------------------- */
   class SCC {
    private:
      vector<Block*> b_list_;
      unordered_map<Block*,vector<Block*>> pred_;
      unordered_map<Block*,vector<Block*>> pred_ext_;

    private:
      static const vector<Block*> empty_;
      bool processed_;

    public:
      SCC(const vector<Block*>& b_list): b_list_(b_list), processed_(false) {};
      ~SCC() {};

      /* Read accessors */
      const vector<Block*>& block_list() const {return b_list_;};
      const vector<Block*>& pred(Block* u) const;
      const vector<Block*>& pred_ext(Block* u) const;
      bool processed() const {return processed_;};

      /* Methods related to CFG */
      void set_as_entry() {pred_ext_[b_list_.front()]=vector<Block*>{nullptr};};
      void build_graph(Block* header, vector<Block*>& ext_target);
      bool is_loop() const;

      /* Methods related to static analysis */
      void execute(const array<AbsState*,DOMAIN_NUM>& s) const;
   };

}

#endif
