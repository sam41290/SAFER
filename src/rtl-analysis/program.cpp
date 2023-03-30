/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "program.h"
#include "framework.h"
#include "function.h"
#include "basicblock.h"
#include "insn.h"
#include "rtl.h"
/* -------------------------------- Program --------------------------------- */
Program::Program(const vector<pair<int64_t,RTL*>>& pairList,
const unordered_map<int64_t,int64_t>& insnSize,
const unordered_map<int64_t,vector<int64_t>>& jumpTable,
const vector<int64_t>& entry, bool& corrupted) {
   entry_ = entry;
   corrupted = false;
   pairList_ = pairList;
   insnSize_ = insnSize;
   jumpTable_ = jumpTable;
}


Program::~Program() {
   for (auto [offset, b]: blockMap_)
      delete b;
   for (auto [offset, i]: insnMap_)
      delete i;
   for (auto [offset, rtl]: pairList_)
      delete rtl;
}


Function* Program::func(int index) {
   if (index < (int)(entry_.size())) {
      for (auto [offset, b]: blockMap_)
         delete b;
      for (auto [offset, i]: insnMap_)
         delete i;
      blockMap_.clear();
      insnMap_.clear();
      index_ = index;
      bool corrupted = false;
      load_asm(pairList_, insnSize_, jumpTable_, corrupted);
      if (corrupted)
         return nullptr;
      auto entryBlock = blockMap_.at(entry_.at(index));
      return new Function(entryBlock);
   }
   return nullptr;
}
/* -------------------------------------------------------------------------- */
void Program::load_asm(const vector<pair<int64_t,RTL*>>& pairList,
const unordered_map<int64_t,int64_t>& insnSize,
const unordered_map<int64_t,vector<int64_t>>& jumpTable,
bool& corrupted) {

  /*--------------------------------------------------------*
   |                  generate instructions                 |
   *--------------------------------------------------------*/
   /* assumption: instructions are sorted by offset  */
   /*             otherwise, sort pairList by offset */
   vector<Insn*> insnList;
   for (auto [offset, rtl]: pairList) {
      auto i = new Insn(offset, rtl, insnSize.at(offset));
      insnMap_[offset] = i;
      insnList.push_back(i);
   }

  /*--------------------------------------------------------*
   |         identify directly reached instructions         |
   *--------------------------------------------------------*/
   unordered_set<Insn*> validInsn;
   unordered_set<Insn*> targetInsn;
   unordered_set<Insn*> justAdded;
   vector<Insn*> validVec;

   function<void(Insn*)> insn_dfs = [&](Insn* i) -> void {
      validInsn.insert(i);
      justAdded.insert(i);

      if (i->transfer()) {
         /* direct transfer */
         if (i->direct()) {
            /* skip direct call targets */
            if (!i->call()) {
               if (insnMap_.contains(i->direct_target().first)) {
                  auto j = insnMap_.at(i->direct_target().first);
                  targetInsn.insert(j);
                  if (!validInsn.contains(j)) {
                     insn_dfs(j);
                     if (corrupted)
                        return;
                  }
               }
               else {
                  LOG(1, "error: missing direct target "
                     << i->direct_target().first);
                  corrupted = true;
                  return;
               }
            }
            /* process fall-through targets */
            if (i->call() || i->cond_jump()) {
               if (insnMap_.contains(i->direct_target().second)) {
                  auto j = insnMap_.at(i->direct_target().second);
                  targetInsn.insert(j);
                  if (!validInsn.contains(j)) {
                     insn_dfs(j);
                     if (corrupted)
                        return;
                  }
               }
               else {
                  LOG(1, "error: missing fall-through target "
                     << i->direct_target().second);
                  corrupted = true;
                  return;
               }
            }
         }
         /* indirect transfer */
         else {
            if (i->call()) {
               if (insnMap_.contains(i->direct_target().first)) {
                  auto j = insnMap_.at(i->direct_target().first);
                  targetInsn.insert(j);
                  if (!validInsn.contains(j)) {
                     insn_dfs(j);
                     if (corrupted)
                        return;
                  }
               }
               else {
                  LOG(1, "error: missing fall-through target "
                     << i->direct_target().first);
                  corrupted = true;
                  return;
               }
            }
         }
      }
      /* exit insn */
      else if (i->exit())
         return;
      /* non-control insn */
      else {
         if (insnMap_.contains(i->next_offset())) {
            auto j = insnMap_.at(i->next_offset());
            if (!validInsn.contains(j)) {
               insn_dfs(j);
               if (corrupted)
                  return;
            }
         }
         else {
            LOG(1, "error: missing successive target " << i->next_offset());
            corrupted = true;
            return;
         }
      }
   };

   function<bool(Insn*)> conflict_insn = [&](Insn* i) -> bool {
      if (i->offset() < validVec.at(0)->offset())
         return i->next_offset() <= validVec.at(0)->offset();
      else {
         int L = 0;
         int R = validVec.size();
         while (L + 1 < R) {
            int M = (L + R) >> 1;
            if (validVec.at(M)->offset() <= i->offset())
               L = M;
            else
               R = M;
         }
         if (i->offset() < validVec.at(L)->next_offset())
            return false;
         if (L + 1 < (int)(validVec.size())
         && i->next_offset() > validVec.at(L+1)->offset())
            return false;
         return true;
      }
   };

   /* explore directly reached targets */
   {
      auto t = entry_.at(index_);
      if (insnMap_.contains(t)) {
         auto i = insnMap_.at(t);
         targetInsn.insert(i);
         if (!validInsn.contains(i))
            insn_dfs(i);
         if (corrupted)
            return;
      }
      else {
         LOG(1, "error: missing entry point " << t);
         corrupted = true;
         return;
      }
   }

   /* explore jump table targets */
   while (!justAdded.empty()) {
      auto temp = justAdded;
      justAdded.clear();
      for (auto i: temp)
         if (jumpTable.contains(i->offset())) {
            validVec.assign(validInsn.begin(), validInsn.end());
            sort(validVec.begin(), validVec.end(),
               [](Insn* a, Insn* b) -> bool {
                  return a->offset() < b->offset();
               });
            for (auto t: jumpTable.at(i->offset()))
               if (insnMap_.contains(t)) {
                  auto j = insnMap_.at(t);
                  targetInsn.insert(j);
                  if (!validInsn.contains(j) && !conflict_insn(j))
                     insn_dfs(j);
                  if (corrupted)
                     return;
               }
               else {
                  LOG(1, "error: missing indirect target " << t);
                  corrupted = true;
                  return;
               }
         }
   }

  /*--------------------------------------------------------*
   |                  generate basic blocks                 |
   *--------------------------------------------------------*/
   function<void(Insn*)> block_dfs = [&](Insn* currInsn) -> void {
      vector<Insn*> currList{currInsn};
      /* curr insn is already added to current block          */
      /* this loop processes the next insn based on curr insn */
      while (true) {
         /* (A) transfer insn */
         if (currInsn->transfer()) {
            /* mark the end of current block */
            auto currBlock = new BasicBlock(currList);
            blockMap_[currBlock->offset()] = currBlock;
            currList.clear();

            /* compute transfer targets */
            vector<pair<int64_t,COMPARE>> targets;
            if (currInsn->direct()) {
               /* skip direct call targets but accept fall-through targets */
               if (!currInsn->call()) {
                  auto t = currInsn->direct_target().first;
                  auto c = currInsn->cond().first;
                  targets.push_back(make_pair(t,c));
               }
               if (currInsn->call() || currInsn->cond_jump()) {
                  auto t = currInsn->direct_target().second;
                  auto c = currInsn->cond().second;
                  targets.push_back(make_pair(t,c));
               }
            }
            else {
               /* fall-through instruction */
               if (currInsn->call()) {
                  auto t = currInsn->direct_target().first;
                  auto c = currInsn->cond().first;
                  targets.push_back(make_pair(t,c));
               }
               /* jump table targets */
               else if (jumpTable.contains(currInsn->offset())) {
                  for (auto t: jumpTable.at(currInsn->offset()))
                     if (validInsn.contains(insnMap_.at(t)))
                        targets.push_back(make_pair(t,COMPARE::NONE));
               }
            }

            /* connect currBlock and targetBlock */
            for (auto const& [t, cond]: targets) {
               /* process target block */
               if (!blockMap_.contains(t))
                  block_dfs(insnMap_.at(t));
               auto targetBlock = blockMap_.at(t);
               currBlock->add_succ(targetBlock, cond);
            }

            return;
         }

         /* (B) exit insn */
         else if (currInsn->exit()) {
            /* mark the end of current block */
            auto currBlock = new BasicBlock(currList);
            blockMap_[currBlock->offset()] = currBlock;
            currList.clear();
            return;
         }

         /* (C) non-control insn */
         else {
            auto nextInsn = insnMap_.at(currInsn->next_offset());
            /* (a) next insn is a transfer target: a new block */
            if (targetInsn.contains(nextInsn)) {
               /* mark the end of current block */
               auto currBlock = new BasicBlock(currList);
               blockMap_[currBlock->offset()] = currBlock;
               currList.clear();
               /* process fall-through block */
               if (!blockMap_.contains(nextInsn->offset()))
                  block_dfs(nextInsn);
               auto nextBlock = blockMap_.at(nextInsn->offset());
               currBlock->add_succ(nextBlock,COMPARE::NONE);
               return;
            }
            /* (b) next insn is not a transfer target: current block */
            else {
               currList.push_back(nextInsn);
               currInsn = nextInsn;
            }
         }

      }
   };

   {
      auto offset = entry_.at(index_);
      if (!blockMap_.contains(offset))
         block_dfs(insnMap_[offset]);
   }
}
