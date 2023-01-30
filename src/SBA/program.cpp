/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "program.h"
#include "framework.h"
#include "function.h"
#include "block.h"
#include "insn.h"
#include "rtl.h"

using namespace SBA;
/* -------------------------------- Program --------------------------------- */
Program::Program(const vector<pair<IMM,RTL*>>& offset_rtl,
                 const unordered_map<IMM,uint8_t>& insn_size,
                 const unordered_map<IMM,vector<IMM>>& jump_tables,
                 const vector<IMM>& func_entries) {
   corrupted_ = false;
   update_graph(offset_rtl, insn_size, jump_tables, func_entries);
}


Program::~Program() {
   for (auto [entry, f]: f_map_)
      delete f;
   for (auto [offset, b]: b_map_)
      delete b;
   for (auto [offset, i]: i_map_)
      delete i;
}


Function* Program::func(IMM entry) {
   if (f_map_.contains(entry))
      return f_map_.at(entry);
   else if (b_map_.contains(entry)) {
      auto entryBlock = b_map_.at(entry);
      TIME_START(start_t);
      auto f = new Function(entryBlock);
      TIME_STOP(Framework::t_cfg, start_t);
      f_map_[entry] = f;
      return f;
   }
   return nullptr;
}
/* -------------------------------------------------------------------------- */
void Program::update_graph(const vector<pair<IMM,RTL*>>& offset_rtl,
                           const unordered_map<IMM,uint8_t>& insn_size,
                           const unordered_map<IMM,vector<IMM>>& jump_tables,
                           const vector<IMM>& func_entries) {

   /* except instructions, all are affected by update */
   for (auto [entry, f]: f_map_)
      delete f;
   for (auto [offset, b]: b_map_)
      delete b;
   f_map_.clear();
   b_map_.clear();

   /* update jump tables and function entries */
   jump_tables_ = jump_tables;
   for (auto e: func_entries)
      if (!func_entries_.contains(e)) {
         func_entries_.insert(e);
         ++Framework::num_func;
      }

  /*--------------------------------------------------------* 
   |                  generate instructions                 | 
   *--------------------------------------------------------*/
   for (auto [offset, rtl]: offset_rtl)
      if (!i_map_.contains(offset))
         i_map_[offset] = new Insn(offset, rtl, insn_size.at(offset));
      else
         delete rtl;

  /*--------------------------------------------------------* 
   |         identify directly reached instructions         | 
   *--------------------------------------------------------*/
   unordered_set<Insn*> validInsn;
   unordered_set<Insn*> targetInsn;
   unordered_set<Insn*> justAdded;
   #if ABORT_INSN_CONFLICT == true
       vector<Insn*> validVec;
   #endif

   function<void(Insn*)> insn_dfs = [&](Insn* i) -> void {
      validInsn.insert(i);
      justAdded.insert(i);

      if (i->transfer()) {
         /* direct transfer */
         if (i->direct()) {
            /* skip direct call targets */
            if (!i->call()) {
               auto it = i_map_.find(i->direct_target().first);
               if (it != i_map_.end()) {
                  targetInsn.insert(it->second);
                  if (!validInsn.contains(it->second)) {
                     insn_dfs(it->second);
                     if (corrupted_)
                        return;
                  }
               }
               else {
                  LOG1("error: missing direct target "
                     << i->direct_target().first);
                  corrupted_ = true;
                  return;
               }
            }
            /* process fall-through targets */
            if (i->call() || i->cond_jump()) {
               auto it = i_map_.find(i->direct_target().second);
               if (it != i_map_.end()) {
                  targetInsn.insert(it->second);
                  if (!validInsn.contains(it->second)) {
                     insn_dfs(it->second);
                     if (corrupted_)
                        return;
                  }
               }
               else {
                  LOG1("error: missing fall-through target "
                     << i->direct_target().second);
                  corrupted_ = true;
                  return;
               }
            }
         }
         /* indirect transfer */
         else {
            if (i->call()) {
               auto it = i_map_.find(i->direct_target().first);
               if (it != i_map_.end()) {
                  targetInsn.insert(it->second);
                  if (!validInsn.contains(it->second)) {
                     insn_dfs(it->second);
                     if (corrupted_)
                        return;
                  }
               }
               else {
                  LOG1("error: missing fall-through target "
                     << i->direct_target().first);
                  corrupted_ = true;
                  return;
               }
            }
         }
      }
      /* exit insn */
      else if (i->halt())
         return;
      /* non-control insn */
      else {
         auto it = i_map_.find(i->next_offset());
         if (it != i_map_.end()) {
            if (!validInsn.contains(it->second)) {
               insn_dfs(it->second);
               if (corrupted_)
                  return;
            }
         }
         else {
            LOG1("error: missing successive target " << i->next_offset());
            corrupted_ = true;
            return;
         }
      }
   };

   #if ABORT_INSN_CONFLICT == true
       function<bool(Insn*)> conflict_insn = [&](Insn* i) -> bool {
          if (i->offset() < validVec.at(0)->offset())
             return i->next_offset() > validVec.at(0)->offset();
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
                return true;
             if (L + 1 < (int)(validVec.size())
             && i->next_offset() > validVec.at(L+1)->offset())
                return true;
             return false;
          }
       };
   #endif

   /* explore directly reached targets */
   for (auto t: func_entries_)
      if (i_map_.contains(t)) {
         auto i = i_map_.at(t);
         targetInsn.insert(i);
         if (!validInsn.contains(i))
            insn_dfs(i);
         if (corrupted_)
            return;
      }
      else {
         LOG1("error: missing entry point " << t);
         corrupted_ = true;
         return;
      }

   /* explore jump table targets */
   while (!justAdded.empty()) {
      auto temp = justAdded;
      justAdded.clear();
      for (auto i: temp)
         if (jump_tables_.contains(i->offset())) {
            #if ABORT_INSN_CONFLICT == true
                validVec.assign(validInsn.begin(), validInsn.end());
                sort(validVec.begin(), validVec.end(),
                   [](Insn* a, Insn* b) -> bool {
                      return a->offset() < b->offset();
                   });
            #endif
            for (auto t: jump_tables_.at(i->offset())) {
               auto it = i_map_.find(t);
               if (it != i_map_.end()) {
                  targetInsn.insert(it->second);
                  #if ABORT_INSN_CONFLICT == true
                      if (!validInsn.contains(it->second) &&
                      !conflict_insn(it->second))
                         insn_dfs(it->second);
                  #else
                      if (!validInsn.contains(it->second))
                         insn_dfs(it->second);
                  #endif
                  if (corrupted_)
                     return;
               }
               else {
                  LOG1("error: missing jump table target " << t);
                  #if ABORT_MISSING_JTABLE_TARGET == true
                     corrupted_ = true;
                     return;
                  #endif
               }
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
            auto b_curr = new Block(currList);
            b_map_[b_curr->offset()] = b_curr;
            currList.clear();

            /* compute transfer targets */
            vector<pair<IMM,COMPARE>> targets;
            vector<IMM> ind_targets;
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
               else {
                  auto it = jump_tables_.find(currInsn->offset());
                  if (it != jump_tables_.end())
                  for (auto t: it->second) {
                     auto it2 = i_map_.find(t);
                     if (it2 != i_map_.end() && validInsn.contains(it2->second))
                        ind_targets.push_back(t);
                  }
               }
            }

            /* connect b_curr and b_target */
            for (auto const& [t, cond]: targets) {
               if (!b_map_.contains(t))
                  block_dfs(i_map_.at(t));
               auto targetBlock = b_map_.at(t);
               b_curr->succ(targetBlock, cond);
            }

            for (auto t: ind_targets) {
               if (!b_map_.contains(t))
                  block_dfs(i_map_.at(t));
               auto targetBlock = b_map_.at(t);
               b_curr->succ_ind(targetBlock);
            }

            return;
         }

         /* (B) exit insn */
         else if (currInsn->halt()) {
            /* mark the end of current block */
            auto b_curr = new Block(currList);
            b_map_[b_curr->offset()] = b_curr;
            currList.clear();
            return;
         }

         /* (C) non-control insn */
         else {
            auto nextInsn = i_map_.at(currInsn->next_offset());
            /* (a) next insn is a transfer target: a new block */
            if (targetInsn.contains(nextInsn)) {
               /* mark the end of current block */
               auto currBlock = new Block(currList);
               b_map_[currBlock->offset()] = currBlock;
               currList.clear();
               /* process fall-through block */
               if (!b_map_.contains(nextInsn->offset()))
                  block_dfs(nextInsn);
               auto nextBlock = b_map_.at(nextInsn->offset());
               currBlock->succ(nextBlock, COMPARE::NONE);
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

   for (auto offset: func_entries_)
      if (!b_map_.contains(offset))
         block_dfs(i_map_[offset]);
}


void Program::set_binary(const string& fpath) {
   {
      /* extract program headers */
      auto phdr_fpath = string("/tmp/sbr2/")
                      + std::to_string(Framework::session_id)
                      + string("/phdr");
      auto cmd = string("readelf -Wl ") + fpath + string(" | grep LOAD")
               + string(" | awk '{print $2 \"\\n\" $3}' > ") + phdr_fpath;
      (void)!system(cmd.c_str());

      string s;
      fstream f_phdr(phdr_fpath, fstream::in);
      while (getline(f_phdr, s)) {
         auto foffset = stoull(s, nullptr, 16);
         getline(f_phdr, s);
         auto vaddr = stoull(s, nullptr, 16);
         phdr_.push_back(make_pair(vaddr, foffset));
      }
      f_phdr.close();
      sort(phdr_.begin(), phdr_.end());

      /* load raw data bytes */
      std::ifstream instream(fpath, std::ios::in | std::ios::binary);
      raw_bytes_ = vector<uint8_t>(std::istreambuf_iterator<char>(instream),
                                   std::istreambuf_iterator<char>());

      /* read_value */
      read_value = [&](IMM offset, uint8_t width) -> uint64_t {
         for (auto const& [vaddr, foffset]: phdr_)
            if (vaddr <= (uint64_t)offset) {
               uint64_t adjusted_offset = (uint64_t)offset - vaddr + foffset;
               uint64_t value = 0;
               for (uint8_t i = 0; i < width; ++i)
                  value += (raw_bytes_[adjusted_offset+i] << (i*8));
               return value;
            }
         return 0;
      };
   }

   {
      /* extract executable segments */
      auto segment_fpath = string("/tmp/sbr2/")
                         + std::to_string(Framework::session_id)
                         + string("/xsegment");
      auto cmd = string("readelf -WS ") + fpath
               + string(" | awk '$8 ~/X/'")
               + string(" | awk '{print $4 \"\\n\" $6}' >")
               + segment_fpath;
      (void)!system(cmd.c_str());

      string s;
      fstream f_segment(segment_fpath, fstream::in);
      while (getline(f_segment, s)) {
         auto addr = stoull(string("0x") + s, nullptr, 16);
         getline(f_segment, s);
         auto size = stoull(string("0x") + s, nullptr, 16);
         code_range_.push_back(Range(addr,addr+size));
      }
      f_segment.close();

      /* valid_code_offset */
      valid_code_offset = [&](IMM offset) -> bool {
         // for (auto const& r: code_range_)
         //    if (r.lo() <= offset && offset < r.hi())
         //       return true;
         // return false;
         return i_map_.contains(offset);
      };
   }
}
