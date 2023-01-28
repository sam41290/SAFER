/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef PROGRAM_H
#define PROGRAM_H

#include "utility.h"

namespace SBA {
   /* Forward declaration */
   class Function;
   class Block;
   class Insn;
   class RTL;
   /* ------------------------------- Program ------------------------------- */
   class Program {
    private:
      unordered_map<IMM,Function*> f_map_;
      unordered_map<IMM,Block*> b_map_;
      unordered_map<IMM,Insn*> i_map_;

    private:
      unordered_set<IMM> func_entries_;
      unordered_map<IMM,vector<IMM>> jump_tables_;

    private:
      bool corrupted_;
      vector<uint8_t> raw_bytes_;
      vector<pair<uint64_t,uint64_t>> phdr_;
      vector<Range> code_range_;

    public:
      function<uint64_t(IMM,uint8_t)> read_value;
      function<bool(IMM)> valid_code_offset;

    public:
      Program(const vector<pair<IMM,RTL*>>& offset_rtl,
              const unordered_map<IMM,uint8_t>& insn_size,
              const unordered_map<IMM,vector<IMM>>& jump_tables,
              const vector<IMM>& func_entries);
      ~Program();

      /* Read accessors */
      bool corrupted() const {return corrupted_;};

      /* Methods related to CFG construction */
      Function* func(IMM entry);
      void update_graph(const vector<pair<IMM,RTL*>>& offset_rtl,
                        const unordered_map<IMM,uint8_t>& insn_size,
                        const unordered_map<IMM,vector<IMM>>& jump_tables,
                        const vector<IMM>& func_entries);

      /* binary-related methods */
      void set_binary(const string& fpath);
   };

}

#endif
