/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef FRAMEWORK_H
#define FRAMEWORK_H

#include "utility.h"

namespace SBA {
   /* Forward declaration */
   class Program;
   class AbsState;
   /* ------------------------------- Framework ----------------------------- */
   class Framework {
    public:
      /* statistics */
      static int session_id;
      static double t_syntax;
      static double t_lift;
      static double t_parse;
      static double t_cfg;
      static double t_analyse;
      static double t_track;
      static double t_jtable;
      static int64_t num_prog;
      static int64_t num_func;
      static int64_t num_insn;
      static void print_stats();

      /* configuration */
      static void config(const string& autoFile);

      /* framework features */
      static Program* create_program(
                      const vector<pair<IMM,RTL*>>& offset_rtl,
                      const unordered_map<IMM,uint8_t>& insn_size,
                      const unordered_map<IMM,vector<IMM>>& jump_tables,
                      const vector<IMM>& func_entries);
      static void update_program(
                      Program* p,
                      const vector<pair<IMM,RTL*>>& offset_rtl,
                      const unordered_map<IMM,uint8_t>& insn_size,
                      const unordered_map<IMM,vector<IMM>>& jump_tables,
                      const vector<IMM>& func_entries);

      /* helper methods */
      static vector<pair<IMM,RTL*>> offset_rtl(const string& att_fpath,
                                               const string& rtl_fpath);
      static vector<pair<IMM,RTL*>> offset_rtl(const string& att_fpath,
                           const unordered_map<IMM,uint8_t>& insn_size);
   };

}

#endif
