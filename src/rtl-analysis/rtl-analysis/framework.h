/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef FRAMEWORK_H
#define FRAMEWORK_H

#include "common.h"
// -----------------------------------------------------------------------------
class Program;
// -----------------------------------------------------------------------------
class Framework {
 public:
   /* Statistics */
   static int sessionId;
   static double time_format;
   static double time_lift;
   static double time_parse;
   static double time_cfg;
   static double time_analysis;
   static double time_track;
   static double time_jump_table;
   static int64_t total_file;
   static int64_t total_insn;

   /* Methods related to setting up framework */
   static void setup(const string& autoFile);
   static void reset_stats();

   /* Methods related to creating program */
   static Program* create_prog(const string& attFile,
                   const unordered_map<int64_t,int64_t>& insnSize,
                   const unordered_map<int64_t,vector<int64_t>>& jumpTable,
                   const vector<int64_t>& entry);
};
// -----------------------------------------------------------------------------
#endif