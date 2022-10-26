/*
   Copyright (C) 2018 - 2021 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef INTERFACE_H
#define INTERFACE_H

#include "util.h"
// -----------------------------------------------------------------------------
class Program;
// -----------------------------------------------------------------------------
class Interface {
 private:
   vector<Program*> progList_;

 public:
   Interface(const string& autoFile);
   ~Interface();

   /* Read accessors */
   const vector<Program*>& prog_list() const {return progList_;};

   /* Methods related to organizing list of programs */
   Program* add(const string& asmFile, const vector<int64_t>& entry,
                const unordered_map<int64_t,vector<int64_t>>& jumpTable);
   void remove(Program* p);

   /* Methods related to LISC */
   static void ocaml_lift_asm(string& asmFile, string& rtlFile);

 private:
   /* Methods related to helper methods */
   static void format_asm(const string& asmFile, const string& outFile);

   /* Methods related to LISC */
   static void ocaml_load_auto(const string& autoFile);

};
// -----------------------------------------------------------------------------
#endif