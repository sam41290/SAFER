/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef INSN_H
#define INSN_H

#include "common.h"
// -----------------------------------------------------------------------------
class State;
class RTL;
class Statement;
class Expr;
// -----------------------------------------------------------------------------
class Insn {
 private:
   enum class EDGE_TYPE: char {DIRECT, INDIRECT, EXIT, NONE};
   enum class EDGE_OP: char {JUMP, CALL, RET, HALT, NONE};

 private:
   int64_t offset_;
   int size_;
   Statement* stmt_;
   EDGE_TYPE type_;
   EDGE_OP op_;
   Expr* indirectTarget_;
   pair<int64_t,int64_t> directTargets_;
   pair<COMPARE,COMPARE> cond_;

 public:
   Insn(int64_t offset, RTL* rtl, int size);
   ~Insn();

   /* Read accessors */
   bool empty() const {return stmt_ == nullptr;};
   int64_t offset() const {return offset_;};
   int64_t next_offset() const {return offset_ + size_;};
   Statement* stmt() const {return stmt_;};
   Expr* indirect_target() const {return indirectTarget_;};
   pair<int64_t,int64_t> direct_target() const {return directTargets_;};
   pair<COMPARE,COMPARE> cond() const {return cond_;};
   string to_string() const;

   /* Methods related to transfer check */
   bool direct() const {return !empty() && type_ == EDGE_TYPE::DIRECT;};
   bool indirect() const {return !empty() && type_ == EDGE_TYPE::INDIRECT;};
   bool exit() const {return !empty() && type_ == EDGE_TYPE::EXIT;};
   bool transfer() const {return direct() || indirect();};
   bool jump() const {return !empty() && op_ == EDGE_OP::JUMP;};
   bool call() const {return !empty() && op_ == EDGE_OP::CALL;};
   bool ret() const {return !empty() && op_ == EDGE_OP::RET;};
   bool cond_jump() const {return jump() && (cond_.first != COMPARE::NONE ||
                                             cond_.second != COMPARE::NONE);};

   /* Methods related to static analysis */
   void execute(const array<State*,domainCnt>& s) const;
   void preset(const array<State*,domainCnt>& s) const;

 private:
   /* Methods related to CFG construction */
   void process_transfer();
};
// -----------------------------------------------------------------------------
#endif