/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef COMMON_H
#define COMMON_H

/* -------------------------------------------------------------------------- */
#define LOG(d, s) if (debugLevel >= d) std::cout << s << std::endl;
#define time_start(start) \
      std::chrono::high_resolution_clock::time_point start; \
      if (timeStat) start = std::chrono::high_resolution_clock::now();
#define time_stop(time, start)   \
      if (timeStat) { \
         auto dur = std::chrono::high_resolution_clock::now() - start; \
         auto tmp = std::chrono::duration_cast<std::chrono::nanoseconds>(dur); \
         time += tmp.count() * 1e-9; \
      }
/* ------------------------------ Headers ----------------------------------- */
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <utility>
#include <string>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <array>
#include <vector>
#include <list>
#include <queue>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <iterator>
#include <functional>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include "config.h"
#include "arch.h"
#include "external.h"
using std::array;
using std::vector;
using std::list;
using std::queue;
using std::stack;
using std::string;
using std::fstream;
using std::function;
using std::pair;
using std::make_pair;
using std::unordered_map;
using std::unordered_set;
/* -------------------------------------------------------------------------- */
extern int64_t const flagSym;
extern int64_t const ctrlSym;
extern int64_t const stackSym;
extern int64_t const staticSym;
enum class COMPARE: char {EQ, NE, GT, GE, LT, LE, OTHER, NONE};
enum class CHANNEL: char {MAIN, BLOCK, INSN};
enum class REGION:  char {REGISTER, STACK, STATIC, NONE, BAD};
/* -------------------------------------------------------------------------- */
class UnitId {
 public:
   static UnitId const ZERO;
   static UnitId const FLAGS;
   static UnitId const CF_FLAGS;

 private:
   char sgn_;
   REGION r_;
   int64_t i_;

 public:
   UnitId() {sgn_=1;  r_=REGION::BAD;  i_=0;};
   UnitId(ARCH::REG r) {sgn_=1;  r_=REGION::REGISTER;  i_=(int)r;};
   UnitId(REGION r, int64_t i) {sgn_=1;  r_=r;  i_=i;};
   UnitId(char sgn, ARCH::REG r) {sgn_=sgn;  r_=REGION::REGISTER;  i_=(int)r;};
   UnitId(char sgn, REGION r, int64_t i) {sgn_=sgn;  r_=r;  i_=i;};
   UnitId(const UnitId& obj) {sgn_=obj.sgn_;  r_=obj.r_;  i_=obj.i_;};

   static UnitId symbolId(int64_t c);
   static UnitId outBoundId(REGION r);

   char sgn() const {return sgn_;};
   REGION r() const {return r_;};
   int64_t i() const {return i_;};

   UnitId operator-() const;
   bool operator==(const UnitId& obj) const;
   bool operator!=(const UnitId& obj) const {return !is_bad() &&!(*this==obj);};

   bool is_const() const {return r_ == REGION::NONE;};
   bool is_reg() const {return r_ == REGION::REGISTER;};
   bool is_stack() const {return r_ == REGION::STACK;};
   bool is_static() const {return r_ == REGION::STATIC;};
   bool is_mem() const {return is_stack() || is_static();};
   bool is_flags() const {return r_==REGION::REGISTER && i_==(int)(ARCH::compareFlags);};
   bool is_ctrl() const {return r_==REGION::REGISTER && i_==(int)(ARCH::controlFlags);};
   bool is_zero() const {return r_ == REGION::NONE && i_ == 0;};
   bool is_bad() const {return r_ == REGION::BAD;};
   int64_t symbol() const;
   bool bounds_check() const;
   string to_string() const;
};
/* -------------------------------------------------------------------------- */
class Range {
 public:
   static Range const ZERO;
   static Range const ONE;
   static Range const EMPTY;
   static Range const UNIVERSAL;

 private:
   int64_t l;  /*    low     */
   int64_t h;  /*    high    */
   bool c;     /* complement */
               /* TRUE only for E set, NE-constraint set */

 public:
   Range() {l=_oo; h=oo; c=true;};              /* empty (E) */
   Range(bool cmpl) {l=_oo; h=oo; c=cmpl;};     /* empty (E), universal (U) */
   Range(int64_t low, int64_t high) {l=low; h=high; c=false; norm();};
   Range(int64_t low, int64_t high, bool cmpl) {l=low; h=high; c=cmpl; norm();};
   Range(COMPARE cmp, int64_t i);               /* constraint */
   Range(COMPARE cmp, const Range& obj);        /* constraint */
   Range(const Range& obj) {l=obj.l; h=obj.h; c=obj.c;};

   int64_t lo() const {return l;};
   int64_t hi() const {return h;};
   bool cmpl() const {return c;};

   int64_t size() const {return h-l+1;};
   bool empty() const {return l==_oo && h==oo && c;};
   bool universal() const {return l==_oo && h==oo && !c;};

   /* Methods related to arithmetic and comparison */
   Range& operator=(const Range& obj);
   Range operator-() const;
   Range operator!() const;
   Range operator+(const Range& obj) const;
   Range operator-(const Range& obj) const;
   Range operator*(const Range& obj) const;
   Range operator/(const Range& obj) const;
   Range operator%(const Range& obj) const;
   Range operator<<(const Range& obj) const;
   Range operator&(const Range& obj) const;
   Range operator|(const Range& obj) const;
   Range operator^(const Range& obj) const;
   bool operator==(const Range& obj) const;
   bool operator!=(const Range& obj) const;
   bool operator>=(const Range& obj) const;
   bool operator<=(const Range& obj) const;
   bool operator>(const Range& obj) const;
   bool operator<(const Range& obj) const;
   bool contains(const Range& obj) const;
   Range abs() const;

   /* Methods related to helper functions */
   void contract(int bytes);
   string to_string() const;

 private:
   void norm();
};
/* -------------------------------------------------------------------------- */
class CompareArgsId {
 public:
   static CompareArgsId const EMPTY;

 public:
   enum class OP: char {AND, PLUS, MINUS};   /* MINUS be transformed to PLUS */

 private:
   OP op_;
   array<UnitId,2> subargs_;
   bool empty_;
   bool constant_;

 public:
   CompareArgsId();
   CompareArgsId(const UnitId& a);
   CompareArgsId(OP op, const UnitId& a, const UnitId& b);
   CompareArgsId(const CompareArgsId& obj);
   ~CompareArgsId() {};

   OP op() const {return op_;};
   UnitId subargs(int index) const {return subargs_[index];};
   bool comparable() const;
   bool is_empty() const {return empty_;};
   bool is_const() const {return constant_;};
   bool operator==(const CompareArgsId& obj) const;
   bool operator!=(const CompareArgsId& obj) const {return !(*this == obj);};
   CompareArgsId* clone() const {return new CompareArgsId(*this);};
   string to_string() const;

   vector<pair<int64_t,Range>> get_cstr(COMPARE cmp, const CompareArgsId* rhs) const;
   void norm(CompareArgsId* rhs);

 private:
   void update(const UnitId& a);
   void update(OP op, const UnitId& a, const UnitId& b);
};
/* -------------------------------------------------------------------------- */
class Function;
class SCC;
class BasicBlock;
class Insn;
class RTL;
class Expr;

struct Loc {
   Function* func;
   SCC* scc;
   BasicBlock* block;
   Insn* insn;
   Loc() {func = nullptr; scc = nullptr; block = nullptr; insn = nullptr;};
   Loc(Function* f, SCC* s, BasicBlock* b, Insn* i) {
      func = f; scc = s; block = b; insn = i;
   }
};

struct ExprLoc {
   Expr* expr;
   struct Loc loc;
   ExprLoc() {expr = nullptr;};
   ExprLoc(Expr* x, struct Loc l) {expr = x; loc = l;};
   ExprLoc(const struct ExprLoc& X) {expr = X.expr; loc = X.loc;};
   RTL* rtl() const;
};
/* -------------------------------------------------------------------------- */
class Util {
 public:
   /* string conversion */
   static int64_t to_int(const string& s);
   static double to_double(const string& s);
   static int64_t max(int bytes);
   static int64_t min(int bytes);
   static int64_t plus(int64_t x, int64_t y);
   static int64_t minus(int64_t x, int64_t y);
   static int64_t mult(int64_t x, int64_t y);
   /* COMPARE */
   static COMPARE opposite(COMPARE cmp);
};
/* -------------------------------------------------------------------------- */
#endif