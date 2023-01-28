/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef UTILITY_H
#define UTILITY_H

/* ------------------------------ Headers ----------------------------------- */
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <utility>
#include <string>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <array>
#include <vector>
#include <list>
#include <queue>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <iterator>
#include <tuple>
#include <functional>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <climits>
#include "arch.h"
#include "config.h"
using std::array;
using std::vector;
using std::list;
using std::queue;
using std::stack;
using std::string;
using std::fstream;
using std::function;
using std::pair;
using std::tuple;
using std::make_pair;
using std::make_tuple;
using std::unordered_map;
using std::unordered_set;
/* ---------------------------------- Macro --------------------------------- */
extern fstream f_log;

#define LOG_START(fpath)   f_log.open(fpath, fstream::out);
#define LOG_STOP()         f_log.close();

#if DLEVEL >= 1
   #define LOG1(s) {f_log << s << std::endl;}
#else
   #define LOG1(s) {}
#endif

#if DLEVEL >= 2
   #define LOG2(s) {f_log << s << std::endl;}
#else
   #define LOG2(s) {}
#endif

#if DLEVEL >= 3
   #define LOG3(s) {f_log << s << std::endl;}
#else
   #define LOG3(s) {}
#endif

#if DLEVEL >= 4
   #define LOG4(s) {f_log << s << std::endl;}
#else
   #define LOG4(s) {}
#endif

#if PERF_STATS == 1
   #define TIME_START(start)                                                   \
      std::chrono::high_resolution_clock::time_point start;                    \
      start = std::chrono::high_resolution_clock::now();
   #define TIME_STOP(time, start) {                                            \
      auto dur = std::chrono::high_resolution_clock::now() - start;            \
      auto tmp = std::chrono::duration_cast<std::chrono::nanoseconds>(dur);    \
      time += tmp.count() * 1e-9;                                              \
   }
#else
   #define TIME_START(start)
   #define TIME_STOP(time,start)
#endif

#define BOUND(r,i)                                                             \
      ((int64_t)((int)r==0? (i==0?                 1: ARCH::NUM_REG-1):        \
                ((int)r==1? (i==0?  STACK_OFFSET_MIN: STACK_OFFSET_MAX):       \
                            (i==0? STATIC_OFFSET_MIN: STATIC_OFFSET_MAX))))

#define FOR_STATE(states, counter, cond, CODE) {                               \
   for (int counter = 0; counter < DOMAIN_NUM; ++counter)                      \
      if (states[counter]->enable_analysis() && cond) {                        \
         CODE                                                                  \
      }                                                                        \
}

#define IF_RTL_TYPE(T, obj, cast_obj, CODE_T, CODE_F) {                        \
   auto cast_obj = (T*)(*((RTL*)obj));                                         \
   if (cast_obj != nullptr) {                                                  \
      CODE_T                                                                   \
   }                                                                           \
   else {                                                                      \
      CODE_F                                                                   \
   }                                                                           \
}

#define FIND_PATTERN_INSTANT(Ret,Expr)   template vector<Ret>                  \
            Function::find_pattern<Ret,Expr>(const ExprLoc& X,                 \
            vector<Ret>(*recur)(const ExprLoc&),                               \
            const function<void(vector<Ret>&,Expr*,const Loc&)>& handler);
/* -------------------------------------------------------------------------- */
namespace SBA {
   /* Enum types */
   enum class CHANNEL: char {MAIN, BLOCK, INSN};
   enum class REGION:  char {REGISTER, STACK, STATIC, NONE, SPECIAL};
   enum class COMPARE: char {EQ, NE, GT, GE, LT, LE, OTHER, NONE};
   enum class TRACK:   char {BEFORE, AFTER};

   /* Basic details */
   constexpr const IMM get_bound(REGION r, uint8_t side) {
      return BOUND(r, side);
   }
   constexpr const IMM get_size(REGION r) {
      return get_bound(r, 1) - get_bound(r, 0) + 1;
   }
   constexpr const IMM get_base(REGION r) {
      return r==REGION::STACK? get_size(REGION::REGISTER) + 1:
             get_size(REGION::REGISTER) + 1 + get_size(REGION::STACK) + 2;
   }
   constexpr const bool is_bounded(REGION r, IMM offset) {
      return offset >= get_bound(r,0) && offset <= get_bound(r,1);
   }

   /* ------------------------------- UnitId -------------------------------- */
   class UnitId {
    public:
      static UnitId const ZERO;
      static UnitId const FLAG;
      static UnitId const CFLAG;
      static UnitId const BAD;
      static UnitId TEMP;
      static array<UnitId,ARCH::NUM_REG+1> const REG;
      static array<UnitId,get_size(REGION::STACK)+2> const STACK;

    private:
      char sign_;
      REGION r_;
      IMM i_;

    public:
      UnitId(char sign, REGION r, IMM i) : sign_(sign), r_(r), i_(i) {};
      UnitId() : UnitId(0, REGION::SPECIAL, 0) {};
      UnitId(ARCH::REG r) : UnitId(1, REGION::REGISTER, (IMM)r) {};
      UnitId(REGION r, IMM i) : UnitId(1, r, i) {};
      UnitId(const UnitId& obj) : UnitId(obj.sign_, obj.r_, obj.i_) {};

      /* read accessors */
      char sign() const {
         return sign_;
      };
      REGION r() const {
         return r_;
      };
      IMM i() const {
         return i_;
      };

      /* operators */
      UnitId operator-() const;
      bool operator==(const UnitId& obj) const;
      bool operator!=(const UnitId& obj) const;

      /* helper methods */
      bool constant() const {
         return r_ == REGION::NONE;
      };
      bool flag() const {
         return r_ == REGION::REGISTER && i_ == (IMM)(ARCH::flags);
      };
      bool zero() const {
         return r_ == REGION::NONE && i_ == 0;
      };
      bool bad() const {
         return r_ == REGION::SPECIAL && i_ == 0;
      };
      uint8_t boundness() const {
         /* 0: inbound         */
         /* 1: outbound (high) */
         /* 2: outbound (low)  */
         return (r_ == REGION::STACK || r_ == REGION::STATIC)?
                (i_ == oo? 1: (i_ == _oo? -1: 0)): 0;
      };
      string to_string() const {
         string s = (sign_ == -1)? string("-"): string("");
         switch (r_) {
            case REGION::REGISTER:
               s.append(ARCH::to_string((ARCH::REG)i_));
               break;
            case REGION::STACK:
               s.append((i_ == _oo)? string("stack[-oo]"):
                       ((i_ == oo)? string("stack[+oo]"):
                        string("stack[").append(std::to_string(i_)).append("]")));
               break;
            case REGION::STATIC:
               s.append((i_ == _oo)? string("static[-oo]"):
                       ((i_ == oo)? string("static[+oo]"):
                        string("static[").append(std::to_string(i_)).append("]")));
               break;
            case REGION::NONE:
               s.append(std::to_string(i_));
               break;
            case REGION::SPECIAL:
               if (i_ == 0)
                  s.append("bad");
               else
                  s.append("cflag");
               break;
            default:
               s.append(string("bad"));
               break;
         }
         return s;
      };
   };

   
   extern const IMM flagSym;
   extern const IMM cflagSym; /* cflag: in-place conditional jump, not through flags */
   extern const IMM stackSym;
   extern const IMM staticSym;
   extern const IMM get_sym(REGION r, IMM i);
   extern const IMM get_sym(ARCH::REG r);
   extern const IMM get_sym(const UnitId& id);
   extern const UnitId& get_id(REGION r, IMM i);
   extern const UnitId& get_id(ARCH::REG r); 
   extern const UnitId& get_id(IMM sym);

   /* -------------------------------- Range -------------------------------- */
   class Range {
    public:
      static Range const ZERO;
      static Range const ONE;
      static Range const EMPTY;
      static Range const UNIVERSAL;

    private:
      IMM l;   /*    low     */
      IMM h;   /*    high    */
      bool c;  /* complement */
               /* TRUE only for E set, NE-constraint set */

    public:
      Range() {l=_oo; h=oo; c=true;};           /* empty (E) */
      Range(bool cmpl) {l=_oo; h=oo; c=cmpl;};  /* empty (E), universal (U) */
      Range(IMM low, IMM high) {l=low; h=high; c=false; norm();};
      Range(IMM low, IMM high, bool cmpl) {l=low; h=high; c=cmpl; norm();};
      Range(COMPARE cmp, IMM i);                /* constraint */
      Range(COMPARE cmp, const Range& obj);     /* constraint */
      Range(const Range& obj) {l=obj.l; h=obj.h; c=obj.c;};

      IMM lo() const {return l;};
      IMM hi() const {return h;};
      bool cmpl() const {return c;};

      IMM size() const {return h-l+1;};
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
      void contract(uint8_t bytes);
      string to_string() const;

    private:
      void norm();
   };

   /* ------------------------------- ExprId -------------------------------- */
   class ExprId {
    public:
      static ExprId const EMPTY;

    public:
      enum class OP: char {AND, PLUS, MINUS};   /* MINUS transformed to PLUS */

    private:
      OP op_;
      array<UnitId,2> subargs_;
      bool empty_;
      bool constant_;

    public:
      ExprId();
      ExprId(const UnitId& a);
      ExprId(OP op, const UnitId& a, const UnitId& b);
      ExprId(const ExprId& obj);
      ~ExprId() {};

      OP op() const {return op_;};
      UnitId subargs(int index) const {return subargs_[index];};
      bool comparable() const;
      bool empty() const {return empty_;};
      bool constant() const {return constant_;};
      bool operator==(const ExprId& obj) const;
      bool operator!=(const ExprId& obj) const {return !(*this == obj);};
      ExprId* clone() const {return new ExprId(*this);};
      string to_string() const;

      vector<pair<IMM,Range>> get_cstr(COMPARE cmp, const ExprId* rhs) const;
      void norm(ExprId* rhs);

    private:
      void update(const UnitId& a);
      void update(OP op, const UnitId& a, const UnitId& b);
   };

   /* -------------------------------- Loc ---------------------------------- */
   class Function;
   class SCC;
   class Block;
   class Insn;
   class RTL;
   class Expr;

   struct Loc {
      Function* func;
      SCC* scc;
      Block* block;
      Insn* insn;
   };

   struct ExprLoc {
      Expr* expr;
      Loc loc;
      RTL* rtl() const;
   };

   /* ------------------------------- Value --------------------------------- */
   class BaseDomain;

   struct Value {
    private:
      array<bool,DOMAIN_NUM> owner;
      array<BaseDomain*,DOMAIN_NUM> val;

    public:
      Value();
      ~Value();
      Value(Value& obj) {
         owner.fill(true);
         obj.owner.fill(false);
         val = obj.val;
      };
      void operator=(Value& obj) {
         owner.fill(true);
         obj.owner.fill(false);
         val = obj.val;
      };
      BaseDomain*& operator[](int index) {
         return val[index];
      };
      void set_val(int index, BaseDomain* v);
      void set_own(int index, bool b) {
         owner[index] = false;
      };
   };

   /* -------------------------------- Util --------------------------------- */
   class Util {
    public:
      static IMM to_int(const string& s);
      static double to_double(const string& s);
      static constexpr IMM max(uint8_t bytes);
      static constexpr IMM min(uint8_t bytes);
      static IMM plus(IMM x, IMM y);
      static IMM minus(IMM x, IMM y);
      static IMM mult(IMM x, IMM y);
      static COMPARE opposite(COMPARE cmp);
      static IMM int_cast(uint64_t val, uint8_t bytes, bool sign = true);
   };

}

#endif
