/*
   Copyright (C) 2018 - 2021 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef UTIL_H
#define UTIL_H
/* ------------------------------ Configuration ----------------------------- */
/* framework settings */
#define ARCH X86_64
#define debugLevel 1
#define domainCount 1

/* enable flags to safely abort when processing erroneous input */
#define flag_unlifted_insn                false
#define flag_unreachable_insn             false
#define flag_unreachable_block            false

/* static analysis configurations */
extern bool enable_weak_update;
extern bool enable_range_union;

/* abstract state configurations */
#define outBoundId(r)   ((int)r==0? UnitId(REGION::STACK,-1000000000): \
                                    UnitId(REGION::STATIC,-1000000000))
#define boundRange(r,i) ((int64_t)((int)r==0? (i==0? -1000: 20 ): \
                                  ((int)r==1? (i==0?     0: 100): \
                                              (i==0?     0: ARCH::NUM_REG-2))))
#define initRange(r,i)  ((int64_t)((int)r==0? (i==0?     0: 20 ): \
                                  ((int)r==1? (i==0?     0: 100): \
                                              (i==0?     0: ARCH::NUM_REG-2))))
#define maxUnionRange 50

/* domain settings */
/*-------------------------------------------------------------------*
| unique id for initial value and memory region base value           |
+--------------------------------------------------------------------+
|  0  initReg[]  baseStack    initStack[]  baseStatic  initStatic[]  |
|     baseHeap1  initHeap1[]  baseHeap2    initHeap2[]               |
+--------------------------------------------------------------------+
|  note:                                                             |
|     init_reg[SP] = baseStack                                       |
*--------------------------------------------------------------------*/
#define boundSize(r) ((int64_t)(boundRange(r,1) - boundRange(r,0) + 1))
#define initSize(r)  ((int64_t)(initRange(r,1) - initRange(r,0)  + 1))
#define checkRange(r,i) (i>=boundRange(r,0) && i<=boundRange(r,1))
#define baseConst(r) \
         ((int64_t)((int)r==0? ARCH::NUM_REG + 1: \
                     ARCH::NUM_REG + initSize(REGION::STACK) + 2))
#define initConst(r,i) \
         ((int64_t)((int)r<2? (baseConst(r) + 1 + i - initRange(r,0)): \
                     (i==(int)ARCH::stackPtr? baseConst(REGION::STACK): i+1)))

#define symbolId(c) \
         (c > baseConst(REGION::STATIC)?    \
              UnitId(REGION::STATIC,        \
                  c-baseConst(REGION::STATIC)-1+initRange(REGION::STATIC,0)):\
         (c > baseConst(REGION::STACK)?     \
              UnitId(REGION::STACK,         \
                  c-baseConst(REGION::STACK)-1+initRange(REGION::STACK,0)):  \
         (c == baseConst(REGION::STACK)?    \
               UnitId(ARCH::stackPtr):      \
         (c > 0? UnitId(REGION::REG, c-1):  \
                 UnitId(REGION::REG, -1))                  \
         )))

#define symbolExtract(v) symbolId(((BaseLH*)v)->symbol())

/* helper methods */
#define LOG(d, s) if (debugLevel >= d) std::cerr << s << std::endl

/* ------------------------------ Headers ----------------------------------- */
#include <cmath>
#include <cstdint>
#include <utility>
#include <string>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <array>
#include <vector>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <iterator>
#include <functional>
#include "arch.h"
using std::array;
using std::vector;
using std::queue;
using std::string;
using std::fstream;
using std::function;
using std::pair;
using std::make_pair;
using std::unordered_map;
using std::unordered_set;

/* -------------------------------------------------------------------------- */
enum class CHANNEL: char {MAIN, TRACK, PARALLEL};
enum class REGION:  char {STACK, STATIC, REG};

struct UnitId {
 private:
   REGION r_;
   int64_t idx_;
 public:
   UnitId(REGION r, int64_t idx) {r_ = r; idx_ = idx;};
   UnitId(ARCH::REG r) {r_ = REGION::REG; idx_ = (int)r;};
   bool operator==(const UnitId& id) const {return r_==id.r() && idx_==id.idx();};
   bool bounds_check() const {return checkRange(r_, idx_);};
   REGION r() const {return r_;};
   int64_t idx() const {return idx_;};
   string to_string();
};

/* -------------------------------------------------------------------------- */
struct HashFunc{
   std::size_t operator() (const UnitId& id) const {
      return std::hash<REGION>{}(id.r()) ^ std::hash<int64_t>{}(id.idx());
   }
};

template<class X>         using u_set = std::unordered_set<X, HashFunc>;
template<class X,class Y> using u_map = std::unordered_map<X, Y, HashFunc>;

/* -------------------------------------------------------------------------- */
class Util {
 public:
   /* string conversion */
   static int64_t to_int(const string& s);
   static double to_double(const string& s);
};

#endif