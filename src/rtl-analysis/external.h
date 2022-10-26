/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef EXTERNAL_H
#define EXTERNAL_H

#include <utility>
#include <string>
#include <vector>

using std::pair;
using std::make_pair;
using std::vector;
using std::string;

/* -------------------------------------------------------------------------- */
namespace analysis {
   /* ~~~~~~~~~~~~~~~~ base ~~~~~~~~~~~~~~~~~ */
   struct JTableBase {
      int64_t val;
      int64_t loc;
      JTableBase() {val = -1; loc = -1;};
      JTableBase(int64_t b, int64_t L) {val = b; loc = L;};
      JTableBase(const struct JTableBase& obj) {val = obj.val; loc = obj.loc;};
      string to_string() const {return std::to_string(val);};
   };
   /* ~~~~~~~~~~~ index * stride ~~~~~~~~~~~~ */
   struct JTableRange {
      int64_t l;
      int64_t h;
      uint8_t stride;
      int64_t loc;
      JTableRange() {l = -1; h = -1; stride = 0; loc = -1;};
      JTableRange(int64_t lo, int64_t hi, int64_t L) {
         l = (lo < -1000000000? -1000000000: lo);
         h = (hi > 1000000000? 1000000000: hi);
         stride = 0; loc = L;
      }
      JTableRange(int64_t lo, int64_t hi, uint8_t s, int64_t L) {
         l = (lo < -1000000000? -1000000000: lo);
         h = (hi > 1000000000? 1000000000: hi);
         stride = s; loc = L;
      };
      JTableRange(const struct JTableRange& obj) {
         l = obj.l; h = obj.h; stride = obj.stride; loc = obj.loc;
      };
      string to_string() const {
         return string("{[").append(std::to_string(l)).append(", ")
                           .append(std::to_string(h)).append("]; ")
                           .append(std::to_string(stride)).append("}");
      }
   };
   /* ~~~~~~~~ base + index * stride ~~~~~~~~ */
   struct JTableAddr {
      struct JTableBase base;
      char op;
      struct JTableRange range;
      int64_t loc;
      JTableAddr() {op = ' '; loc = -1;};
      JTableAddr(const struct JTableBase& b, char o,
                 const struct JTableRange& r, int64_t L) {
         base = b; op = o; range = r; loc = L;
      };
      JTableAddr(const struct JTableAddr& obj) {
         base = obj.base; op = obj.op; range = obj.range; loc = obj.loc;
      };
      string to_string() const {
         return string("(").append(base.to_string()).append(" ")
                           .append(string(1,op)).append(" ")
                           .append(range.to_string()).append(")");
      };
   };
   /* ~~~~~~ *(base + index * stride) ~~~~~~~ */
   struct JTableMem {
      struct JTableAddr addr;
      int64_t loc;
      JTableMem() {loc = -1;};
      JTableMem(const struct JTableAddr& a, uint8_t s, int64_t L) {
         addr = a; addr.range.stride = s; loc = L;
      };
      JTableMem(const struct JTableMem& obj) {
         addr = obj.addr; loc = obj.loc;
      };
      string to_string() const {
         return string("*").append(addr.to_string());
      };
   };
   /* ~~ offset + *(base + index * stride) ~~ */
   struct JTableOffsetMem {
      struct JTableBase offset;
      char op;
      struct JTableMem mem;
      int64_t loc;
      JTableOffsetMem() {op = ' '; loc = -1;};
      JTableOffsetMem(const struct JTableBase& b, char o,
                      const struct JTableMem& m, int64_t L) {
         offset = b; op = o; mem = m; loc = L;
      };
      JTableOffsetMem(const struct JTableOffsetMem& obj) {
         offset = obj.offset; op = obj.op; mem = obj.mem; loc = obj.loc;
      };
      string to_string() const {
         return offset.to_string().append(" ").append(string(1,op)).append(" ")
                .append(mem.to_string());
      };
   };
   /* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
   struct JTable {
    private:
      /* ----------------------------------*/
      /*               type 1              */
      /* base + *(offset + index * stride) */
      /* ----------------------------------*/
      /*               type 2              */
      /*        base + index * stride      */
      /* ----------------------------------*/
      /*               type 3              */
      /*      *(base + index * stride)     */
      /* ----------------------------------*/
      vector<pair<int64_t,struct JTableOffsetMem>> t1;
      vector<pair<int64_t,struct JTableAddr>> t2;
      vector<pair<int64_t,struct JTableMem>> t3;

    public:
      void add(int64_t jumpLoc, const struct JTableOffsetMem& v) {
         t1.push_back(make_pair(jumpLoc,v));
      };
      void add(int64_t jumpLoc, const struct JTableAddr& v) {
         t2.push_back(make_pair(jumpLoc,v));
      };
      void add(int64_t jumpLoc, const struct JTableMem& v) {
         t3.push_back(make_pair(jumpLoc,v));
      };
      const vector<pair<int64_t,JTableOffsetMem>>& type1() {return t1;};
      const vector<pair<int64_t,JTableAddr>>&      type2() {return t2;};
      const vector<pair<int64_t,JTableMem>>&       type3() {return t3;};
   };
   /* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
}
/* -------------------------------------------------------------------------- */
#endif