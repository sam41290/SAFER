/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef JUMP_TABLE_H
#define JUMP_TABLE_H

#include "utility.h"

namespace SBA {
   /* Forward declaration */
   class Function;

   struct JTBase {
      IMM val;
      ExprLoc holder;
      IMM loc() const;
      JTBase(IMM v, const ExprLoc& hd): val(v), holder(hd) {};
      JTBase(const JTBase& obj): JTBase(obj.val, obj.holder) {};
      string to_string() const {return std::to_string(val);};
   };

   struct JTRange {
      /* -oo .. +oo -> [ 0,  0] */
      /* -oo .. -3  -> [-3, -3] */
      /* -oo ..  3  -> [ 0,  3] */
      /*  -4 .. -3  -> [-4, -3] */
      /*  -3 ..  4  -> [-3,  4] */
      /*   3 ..  4  -> [ 3,  4] */
      /*  -3 .. +oo -> [-3,  0] */
      /*   3 .. +oo -> [ 3,  3] */
      IMM lo;
      IMM hi;
      uint8_t stride;
      ExprLoc holder;
      IMM loc() const;
      JTRange(IMM l, IMM h, uint8_t s, const ExprLoc& hd):
              lo((l <= _oo)? ((h >= 0)? 0: h) : l),
              hi((h >=  oo)? ((l <= 0)? 0: l) : h),
              stride(s), holder(hd) {};
      JTRange(const JTRange& obj):
              JTRange(obj.lo, obj.hi, obj.stride, obj.holder) {};
      string to_string() const {
         return string("{[").append(std::to_string(lo)).append(", ")
                            .append(std::to_string(hi)).append("]; ")
                            .append(std::to_string(stride)).append("}");
      };
   };

   struct JTable {
      uint8_t type;
      ExprLoc holder;
      IMM loc() const;
      JTable(uint8_t t, const ExprLoc& hd): type(t), holder(hd) {};
      virtual ~JTable() {};
      virtual string to_string() const = 0;
      virtual IMM start() const = 0;
      virtual IMM end() const = 0;
      virtual uint8_t stride() const = 0;
      virtual uint8_t width() const = 0;
      virtual bool sign() const = 0;
      virtual vector<uint64_t> targets(
              const function<uint64_t(IMM,uint8_t)>& read_value,
              const function<bool(IMM)>& valid_code_offset) const = 0;
   };

   struct JTAddr: public JTable {
      JTBase base;
      char op;
      JTRange range;
      JTAddr(const JTBase& b, char o, const JTRange& r, const ExprLoc& hd):
            JTable(3,hd), base(b), op(o), range(r) {};
      JTAddr(const JTAddr& obj):
            JTAddr(obj.base, obj.op, obj.range, obj.holder) {};
      string to_string() const override {
         return string("(").append(base.to_string()).append(" ")
                           .append(string(1,op)).append(" ")
                           .append(range.to_string()).append(")");
      };
      IMM start() const {
         return (op == '+')? (base.val + range.lo): (base.val - range.hi);
      };
      IMM end() const {
         return (op == '+')? (base.val + range.hi): (base.val - range.lo);
      };
      uint8_t stride() const {return range.stride;};
      uint8_t width() const {return -1;};
      bool sign() const {return false;};
      vector<uint64_t> targets(
                   const function<uint64_t(IMM,uint8_t)>& read_value,
                   const function<bool(IMM)>& valid_code_offset) const override;
   };

   struct JTMem: public JTable {
      JTAddr addr;
      uint8_t read_size;
      bool sgn;
      JTMem(const JTAddr& a, uint8_t sz, bool s, const ExprLoc& hd):
            JTable(2,hd), addr(a), read_size(sz), sgn(s) {};
      JTMem(const JTMem& obj):
            JTMem(obj.addr, obj.read_size, obj.sgn, obj.holder) {};
      string to_string() const {return string("*").append(addr.to_string());};
      IMM start() const {return addr.start();};
      IMM end() const {return addr.end();};
      uint8_t stride() const {return addr.stride();};
      uint8_t width() const {return read_size;};
      bool sign() const {return sgn;};
      vector<uint64_t> targets(
                   const function<uint64_t(IMM,uint8_t)>& read_value,
                   const function<bool(IMM)>& valid_code_offset) const override;
   };

   struct JTBaseMem: public JTable {
      JTBase base;
      char op;
      JTMem mem;
      JTBaseMem(const JTBase& b, char o, const JTMem& m, const ExprLoc& hd):
               JTable(1,hd), base(b), op(o), mem(m) {};
      JTBaseMem(const JTBaseMem& obj):
               JTBaseMem(obj.base, obj.op, obj.mem, obj.holder) {};
      string to_string() const {
         return base.to_string().append(" ").append(string(1,op)).append(" ")
                .append(mem.to_string());
      };
      IMM start() const {return mem.start();};
      IMM end() const {return mem.end();};
      uint8_t stride() const {return mem.stride();};
      uint8_t width() const {return mem.width();};
      bool sign() const {return mem.sign();};
      vector<uint64_t> targets(
                   const function<uint64_t(IMM,uint8_t)>& read_value,
                   const function<bool(IMM)>& valid_code_offset) const override;
   };

   struct JTAnalyser {
      vector<tuple<JTable*,IMM,bool>> items;
      ~JTAnalyser() {for (auto [jtable,jloc,safe]: items) delete jtable;};
      void analyse(const ExprLoc& exprloc);
      void verify(Function* f);
   };

}

#endif
