/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "jtable.h"
#include "framework.h"
#include "function.h"
#include "scc.h"
#include "block.h"
#include "insn.h"
#include "domain.h"
#include "rtl.h"
#include "expr.h"
#include "arithmetic.h"

using namespace SBA;

IMM JTBase::loc() const {
   return holder.loc.insn->offset();
}
IMM JTRange::loc() const {
   return holder.loc.insn->offset();
}
IMM JTable::loc() const {
   return holder.loc.insn->offset();
}

vector<uint64_t> JTAddr::targets(const function<uint64_t(IMM,uint8_t)>&
read_value, const function<bool(IMM)>& valid_code_offset) const {
   auto first = start();
   auto last = end();
   auto s = stride();
   vector<uint64_t> res;
   for (auto i = first; i <= last; i += s)
      res.push_back(i);
   return res;
}
vector<uint64_t> JTMem::targets(const function<uint64_t(IMM,uint8_t)>&
read_value, const function<bool(IMM)>& valid_code_offset) const {
   auto first = start();
   auto last = end();
   auto s = stride();
   auto w = width();
   auto sgn = sign();
   vector<uint64_t> res;
   if (first < last) {
      for (auto i = first; i <= last; i += s)
         res.push_back(Util::int_cast(read_value(i,w),w,sgn));
   }
   else {
      for (auto i = first;; i += s) {
         auto t = Util::int_cast(read_value(i,w),w,sgn);
         if (valid_code_offset(t))
            res.push_back(t);
         else
            break;
      }
   }
   return res;
}
vector<uint64_t> JTBaseMem::targets(const function<uint64_t(IMM,uint8_t)>&
read_value, const function<bool(IMM)>& valid_code_offset) const {
   auto first = start();
   auto last = end();
   auto s = stride();
   auto w = width();
   auto sgn = sign();
   vector<uint64_t> res;
   if (first < last) {
      for (auto i = first; i <= last; i += s)
         res.push_back(base.val + Util::int_cast(read_value(i,w),w,sgn));
   }
   else {
      for (auto i = first;; i += s) {
         auto t = base.val + Util::int_cast(read_value(i,w),w,sgn);
         if (valid_code_offset(t))
            res.push_back(t);
         else
            break;
      }
   }
   return res;
}
/* -------------------------------------------------------------------------- */
static ExprLoc gen_holder(const ExprLoc& X, RTL* x, const Loc& loc) {
   Reg* reg = nullptr;
   if (X.rtl() != x) {
      auto rtl = loc.insn->stmt()->find_container(x, [](const RTL* v) {
         return (Assign*)(*v) != nullptr;
      });
      IF_RTL_TYPE(Assign, rtl, assign, {
         if (assign->src()->simplify() == x)
            reg = (Reg*)(*(assign->dst()->simplify()));
      }, {});
   }
   return ExprLoc{reg, loc};
}
/* -------------------------------------------------------------------------- */
static unordered_map<int,vector<JTBase>> baseCache;
static vector<JTBase> find_base(const ExprLoc& X) {
   /* special case:                                          */
   /*   jump table is used within a loop using %rsi as base  */
   /*   a call in the loop body which takes %rsi as args     */
   /*   as a result, %rsi is backed up and restored          */
   /*   pattern matching cannot resolve loop                 */
   /* solution:                                              */
   /*   cache result, get empty if confront a repeated node  */
   IF_RTL_TYPE(Reg, X.rtl(), r, {
      auto serial = ARCH::serial(r->reg(), X.loc.insn->offset());
      if (baseCache.contains(serial))
         return baseCache[serial];
      else
         baseCache[serial] = vector<JTBase>{};
   }, {});

   /* x = const */
   auto vec1 = X.loc.func->find_pattern<JTBase,Const>
   (X, &find_base, [&](vector<JTBase>& res, Const* x, const Loc& loc) {
      res.push_back(JTBase(x->to_int(), gen_holder(X,x,loc)));
   });

   /* x = %rip + const */
   auto vec2 = X.loc.func->find_pattern<JTBase,Binary>
   (X, &find_base, [&](vector<JTBase>& res, Binary* x, const Loc& loc) {
      char op = (x->op() == Binary::OP::PLUS  ? 1 :
                (x->op() == Binary::OP::MINUS ? -1 : 0));
      if (op != 0) {
         array<Expr*,2> args;
         for (int i = 0; i < 2; ++i)
            args[i] = x->operand(i)->simplify();
         for (int i = 0; i < 2; ++i)
            IF_RTL_TYPE(Reg, args[i], reg, {
               if (reg->reg()==ARCH::insn_pointer)
                  IF_RTL_TYPE(Const, args[1-i], cst, {
                     auto pc = loc.insn->next_offset();
                     auto c  = cst->to_int() * op;
                     res.push_back(JTBase(pc + c, gen_holder(X,x,loc)));
                     break;
                  }, {});
            }, {});
      }
   });

   vec1.insert(vec1.end(), vec2.begin(), vec2.end());
   IF_RTL_TYPE(Reg, X.rtl(), r, {
      auto serial = ARCH::serial(r->reg(),X.loc.insn->offset());
      baseCache[serial] = vec1;
   }, {});
   return vec1;
}


static vector<JTBase> jtable_base(const ExprLoc& X) {
   auto res = find_base(X);
   baseCache.clear();
   unordered_set<IMM> taken_val;
   vector<JTBase> res2;
   for (auto const& v: res)
      if (!taken_val.contains(v.val)) {
         res2.push_back(v);
         taken_val.insert(v.val);
      }
   return res2;
}
/* -------------------------------------------------------------------------- */
static vector<JTRange> jtable_range(const ExprLoc& X) {
   return X.loc.func->find_pattern<JTRange,Binary>
   (X, &jtable_range, [&](vector<JTRange>& res, Binary* x, const Loc& loc) {
      auto op = x->op();
      if (op == Binary::OP::MULT || op == Binary::OP::ASHIFT) {
         array<Expr*,2> args;
         for (int i = 0; i < 2; ++i)
            args[i] = x->operand(i)->simplify();
         for (int i = 0; i < (op == Binary::OP::MULT? 2: 1); ++i) {
            auto reg = (Reg*)(*args[i]);
            auto cst = (Const*)(*args[1-i]);
            if (reg != nullptr && cst != nullptr) {
               auto const& id = get_id(reg->reg());
               auto vec = loc.func->track(TRACK::BEFORE, 1, id, loc,
               [&](Insn* i) {
                  return i==loc.insn;
               });
               auto idx = (BaseLH*)(vec.front());
               auto c = cst->to_int();
               auto s = (op == Binary::OP::MULT)? c: (1 << c);
               if (idx->top() || BaseLH::notlocal(idx) || idx->base() != 0) {
                  auto holder = gen_holder(X, x, loc);
                  res.push_back(JTRange(_oo, oo, s, holder));
               }
               else {
                  auto r = idx->range();
                  auto holder = gen_holder(X, x, loc);
                  res.push_back(JTRange(s*r.lo(), s*r.hi(), s, holder));
               }
               BaseDomain::safe_delete(idx);
               break;
            }
         }
      }
   });
}
/* -------------------------------------------------------------------------- */
static vector<JTAddr> jtable_addr(const ExprLoc& X) {
   return X.loc.func->find_pattern<JTAddr,Binary>
   (X, &jtable_addr, [&](vector<JTAddr>& res, Binary* x, const Loc& loc) {
      char op = (x->op() == Binary::OP::PLUS ? '+':
                (x->op() == Binary::OP::MINUS? '-': 0));
      if (op != 0) {
         array<ExprLoc,2> args;
         for (int i = 0; i < 2; ++i)
            args[i] = ExprLoc{x->operand(i)->simplify(), loc};
         for (int i = 0; i < (op == '+'? 2: 1); ++i) {
            auto base = jtable_base(args[i]);
            if (!base.empty()) {
               auto range = jtable_range(args[1-i]);
               for (auto const& b: base)
               for (auto const& r: range) {
                  auto holder = gen_holder(X, x, loc);
                  res.push_back(JTAddr(b, op, r, holder));
               }
               break;
            }
         }
      }
   });
}
/* -------------------------------------------------------------------------- */
static vector<JTMem> jtable_mem(const ExprLoc& X) {
   return X.loc.func->find_pattern<JTMem,Mem>
   (X, &jtable_mem, [&](vector<JTMem>& res, Mem* x, const Loc& loc) {
      auto read_size = x->mode_size();
      auto addr = jtable_addr(ExprLoc{x->addr(),loc});
      for (auto& a: addr) {
         auto holder = gen_holder(X, x, loc);
         /* TODO: update signedness based on zero_extend/sign_extend */
         res.push_back(JTMem(a, read_size, false, holder));
      }
   });
}
/* -------------------------------------------------------------------------- */
static vector<JTBaseMem> jtable_base_mem(const ExprLoc& X) {
   return X.loc.func->find_pattern<JTBaseMem,Binary>
   (X, &jtable_base_mem, [&](vector<JTBaseMem>& res, Binary* x, const Loc& loc){
      char op = (x->op() == Binary::OP::PLUS  ? '+' :
                (x->op() == Binary::OP::MINUS ? '-' : 0));
      if (op != 0) {
         array<ExprLoc,2> args;
         for (int i = 0; i < 2; ++i)
            args[i] = ExprLoc{x->operand(i)->simplify(), loc};
         for (int i = 0; i < (op == '+'? 2: 1); ++i) {
            auto base = jtable_base(args[i]);
            if (!base.empty()) {
               auto mem = jtable_mem(args[1-i]);
               for (auto& b: base)
               for (auto& m: mem) {
                  auto holder = gen_holder(X, x, loc);
                  res.push_back(JTBaseMem(b, op, m, holder));
               }
               break;
            }
         }
      }
   });
}
/* -------------------------------------------------------------------------- */
void JTAnalyser::analyse(const ExprLoc& exprloc) {
   TIME_START(start_t);
   auto size = items.size();
   auto jloc = exprloc.loc.insn->offset();
   /* type 1 */
   for (const auto& v: jtable_base_mem(exprloc)) {
      uint8_t error = 0;
      items.push_back(make_tuple(new JTBaseMem(v), jloc, error));
   }
   if (items.size() == size) {
      /* type 2 */
      for (const auto& v: jtable_mem(exprloc)) {
         uint8_t error = 0;
         items.push_back(make_tuple(new JTMem(v), jloc, error));
      }
      if (items.size() == size) {
         /* type 3 */
         for (const auto& v: jtable_addr(exprloc)) {
            uint8_t error = 0;
            items.push_back(make_tuple(new JTAddr(v), jloc, error));
         }
      }
   }
   TIME_STOP(Framework::t_jtable, start_t);
}


void JTAnalyser::verify(Function* f) {
   unordered_map<Insn*,unordered_set<IMM>> type1, type4;
   for (auto [expr, jloc, error]: items) {
      switch (expr->type) {
         case 1: {
            auto cast = (JTBaseMem*)expr;
            type4[cast->base.holder.loc.insn].insert(jloc);
            type4[cast->mem.addr.base.holder.loc.insn].insert(jloc);
            type1[cast->mem.addr.base.holder.loc.insn].insert(cast->mem.holder.loc.insn->offset());
            break;
         }
         case 2: {
            auto cast = (JTMem*)expr;
            type4[cast->addr.base.holder.loc.insn].insert(jloc);
            type1[cast->addr.base.holder.loc.insn].insert(cast->holder.loc.insn->offset());
            break;
         }
         case 3: {
            auto cast = (JTAddr*)expr;
            type4[cast->base.holder.loc.insn].insert(jloc);
            break;
         }
         default:
            break;
      }
   }

   auto safe_def = [&](Insn* def) -> bool {
      if (f->escaped_taint[0].contains(def)) {
         for (auto use: f->escaped_taint[0][def]) {
            LOG4("unsafe jump table [type 0]: " << def->offset()
                                      << " -> " << use->offset());
         }
         return false;
      }

      auto it1 = f->escaped_taint[1].find(def);
      if (it1 != f->escaped_taint[1].end()) {
         auto& valid_uses = type1[def];
         for (auto use: it1->second)
            if (!valid_uses.contains(use->offset())) {
               LOG4("unsafe jump table [type 1]: " << def->offset()
                                         << " -> " << use->offset());
               return false;
            }
      }

      if (f->escaped_taint[2].contains(def)) {
         for (auto use: f->escaped_taint[2][def]) {
            LOG4("unsafe jump table [type 2]: " << def->offset()
                                      << " -> " << use->offset());
         }
         return false;
      }

      if (f->escaped_taint[3].contains(def)) {
         for (auto use: f->escaped_taint[3][def]) {
            LOG4("unsafe jump table [type 3]: " << def->offset()
                                      << " -> " << use->offset());
         }
         return false;
      }

      auto it4 = f->escaped_taint[4].find(def);
      if (it4 != f->escaped_taint[4].end()) {
         auto& valid_uses = type4[def];
         for (auto use: it4->second)
            if (!valid_uses.contains(use->offset())) {
               LOG4("unsafe jump table [type 4]: " << def->offset()
                                         << " -> " << use->offset());
               return false;
            }
      }

      return true;
   };

   for (auto& [expr, jloc, safe]: items) {
      safe = true;
      switch (expr->type) {
         case 1: {
            auto cast = (JTBaseMem*)expr;
            safe &= safe_def(cast->base.holder.loc.insn);
            safe &= safe_def(cast->mem.addr.base.holder.loc.insn);
            break;
         }
         case 2: {
            auto cast = (JTMem*)expr;
            safe &= safe_def(cast->addr.base.holder.loc.insn);
            break;
         }
         case 3: {
            auto cast = (JTAddr*)expr;
            safe &= safe_def(cast->base.holder.loc.insn);
            break;
         }
         default:
            break;
      }
   }
}
