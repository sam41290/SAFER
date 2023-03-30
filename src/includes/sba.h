/*
      Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems
         Lab, Stony Brook University, Stony Brook, NY 11794.
         */

#ifndef SBA_H
#define SBA_H

#include "../SBA/utility.h"
#include "../SBA/state.h"
#include "../SBA/domain.h"
#include "../SBA/framework.h"
#include "../SBA/program.h"
#include "../SBA/function.h"
#include "../SBA/scc.h"
#include "../SBA/block.h"
#include "../SBA/insn.h"
#include "../SBA/rtl.h"
#include "../SBA/expr.h"
#include "../SBA/jtable.h"
#include "../../run/config.h"

using namespace SBA;

namespace SBA_Wrapper {

   function<BaseDomain*(const UnitId& id)> init0=[](const UnitId& id)->BaseDomain* {
      return (id.boundness() != 0)? BaseDomain::TOP:
                                    BaseLH::create(get_sym(id),Range::ZERO);
   };
   function<BaseDomain*(const UnitId& id)> init1=[](const UnitId& id)->BaseDomain* {
      return (id.boundness() != 0)? BaseDomain::TOP:
             ((id.flag())? (BaseDomain*)(FlagDomain<BaseLH>::create()):
                           (BaseDomain*)(BaseLH::create(get_sym(id),Range::ZERO)));
   };
   function<BaseDomain*(const UnitId& id)> init2_uninit_analysis=[](const UnitId& id)->BaseDomain* {
      if (id.r() == REGION::STACK)
         return id.i() >= 0? TaintDomain::create(0x0, nullptr):
                             TaintDomain::create(0xffffffff, nullptr);
      else if (id.r() == REGION::REGISTER) {
         ARCH::REG reg = (ARCH::REG)(id.i());
         return (ARCH::call_args.contains(reg) || reg == ARCH::stack_pointer)?
                TaintDomain::create(0x0, nullptr):
                (reg == ARCH::REG::AX ? TaintDomain::create(0xfffffffe, nullptr):
                                        TaintDomain::create(0xffffffff, nullptr));
      }
      else
         return BaseDomain::TOP;
   };
   function<BaseDomain*(const UnitId& id)> init2_safe_jtable=[](const UnitId& id)->BaseDomain* {
      return TaintDomain::create(0x0, nullptr);
   };
   auto init_general = [](array<AbsState*,DOMAIN_NUM>& s) -> void {
      s[0] = new State<BaseLH>(false,true,false,true,false,false,true,&init0);
      s[1] = new State<BaseLH>(true,true,false,true,false,false,true,&init1);
      s[2] = new State<TaintDomain>(false,true,false,true,true,false,true,&init2_uninit_analysis);
   };
   
   auto reg_preserve = vector<string>{"sp","bx","bp","r12","r13","r14","r15"};
   unordered_map<IMM,BaseDomain*> init_val;
   Program* p = nullptr;
   Function* f = nullptr;
   unordered_map<IMM,uint8_t> insn_size;
   unordered_map<IMM,vector<IMM>> jtables;
   

   void start() {
      LOG_START("/tmp/sba.log");
      Framework::config(TOOL_PATH"auto/output_old_ocaml.auto");
      for (auto const& s: reg_preserve) {
         auto reg = ARCH::to_reg(s);
         init_val[get_sym(reg)] = init0(get_id(reg));
      }
   }


   void load(const string& fpath,
   const unordered_map<IMM,uint8_t>& insn_size,
   const unordered_map<IMM,vector<IMM>>& jtables,
   const vector<IMM>& entries) {
      if (p != nullptr)
         delete p;
      auto offset_rtl = Framework::offset_rtl(fpath+".s", insn_size);
      // auto offset_rtl = Framework::offset_rtl(fpath+".s", "/tmp/sbr2/1686/tmp_3");
      p = Framework::create_program(offset_rtl, insn_size, jtables, entries);
   }
   
   void analyse(int32_t entry) {
      if (p != nullptr) {
         f = p->func(entry);
         if (f != nullptr) {
            LOG3("process function " << entry);
            f->init(init_general);
            f->forward_analysis();
         }
      }
   }


   bool preserve() {
      if (f == nullptr)
         return false;
      bool res = true;
      for (auto const& s: reg_preserve) {
         auto reg = ARCH::to_reg(s);
         auto id = get_id(reg);
         auto sym = get_sym(reg);
         for (auto scc: f->scc_list())
         for (auto b: scc->block_list())
         if (b->last_insn()->ret())
         for (auto v: f->track(TRACK::BEFORE, 0, id, {f,scc,b,nullptr},
         [](Insn* i)->bool {return i->ret();})) {
            if (!(v->top() || v->bot()
            || (BaseLH::notlocal(v) && reg != ARCH::stack_pointer)
            || v->equal(init_val[sym]))) {
               res = false;
               LOG2(s << " is not preserved: " << v->to_string());
            }
            BaseLH::safe_delete(v);
         }
      }
      return res;
   }
   

   bool uninit() {
      if (f == nullptr)
         return false;
      bool res = true;
      switch (f->uninit_error) {
         case 0x1: res = false; LOG2("uninit memory address"); break;
         case 0x2: res = false; LOG2("uninit control target"); break;
         case 0x4: res = false; LOG2("uninit critical data"); break;
         case 0x8: res = false; LOG2("uninit loop index/limit"); break;
         default: break;
      }
      return res;
   }


   JTAnalyser jump_table() {
      JTAnalyser res;
      if (f == nullptr)
         return res;
      unordered_set<Insn*> taint_src;
      for (auto scc: f->scc_list())
      for (auto b: scc->block_list())
      for (auto i: b->insn_list())
         if (i->jump() && i->indirect())
            res.analyse({i->indirect_target(), {f, scc, b, i}});
   
      for (auto const& [expr, jloc, safe]: res.items) {
         switch (expr->type) {
            case 1: {
               auto cast = (JTBaseMem*)expr;
               taint_src.insert(cast->base.holder.loc.insn);
               taint_src.insert(cast->mem.addr.base.holder.loc.insn);
               break;
            }
            case 2: {
               auto cast = (JTMem*)expr;
               taint_src.insert(cast->addr.base.holder.loc.insn);
               break;
            }
            case 3: {
               auto cast = (JTAddr*)expr;
               taint_src.insert(cast->base.holder.loc.insn);
               break;
            }
            default:
               break;
         }
      }
      auto init_safe_jtable = [&](array<AbsState*,DOMAIN_NUM>& s) -> void {
         s[0] = new State<BaseLH>(false,true,false,true,false,false,true,&init0);
         s[1] = new State<BaseLH>(true,true,false,true,false,false,true,&init1);
         s[2] = new State<TaintDomain>(false,true,false,true,true,false,true,&init2_safe_jtable,taint_src);
         s[1]->enable_analysis(false);
      };
   
      f->clear();
      f->init(init_safe_jtable);
      f->forward_analysis();
      res.verify(f);
   
      for (auto const& [expr, jloc, safe]: res.items) {
         auto start = expr->start();
         auto stride = expr->stride();
         LOG2((safe? "[safe]": "[unsafe]") << " jump table " << jloc
              << " " << start
              << " " << ((IMM)stride)
              << " -> " << expr->to_string());
      }

      return res;
   }


   /* <0,d> : base_sp + d */
   /* <1,d> : base_bp + d*/
   vector<pair<uint8_t,IMM>> canary() {
      if (f == nullptr)
         return vector<pair<uint8_t,IMM>>{};
      vector<pair<uint8_t,IMM>> res;
      auto tmp = new Assign(nullptr, nullptr);
      for (auto scc: f->scc_list())
      for (auto b: scc->block_list())
      for (auto i: b->insn_list())
      if (!i->empty()) {
         auto vec = i->stmt()->find(RTL_EQUAL::OPCODE, tmp);
         if (!vec.empty()) {
            auto a1 = (Assign*)(vec.front());
            auto r_store = (Reg*)(*a1->dst()->simplify());
            auto m_canary = (Mem*)(*a1->src()->simplify());
            if (m_canary != nullptr && r_store != nullptr &&
            m_canary->expr_mode() == Expr::EXPR_MODE::FSDI) {
               auto c_addr = (Const*)(*m_canary->addr()->simplify());
               if (c_addr != nullptr && c_addr->to_int() == 0x28) {
                  auto uses = f->find_reached(r_store->reg(), Loc{f,scc,b,i});
                  for (auto const& use: uses) {
                     auto stmt = use.loc.insn->stmt();
                     auto a2 = (Assign*)(stmt->find_container(use.expr, [](const RTL* rtl)->bool {
                        return (Assign*)(*rtl) != nullptr;
                     }));
                     if (a2 != nullptr) {
                        auto m_stack = (Mem*)(*a2->dst());
                        if (m_stack != nullptr) {
                           auto s_addr = m_stack->addr();
                           auto v = f->track_subexpr(0, s_addr, use.loc);
                           if (!v->top() && !v->bot() && !BaseLH::notlocal(v)) {
                              auto v_cast = (BaseLH*)v;
                              auto b = v_cast->base();
                              auto lo = v_cast->range().lo();
                              auto hi = v_cast->range().hi();
                              if (lo == hi) {
                                 if (b == get_sym(ARCH::stack_pointer)) {
                                    res.push_back(make_pair(0, lo));
                                    LOG2("canary at (base_sp" <<
                                          (lo < 0? (" - " + std::to_string(-lo)):
                                                   (" + " + std::to_string(lo))) << ")");
                                 }
                                 else if (b == get_sym(ARCH::frame_pointer)) {
                                    res.push_back(make_pair(1, lo));
                                    LOG2("canary at (base_bp" <<
                                          (lo < 0? (" - " + std::to_string(-lo)):
                                                   (" + " + std::to_string(lo))) << ")");
                                 }
                              }
                           }
                           BaseDomain::safe_delete(v);
                        }
                     }
                  }
               }
            }
         }
      }
      delete tmp;
      return res;
   }


   void stop() {
      Framework::print_stats();
      for (auto const& [sym, v]: init_val)
         BaseDomain::safe_delete(v);
      LOG_STOP();
   }
}

#endif
