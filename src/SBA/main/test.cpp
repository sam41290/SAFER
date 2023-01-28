/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems
   Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include "../utility.h"
#include "../state.h"
#include "../domain.h"
#include "../framework.h"
#include "../program.h"
#include "../function.h"
#include "../scc.h"
#include "../block.h"
#include "../insn.h"
#include "../jtable.h"
#include "../../../run/config.h"

using namespace std;
using namespace SBA;


auto reg_preserve = vector<string>{"sp","bx","bp","r12","r13","r14","r15"};


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


int main(int argc, char **argv) {
   LOG_START("/tmp/sba.log");
   Framework::config(TOOL_PATH"auto/output_old_ocaml.auto");

   /* initial values - used for register preservation */
   unordered_map<IMM,BaseDomain*> init_val;
   for (auto const& s: reg_preserve) {
      auto reg = ARCH::to_reg(s);
      init_val[get_sym(reg)] = init0(get_id(reg));
   }

   vector<IMM> entries;
   string fpath = string(argv[1]);
   unordered_map<IMM,uint8_t> insn_size;
   unordered_map<IMM,vector<IMM>> jtables;

   auto init_general = [](array<AbsState*,DOMAIN_NUM>& s) -> void {
      s[0] = new State<BaseLH>(false,true,false,true,false,false,true,&init0);
      s[1] = new State<BaseLH>(true,true,false,true,false,false,true,&init1);
      s[2] = new State<TaintDomain>(false,true,false,true,true,false,true,&init2_uninit_analysis);
   };

   /* load function entries, instruction size and jump table targets */
   {
      string s;
      fstream fmeta(fpath + ".func");
      while (getline(fmeta, s))
          entries.push_back(Util::to_int(s));
      fmeta.close();
   }
   {
      string s;
      fstream fmeta(fpath + ".sz");
      while (getline(fmeta, s)) {
         auto offset = Util::to_int(s.substr(0, s.find(" ")));
         auto size = Util::to_int(s.substr(s.find(" "), string::npos));
         insn_size[offset] = size;
      }
      fmeta.close();
   }

   // auto offset_rtl = Framework::offset_rtl(fpath+".s", insn_size);
   auto offset_rtl = Framework::offset_rtl(fpath+".s","/tmp/sbr2/20784/tmp_3");
   auto p = Framework::create_program(offset_rtl, insn_size, jtables, entries);

   if (p != nullptr) {
      p->set_binary(fpath);

      while (true) {
         auto prev_jtable_cnt = jtables.size();
         jtables.clear();

         for (auto e: entries) {
            LOG1("process function " << e);
            auto f = p->func(e);
            if (f != nullptr) {
               /* general */
               f->init(init_general);
               f->forward_analysis();

               /* register preservation */
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
                     || v->equal(init_val[sym])))
                        LOG2(s << " is not preserved: " << v->to_string());
                     BaseLH::safe_delete(v);
                  }
               }

               /* uninit analysis */
               switch (f->uninit_error) {
                  case 0x1: LOG2("uninit memory address"); break;
                  case 0x2: LOG2("uninit control target"); break;
                  case 0x4: LOG2("uninit critical data"); break;
                  case 0x8: LOG2("uninit loop index/limit"); break;
                  default: break;
               }

               /* jump table analysis */
               JTAnalyser res;
               unordered_set<Insn*> taint_src;
               for (auto scc: f->scc_list())
               for (auto b: scc->block_list())
               for (auto i: b->insn_list())
                  if (i->jump() && i->indirect()) {
                     res.analyse({i->indirect_target(), {f, scc, b, i}});
                     LOG3("analyze indirect jump " << std::dec << i->offset());
                  }

               for (auto const& [expr, jloc, safe]: res.items) {
                  auto targets = expr->targets(p->read_value,p->valid_code_offset);
                  unordered_set<uint64_t> uniq(targets.begin(),targets.end());
                  for (auto t: uniq)
                     jtables[(IMM)jloc].push_back((IMM)t);

                  /* extract taint_src */
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

               /* verify safe jump table */
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
                  auto targets = expr->targets(p->read_value,p->valid_code_offset);
                  LOG2((safe? "[safe]": "[unsafe]") << " jump table " << jloc
                       << " " << start
                       << " " << ((IMM)stride)
                       << " " << targets.size()
                       << " -> " << expr->to_string());
               }
            }
         }
         LOG2("--> found " << jtables.size() << " jump tables");
         LOG2("=====================================");
         LOG2("+++++++++++++++++++++++++++++++++++++");
         LOG2("=====================================");
         if (jtables.size() == prev_jtable_cnt)
            break;
         p->update_graph(vector<pair<IMM,RTL*>>{}, insn_size, jtables, entries);
      }
      delete p;
   }
   Framework::print_stats();

   for (auto const& [sym, v]: init_val)
      BaseDomain::safe_delete(v);

   LOG_STOP();
   return 0;
}
