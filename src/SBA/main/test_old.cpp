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


function<BaseDomain*(const UnitId& id)> init2=[](const UnitId& id)->BaseDomain* {
   if (id.r() == REGION::STACK)
      return id.i() >= 0? InitDomain::create(0): InitDomain::create(0xffffffff);
   else if (id.r() == REGION::REGISTER) {
      ARCH::REG reg = (ARCH::REG)(id.i());
      return (ARCH::call_args.contains(reg) || reg == ARCH::stack_pointer)?
             InitDomain::create(0):
             (reg == ARCH::REG::AX ? InitDomain::create(0xfffffffe):
                                     InitDomain::create(0xffffffff));
   }
   else
      return BaseDomain::TOP;
};


function<void(array<AbsState*,DOMAIN_NUM>&)> init = [](array<AbsState*,DOMAIN_NUM>& s) -> void {
   s[0] = new State<BaseLH>(false,true,false,true,false,false,true,&init0);
   s[1] = new State<BaseLH>(true,true,false,true,false,false,true,&init1);
   s[2] = new State<InitDomain>(false,true,false,true,true,false,true,&init2);
   // s[1]->enable_analysis(false);
};


int main(int argc, char **argv) {
   LOG_START("/tmp/sba.log");

   /* initial values */
   unordered_map<IMM,BaseDomain*> init_val;
   for (auto const& s: reg_compact) {
      auto reg = ARCH::to_reg(s);
      init_val[get_sym(reg)] = init0(get_id(reg));
   }

   vector<IMM> entries;
   string fname = string(argv[1]);
   unordered_map<IMM,uint8_t> insn_size;
   unordered_map<IMM, vector<IMM>> jtables;
   Framework::config(TOOL_PATH"auto/output_old_ocaml.auto");
   /* load function entries, instruction size and jump table targets */
   {
      string s;
      fstream fmeta(fname + ".func");
      while (getline(fmeta, s))
          entries.push_back(Util::to_int(s));
      fmeta.close();
   }
   {
      string s;
      IMM prev_offset, offset;
      fstream fmeta(fname + ".s");
      {
         getline(fmeta, s);
         prev_offset = Util::to_int(s.substr(1, s.find(":")-1));
      }
      while (getline(fmeta, s)) {
         offset = Util::to_int(s.substr(1, s.find(":")-1));
         insn_size[prev_offset] = offset-prev_offset;
         prev_offset = offset;
      }
      insn_size[prev_offset] = 4;
      fmeta.close();
   }

   /* for every program */
   auto p = Framework::create_program(fname+".s","/tmp/sbr2/3186/tmp_3",insn_size,jtables,entries);
   if (p != nullptr)

   /* for every function */
   for (auto e: entries) {
      LOG1("function " << e);
      auto f = p->func(e);
      if (f == nullptr) continue;

      /* analyse function */
      InitDomain::ERROR = 0;
      f->forward_analysis(init);

      /* uninit */
      if ((InitDomain::ERROR & 0x1)!=0) LOG2("uninit memory address");
      if ((InitDomain::ERROR & 0x2)!=0) LOG2("uninit control target");
      if ((InitDomain::ERROR & 0x4)!=0) LOG2("uninit critical data");

      /* register preserve */
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

      /* jtable */
      JTAnalyser jtables;
      for (auto scc: f->scc_list())
      for (auto b: scc->block_list()) {
         for (auto i: b->insn_list())
         if (i->jump() && i->indirect())
            jtables.analyse({i->indirect_target(), {f, scc, b, i}});
      }
      for (auto const& [expr, jloc, error]: jtables.items)
         LOG2("jump table " << jloc
              << " " << expr->start()
              << " " << (IMM)(expr->entry_size())
              << " " << ((expr->end()-expr->start())/(IMM)(expr->entry_size())+1)
              << " -> " << expr->to_string());
   }
   delete p;
   Framework::print_stats();

   for (auto const& [sym, v]: init_val)
      BaseDomain::safe_delete(v);

   LOG_STOP();
   return 0;
}
