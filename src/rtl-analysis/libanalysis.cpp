/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems
   Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include "../includes/libanalysis.h"
#include "framework.h"
#include "program.h"
#include "function.h"
#include "basicblock.h"
#include "insn.h"
#include "state.h"
#include "domain.h"
#include "config.h"

using namespace std;
/* -------------------------------------------------------------------------- */
static Program* p = nullptr;
static Function* f = nullptr;
static bool run_analysis = true;
static int init_opt = 1;


static function<void(array<State*,domainCnt>&)> init1 =
[](array<State*,domainCnt>& s) -> void {
                                /*  cstr   weak   clob  appr   call   fixp  logs  */
   s[0] = new AbsState<BaseLH>(    false,  true, false, true, false, false, true);
   s[1] = new AbsState<BaseLH>(     true,  true, false, true, false, false, true);
   s[2] = new AbsState<InitDomain>(false, false, false, true, true,  false, true);

   s[0]->init([&](UnitId id) -> BaseDomain* {
      return BaseLH::create_instance(id.symbol(), Range::ZERO);
   });
   s[1]->init([&](UnitId id) -> BaseDomain* {
      return (id.is_flags())?
             (BaseDomain*)(FlagDomain<BaseLH>::create_instance()):
             (BaseDomain*)(BaseLH::create_instance(id.symbol(), Range::ZERO));
   });
   s[2]->init([&](UnitId id) -> BaseDomain* {
      if (id.r() == REGION::STACK)
         return id.i() >= 0? InitDomain::create_instance(0):
                             InitDomain::create_instance(-1);
      else if (id.r() == REGION::REGISTER)
         return InitDomain::create_instance(0);
      else
         return BaseDomain::TOP;
   });
};


static function<void(array<State*,domainCnt>&)> init2 =
[](array<State*,domainCnt>& s) -> void {
                                /*  cstr   weak   clob  appr   call   fixp  logs  */
   s[0] = new AbsState<BaseLH>(    false,  true, false, true, false, false, true);
   s[1] = new AbsState<BaseLH>(     true,  true, false, true, false, false, true);
   s[2] = new AbsState<InitDomain>(false, false, false, true, true,  false, true);

   s[0]->init([&](UnitId id) -> BaseDomain* {
      return BaseLH::create_instance(id.symbol(), Range::ZERO);
   });
   s[1]->init([&](UnitId id) -> BaseDomain* {
      return (id.is_flags())?
             (BaseDomain*)(FlagDomain<BaseLH>::create_instance()):
             (BaseDomain*)(BaseLH::create_instance(id.symbol(), Range::ZERO));
   });
   s[2]->init([&](UnitId id) -> BaseDomain* {
      if (id.r() == REGION::STACK)
         return id.i() >= 0? InitDomain::create_instance(0):
                             InitDomain::create_instance(-1);
      else if (id.r() == REGION::REGISTER) {
         ARCH::REG reg = (ARCH::REG)(id.i());
         return (ARCH::args(reg) || ARCH::callee_saved(reg))?
                InitDomain::create_instance(0): InitDomain::create_instance(-1);
      }
      else
         return BaseDomain::TOP;
   });
};


static function<void(array<State*,domainCnt>&)> init3 =
[](array<State*,domainCnt>& s) -> void {
                                /*  cstr   weak   clob  appr   call   fixp  logs  */
   s[0] = new AbsState<BaseLH>(    false,  true, false, true, false, false, true);
   s[1] = new AbsState<BaseLH>(     true,  true, false, true, false, false, true);
   s[2] = new AbsState<InitDomain>(false, false, false, true, true,  false, true);

   s[0]->init([&](UnitId id) -> BaseDomain* {
      return BaseLH::create_instance(id.symbol(), Range::ZERO);
   });
   s[1]->init([&](UnitId id) -> BaseDomain* {
      return (id.is_flags())?
             (BaseDomain*)(FlagDomain<BaseLH>::create_instance()):
             (BaseDomain*)(BaseLH::create_instance(id.symbol(), Range::ZERO));
   });
   s[2]->init([&](UnitId id) -> BaseDomain* {
      if (id.r() == REGION::STACK)
         return id.i() >= 0? InitDomain::create_instance(0):
                             InitDomain::create_instance(-1);
      else if (id.r() == REGION::REGISTER) {
         ARCH::REG reg = (ARCH::REG)(id.i());
         return (ARCH::args(reg) || reg == ARCH::stackPtr)?
                InitDomain::create_instance(0):
                (reg == ARCH::REG::AX? InitDomain::create_instance(0xfffffffe) : InitDomain::create_instance(-1));
      }
      else
         return BaseDomain::TOP;
   });
};


static function<void(array<State*,domainCnt>&)> init4 =
[](array<State*,domainCnt>& s) -> void {
                                /*  cstr   weak   clob  appr   call   fixp  logs  */
   s[0] = new AbsState<BaseLH>(    false,  true, false, true, false, false, true);
   s[1] = new AbsState<BaseLH>(     true,  true, false, true, false, false, true);
   s[2] = new AbsState<InitDomain>(false, false, false, true, true,  false, true);

   s[0]->init([&](UnitId id) -> BaseDomain* {
      return BaseLH::create_instance(id.symbol(), Range::ZERO);
   });
   s[1]->init([&](UnitId id) -> BaseDomain* {
      return (id.is_flags())?
             (BaseDomain*)(FlagDomain<BaseLH>::create_instance()):
             (BaseDomain*)(BaseLH::create_instance(id.symbol(), Range::ZERO));
   });
   s[2]->init([&](UnitId id) -> BaseDomain* {
      if (id.r() == REGION::STACK)
         return InitDomain::create_instance(0);
      else if (id.r() == REGION::REGISTER) {
         ARCH::REG reg = (ARCH::REG)(id.i());
         return (ARCH::args(reg) || reg == ARCH::stackPtr)?
                InitDomain::create_instance(0):
                (reg == ARCH::REG::AX? InitDomain::create_instance(0xfffffffe) : InitDomain::create_instance(-1));
      }
      else
         return BaseDomain::TOP;
   });
};


static function<void(array<State*,domainCnt>&)> init() {
   switch (init_opt) {
      case 1: return init1;
      case 2: return init2;
      case 3: return init3;
      case 4: return init4;
      default: return init1;
   }
}
/* -------------------------------------------------------------------------- */
void analysis::setup(const string& autoFile) {
   Framework::setup(autoFile);
   InitDomain::uninit_allowed = 0;
}


bool analysis::load(const string& asmFile, const unordered_map<int64_t,int64_t>&
insnSize, const unordered_map<int64_t,vector<int64_t>>& jumpTable,
const vector<int64_t>& entry) {
   if (p != nullptr)
      delete p;
   p = Framework::create_prog(asmFile, insnSize, jumpTable, entry);
   return (p != nullptr);
}


static void forward_analysis() {
   if (f != nullptr && run_analysis) {
      run_analysis = false;
      f->forward_analysis(init());
   }
}
/* -------------------------------------------------------------------------- */
bool analysis::analyze(int func_index) {
   if (f != nullptr)
      delete f;
   f = p->func(func_index);
   run_analysis = true;
   return (f != nullptr);
}

void analysis::set_init(int init_option) {
   run_analysis = true;
   init_opt = init_option;
}


void analysis::print_stats() {
   LOG(2, "_____________________________________________________ ");
   LOG(2, "#file: " << Framework::total_file);
   LOG(2, "#insn: " << Framework::total_insn);
   LOG(2, "--> format:     " << Framework::time_format << " seconds");
   LOG(2, "--> lift:       " << Framework::time_lift << " seconds");
   LOG(2, "--> parse:      " << Framework::time_parse << " seconds");
   LOG(2, "--> cfg:        " << Framework::time_cfg << " seconds");
   LOG(2, "--> analysis:   " << Framework::time_analysis << " seconds");
   LOG(2, "--> track:      " << Framework::time_track << " seconds");
   LOG(2, "--> jump table: " << Framework::time_jump_table << " seconds");
}


int analysis::uninit() {
   forward_analysis();
   auto err = f->uninit();
   if (err != 0) {
      string errMsg = "uninitialized data analysis: ";
      if ((err & 0x1) != 0)
         errMsg.append("memory address, ");
      if ((err & 0x2) != 0)
         errMsg.append("control target, ");
      if ((err & 0x4) != 0)
         errMsg.append("critical data, ");
      if ((err & 0x8) != 0)
         errMsg.append("loop index/limit, ");
      errMsg.erase(errMsg.length()-2, 2);
      LOG(2, errMsg);
   }
   return err;
}


int64_t analysis::first_used_redef() {
   forward_analysis();
   auto res = ((AbsState<BaseLH>*)(f->s_[0]))->first_used_redef_;
   LOG(2, "first used redef = " << res);
   return res;
}


bool analysis::preserved(const vector<string>& regs) {
   forward_analysis();
   auto intact = true;
   for (auto r: regs) {
      auto id = UnitId(ARCH::from_string(r));
      for (auto scc: f->scc_list())
      for (auto b: scc->block_list()) {
         Loc loc = Loc(f, scc, b, nullptr);
         auto vec = f->track_before(0, id, loc,
                                    [](Insn* i) -> bool {return i->ret();});
         for (auto val: vec) {
            auto v = (BaseLH*)val;
            if (!v->top() && !(BaseLH::notlocal(v) && !id.is_stack())) {
               auto base = v->base();
               auto range = v->range();
               if (!(base == id.symbol() && range.contains(Range::ZERO))) {
                  intact = false;
                  LOG(2, r << " is not preserved: " << v->to_string());
               }
            }
            BaseDomain::safe_delete(val);
         }
      }
   }
   return intact;
}


analysis::JTable analysis::jump_table_analysis() {
   forward_analysis();
   auto res = f->jump_table_analysis();
   for (auto const& [loc, x]: res.type1())
      LOG(2, "jump table " << loc << " --> " << x.to_string());
   for (auto const& [loc, x]: res.type2())
      LOG(2, "jump table " << loc << " --> " << x.to_string());
   for (auto const& [loc, x]: res.type3())
      LOG(2, "jump table " << loc << " --> " << x.to_string());
   return res;
}