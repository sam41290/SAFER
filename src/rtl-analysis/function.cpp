/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "framework.h"
#include "function.h"
#include "basicblock.h"
#include "insn.h"
#include "state.h"
#include "domain.h"
#include "rtl.h"
#include "expr.h"
#include "arithmetic.h"

/* -------------------------------------------------------------------------- */
static vector<SCC*> sccList;
static unordered_set<SCC*> sccVisited;
static unordered_map<BasicBlock*,SCC*> sccMap;
static unordered_set<int> udQueue;
/* --------------------- Strongly Connected Component ----------------------- */
void SCC::build_graph(BasicBlock* header, BasicBlock* pred) {
   /* update header for current SCC */
   if (pred != nullptr)
      predScc_[header].push_back(make_pair(pred, sccMap.at(pred)));
   else
      predScc_[header].push_back(make_pair(nullptr, nullptr));

   /* if already processed -> skip */
   if (sccVisited.contains(this))
      return;
   sccVisited.insert(this);

   /* initialize for current SCC */
   for (auto u: blockList_) {
      succ_[u];
      pred_[u];
   }

   /* build graph for current SCC -> reverse postorder for blockList_ */
   unordered_set<BasicBlock*> total(blockList_.begin(),blockList_.end());
   unordered_set<BasicBlock*> blockVisited;
   vector<pair<BasicBlock*,BasicBlock*>> outside;

   function<void(BasicBlock*)> dfs = [&](BasicBlock* u) -> void {
      blockVisited.insert(u);
      for (auto [v,cond]: u->succ())
         if (total.contains(v)) {
            succ_[u].push_back(v);
            pred_[v].push_back(u);
            if (!blockVisited.contains(v))
               dfs(v);
         }
         else
            outside.push_back(make_pair(u,v));
      blockList_.push_back(u);
   };

   blockList_.clear();
   dfs(header);
   std::reverse(blockList_.begin(), blockList_.end());

   /* build graph for successor SCC */
   for (auto [u,v]: outside)
      sccMap.at(v)->build_graph(v, u);

   /* postorder for sccList */
   sccList.push_back(this);
}


vector<pair<BasicBlock*,SCC*>> SCC::pred_scc(BasicBlock* u) const {
   return  predScc_.contains(u)? predScc_.at(u):
                                 vector<pair<BasicBlock*,SCC*>>{};
}


bool SCC::is_loop() const {
   if (blockList_.size() == 1) {
      auto u = blockList_.front();
      for (auto v: succ(u))
         if (v == u)
            return true;
      return false;      
   }
   return true;
}


void SCC::execute(const array<State*,domainCnt>& s) const {
   /* set location */
   for (auto ss: s)
      ss->loc().scc = (SCC*)this;

   /* loop until fixpoint */
   bool change = false;
   bool loop = is_loop();

   /* if !fixpoint, preset all targets to TOP */
   if (loop)
      for (auto b: block_list())
         b->preset(s);
   do {
      change = false;
      for (auto b: block_list())
         change |= b->execute(s);
      break;
   }
   while (loop && change);
   LOG(3, "======================================\n");
}
/* -------------------------------- Function -------------------------------- */
Function::Function(BasicBlock* entry) {
   entry_ = entry;
   s_.fill(nullptr);
   build_graph();
}


Function::~Function() {
   clear();
   for (auto scc: sccList_)
      delete scc;
}


int64_t Function::offset() const {
   return entry_->offset();
}


void Function::clear() {
   for (auto& ss: s_)
      if (ss != nullptr) {
         delete ss;
         ss = nullptr;
      }
}


void Function::build_graph() {
   /* initialize global variables */
   sccMap.clear();
   sccList.clear();
   sccVisited.clear();

   /* tarjan algorithm */
   int cnt = 0;
   unordered_map<BasicBlock*,int> num;
   unordered_map<BasicBlock*,int> low;
   stack<BasicBlock*> st;

   function<void(BasicBlock*)> tarjan = [&](BasicBlock* u) -> void {
      ++cnt;
      num[u] = cnt;
      low[u] = cnt;
      st.push(u);

      for (auto [v,cond]: u->succ()) {
         /* if v is not visited */
         if (!num.contains(v)) {
            tarjan(v);
            low[u] = std::min(low[u], low[v]);
         }
         /* if v is visited */
         else if (num[v] > 0)
            low[u] = std::min(low[u], num[v]);
      }

      /* found a new SCC */
      if (num[u] == low[u]) {
         vector<BasicBlock*> vec;

         while (true) {
            auto v = st.top();
            st.pop();
            vec.push_back(v);
            // remove v from graph
            num[v] = -1;
            if (u == v)
               break;
         }

         auto scc = new SCC(vec);
         for (auto v: vec)
            sccMap[v] = scc;
      }
   };

   tarjan(entry_);

   /* construct SCC graph, recursively */
   sccMap[entry_]->build_graph(entry_, nullptr);

   /* reverse postorder for sccList_ */
   sccList_ = sccList;
   std::reverse(sccList_.begin(), sccList_.end());
}


void Function::forward_analysis(
const function<void(array<State*,domainCnt>&)>& f_init) {
   LOG(3, "############# analyzing ##############");
   time_start(start1);

   /* initialize domain */
   clear();
   f_init(s_);

   /* initialize uninitialized analysis */
   uninit_ = 0;

   /* set location */
   for (auto ss: s_)
      ss->loc().func = this;

   /* execute scc in reverse postorder */
   for (auto scc: scc_list())
      scc->execute(s_);

   time_stop(Framework::time_analysis, start1);
   LOG(3, "######################################");
}


vector<BaseDomain*> Function::track_before(int domainIndex, const UnitId& id,
const Loc& loc, const function<bool(Insn*)>& select) {
   /* get list of insn to be tracked */
   vector<Insn*> insns;
   for (auto i: loc.block->insn_list())
      if (select(i))
         insns.push_back(i);
   if (insns.empty())
      return vector<BaseDomain*>{};

   LOG(3, "########### track before " << id.to_string() << " ###########");
   time_start(start1);

   /* initialize block channel */
   for (auto ss: s_) {
      ss->loc() = loc;
      ss->refresh();
   }

   /* execute instructions */
   vector<BaseDomain*> res;
   auto it = insns.begin();
   for (auto i: loc.block->insn_list()) {
      /* get track result before execute insn */
      if (i == *it) {
         res.push_back(s_[domainIndex]->value_unit(id)->clone());
         if (++it == insns.end())
            break;
      }
      /* execute, but NOT commit to main channel */
      i->execute(s_);
   }

   /* clear block channel */
   for (auto ss: s_)
      ss->clear();

   time_stop(Framework::time_track, start1);
   LOG(3, "######################################");

   return res;
}


vector<BaseDomain*> Function::track_after(int domainIndex, const UnitId& id,
const Loc& loc, const function<bool(Insn*)>& select) {
   /* get list of insn to be tracked */
   vector<Insn*> insns;
   for (auto i: loc.block->insn_list())
      if (select(i))
         insns.push_back(i);
   if (insns.empty())
      return vector<BaseDomain*>{};

   LOG(3, "########### track after " << id.to_string() << " ###########");
   time_start(start1);

   /* initialize block channel */
   for (auto ss: s_) {
      ss->loc() = loc;
      ss->refresh();
   }

   /* execute instructions */
   vector<BaseDomain*> res;
   auto it = insns.begin();
   for (auto i: loc.block->insn_list()) {
      /* execute, but NOT commit to main channel */
      i->execute(s_);
      /* get track result after execute insn */
      if (i == *it) {
         res.push_back(s_[domainIndex]->value_unit(id)->clone());
         if (++it == insns.end())
            break;
      }
   }

   /* clear block channel */
   for (auto ss: s_)
      ss->clear();

   time_stop(Framework::time_track, start1);
   LOG(3, "######################################");

   return res;
}


BaseDomain* Function::track_subexpr(int domainIndex, const ExprLoc& X) {
   /* initialize block channel */
   for (auto ss: s_) {
      ss->loc() = X.loc;
      ss->refresh();
   }

   /* execute instructions */
   BaseDomain* res = BaseDomain::BOT;
   for (auto i: X.loc.block->insn_list()) {
      if (i == X.loc.insn) {
         res = (i->stmt()->eval(s_, X.expr)[domainIndex])->clone();
         break;
      }
      i->execute(s_);
   }

   /* clear block channel */
   for (auto ss: s_)
      ss->clear();
   return res;
}


vector<ExprLoc> Function::find_def(const ExprLoc& reg) {
   vector<ExprLoc> res;
   auto r = (Reg*)(*(reg.rtl()));
   if (r != nullptr) {
      /* assign has def expr; clobber/call only has def val */
      auto id = UnitId(r->reg());
      auto loc = reg.loc;
      auto track = new Assign(r->clone(), nullptr);
      /* any abstract state should have proper ud_chain */
      for (auto L: s_[0]->ud_chain(id, loc)) {
         auto stmt = L.insn->stmt();
         auto vec = stmt->find(RTL_EQUAL::PARTIAL, track);
         if (!vec.empty()) {
            auto assign = (Assign*)(*(vec.front()));
            res.push_back(ExprLoc(assign->src(), L));
         }
      }
      delete track;
   }
   return res;
}


template<class RetType,class ExprType>
vector<RetType> Function::find_pattern(const ExprLoc& X,
vector<RetType>(*recur)(const ExprLoc&),
const function<void(vector<RetType>&,ExprType*,const Loc&)>& handler) {
   auto defs = find_def(X);
   if ((ExprType*)(*(X.rtl())) != nullptr)
      defs.push_back(X);

   vector<RetType> res;
   if (!defs.empty())
      for (auto x: defs) {
         /* continue to unfold if x is register */
         auto xreg = ((Reg*)(*(x.rtl())));
         if (xreg != nullptr) {
            auto vec = recur(x);
            res.insert(res.end(), vec.begin(), vec.end());
            continue;
         }
         /* otherwise, handle x */
         auto xT = ((ExprType*)(*(x.rtl())));
         if (xT != nullptr) {
            handler(res, xT, x.loc);
            continue;
         }
      }
   return res;
}
/* --------------------------- Jump Table Analysis ---------------------------*/
static vector<analysis::JTableBase> jtable_base_pattern(const ExprLoc& X) {
   vector<analysis::JTableBase> res;

   bool isReg = ((Reg*)(*(X.rtl())) != nullptr);
   if (isReg) {
      auto L = X.loc.insn->offset();
      if (udQueue.contains((int)(L ^ (int64_t)(X.rtl())))) {
         auto v = (BaseLH*)(X.loc.func->track_subexpr(0, X));
         if (!v->top() && !v->bot() && !BaseLH::notlocal(v)
         && (v->base()==0 || v->base()==staticSym)) {
            if (v->range().lo() == v->range().hi())
               res.push_back(analysis::JTableBase(v->range().lo(), L));
            else {
               res.push_back(analysis::JTableBase(v->range().lo(), L));
               res.push_back(analysis::JTableBase(v->range().hi(), L));
            }
         }
         return res;
      }
      else
         udQueue.insert((int)(L ^ (int64_t)(X.rtl())));
   }

   auto defs = X.loc.func->find_def(X);
   if (!isReg)
      defs.push_back(X);

   for (auto x: defs) {
      auto xx = x.rtl();
      auto L = x.loc.insn->offset();
      /* continue to unfold if x is register */
      auto xreg = (Reg*)(*xx);
      if (xreg != nullptr) {
         auto vec = jtable_base_pattern(x);
         res.insert(res.end(), vec.begin(), vec.end());
         continue;
      }
      /* if x is constant */
      auto xcst = (Const*)(*xx);
      if (xcst != nullptr) {
         res.push_back(analysis::JTableBase(xcst->to_int(), L));
         continue;
      }
      /* if x is (%rip + const) */
      auto xbin = (Binary*)(*xx);
      if (xbin != nullptr) {
         int8_t op = (xbin->op() == Binary::OP::PLUS  ? 1 :
                   (xbin->op() == Binary::OP::MINUS ? -1 : 0));
         if (op != 0) {
            array<Expr*,2> args;
            for (int i = 0; i < 2; ++i)
               args[i] = xbin->operand(i)->simplify();
            for (int i = 0; i < 2; ++i) {
               auto reg = (Reg*)(*args[i]);
               auto cst = (Const*)(*args[1-i]);
               if (reg != nullptr && reg->reg() == ARCH::insnPtr
               && cst != nullptr) {
                  auto pc = x.loc.insn->next_offset();
                  auto c  = cst->to_int() * op;
                  res.push_back(analysis::JTableBase(pc + c, L));
                  break;
               }
            }
         }
         continue;
      }
   }
   return res;
}


static vector<analysis::JTableRange> jtable_range_pattern(const ExprLoc& X) {
   return X.loc.func->find_pattern<analysis::JTableRange,Binary>
   (X, &jtable_range_pattern,
   [](vector<analysis::JTableRange>& res, Binary* x, const Loc& loc) {
      auto L = loc.insn->offset();
      auto op = x->op();
      if (op == Binary::OP::MULT || op == Binary::OP::ASHIFT) {
         array<Expr*,2> args;
         for (int i = 0; i < 2; ++i)
            args[i] = x->operand(i)->simplify();
         for (int i = 0; i < 2; ++i) {
            auto reg = (Reg*)(*args[i]);
            auto cst = (Const*)(*args[1-i]);
            if (reg != nullptr && cst != nullptr) {
               auto id = UnitId(reg->reg());
               auto vec = loc.func->track_before(1, id, loc,
                          [&](Insn* i) {return i==loc.insn;});
               auto idx = (BaseLH*)(vec.front());
               auto c = cst->to_int();
               auto s = (op == Binary::OP::MULT)? c: (1 << c);
               if (idx->top() || BaseLH::notlocal(idx) || idx->base() != 0)
                  res.push_back(analysis::JTableRange(_oo, oo, s, L));
               else {
                  auto r = idx->range();
                  res.push_back(analysis::JTableRange(s*r.lo(),s*r.hi(),s,L));
               }
               BaseDomain::safe_delete(idx);
               return;
            }
         }
      }
   });
}


static vector<analysis::JTableAddr> jtable_addr_stride_pattern(const ExprLoc&
X) {
   return X.loc.func->find_pattern<analysis::JTableAddr,Binary>(
   X, &jtable_addr_stride_pattern,
   [](vector<analysis::JTableAddr>& res, Binary* x, const Loc& loc) {
      auto L = loc.insn->offset();
      char op = (x->op() == Binary::OP::PLUS ? '+':
                (x->op() == Binary::OP::MINUS? '-': 0));
      if (op != 0) {
         array<ExprLoc,2> args;
         for (int i = 0; i < 2; ++i)
            args[i] = ExprLoc(x->operand(i)->simplify(), loc);
         for (int i = 0; i < (op == '+'? 2: 1); ++i) {
            udQueue.clear();
            auto base = jtable_base_pattern(args[i]);
            if (base.size() > 0) {
               auto r = Range::EMPTY;
               uint8_t s = 0;
               int64_t rLoc = 0;
               for (auto rgn: jtable_range_pattern(args[1-i])) {
                  r = r | Range(rgn.l, rgn.h);
                  rLoc = (rLoc == 0)? rgn.loc: -1;
                  s = rgn.stride;
               }
               if (!r.empty() && !r.universal()) {
                  auto range = analysis::JTableRange(r.lo(), r.hi(), s, rLoc);
                  for (auto b: base)
                     res.push_back(analysis::JTableAddr(b, op, range, L));
               }
            }
         }
      }
   });
}


static vector<analysis::JTableAddr> jtable_addr_pattern(const ExprLoc& X) {
   return X.loc.func->find_pattern<analysis::JTableAddr,Binary>
   (X, &jtable_addr_pattern,
   [](vector<analysis::JTableAddr>& res, Binary* x, const Loc& loc) {
      auto L = loc.insn->offset();
      char op = (x->op() == Binary::OP::PLUS  ? '+' :
                (x->op() == Binary::OP::MINUS ? '-' : 0));
      if (op != 0) {
         array<ExprLoc,2> args;
         for (int i = 0; i < 2; ++i)
            args[i] = ExprLoc(x->operand(i)->simplify(), loc);
         for (int i = 0; i < (op == '+'? 2: 1); ++i) {
            udQueue.clear();
            auto base = jtable_base_pattern(args[i]);
            if (base.size() > 0) {
               /* args[1-i] might not be register */
               auto v = (BaseLH*)(loc.func->track_subexpr(1, args[1-i]));
               if (!v->top() && !v->bot() && !BaseLH::notlocal(v)
               && v->base()==0) {
                  auto r = v->range();
                  if (!r.empty() && !r.universal()) {
                     auto range = analysis::JTableRange(r.lo(), r.hi(), -1);
                     for (auto b: base)
                        res.push_back(analysis::JTableAddr(b, op, range, L));
                  }
               }
               else {
                  auto range = analysis::JTableRange(norm_min, norm_max, -1);
                  for (auto b: base)
                     res.push_back(analysis::JTableAddr(b, op, range, L));
               }
               BaseDomain::safe_delete(v);
               return;
            }
         }
      }
   });
}


static vector<analysis::JTableMem> jtable_mem_pattern(const ExprLoc& X) {
   return X.loc.func->find_pattern<analysis::JTableMem,Mem>
   (X, &jtable_mem_pattern,
   [](vector<analysis::JTableMem>& res, Mem* x, const Loc& loc) {
      auto L = loc.insn->offset();
      auto addr = jtable_addr_pattern(ExprLoc(x->addr(), loc));
      for (auto a: addr)
         res.push_back(analysis::JTableMem(a, x->mode_size(), L));
   });
}


static vector<analysis::JTableOffsetMem> jtable_offset_mem_pattern(
const ExprLoc& X) {
   return X.loc.func->find_pattern<analysis::JTableOffsetMem,Binary>
   (X, &jtable_offset_mem_pattern,
   [](vector<analysis::JTableOffsetMem>& res, Binary* x, const Loc& loc) {
      auto L = loc.insn->offset();
      char op = (x->op() == Binary::OP::PLUS  ? '+' :
                (x->op() == Binary::OP::MINUS ? '-' : 0));
      if (op != 0) {
         array<ExprLoc,2> args;
         for (int i = 0; i < 2; ++i)
            args[i] = ExprLoc(x->operand(i)->simplify(), loc);
         for (int i = 0; i < (op == '+'? 2: 1); ++i) {
            udQueue.clear();
            auto offset = jtable_base_pattern(args[i]);
            if (!offset.empty()) {
               auto mem = jtable_mem_pattern(args[1-i]);
               if (mem.size() > 0) {
                  if (offset.size() > 1)
                     LOG(3, "warning: multiple code offsets share same "
                            "jump table base!");
                  for (auto o: offset)
                  for (auto m: mem)
                     res.push_back(analysis::JTableOffsetMem(o, op, m, L));
                  return;
               }
            }
         }
      }
   });
}


analysis::JTable Function::jump_table_analysis() {
   time_start(start1);
   analysis::JTable res;
   for (auto scc: scc_list())
   for (auto b: scc->block_list())
   for (auto i: b->insn_list())
      if (i->jump() && i->indirect()) {
         auto exprLoc = ExprLoc(i->indirect_target(), Loc(this, scc, b, i));
         auto jumpLoc = i->offset();
         /* type 1 */
         auto vec1 = jtable_offset_mem_pattern(exprLoc);
         if (!vec1.empty()) {
            for (auto v: vec1)
               res.add(jumpLoc, v);
            continue;
         }
         /* type 2 */
         auto vec2 = jtable_addr_stride_pattern(exprLoc);
         if (!vec2.empty()) {
            for (auto v: vec2)
               res.add(jumpLoc, v);
            continue;
         }
         /* type 3 */
         auto vec3 = jtable_mem_pattern(exprLoc);
         if (!vec3.empty()) {
            for (auto v: vec3)
               res.add(jumpLoc, v);
            continue;
         }
      }
   udQueue.clear();
   time_stop(Framework::time_jump_table, start1);
   return res;
}
