/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "state.h"
#include "function.h"
#include "basicblock.h"
#include "insn.h"
/* -------------------------------------------------------------------------- */
static int64_t loadSym;
static REGION loadRegion;
static UnitVal* val_main;
static UnitVal* val_block;
static unordered_set<BasicBlock*> blockVisited;

static Insn* binary_search(const vector<Insn*>& insnList, int offset) {
   if (insnList.size() == 0 || insnList.at(0)->offset() >= offset)
      return nullptr;
   int l = 0;
   int r = insnList.size();
   while (l + 1 < r) {
      int m = (l + r) >> 1;
      if (insnList.at(m)->offset() < offset)
         l = m;
      else
         r = m;
   }
   return insnList.at(l);
}
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* -------------------------------- AbsState -------------------------------- */
template<class T> AbsState<T>::AbsState(bool cstrMode, bool weakUpdate,
bool clobberMem, bool approxRange, bool calleeEffect, bool fixpoint,
bool printLogs) {
   cstrMode_ = cstrMode;
   weakUpdate_ = weakUpdate;
   clobberMem_ = clobberMem;
   approxRange_ = approxRange;
   calleeEffect_ = calleeEffect;
   fixpoint_ = fixpoint;
   printLogs_ = printLogs;
   domainName_ = string("*").append(T::NAME).append(cstrMode? "-cstr*":"*");
   domainName_.append(string(max_domain_length + 8 - domainName_.length(), ' '));
}


template<class T> AbsState<T>::~AbsState() {
   clear(CHANNEL::INSN);
   clear(CHANNEL::BLOCK);
   clear(CHANNEL::MAIN);
   if (cstrMode_) {
      for (auto const& [b, c]: cstrValue_)
         BaseDomain::safe_delete(c);
      cstrValue_.clear();
   }
}


template<class T> BaseDomain* AbsState<T>::value_unit(const UnitId& id) {
   auto loadId = (id.bounds_check())? id: UnitId::outBoundId(id.r());
   loadSym = loadId.symbol();
   loadRegion = loadId.r();
   val_main  = &(state_[(int)CHANNEL::MAIN][loadSym]);
   val_block = &(state_[(int)CHANNEL::BLOCK][loadSym]);
   blockVisited.clear();
   auto res = load_value(CHANNEL::BLOCK, loc_.scc, loc_.block);
   if (cstrMode_ && !loadId.is_flags() && !loadId.is_ctrl()) {
      auto constraint = cstrValue_[loc_.block];
      if (!constraint->bot()) {
         if (res->ref() > 1) {
            res = res->clone();
            replace(state_[(int)CHANNEL::BLOCK][loadSym][loc_.block], res);
         }
         CstrDomain<T>::use_cstr(constraint, res, loadId);
      }
   }
   print_logs("value", id, res);
   return res;
}


template<class T> BaseDomain* AbsState<T>::value_range(const UnitId& lo,
const UnitId& hi) {
   /* normalize range */
   auto r = lo.r();
   if (lo.i() > hi.i()) {
      print_logs("value", lo, hi, BaseDomain::BOT);
      return BaseDomain::BOT;
   }
   else if (lo.i() > boundRange(r,1) || hi.i() < boundRange(r,0)) {
      auto res = value_unit(UnitId::outBoundId(r));
      print_logs("value", lo, hi, res);
      return res;
   }

   auto l = std::max(lo.i(), boundRange(r,0));
   auto h = std::min(hi.i(), boundRange(r,1));

   /* if range is too large, return TOP with appropriate configuration */
   if (approxRange_ && h - l > rangeLimit) {
      print_logs("value", lo, hi, BaseDomain::TOP);
      return BaseDomain::TOP;
   }

   /* if [lo, hi] covers out-of-bounds, init with out-of-bounds value */

   auto res = (lo.bounds_check() && hi.bounds_check())? BaseDomain::BOT:
              value_unit(UnitId::outBoundId(r))->clone();
   for (int i = l; i <= h; ++i) {
      /* not modify a stored value */
      if (res->ref() > 0)
         res = res->clone();
      /* union with value at location i */
      auto id = UnitId(r, i);
      auto v = value_unit(id);
      res = res->abs_union(v);
      /* if res is TOP, stop */
      if (res->top())
         break;
   }
   print_logs("value", lo, hi, res);

   return res;
}


template<class T> void AbsState<T>::update_unit(const UnitId& dst,
BaseDomain* src_val, const CompareArgsId& src_expr) {
   auto storeId = (dst.bounds_check())? dst: UnitId::outBoundId(dst.r());
   if (cstrMode_) {
      if (!storeId.is_flags() && !storeId.is_ctrl())
         propagate(dst, src_expr);
      else if (src_val->top())
         src_val = FlagDomain<T>::create_instance();
   }
   define(storeId);
   store_s(storeId, src_val);
   print_logs("strong update", dst, src_val);
}


template<class T> void AbsState<T>::update_range(const UnitId& lo,
const UnitId& hi, BaseDomain* src_val, const CompareArgsId& src_expr) {
   /* normalize range */
   auto r = lo.r();
   if (lo.i() > hi.i())
      return;
   else if (lo.i() > boundRange(r,1) || hi.i() < boundRange(r,0)) {
      auto id = UnitId::outBoundId(r);
      store_w(id, src_val);
      print_logs("weak update", id, src_val);
      return;
   }

   auto l = std::max(lo.i(), boundRange(r,0));
   auto h = std::min(hi.i(), boundRange(r,1));

   /* if range is too large, clobber region with appropriate configuration */
   if (approxRange_ && h - l > rangeLimit) {
      clobber(r);
      return;
   }

   /* if [lo, hi] covers out-of-bounds, weak update on out-of-bounds value */
   /* weak update is not recorded as a definition  */
   if (!(lo.bounds_check() && hi.bounds_check())) {
      auto id = UnitId::outBoundId(r);
      store_w(id, src_val);
      print_logs("weak update", id, src_val);
   }

   /* strong update when lo == hi after normalization */
   /* strong update is recorded as a definition  */
   if (l == h) {
      auto id = UnitId(r, l);
      update_unit(id, src_val, src_expr);
   }

   /* weak update when lo < hi after normalization */
   /* weak update is not recorded as a definition  */
   else if (l < h) {
      for (int i = l; i <= h; ++i) {
         auto id = UnitId(r, i);
         store_w(id, src_val);
      }
      print_logs("weak update", lo, hi, src_val);
   }
}


template<class T> void AbsState<T>::init(const function<BaseDomain*(UnitId)>&
f_init) {
   first_used_redef_ = -1;
   auto& mainState = state_[(int)CHANNEL::MAIN];
   for (int rr = 0; rr <= 2; ++rr) {
      auto r = (REGION)rr;
      if (r == REGION::STACK || r == REGION::STATIC) {
         auto id = UnitId::outBoundId(r);
         replace(mainState[id.symbol()][nullptr], BaseDomain::TOP);
      }
      for (int i = boundRange(r,0); i <= boundRange(r,1); ++i) {
         auto id = UnitId(r,i);
         if (!id.is_ctrl())
            replace(mainState[id.symbol()][nullptr], f_init(id));
      }
   }
   if (cstrMode_)
      cstrValue_[nullptr] = CstrDomain<T>::create_instance();
}


template<class T> void AbsState<T>::clobber(REGION r) {
   if (weakUpdate_ && clobberMem_) {
      auto& uloc = clobber_[(int)r][loc_.block];
      if (uloc.size() == 0 || uloc.back()->offset() < loc_.insn->offset())
         uloc.push_back(loc_.insn);
      print_logs(string("clobber: ").append(r==REGION::STACK?"stack":"static"));
   }
}


template<class T> void AbsState<T>::clobber(const UnitId& id) {
   update_unit(id, cstrMode_ && id.is_flags()? FlagDomain<T>::create_instance():
                   BaseDomain::TOP, CompareArgsId::EMPTY);
}


template<class T> void AbsState<T>::preset(const UnitId& id) {
   auto storeId = (id.bounds_check())? id: UnitId::outBoundId(id.r());
   auto storeVal = (cstrMode_ && id.is_flags())?
                   FlagDomain<T>::create_instance(): BaseDomain::TOP;
   store_s(storeId, storeVal);
   print_preset("preset", id, storeVal);
}


template<class T> bool AbsState<T>::commit(CHANNEL ch) {
   auto change = false;
   for (auto& [sym, uval]: state_[(int)ch]) {
      auto  valSource = uval[loc_.block];
      auto& valCommit = state_[(int)ch-1][sym][loc_.block];
      /* track change only when commit block -> main */
      if (ch == CHANNEL::BLOCK && !change)
         change = valSource->equal(valCommit);
      /* replace value */
      replace(valCommit, valSource);
      /* discard value from source channel */
      BaseDomain::discard(valSource);
   }
   /* clear current channel after commit */
   state_[(int)ch].clear();
   return change;
}


template<class T> void AbsState<T>::clear() {
   clear(CHANNEL::BLOCK);
}


template<class T> void AbsState<T>::refresh() {
   value_unit(UnitId::FLAGS);
   if (cstrMode_)
      load_cstr(loc_.scc, loc_.block);
   for (auto sym: refresh_[loc_.block])
      if (sym != flagSym)
         value_unit(UnitId::symbolId(sym));
}
/* -------------------------------------------------------------------------- */
template<class T> BaseDomain* AbsState<T>::load_value(CHANNEL ch, SCC* scc,
BasicBlock* b) {
   /*--------------------------------------------------+
   |                  passing blocks                   |
   +---------------------------------------------------+
   | 1. track back:                                    |
   |   +-------------------------------------------+   |
   |   | (a) before 1st execution and track back   |   |
   |   |     -> no stored value or just a BOT      |   |
   |   |     -> track back (main channel)          |   |
   |   |     -> store value (main channel)         |   |
   |   |     -> mark refresh                       |   |
   |   +-------------------------------------------+   |
   |   | (b) during execution                      |   |
   |   |     after execution                       |   |
   |   |     before execution (after track back)   |   |
   |   |     -> has latest value, either by        |   |
   |   |        -> already refreshed (executed)    |   |
   |   |        -> already tracked (not executed)  |   |
   |   |     -> not track back or mark refresh     |   |
   |   |     +---------------------------------+   |   |
   |   |     | clobber (stack and static)      |   |   |
   |   |     +---------------------------------+   |   |
   |   |     | -> before execution:            |   |   |
   |   |     |    not execute, rely on correct |   |   |
   |   |     |    result from predecessors     |   |   |
   |   |     +---------------------------------+   |   |
   |   |     | -> during execution:            |   |   |
   |   |     |    verify the case:             |   |   |
   |   |     |      |--- b == loc_.block       |   |   |
   |   |     |      |--- ch == CHANNEL::BLOCK  |   |   |
   |   |     |    effect before loc_.insn      |   |   |
   |   |     |      |--- clobber_              |   |   |
   |   |     |      |--- def_                  |   |   |
   |   |     |      |--- neither of both       |   |   |
   |   |     |    if effect == clobber_ -> TOP |   |   |
   |   |     |    otherwise, return stored val |   |   |
   |   |     +---------------------------------+   |   |
   |   |     | -> after execution:             |   |   |
   |   |     |    verify the case:             |   |   |
   |   |     |      |--- b != loc_.block       |   |   |
   |   |     |      |--- ch == CHANNEL::MAIN   |   |   |
   |   |     |    effect at the end of block b |   |   |
   |   |     |      |--- clobber_              |   |   |
   |   |     |      |--- def_                  |   |   |
   |   |     |      |--- neither of both       |   |   |
   |   |     |    if effect == clobber_ -> TOP |   |   |
   |   |     |    otherwise, return stored val |   |   |
   |   |     +---------------------------------+   |   |
   |   +-------------------------------------------+   |
   |   | ::note:: during track back ...            |   |
   |   |     -> not execute any block              |   |
   |   |     -> not visit any block twice          |   |
   |   |     -> mark predecessor SCCs refresh      |   |
   |   |        (+) no time cost, but those blocks |   |
   |   |            never get refreshed            |   |
   |   |        (+) some memory cost, so disable   |   |
   |   |            marking when out of current    |   |
   |   |            SCC during track back          |   |
   |   +-------------------------------------------+   |
   +---------------------------------------------------+
   | 2. refresh:                                       |
   |   +-------------------------------------------+   | 
   |   | (a) if block b is marked refresh for unit |   |
   |   |     x, store the union value of x from    |   |
   |   |     immediate predecessors (main channel) |   |
   |   |     to block b (block channel) before     |   |
   |   |     executing block b                     |   |
   |   +-------------------------------------------+   |
   |   | (b) in theory, if block b                 |   |
   |   |     (+) define x before use x             |   |
   |   |     (+) mark refresh for x                |   |
   |   |     we can remove refresh mark because    |   |
   |   |     that definition superseeds union      |   |
   |   |     before execution of block b, but      |   |
   |   |     it doesn't work with memory where     |   |
   |   |     each iteration affects different      |   |
   |   |     memory range -> keep refresh mark     |   |
   |   +-------------------------------------------+   |
   |   | ::note::                                  |   |
   |   |     -> must take clobber into account     |   |
   |   +-------------------------------------------+   |
   +--------------------------------------------------*/

   blockVisited.insert(b);
   auto unitVal = (ch == CHANNEL::BLOCK)? val_block: val_main;

   /* ---------------------------------------------------------------- */
   /* (1b) if current channel has stored value, it is the latest value */
   auto it = unitVal->find(b);

   /* ---------- causes of BOT being stored ---------- */
   /*                 entry  -> A                      */
   /*                     A <-> B                      */
   /*                     A  -> C                      */
   /*                     B  -> D                      */
   /* ------------------------------------------------ */
   /* suppose we track back at C, then at D            */
   /*    (i)  C visits A                               */
   /*         --> A visits B                           */
   /*             --> B can't visit A                  */
   /*                 B = BOT                          */
   /*         --> A visit entry                        */
   /*             entry = v                            */
   /*             A = v                                */
   /*    (ii) D visits B                               */
   /*         B = BOT                                  */
   /*         D = BOT                                  */
   /* ------------------------------------------------ */
   /* storing BOT is an undesired side effect during   */
   /* tracking at C: it doesn't affect tracking result */
   /* at C, but might affect other tracking results    */
   /*                                                  */
   /* BOT is always unsound and should not be treated  */
   /* as track-finished value, when encountering BOT,  */
   /* we need to track back -> skip to (1a)            */
   /* ------------------------------------------------ */
   if (it != unitVal->end() && !it->second->bot()) {
      auto storedVal = it->second;

      /* check for clobber effect (stack and static) */
      if (loadRegion != REGION::REGISTER) {
         auto& c = clobber_[(int)loadRegion][b];
         auto& d = def_[loadSym][b];
         Insn* recent_c = nullptr;        /* most recent clb */
         Insn* recent_d = nullptr;        /* most recent def */

         /* case 1: during execution of block b */
         if (b == loc_.block) {
            /* binary search: find most recent clobber before loc_.insn */
            auto offset = loc_.insn->offset();
            recent_c = binary_search(c, offset);
            recent_d = binary_search(d, offset);
         }
         /* case 2: after execution of block b */
         else {
            recent_c = (c.size() == 0? nullptr: c.back());
            recent_d = (d.size() == 0? nullptr: d.back());
         }

         /* if clobber found and def before clobber --> TOP */
         if (recent_c != nullptr &&
         (recent_d == nullptr || recent_d->offset() < recent_c->offset())) {
            if (cstrMode_) {
               auto& flagVal = state_[(int)ch][flagSym];
               if (flagVal.contains(b))
                  FlagDomain<T>::invalidate(flagVal[b], loadRegion);
               if (cstrValue_.contains(b))
                  CstrDomain<T>::invalidate(cstrValue_[b], loadRegion);
            }
            return BaseDomain::TOP;
         }
         /* if clobber not found or after def --> stored value */
         else
            return storedVal;
      }

      /* no clobber effect (register) --> stored value */
      else
         return storedVal;
   }

   /* ---------------------------------------------------------------- */
   /* (1a) if current channel has no stored value, track predecessors  */
   /*      in main channel, mark refresh for predecessor if applicable */

   /* res is union of all immediate predecessors, regardless their SCC */
   auto res = BaseDomain::BOT;

   /* predecessors p in current SCC */
   for (auto p: scc->pred(b))
      /* not visit a block in current SCC twice */
      if (!blockVisited.contains(p)) {
         /* (+) pscc is already finalized, so only mark refresh for id */
         /*     in predecessors in current SCC                         */
         /* (+) to avoid duplicate refresh marks, only mark for the    */
         /*     first time track back p --> val_main[p] not existed    */
         if (scc == loc_.scc && !val_main->contains(p))
            refresh_[p].push_back(loadSym);
         auto v = load_value(CHANNEL::MAIN, scc, p);
         if (res->ref() > 0)
            res = res->clone();
         res = res->abs_union(v);
      }

   /* predecessors p in predecessor SCCs pscc */
   for (auto [p, pscc]: scc->pred_scc(b)) {
      /* if p in scc, might return BOT                   */
      /* --> cyclic dependency                           */
      /* if p in pscc, never return BOT                  */
      /* --> exist path to entry, which init everything  */
      /* --> retrack blocks already assigned to BOT as   */
      /*     some nodes in pscc might have values from   */
      /*     previous tracking attempt, e.g., retrack B  */
      /* --> retrack a node in pscc is enabled by reset  */
      /*     blockVisited, force same-scc track for pscc */
      if (pscc != nullptr)
         for (auto a: pscc->block_list())
            blockVisited.erase(a);
      auto v = load_value(CHANNEL::MAIN, pscc, p);
      if (res->ref() > 0)
         res = res->clone();
      res = res->abs_union(v);
   }

   /* store res to block b */
   replace((*unitVal)[b], res);

   return res;
}


template<class T> void AbsState<T>::load_cstr(SCC* scc, BasicBlock* b) {
   auto c = BaseDomain::BOT;
   auto res = BaseDomain::BOT;
   auto& unitCtrl = state_[(int)CHANNEL::MAIN][ctrlSym];
   /* predecessors p in current SCC */
   for (auto p: scc->pred(b)) {
      c = (!unitCtrl.contains(p))? CstrDomain<T>::create_instance():
          CstrDomain<T>::create_instance(p->edge_cond(b), unitCtrl[p]);
      if (cstrValue_.contains(p))
         CstrDomain<T>::abs_and(c, cstrValue_[p]);
      if (res->ref() > 0)
         res = res->clone();
      CstrDomain<T>::abs_ior(res, c);
   }
   /* predecessors p in predecessor SCCs */
   for (auto [p, pscc]: scc->pred_scc(b)) {
      c = (!unitCtrl.contains(p))? CstrDomain<T>::create_instance():
          CstrDomain<T>::create_instance(p->edge_cond(b), unitCtrl[p]);
      CstrDomain<T>::abs_and(c, cstrValue_[p]);
      if (res->ref() > 0)
         res = res->clone();
      CstrDomain<T>::abs_ior(res, c);
   }
   replace(cstrValue_[b], res);
   BaseDomain::safe_delete(c);
}


template<class T> void AbsState<T>::propagate(const UnitId& dst,
const CompareArgsId& src_expr) {
   auto& f = state_[(int)CHANNEL::BLOCK][flagSym][loc_.block];
   auto& c = cstrValue_[loc_.block];
   /* propagation might alter flags and cstrs shared with others -> clone */
   if (f->ref() > 1)
      replace(f, f->clone());
   if (c->ref() > 1)
      replace(c, c->clone());
   FlagDomain<T>::invalidate(f, dst, src_expr);
   CstrDomain<T>::propagate(c, dst, src_expr);
}


template<class T> void AbsState<T>::store_s(const UnitId& id, BaseDomain* v) {
   state_[(int)CHANNEL::INSN][id.symbol()][loc_.block] = v;
   BaseDomain::save(v);
}


template<class T> void AbsState<T>::store_w(const UnitId& id, BaseDomain* v) {
   if (weakUpdate_) {
      auto out = value_unit(id)->clone();
      out = out->abs_union(v);
      state_[(int)CHANNEL::INSN][id.symbol()][loc_.block] = out;
      BaseDomain::save(out);
   }
}


template<class T> void AbsState<T>::replace(BaseDomain*& out, BaseDomain* v) {
   BaseDomain::save(v);
   BaseDomain::discard(out);
   out = v;
}


template<class T> void AbsState<T>::redefine(const UnitId& id) {
   if (first_used_redef_ == -1)
      first_used_redef_ = redef_.find(id.symbol()) == redef_.end()? -1: redef_[id.symbol()];
}


template<class T> void AbsState<T>::clear(CHANNEL ch) {
   for (auto const& [sym, uval]: state_[(int)ch])
   for (auto const& [b, v]: uval)
      BaseDomain::discard(v);
   state_[(int)ch].clear();
}


template<class T> void AbsState<T>::define(const UnitId& id) {
   if (redef_.find(id.symbol()) == redef_.end())
      redef_[id.symbol()] = loc_.insn->offset();
   auto& uloc = def_[id.symbol()][loc_.block];
   if (uloc.size()==0 || uloc.back()->offset() < loc_.insn->offset())
      uloc.push_back(loc_.insn);
}
/* -------------------------------------------------------------------------- */
template<class T> vector<Loc> AbsState<T>::ud_chain(const UnitId& id,
const Loc& l) {
   vector<Loc> res;
   auto& d_record = def_[id.symbol()];

   /* (a) binary search: find the most recent def in l.block */
   auto offset = l.insn->offset();
   auto recent_d = binary_search(d_record[l.block], offset);
   if (recent_d != nullptr) {
      auto defLoc = l;
      defLoc.insn = recent_d;
      res.push_back(defLoc);
   }

   /* (b) find defs from predecessor blocks */
   else {
      stack<pair<BasicBlock*,SCC*>> st;
      st.push(make_pair(l.block, l.scc));
      blockVisited.clear();
      blockVisited.insert(nullptr);

      while (!st.empty()) {
         auto [u, scc] = st.top();
         st.pop();
         blockVisited.insert(u);

         /* if block u defines id -> return last def, stop track back  */
         /* note that l.block is already checked (a) -> ignore l.block */
         if (u != l.block && d_record[u].size() > 0)
            res.push_back(Loc(l.func, scc, u, d_record[u].back()));

         /* if block u not define id -> track back */
         else {
            /* predecessors p in current SCC */
            for (auto p: scc->pred(u))
               if (!blockVisited.contains(p))
                  st.push(make_pair(p, scc));
            /* predecessors p in predecessor SCCs pscc */
            for (auto [p, pscc]: scc->pred_scc(u))
               if (!blockVisited.contains(p))
                  st.push(make_pair(p, pscc));
         }
      }
   }

   return res;
}
/* -------------------------------------------------------------------------- */
template<class T> void AbsState<T>::print_logs(const string& task) {
   if (printLogs_) {
      LOG(3, domainName_ << task);
   }
}


template<class T> void AbsState<T>::print_logs(const string& task,
const UnitId& id, BaseDomain* v) {
   if (printLogs_) {
      LOG(3, domainName_ << task << ": " << id.to_string() << " = "
         << v->to_string());
      if (cstrMode_ && !id.is_flags())
         print_flags_cstr(domainName_.length() + task.length() + 2);
   }
}


template<class T> void AbsState<T>::print_logs(const string& task,
const UnitId& lo, const UnitId& hi, BaseDomain* v) {
   if (printLogs_) {
      LOG(3, domainName_ << task << ": " << lo.to_string() << " .. "
         << hi.to_string() << " = " << v->to_string());
      if (cstrMode_)
         print_flags_cstr(domainName_.length() + task.length() + 2);
   }
}


template<class T> void AbsState<T>::print_preset(const string& task,
const UnitId& id, BaseDomain* v) {
   if (printLogs_) {
      LOG(3, domainName_ << task << ": " << id.to_string() << " = "
         << v->to_string());
   }
}


template<class T> void AbsState<T>::print_flags_cstr(int indent) {
   auto f = state_[(int)CHANNEL::BLOCK][flagSym][loc_.block];
   auto c = cstrValue_[loc_.block];
   LOG(4, string(indent, ' ') << "flags = " << f->to_string() << "\n"
      <<  string(indent, ' ') << "cstrs = " << c->to_string());
}
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* ---------------------- Template Class Instantiation ---------------------- */
INSTANTIATE_ABS_STATE