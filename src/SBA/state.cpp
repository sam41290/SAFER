/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "state.h"
#include "function.h"
#include "scc.h"
#include "block.h"
#include "insn.h"

using namespace SBA;
/* -------------------------------------------------------------------------- */
static Insn* binary_search(const vector<Insn*>& insnList, int offset) {
   /* find the right most instruction whose offset < offset */
   if (insnList.empty() || insnList.at(0)->offset() >= offset)
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
/* --------------------------------- State ---------------------------------- */
template<class T> State<T>::State(bool cstr, bool weak_update, bool clobber_mem,
bool approx_range, bool call_effect, bool fixpoint, bool logs,
function<BaseDomain*(const UnitId&)>* init,
const unordered_set<Insn*>& taint_src):
AbsState(cstr, weak_update, clobber_mem, approx_range, call_effect, fixpoint,
logs, T::NAME, init, taint_src) {
   auto& main = state_[(int)CHANNEL::MAIN];
   replace(main[get_sym(REGION::STACK, _oo)][nullptr], BaseDomain::TOP);
   replace(main[get_sym(REGION::STACK, oo)][nullptr], BaseDomain::TOP);
   replace(main[get_sym(REGION::STATIC, _oo)][nullptr], BaseDomain::TOP);
   replace(main[get_sym(REGION::STATIC, oo)][nullptr], BaseDomain::TOP);
   if (enable_cstr_)
      replace(cstr_[nullptr], CstrDomain<T>::create());
}


template<class T> State<T>::State(bool cstr, bool weak_update, bool clobber_mem,
bool approx_range, bool call_effect, bool fixpoint, bool logs,
function<BaseDomain*(const UnitId&)>* init):
AbsState(cstr, weak_update, clobber_mem, approx_range, call_effect, fixpoint,
logs, T::NAME, init, unordered_set<Insn*>{}) {}


template<class T> State<T>::~State() {
   clear(CHANNEL::INSN);
   clear(CHANNEL::BLOCK);
   clear(CHANNEL::MAIN);
   if (enable_cstr_) {
      for (auto const& [b, c]: cstr_)
         BaseDomain::safe_delete(c);
      cstr_.clear();
   }
}


template<class T> BaseDomain* State<T>::value_unit(const UnitId& id) {
   use(id);
   auto res = load(id, CHANNEL::BLOCK, loc.scc, loc.block);
   if (enable_cstr_ && !id.flag()) {
      auto cstr = cstr_[loc.block];
      if (!cstr->bot()) {
         if (res->ref() > 1) {
            res = res->clone();
            replace(state_[(int)CHANNEL::BLOCK][get_sym(id)][loc.block], res);
         }
         CstrDomain<T>::use_cstr(cstr, res, id);
      }
   }
   print_logs("value", id, res);
   return res;
}


template<class T> BaseDomain* State<T>::value_range(const UnitId& lo,
const UnitId& hi, uint8_t stride) {
   auto lo_boundness = lo.boundness();
   auto hi_boundness = hi.boundness();
   BaseDomain* res = BaseDomain::BOT;

   #if DEBUG_MODE > 2
      auto tmp = enable_logs_;   
      enable_logs_ = false;
   #endif

   if (enable_approx_range_ && hi.i() - lo.i() > APPROX_RANGE_SIZE)
      res = BaseDomain::TOP;
   if (lo_boundness != 0)
      res = value_unit(lo);
   if (hi_boundness != 0 && lo != hi) {
      res = (res->ref() > 0)? res->clone(): res;
      res = res->abs_union(value_unit(hi));
   }
   if (lo_boundness != 1 && hi_boundness != -1) {
      auto r = lo.r();
      auto l = std::max(lo.i(), get_bound(r,0));
      auto h = std::min(hi.i(), get_bound(r,1));
      for (auto i = l; i <= h; i += stride) {
         auto v = value_unit(get_id(r,i));
         res = (res->ref() > 0)? res->clone(): res;
         res = res->abs_union(v);
         if (res->top())
            break;
      }
   }

   #if DEBUG_MODE > 2
      enable_logs_ = tmp;
   #endif

   print_logs("value", lo, hi, res);
   return res;
}


template<class T> void State<T>::update_unit(const UnitId& id,
BaseDomain* src_val, const ExprId& src_expr) {
   define(id);
   if (enable_cstr_) {
      if (!id.flag())
         assign_cstr(id, src_expr);
      else {
         if (src_val->top())
            src_val = FlagDomain<T>::create();
      }
   }

   if (enable_taint_ && taint_src_.contains(loc.insn))
      src_val = src_val->tainted_val(loc.insn);

   store_s(id, src_val);
   print_logs("strong update", id, src_val);
}


template<class T> void State<T>::update_range(const UnitId& lo,
const UnitId& hi, uint8_t stride, BaseDomain* src_val, const ExprId& src_expr) {
   auto lo_boundness = lo.boundness();
   auto hi_boundness = hi.boundness();
   auto r = lo.r();

   if (enable_approx_range_ && hi.i() - lo.i() > APPROX_RANGE_SIZE) {
      clobber(r);
      return;
   }

   if (enable_taint_ && taint_src_.contains(loc.insn))
      src_val = src_val->tainted_val(loc.insn);

   if (lo_boundness != 0) {
      store_w(lo, src_val);
      print_logs("weak update", lo, lo, src_val);
   }
   if (hi_boundness != 0 && lo != hi) {
      store_w(hi, src_val);
      print_logs("weak update", hi, hi, src_val);
   }
   if (lo_boundness != 1 && hi_boundness != -1) {
      auto l = std::max(lo.i(), get_bound(r,0));
      auto h = std::min(hi.i(), get_bound(r,1));
      /* strong update when lo == hi after normalization */
      /* strong update is recorded as a definition       */
      if (l == h) {
         update_unit(get_id(r,l), src_val, src_expr);
         for (int j = 1; j < stride; ++j)
            store_s(get_id(r,l+j), BaseDomain::TOP);
      }
      /* weak update when lo < hi after normalization */
      /* weak update is not recorded as a definition  */
      else {
         for (auto i = l; i <= h; i += stride) {
            store_w(get_id(r,i), src_val);
            for (int j = 1; j < stride; ++j)
               store_w(get_id(r,i+j), BaseDomain::TOP);
         }
         print_logs("weak update", lo, hi, src_val);
      }
   }
}


template<class T> void State<T>::clobber(REGION r) {
   if (enable_weak_update_) {
      auto& uloc = clobber_[(int)r][loc.block];
      if (uloc.empty() || uloc.back()->offset() < loc.insn->offset())
         uloc.push_back(loc.insn);
      print_logs(string("clobber: ").append(r==REGION::STACK?"stack":"static"));
   }
}


template<class T> void State<T>::clobber(const UnitId& id) {
   auto src_val = enable_cstr_ && id.flag()?
                  FlagDomain<T>::create(): BaseDomain::TOP;
   update_unit(id, src_val);
}


template<class T> void State<T>::preset(const UnitId& id) {
   auto src_val = enable_cstr_ && id.flag()?
                  FlagDomain<T>::create(): BaseDomain::TOP;
   state_[(int)CHANNEL::MAIN][get_sym(id)][loc.block] = src_val;
   BaseDomain::save(src_val);
}


template<class T> bool State<T>::commit(CHANNEL ch) {
   auto change = false;
   for (auto& [sym, uval]: state_[(int)ch]) {
      auto  src = uval[loc.block];
      auto& dst = state_[(int)ch-1][sym][loc.block];
      /* track change only when commit block -> main */
      if (ch == CHANNEL::BLOCK && !change)
         change = src->equal(dst);
      replace(dst, src);
      BaseDomain::discard(src);
   }
   state_[(int)ch].clear();
   return change;
}


template<class T> void State<T>::clear() {
   clear(CHANNEL::BLOCK);
}


template<class T> void State<T>::refresh() {
   loc.insn = nullptr;

   if (enable_cstr_) {
      value_unit(UnitId::FLAG);
      auto c = BaseDomain::BOT;
      auto resc = BaseDomain::BOT;
      auto& cflag = state_[(int)CHANNEL::MAIN][cflagSym];
      /* predecessors p in current SCC */
      for (auto const& p: loc.scc->pred(loc.block)) {
         c = (!cflag.contains(p))? CstrDomain<T>::create():
             CstrDomain<T>::create(p->cond(loc.block), cflag[p]);
         if (cstr_.contains(p))
            CstrDomain<T>::abs_and(c, cstr_[p]);
         CstrDomain<T>::abs_ior(resc, c);
         if (resc != c)
            BaseDomain::safe_delete(c);
      }
      /* predecessors p in predecessor SCCs */
      for (auto const& p: loc.scc->pred_ext(loc.block))
      if (p != nullptr) {
         c = (!cflag.contains(p))? CstrDomain<T>::create():
             CstrDomain<T>::create(p->cond(loc.block), cflag[p]);
         if (cstr_.contains(p))
            CstrDomain<T>::abs_and(c, cstr_[p]);
         CstrDomain<T>::abs_ior(resc, c);
         if (resc != c)
            BaseDomain::safe_delete(c);
      }
      replace(cstr_[loc.block], resc);
   }

   for (auto const& id: refresh_[loc.block])
      if (!id.flag())
         value_unit(id);
}
/* -------------------------------------------------------------------------- */

   /*--------------------------------------------------+
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
   |   |     |      |--- b == loc.block        |   |   |
   |   |     |      |--- ch == CHANNEL::BLOCK  |   |   |
   |   |     |    effect before loc.insn       |   |   |
   |   |     |      |--- clobber_              |   |   |
   |   |     |      |--- def_                  |   |   |
   |   |     |      |--- neither of both       |   |   |
   |   |     |    if effect == clobber_ -> TOP |   |   |
   |   |     |    otherwise, return stored val |   |   |
   |   |     +---------------------------------+   |   |
   |   |     | -> after execution:             |   |   |
   |   |     |    verify the case:             |   |   |
   |   |     |      |--- b != loc.block        |   |   |
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

   /* ---------- resolve cyclic dependency ---------- */
   /* (1b) if current channel has stored value, it is */
   /* the latest value                                */
   /* ---------- causes of BOT being stored --------- */
   /*                 entry  -> A                     */
   /*                     A <-> B                     */
   /*                     A  -> C                     */
   /*                     B  -> D                     */
   /* ----------------------------------------------- */
   /* suppose we track back at C, then at D           */
   /*    (i)  C visits A                              */
   /*         --> A visits B                          */
   /*             --> B can't visit A                 */
   /*                 B = BOT                         */
   /*         --> A visit entry                       */
   /*             entry = v                           */
   /*             A = v                               */
   /*    (ii) D visits B                              */
   /*         B = BOT                                 */
   /*         D = BOT                                 */
   /* ----------------------------------------------- */
   /* storing BOT is an undesired side effect during  */
   /* tracking at C: it doesn't affect track result   */
   /* at C, but might affect other tracking results   */
   /*                                                 */
   /* BOT is always unsound and should not be treated */
   /* as track-finished value, when encountering BOT, */
   /* we need to track back -> skip to (1a)           */
   /* ----------------------------------------------- */

template<class T> BaseDomain* State<T>::load(const UnitId& id, CHANNEL channel,
SCC* sccom, Block* block) {
   auto const& r = id.r();
   auto sym = get_sym(id);
   auto& val_main  = state_[(int)CHANNEL::MAIN][sym];
   auto& val_block = state_[(int)CHANNEL::BLOCK][sym];
   unordered_set<Block*> visited;

   function<BaseDomain*(CHANNEL,SCC*,Block*)> load_value =
   [&](CHANNEL ch, SCC* scc, Block* b) -> BaseDomain* {
      visited.insert(b);
      auto& val = (ch==CHANNEL::BLOCK)? val_block: val_main;

      /* generate initial state on demand */
      if (b == nullptr)
         replace(val[nullptr], (*init_)(id));

      /* check for clobber effect (stack and static) */
      if (r == REGION::STACK || r == REGION::STATIC) {
         auto const& c = clobber_[(int)r];
         auto const& d = def_[sym];
         auto it_c = c.find(b);
         auto it_d = d.find(b);
         Insn* recent_c = nullptr;  /* most recent clobber */
         Insn* recent_d = nullptr;  /* most recent def     */

         /* case 1: during execution of block b (ignore refresh) */
         if (b == loc.block && loc.insn != nullptr) {
            auto offset = loc.insn->offset();
            if (it_c != c.end())
               recent_c = binary_search(it_c->second, offset);
            if (it_d != d.end())
               recent_d = binary_search(it_d->second, offset);
         }
         /* case 2: after execution of block b */
         else {
            if (it_c != c.end())
               recent_c = it_c->second.back();
            if (it_d != d.end())
               recent_d = it_d->second.back();
         }
         /* if clobber overrides def --> TOP */
         if (recent_c != nullptr &&
         (recent_d == nullptr || recent_d->offset() < recent_c->offset())) {
            if (enable_cstr_) {
               auto& flag_val = state_[(int)ch][flagSym];
               if (flag_val.contains(b))
                  FlagDomain<T>::invalidate(flag_val[b], r);
               if (cstr_.contains(b))
                  CstrDomain<T>::invalidate(cstr_[b], r);
            }
            return BaseDomain::TOP;
         }
      }

      /* check for stored value */
      auto it = val.find(b);
      if (it != val.end() && !it->second->bot())
         return it->second;

      /* ---------------------------------------------------------------- */
      /* (1a) if current channel has no stored value, track predecessors  */
      /*      in main channel, mark refresh for predecessor if applicable */
      auto res = BaseDomain::BOT;

      /* predecessors p in current SCC */
      for (auto const& p: scc->pred(b))
         /* not visit a block in current SCC twice */
         if (!visited.contains(p)) {
            /* (+) pscc is already finalized, so only mark refresh for id */
            /*     from predecessors in current SCC                       */
            /* (+) to avoid duplicate refresh, only mark for the first    */
            /*     time track back p --> val_main[p] not existed          */
            if (scc == loc.scc && !val_main.contains(p))
               refresh_[p].push_back(id);

            auto v = BaseDomain::BOT;
            auto c = BaseDomain::BOT;
            if (enable_cstr_ && !id.flag()) {
               auto& cflag = state_[(int)CHANNEL::MAIN][cflagSym];
               c = (!cflag.contains(p))? CstrDomain<T>::create():
                   CstrDomain<T>::create(p->cond(b), cflag[p]);
               if (cstr_.contains(p))
                  CstrDomain<T>::abs_and(c, cstr_[p]);
               v = load_value(CHANNEL::MAIN, scc, p)->clone();
               CstrDomain<T>::use_cstr(c, v, id);
               BaseDomain::safe_delete(c);
            }
            else
               v = load_value(CHANNEL::MAIN, scc, p);

            if (res->ref() > 0)
               res = res->clone();
            res = res->abs_union(v);
            if (v->ref() == 0 && res != v)
               BaseDomain::safe_delete(v);
         }

      /* predecessors p in predecessor SCCs pscc */
      for (auto const& p: scc->pred_ext(b)) {
         /* if p in scc, might return BOT                   */
         /* --> cyclic dependency                           */
         /* if p in pscc, never return BOT                  */
         /* --> exist path to entry, which init everything  */
         /* --> retrack blocks already assigned to BOT as   */
         /*     some nodes in pscc might have values from   */
         /*     previous tracking attempt, e.g., retrack B  */
         /* --> retrack a node in pscc is enabled by reset  */
         /*     visited, force same-scc track for pscc      */
         auto pscc = (p != nullptr)? p->container: nullptr;
         if (pscc != nullptr)
            for (auto a: pscc->block_list())
               visited.erase(a);

         auto v = BaseDomain::BOT;
         auto c = BaseDomain::BOT;
         if (enable_cstr_ && !id.flag()) {
            auto& cflag = state_[(int)CHANNEL::MAIN][cflagSym];
            c = (!cflag.contains(p))? CstrDomain<T>::create():
                CstrDomain<T>::create(p->cond(b), cflag[p]);
            if (cstr_.contains(p))
               CstrDomain<T>::abs_and(c, cstr_[p]);
            v = load_value(CHANNEL::MAIN, pscc, p)->clone();
            CstrDomain<T>::use_cstr(c, v, id);
            BaseDomain::safe_delete(c);
         }
         else
            v = load_value(CHANNEL::MAIN, pscc, p);

         if (res->ref() > 0)
            res = res->clone();
         res = res->abs_union(v);
         if (v->ref() == 0 && res != v)
            BaseDomain::safe_delete(v);
      }

      /* store res to block b */
      replace(val[b], res);
      return res;
   };

   auto res = load_value(channel, sccom, block);
   return res;
}


template<class T> void State<T>::assign_cstr(const UnitId& dst,
const ExprId& src_expr) {
   auto& f = state_[(int)CHANNEL::BLOCK][flagSym][loc.block];
   auto& c = cstr_[loc.block];
   /* propagation might alter flags and cstrs shared with others -> clone */
   if (f->ref() > 1)
      replace(f, f->clone());
   if (c->ref() > 1)
      replace(c, c->clone());
   FlagDomain<T>::invalidate(f, dst, src_expr);
   CstrDomain<T>::assign_cstr(c, dst, src_expr);
}


template<class T> void State<T>::store_s(const UnitId& id, BaseDomain* v) {
   /* no need to discard previous value in channel insn */
   state_[(int)CHANNEL::INSN][get_sym(id)][loc.block] = v;
   BaseDomain::save(v);
}


template<class T> void State<T>::store_w(const UnitId& id, BaseDomain* v) {
   /* no need to discard previous value in channel insn */
   if (enable_weak_update_) {
      auto out = value_unit(id)->clone();
      out = out->abs_union(v);
      state_[(int)CHANNEL::INSN][get_sym(id)][loc.block] = out;
      BaseDomain::save(out);
   }
}


template<class T> void State<T>::replace(BaseDomain*& out, BaseDomain* v) {
   BaseDomain::save(v);
   BaseDomain::discard(out);
   out = v;
}


template<class T> void State<T>::clear(CHANNEL ch) {
   for (auto const& [sym, uval]: state_[(int)ch])
   for (auto const& [b, v]: uval)
      BaseDomain::discard(v);
   state_[(int)ch].clear();
}


template<class T> void State<T>::define(const UnitId& id) {
   auto& uloc = def_[get_sym(id)][loc.block];
   if (uloc.size() == 0 || uloc.back()->offset() < loc.insn->offset())
      uloc.push_back(loc.insn);
}


template<class T> void State<T>::use(const UnitId& id) {
   /* ignore if invoked from refresh() */
   if (loc.insn == nullptr)
      return;
   auto& uloc = use_[get_sym(id)][loc.block];
   if (uloc.size() == 0 || uloc.back()->offset() < loc.insn->offset())
      uloc.push_back(loc.insn);
}
/* -------------------------------------------------------------------------- */
template<class T> vector<Loc> State<T>::use_def(const UnitId& id, const Loc& l) {
   vector<Loc> res;
   auto& d_record = def_[get_sym(id)];

   /* (a) binary search: find the most recent def in l.block */
   auto recent_d = binary_search(d_record[l.block], l.insn->offset());
   if (recent_d != nullptr)
      res.push_back(Loc{l.func, l.scc, l.block, recent_d});

   /* (b) find defs from predecessor blocks */
   else {
      stack<Block*> st;
      st.push(l.block);
      unordered_set<Block*> visited({nullptr});

      while (!st.empty()) {
         auto b = st.top();
         auto scc = b->container;
         st.pop();

         /* if block b defines id -> return last def, stop track back  */
         /* note that l.block is already checked (a) -> ignore l.block */
         auto& tmp = d_record[b];
         if (b != l.block && !tmp.empty())
            res.push_back(Loc{l.func, b->container, b, tmp.back()});

         /* if block b not define id -> track back */
         else {
            visited.insert(b);
            /* predecessors p in current SCC */
            for (auto const& p: scc->pred(b))
               if (!visited.contains(p))
                  st.push(p);
            /* predecessors p in predecessor SCCs pscc */
            for (auto const& p: scc->pred_ext(b))
               if (!visited.contains(p))
                  st.push(p);
         }
      }
   }

   return res;
}


template<class T> vector<Loc> State<T>::def_use(const UnitId& id, const Loc& l) {
   vector<Loc> res;
   auto sym = get_sym(id);
   auto& u_record = use_[sym];
   auto& d_record = def_[sym];
   stack<Block*> st;

   /* --------------- find uses in l.block --------------- */
   /* note: at this point, we only process part of l.block */
   /*       since there could be a loop where l.block will */
   /*       later use definition in l.insn, we do not mark */
   /*       l.block as a visited block.                    */

   /* find def immediately following l.insn */
   Insn* next_d = nullptr;
   for (auto i: d_record[l.block])
      if (i->offset() > l.insn->offset()) {
         next_d = i;
         break;
      }
   /* if redefine in l.block, not navigate successors */
   if (next_d != nullptr) {
      for (auto i: u_record[l.block])
         /* note: not yet support (sequence (def id) (use id)) */
         if (i->offset() > l.insn->offset()) {
            if (i->offset() <= next_d->offset())
               res.push_back(Loc{l.func, l.scc, l.block, i});
            else
               break;
         }
   }
   /* if not redefine in block b, navigate successors */
   else {
      for (auto i: u_record[l.block])
         if (i->offset() > l.insn->offset())
            res.push_back(Loc{l.func, l.scc, l.block, i});

      for (uint8_t i = 0; i < l.block->num_succ(); ++i)
         st.push(l.block->succ(i));
      if (l.block->succ_ind() != nullptr)
         for (auto s: *(l.block->succ_ind()))
            st.push(s);
   }

   /* ------------- find uses in successors -------------- */
   unordered_set<Block*> visited;

   while (!st.empty()) {
      auto b = st.top();
      auto scc = b->container;
      st.pop();
      visited.insert(b);

      /* if redefine in block b, not navigate successors */
      if (!d_record[b].empty()) {
         auto first_d = d_record[b].front()->offset();
         /* note: not yet support (sequence (def id) (use id)) */
         for (auto i: u_record[b])
            if (i->offset() <= first_d)
               res.push_back(Loc{l.func, scc, b, i});
            else
               break;
      }
      /* if not redefine in block b, navigate successors */
      else {
         for (auto i: u_record[b])
            res.push_back(Loc{l.func, scc, b, i});
         /* successors s in current SCC */
         for (uint8_t i = 0; i < l.block->num_succ(); ++i) {
            auto s = l.block->succ(i);
            if (!visited.contains(s))
               st.push(s);
         }
         if (l.block->succ_ind() != nullptr)
            for (auto s: *(l.block->succ_ind()))
               if (!visited.contains(s))
                  st.push(s);
      }
   }

   return res;
}
/* -------------------------------------------------------------------------- */
template<class T> void State<T>::print_logs(const string& task) {
   if (enable_logs_)
      LOG3(name_ << task);
}


template<class T> void State<T>::print_logs(const string& task,
const UnitId& id, BaseDomain* v) {
   if (enable_logs_) {
      LOG3(name_ << task << ": " << id.to_string() << " = "
         << v->to_string());
      if (enable_cstr_ && !id.flag())
         print_flags_cstr(task);
   }
}


template<class T> void State<T>::print_logs(const string& task,
const UnitId& lo, const UnitId& hi, BaseDomain* v) {
   if (enable_logs_) {
      LOG3(name_ << task << ": " << lo.to_string() << " .. "
         << hi.to_string() << " = " << v->to_string());
      if (enable_cstr_)
         print_flags_cstr(task);
   }
}


template<class T> void State<T>::print_flags_cstr(const string& task) {
   LOG4(string(name_.length() + task.length() + 2, ' ') << "flags = " <<
        state_[(int)CHANNEL::BLOCK][flagSym][loc.block]->to_string() << "\n" <<
        string(name_.length() + task.length() + 2, ' ') << "cstrs = " <<
        cstr_[loc.block]->to_string());
}

STATE_INSTANT
