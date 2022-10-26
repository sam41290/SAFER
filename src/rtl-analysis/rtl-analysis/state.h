/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef ABS_STATE_H
#define ABS_STATE_H

#include "domain.h"
#include "common.h"
/* -------------------------------------------------------------------------- */
class Function;
class SCC;
class BasicBlock;
class Insn;
/* -------------------------------------------------------------------------- */
using UnitVal = unordered_map<BasicBlock*, BaseDomain*>;
using UnitLoc = unordered_map<BasicBlock*, vector<Insn*>>;
using ScopeId = unordered_map<BasicBlock*, vector<int64_t>>;
using StateVal = unordered_map<int64_t, UnitVal>;
using StateLoc = unordered_map<int64_t, UnitLoc>;
using RegionVal = array<StateVal,3>;
using RegionLoc = array<UnitLoc,3>;
/* -------------------------------- AbsState -------------------------------- */
class State {
 protected:
   bool cstrMode_;
   bool weakUpdate_;
   bool clobberMem_;
   bool approxRange_;
   bool calleeEffect_;
   bool fixpoint_;
   bool printLogs_;
   string domainName_;
   Loc loc_;

 public:
   virtual ~State() {};

   /* Methods related to state operator */
   virtual BaseDomain* value_unit(const UnitId& id) = 0;
   virtual BaseDomain* value_range(const UnitId& lo, const UnitId& hi) = 0;
   virtual void update_unit(const UnitId& dst, BaseDomain* src_val,
                            const CompareArgsId& src_expr) = 0;
   virtual void update_range(const UnitId& lo, const UnitId& hi, BaseDomain* src_val,
                             const CompareArgsId& src_expr) = 0;
   virtual void init(const function<BaseDomain*(UnitId)>& f_init) = 0;
   virtual void clobber(REGION r) = 0;
   virtual void clobber(const UnitId& id) = 0;
   virtual void preset(const UnitId& id) = 0;
   virtual bool commit(CHANNEL ch) = 0;
   virtual void clear() = 0;
   virtual void refresh() = 0;

   /* Methods related to use-def chain */;
   virtual vector<Loc> ud_chain(const UnitId& id, const Loc& l) = 0;

   /* Read accessors */
   virtual bool cstr_mode() const {return cstrMode_;};
   virtual bool callee_effect() const {return calleeEffect_;};
   virtual bool fixpoint() const {return fixpoint_;};
   virtual Loc& loc() {return loc_;};
};

template<class T> class AbsState: public State {
 protected:
   /* States */
   /*---------+--------------------------------------------+
   |  channel | state                                      |
   +----------+--------------------------------------------+
   |  main    | (1) store:                                 |
   |          |     - committed state of every block       |
   |          |     - partial state of passing blocks      |
   |          |     - initial state (block "nullptr")      |
   |          | (2) input:                                 |
   |          |     - main channel (predecessor blocks)    |
   |          | (3) refresh:                               |
   |          |     - partial state of passing blocks      |
   |          |       is refreshed prior before executing  |
   |          |       those blocks                         |
   +----------+--------------------------------------------+
   |  block   | (1) store:                                 |
   |          |     - state of a block during execution    |
   |          | (2) input:                                 |
   |          |     - block channel (current block)        |
   |          |     - main channel (predecessor blocks)    |
   |          | (3) commit:                                |
   |          |     - main channel                         |
   |          |       (after complete execution of block)  |
   +----------+--------------------------------------------+
   |  insn    | (1) store:                                 |
   |          |     - new state of an insn                 |
   |          | (2) input:                                 |
   |          |     - block channel (current block)        |
   |          | (3) commit:                                |
   |          |     - block channel                        |
   |          |       (after complete execution of insn)   |
   +----------+-------------------------------------------*/
   RegionVal state_;
   UnitVal cstrValue_;
   StateLoc def_;
   RegionLoc clobber_;
   ScopeId refresh_;
   unordered_map<int64_t,int64_t> redef_;

 public:
   AbsState() {};
   AbsState(bool cstrMode, bool weakUpdate, bool clobberMem, bool approxRange,
            bool calleeEffect, bool fixpoint, bool printLogs);
   ~AbsState();

   int64_t first_used_redef_;
   /* Methods related to state operator */
   BaseDomain* value_unit(const UnitId& id);
   BaseDomain* value_range(const UnitId& lo, const UnitId& hi);
   void update_unit(const UnitId& dst, BaseDomain* src_val,
                    const CompareArgsId& src_expr);
   void update_range(const UnitId& lo, const UnitId& hi, BaseDomain* src_val,
                     const CompareArgsId& src_expr);
   void init(const function<BaseDomain*(UnitId)>& f_init);
   void clobber(REGION r);
   void clobber(const UnitId& id);
   void preset(const UnitId& id); /* similar to clobber(id), but ignore cstr */
   void redefine(const UnitId& id);
   bool commit(CHANNEL ch);
   void clear();
   void refresh();

   /* Methods related to use-def chain */;
   vector<Loc> ud_chain(const UnitId& id, const Loc& l);

 protected:
   /* Methods related to core features */
   BaseDomain* load_value(CHANNEL ch, SCC* scc, BasicBlock* b);
   void load_cstr(SCC* scc, BasicBlock* b);
   void propagate(const UnitId& dst, const CompareArgsId& src_expr);
   void store_s(const UnitId& id, BaseDomain* v);
   void store_w(const UnitId& id, BaseDomain* v);
   void replace(BaseDomain*& out, BaseDomain* v);
   void clear(CHANNEL ch);
   void define(const UnitId& id);

 protected:
   void print_logs(const string& task);
   void print_logs(const string& task, const UnitId& id, BaseDomain* v);
   void print_logs(const string& task, const UnitId& lo, const UnitId& hi, BaseDomain* v);
   void print_preset(const string& task, const UnitId& id, BaseDomain* v);
   void print_flags_cstr(int indent);
};
/* -------------------------------------------------------------------------- */
EXTERN_ABS_STATE

#endif