/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef STATE_H
#define STATE_H

#include "domain.h"
#include "utility.h"
#include "user.h"

namespace SBA {
   /* Forward declaration */
   class Function;
   class SCC;
   class Block;
   class Insn;

   struct CompactStateSettings {
      unordered_set<IMM> sym;
      unordered_set<Block*> block;
   };
   /* ------------------------------- AbsState ------------------------------ */
   class AbsState {
    public:
      Loc loc;

    protected:
      bool enable_analysis_;
      bool enable_cstr_;
      bool enable_weak_update_;
      bool enable_clobber_mem_;
      bool enable_approx_range_;
      bool enable_call_effect_;
      bool enable_fixpoint_;
      bool enable_logs_;
      bool enable_taint_;
      string name_;
      function<BaseDomain*(const UnitId&)>* init_;
      unordered_set<Insn*> taint_src_;

    public:
      AbsState(bool cstr, bool weak_update, bool clobber_mem, bool approx_range,
               bool call_effect, bool fixpoint, bool logs, const string& name,
               function<BaseDomain*(const UnitId&)>* init,
               const unordered_set<Insn*>& taint_src):
               enable_analysis_(true),
               enable_cstr_(cstr),
               enable_weak_update_(weak_update),
               enable_clobber_mem_(clobber_mem),
               enable_approx_range_(approx_range),
               enable_call_effect_(call_effect),
               enable_fixpoint_(fixpoint),
               enable_logs_(logs),
               init_(init),
               taint_src_(taint_src) {
                  name_ = string("*").append(name).append(cstr? "-cstr*":"*");
                  name_.append(string(DOMAIN_LEN + 8 - name_.length(), ' '));
                  enable_taint_ = !taint_src.empty();
               };
      virtual ~AbsState() {};

      /* Methods related to state operator */
      virtual BaseDomain* value_unit(const UnitId& id) = 0;
      virtual BaseDomain* value_range(const UnitId& lo, const UnitId& hi,
                                      uint8_t stride) = 0;
      virtual void update_unit(const UnitId& id, BaseDomain* src_val,
                               const ExprId& src_expr = ExprId::EMPTY) = 0;
      virtual void update_range(const UnitId& lo, const UnitId& hi, uint8_t stride,
                                BaseDomain* src_val, const ExprId& src_expr =
                                ExprId::EMPTY) = 0;
      virtual void clobber(REGION r) = 0;
      virtual void clobber(const UnitId& id) = 0;
      virtual void preset(const UnitId& id) = 0; /* clobber but ignore cstr */
      virtual bool commit(CHANNEL ch) = 0;
      virtual void clear() = 0;
      virtual void refresh() = 0;

      /* Methods related to use-def chain */;
      virtual vector<Loc> use_def(const UnitId& id, const Loc& l) = 0;
      virtual vector<Loc> def_use(const UnitId& id, const Loc& l) = 0;

      /* Read accessors */
      bool enable_cstr() const {return enable_cstr_;};
      bool enable_clobber_mem() const {return enable_clobber_mem_;};
      bool enable_call_effect() const {return enable_call_effect_;};
      bool enable_fixpoint() const {return enable_fixpoint_;};
      bool enable_analysis() const {return enable_analysis_;};
      bool enable_taint() const {return enable_taint_;};

      /* Write accessors */
      void enable_analysis(bool b) {enable_analysis_ = b;};
   };
   /* -------------------------------- State -------------------------------- */
   template<class T> class State: public AbsState {
    private:
      using UnitVal = unordered_map<Block*, BaseDomain*>;
      using UnitLoc = unordered_map<Block*, vector<Insn*>>;
      using ScopeId = unordered_map<Block*, vector<UnitId>>;
      using StateVal = unordered_map<IMM, UnitVal>;
      using StateLoc = unordered_map<IMM, UnitLoc>;
      using RegionVal = array<StateVal,3>;
      using RegionLoc = array<UnitLoc,3>;

    private:
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
      UnitVal cstr_;
      StateLoc def_;
      StateLoc use_;
      RegionLoc clobber_;
      ScopeId refresh_;

    public:
      State(bool cstr, bool weak_update, bool clobber_mem, bool approx_range,
            bool call_effect, bool fixpoint, bool logs,
            function<BaseDomain*(const UnitId&)>* init,
            const unordered_set<Insn*>& taint_src);
      State(bool cstr, bool weak_update, bool clobber_mem, bool approx_range,
            bool call_effect, bool fixpoint, bool logs,
            function<BaseDomain*(const UnitId&)>* init);
      ~State();

      /* Methods related to state operator */
      BaseDomain* value_unit(const UnitId& id) override;
      BaseDomain* value_range(const UnitId& lo, const UnitId& hi,
                  uint8_t stride) override;
      void update_unit(const UnitId& id, BaseDomain* src_val,
           const ExprId& src_expr = ExprId::EMPTY) override;
      void update_range(const UnitId& lo, const UnitId& hi, uint8_t stride,
           BaseDomain* src_val, const ExprId& src_expr=ExprId::EMPTY) override;
      void clobber(REGION r) override;
      void clobber(const UnitId& id) override;
      void preset(const UnitId& id) override;
      bool commit(CHANNEL ch) override;
      void clear() override;
      void refresh() override;

      /* Methods related to use-def chain */;
      vector<Loc> use_def(const UnitId& id, const Loc& l) override;
      vector<Loc> def_use(const UnitId& id, const Loc& l) override;

    private:
      /* Methods related to core features */
      BaseDomain* load(const UnitId& id, CHANNEL ch, SCC* scc, Block* b);
      void assign_cstr(const UnitId& dst, const ExprId& src_expr);
      void store_s(const UnitId& id, BaseDomain* v);
      void store_w(const UnitId& id, BaseDomain* v);
      void replace(BaseDomain*& out, BaseDomain* v);
      void clear(CHANNEL ch);
      void define(const UnitId& id);
      void use(const UnitId& id);

      /* Methods related to helper functions */
      void print_logs(const string& task);
      void print_logs(const string& task, const UnitId& id, BaseDomain* v);
      void print_logs(const string& task, const UnitId& lo, const UnitId& hi,
                      BaseDomain* v);
      void print_flags_cstr(const string& task);
   };

   STATE_EXTERN
}

#endif
