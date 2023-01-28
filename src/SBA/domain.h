/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef DOMAIN_H
#define DOMAIN_H

#include "utility.h"
#include "user.h"

namespace SBA {
   /* ------------------------------ BaseDomain ----------------------------- */
   class BaseDomain {
    public:
      static BaseDomain* const TOP;
      static BaseDomain* const BOT;

    private:
      int16_t ref_;

    public:
      BaseDomain() {ref_ = 0;};
      BaseDomain(int16_t ref) {ref_ = ref;};
      virtual ~BaseDomain() {};

      /* Read accessors */
      int16_t ref() const {return ref_;};

      /* Generic methods related to abstract domain */
      virtual bool top() const {return this==BaseDomain::TOP;};
      virtual bool bot() const {return this==BaseDomain::BOT;};
      virtual BaseDomain* clone() const {return (BaseDomain*)this;};
      virtual BaseDomain* mode(uint8_t bytes) {return (BaseDomain*)this;};
      virtual BaseDomain* abs_union(const BaseDomain* object);
      virtual BaseDomain* abs_intersect(const BaseDomain* object);
      virtual BaseDomain* tainted_val(Insn* taint_insn) {return this;};
      virtual bool equal(const BaseDomain* object) const {return this==object;};
      virtual bool abstract() const {return true;};
      virtual bool comparable() const {return false;};
      virtual BaseDomain* norm() {return this;};
      virtual string to_string() const {return top()?string("TOP"):string("BOT");};

      /* Methods related to memory management */
      static void safe_delete(BaseDomain* object);
      static void save(BaseDomain* object);
      static void discard(BaseDomain* object);
   };
   /* -------------------------------- BaseLH ------------------------------- */
   class BaseLH: public BaseDomain {
    public:
      static string const NAME;
      static BaseDomain* const NOTLOCAL;

    private:
      IMM b;
      Range r;

    public:
      enum class EXPR_VAL_OP: char {AND, NONE};
      using ComparableType = IMM;
      ComparableType comparable_sym() {return b;};
      Range cstr_val(const Range& baseCstr);
      void use_cstr(const Range& cstr);
      static string to_string(ComparableType v);

    public:
      BaseLH() : BaseDomain(-1) {
         b = 0;
         r = Range();
      };
      BaseLH(IMM base, const Range& range) : BaseDomain(0) {
         b = base;
         r = range;
      };
      BaseLH(const Range& range) : BaseLH(0, range) {};
      BaseLH(const BaseLH& obj) {
         b = obj.b;
         r = obj.r;
      };
      ~BaseLH() {};

      static BaseLH* create(const Range& range);
      static BaseLH* create(IMM base, const Range& range);

      /* Read accessors */
      IMM base() const {return b;};
      Range range() const {return r;};

      /* Generic methods related to abstract domain */
      BaseDomain* clone() const override;
      BaseDomain* mode(uint8_t bytes) override;
      BaseDomain* abs_union(const BaseDomain* object) override;
      BaseDomain* abs_intersect(const BaseDomain* object) override;
      bool equal(const BaseDomain* object) const override;
      bool abstract() const override {return notlocal(this) || b != 0;};
      bool comparable() const override {return !notlocal(this);};
      BaseDomain* norm() override;
      string to_string() const override;

      /* Assignment and Comparison -- not support BOT, TOP and NOTLOCAL */
      BaseLH& operator=(IMM c) {b = 0; r = Range(c,c); return *this;};
      BaseLH& operator=(const BaseLH& obj) {b = obj.b; r = obj.r; return *this;};
      bool operator==(IMM c) const {return b == 0 && r == Range(c,c);};
      bool operator==(const BaseLH& obj) const {return b == obj.b && r == obj.r;};
      bool operator!=(IMM c) const {return !(*this == c);};
      bool operator!=(const BaseLH& obj) const {return !(*this == obj);};
      bool operator>=(const BaseLH& obj) const {return b == obj.b && r >= obj.r;};
      bool operator<=(const BaseLH& obj) const {return b == obj.b && r <= obj.r;};
      bool operator>(const BaseLH& obj) const {return b == obj.b && r > obj.r;};
      bool operator<(const BaseLH& obj) const {return b == obj.b && r < obj.r;};

      /* Methods related to BaseLH */
      static bool notlocal(const BaseDomain* object);
      static bool excludeLocal(const BaseDomain* object);
      static void abs_plus(BaseDomain*& obj, const BaseDomain* obj2);
      static void abs_minus(BaseDomain*& obj, const BaseDomain* obj2);
      static void abs_mult(BaseDomain*& obj, const BaseDomain* obj2);
      static void abs_div(BaseDomain*& obj, const BaseDomain* obj2);
      static void abs_mod(BaseDomain*& obj, const BaseDomain* obj2);
      static void abs_ashift(BaseDomain*& obj, const BaseDomain* obj2);
      static void abs_xor(BaseDomain*& obj, const BaseDomain* obj2);
      static void abs_ior(BaseDomain*& obj, const BaseDomain* obj2);
      static void abs_and(BaseDomain*& obj, const BaseDomain* obj2);
      static void abs_abs(BaseDomain*& obj);
      static void abs_neg(BaseDomain*& obj);
   };
   /* ----------------------------- TaintDomain ----------------------------- */
   class TaintDomain: public BaseDomain {
    public:
      static string const NAME;
      static uint8_t const MAX_SIZE;

    private:
      uint32_t state_;    /* 0 = init byte; 1 = uninit byte */
      Insn* taint_src_;

    public:
      enum class EXPR_VAL_OP: char {NONE};
      using ComparableType = IMM;
      ComparableType comparable_sym() {return -1;};
      Range cstr_val(const Range& baseCstr) {return Range::EMPTY;};
      void use_cstr(const Range& cstr) {};
      static string to_string(ComparableType v) {return string("");};
   
    public:
      TaintDomain() {state_=0; taint_src_=nullptr;};
      TaintDomain(uint32_t s, Insn* taint_src) {state_=s; taint_src_=taint_src;};
      ~TaintDomain() {};
   
      static TaintDomain* create(uint32_t s, Insn* taint_src) {
         return (s!=0)? new TaintDomain(s,taint_src): new TaintDomain(s,nullptr);
      };

      static TaintDomain* create(const Range& r) {
         return (TaintDomain*)(BaseDomain::TOP);
      };
   
      /* Generic methods related to abstract domain */
      BaseDomain* clone() const override {
         return new TaintDomain(state_, taint_src_);
      };
      BaseDomain* mode(uint8_t bytes) override;
      BaseDomain* abs_union(const BaseDomain* object) override;
      BaseDomain* tainted_val(Insn* taint_insn) override;
      bool equal(const BaseDomain* object) const override;
      string to_string() const override;
   
      /* Methods related to TaintDomain */
      static uint8_t init(const BaseDomain* object);
      static uint8_t uninit(const BaseDomain* object);
      static bool valid(const BaseDomain* object, uint8_t mode_size);
      static void binary_op(BaseDomain*& obj, const BaseDomain* obj2);
      static void unary_op(BaseDomain*& obj);
      static Insn* taint_src(BaseDomain* obj);
   
    private:
      /* Methods related to TaintDomain */
      uint32_t extract(uint8_t lsb, uint8_t msb) const;
   };
   /* ------------------------------- ExprVal ------------------------------- */
   template<class T> class ExprVal {
    protected:
      T::EXPR_VAL_OP op_;
      array<T*,2> subargs_;

    public:
      ExprVal();
      ExprVal(T* a);
      ExprVal(T::EXPR_VAL_OP op, T* a, T* b);
      ExprVal(const ExprVal<T>& obj);
      ~ExprVal();
      T* subargs(int index) const {return subargs_[index];};
      ExprVal<T>* clone() const {return new ExprVal<T>(*this);};
      bool comparable() const;
      string to_string() const;
      void norm(ExprVal<T>* rhs);
      vector<pair<typename T::ComparableType,Range>>
            get_cstr(COMPARE cmp, const ExprVal<T>* rhs) const;

    private:
      void update(T::EXPR_VAL_OP op, T* a, T* b);
      void update(T* a) {update(T::EXPR_VAL_OP::NONE, a, nullptr);};
   };
   /* ------------------------------ FlagDomain ----------------------------- */
   template<class T> class FlagUnit {
    private:
      vector<ExprId*> id_;
      vector<ExprVal<T>*> val_;

    public:
      FlagUnit(const array<ExprId*,2>& id,
               const array<ExprVal<T>*,2>& val);
      FlagUnit(const FlagUnit<T>& obj) {id_ = obj.id_; val_ = obj.val_;};
      ~FlagUnit();

      const vector<ExprId*>& args_id() const {return id_;};
      const vector<ExprVal<T>*>& args_val() const {return val_;};
      bool empty() const {return id_.empty() && val_.empty();};
      void invalidate(const UnitId& id);
      void invalidate(REGION r);
      string to_string() const;
   };

   template<class T> class FlagDomain: public BaseDomain {
    private:
      /* flag cannot be TOP --> initialize with empty units_ */
      /*                    --> clobber with empty units_    */
      vector<FlagUnit<T>> units_;        /* OR of flag units */

    public:
      FlagDomain() {};
      FlagDomain(const FlagUnit<T>& u);
      FlagDomain(const FlagDomain<T>& obj) {units_ = obj.units_;};
      ~FlagDomain() {};

      static FlagDomain<T>* create() {return new FlagDomain<T>();};
      static FlagDomain<T>* create(const FlagUnit<T>& u);

      /* Read accessors */
      const vector<FlagUnit<T>>& units() const {return units_;};

      /* Generic methods related to abstract domain */
      BaseDomain* clone() const override;
      BaseDomain* abs_union(const BaseDomain* object) override;
      bool equal(const BaseDomain* object) const override {return true;};
      string to_string() const override;

      /* Methods related to FlagDomain */
      static void invalidate(BaseDomain* flags, REGION r);
      static void invalidate(BaseDomain* flags, const UnitId& dst,
                             const ExprId& src_expr);
   };
   /* ------------------------------ CstrDomain ----------------------------- */
   template<class T> class CstrDomain: public BaseDomain {
    public:
      using ValType = typename T::ComparableType;

    private:
      /* constraint cannot be TOP --> initialize with empty cstrVal_, cstrId_ */
      /*                          --> clobber does not affect constraint      */
      unordered_map<IMM, Range> cstrId_;                /* AND of constraints */
      unordered_map<ValType, Range> cstrVal_;           /* AND of constraints */
      unordered_map<IMM, ExprId> exprEq_;               /* {x = a + 3; y = b} */

    public:
      CstrDomain() {};
      CstrDomain(COMPARE cmp, const BaseDomain* f);
      CstrDomain(const CstrDomain<T>& obj);
      ~CstrDomain() {};

      static CstrDomain<T>* create() {return new CstrDomain<T>();};
      static CstrDomain<T>* create(COMPARE cmp, const BaseDomain* f);

      /* Generic methods related to abstract domain */
      BaseDomain* clone() const override;
      string to_string() const override;

      /* Methods related to CstrDomain */
      static void abs_and(BaseDomain*& object, const BaseDomain* object2);
      static void abs_ior(BaseDomain*& object, const BaseDomain* object2);
      static void use_cstr(const BaseDomain* constraint, BaseDomain*& value,
                           const UnitId& id);
      static void assign_cstr(BaseDomain* constraint, const UnitId& dst,
                              const ExprId& src_expr);
      static void invalidate(BaseDomain* constraint, REGION r);

    private:
      Range get_cstr(const UnitId& id);
      Range get_cstr(const BaseDomain* object);
   };

   DOMAIN_HDR
   FLAG_UNIT_EXTERN
   FLAG_DOMAIN_EXTERN
   CSTR_DOMAIN_EXTERN
}

#endif
