/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef DOMAIN_H
#define DOMAIN_H

#include "common.h"
/* ------------------------------- BaseDomain ------------------------------- */
class BaseDomain {
 public:
   static BaseDomain* const TOP;
   static BaseDomain* const BOT;

 private:
   int ref_;

 public:
   BaseDomain() {ref_ = 0;};
   BaseDomain(bool special) {ref_ = special? -1: 0;};
   virtual ~BaseDomain() {};

   /* Read accessors */
   int ref() const {return ref_;};

   /* Write accessors */
   void ref(int x) {ref_ = x;};

   /* Generic methods related to abstract domain */
   virtual bool top() const {return this==BaseDomain::TOP;};
   virtual bool bot() const {return this==BaseDomain::BOT;};
   virtual BaseDomain* clone() const {return (BaseDomain*)this;};
   virtual BaseDomain* mode(uint8_t bytes) {return (BaseDomain*)this;};
   virtual BaseDomain* abs_union(const BaseDomain* object);
   virtual BaseDomain* abs_intersect(const BaseDomain* object);
   virtual bool equal(const BaseDomain* object) const {return this==object;};
   virtual bool abstract() const {return true;};
   virtual bool comparable() const {return false;};
   virtual BaseDomain* norm() {return this;};
   virtual string to_string() const {return top()?string("TOP"):string("BOT");};

   /* Methods related to helper functions */
   static void safe_delete(BaseDomain* object);
   static void save(BaseDomain* object);
   static void discard(BaseDomain* object);
};
/* --------------------------------- BaseLH --------------------------------- */
class BaseLH: public BaseDomain {
 public:
   static string const NAME;
   static BaseDomain* const NOTLOCAL;

 private:
   int64_t b;
   Range r;

 public:
   enum class COMPARE_ARGS_OP: char {AND, NONE};
   using ComparableType = int64_t;
   ComparableType comparable_val() {return b;};
   Range val_with_cstr(const Range& baseCstr);
   void use_cstr(const Range& cstr);
   static string to_string(ComparableType v);

 public:
   BaseLH() {b = 0; r = Range(); ref(-1);};
   BaseLH(const Range& range) {b = 0; r = range;};
   BaseLH(int64_t base, const Range& range) {b = base; r = range;};
   BaseLH(const BaseLH& obj) {b = obj.b; r = obj.r;};
   ~BaseLH() {};

   static BaseLH* create_instance(const Range& range);
   static BaseLH* create_instance(int64_t base, const Range& range);

   /* Read accessors */
   int64_t base() const {return b;};
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
   BaseLH& operator=(int64_t c) {b = 0; r = Range(c,c); return *this;};
   BaseLH& operator=(const BaseLH& obj) {b = obj.b; r = obj.r; return *this;};
   bool operator==(int64_t c) const {return b == 0 && r == Range(c,c);};
   bool operator==(const BaseLH& obj) const {return b == obj.b && r == obj.r;};
   bool operator!=(int64_t c) const {return !(*this == c);};
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
/* ------------------------------- InitDomain ------------------------------- */
class InitDomain: public BaseDomain {
 public:
   static string const NAME;
   static uint8_t uninit_allowed;

 private:
   uint32_t state_;    /* 0 = init byte; 1 = uninit byte */

 public:
   enum class COMPARE_ARGS_OP: char {NONE};
   using ComparableType = int64_t;
   ComparableType comparable_val() {return -1;};
   Range val_with_cstr(const Range& baseCstr) {return Range::EMPTY;};
   void use_cstr(const Range& cstr) {};
   static string to_string(ComparableType v) {return string("");};

 public:
   InitDomain() {state_ = 0;};
   InitDomain(uint32_t s) {state_ = s;};
   ~InitDomain() {};

   static InitDomain* create_instance(uint32_t s) {return new InitDomain(s);};
   static InitDomain* create_instance(Range r) {return new InitDomain(-1);};

   /* Generic methods related to abstract domain */
   BaseDomain* clone() const override {return new InitDomain(state_);};
   BaseDomain* mode(uint8_t bytes) override;
   BaseDomain* abs_union(const BaseDomain* object) override;
   bool equal(const BaseDomain* object) const override;
   string to_string() const override;

   /* Methods related to InitDomain */
   static uint8_t init(const BaseDomain* object);
   static uint8_t uninit(const BaseDomain* object);
   static bool valid(const BaseDomain* object, int8_t mode_size);
   static void binary_op(BaseDomain*& obj, const BaseDomain* obj2);
   static void unary_op(BaseDomain*& obj);

 private:
   /* Methods related to InitDomain */
   uint32_t extract(uint8_t lsb, uint8_t msb) const;
};
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* ----------------------------- CompareArgsVal ----------------------------- */
template<class T> class CompareArgsVal {
 protected:
   T::COMPARE_ARGS_OP op_;
   array<T*,2> subargs_;

 public:
   CompareArgsVal();
   CompareArgsVal(T* a);
   CompareArgsVal(T::COMPARE_ARGS_OP op, T* a, T* b);
   CompareArgsVal(const CompareArgsVal<T>& obj);
   ~CompareArgsVal();
   T* subargs(int index) const {return subargs_[index];};
   CompareArgsVal<T>* clone() const {return new CompareArgsVal<T>(*this);};
   bool comparable() const;
   string to_string() const;
   void norm(CompareArgsVal<T>* rhs);
   vector<pair<typename T::ComparableType,Range>>
         get_cstr(COMPARE cmp, const CompareArgsVal<T>* rhs) const;

 private:
   void update(T::COMPARE_ARGS_OP op, T* a, T* b);
   void update(T* a) {update(T::COMPARE_ARGS_OP::NONE, a, nullptr);};
};
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* ------------------------------- FlagDomain ------------------------------- */
template<class T> class FlagUnit {
 private:
   vector<CompareArgsId*> id_;
   vector<CompareArgsVal<T>*> val_;

 public:
   FlagUnit(const array<CompareArgsId*,2>& id,
            const array<CompareArgsVal<T>*,2>& val);
   FlagUnit(const FlagUnit<T>& obj) {id_ = obj.id_; val_ = obj.val_;};
   ~FlagUnit() {};

   const vector<CompareArgsId*>& args_id() const {return id_;};
   const vector<CompareArgsVal<T>*>& args_val() const {return val_;};
   bool empty() const {return id_.empty() && val_.empty();};
   void invalidate(const UnitId& id);
   void invalidate(REGION r);
   string to_string() const;
};
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
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

   static FlagDomain<T>* create_instance() {return new FlagDomain<T>();};
   static FlagDomain<T>* create_instance(const FlagUnit<T>& u);

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
                          const CompareArgsId& src_expr);
};
/* ------------------------------- CstrDomain ------------------------------- */
template<class T> class CstrDomain: public BaseDomain {
 public:
   using ValType = typename T::ComparableType;

 private:
   /* constraint cannot be TOP --> initialize with empty cstrVal_, cstrId_ */
   /*                          --> clobber does not affect constraint      */
   unordered_map<int64_t, Range> cstrId_;            /* AND of constraints */
   unordered_map<ValType, Range> cstrVal_;           /* AND of constraints */
   unordered_map<int64_t, CompareArgsId> exprEq_;    /* {x = a + 3; y = b} */

 public:
   CstrDomain() {};
   CstrDomain(COMPARE cmp, const BaseDomain* f);
   CstrDomain(const CstrDomain<T>& obj);
   ~CstrDomain() {};

   static CstrDomain<T>* create_instance() {return new CstrDomain<T>();};
   static CstrDomain<T>* create_instance(COMPARE cmp, const BaseDomain* f);

   /* Generic methods related to abstract domain */
   BaseDomain* clone() const override;
   string to_string() const override;

   /* Methods related to CstrDomain */
   static void abs_and(BaseDomain*& object, const BaseDomain* object2);
   static void abs_ior(BaseDomain*& object, const BaseDomain* object2);
   static void use_cstr(const BaseDomain* constraint, BaseDomain*& value,
                        const UnitId& id);
   static void propagate(BaseDomain* constraint, const UnitId& dst,
                         const CompareArgsId& src_expr);
   static void invalidate(BaseDomain* constraint, REGION r);

 private:
   Range cstr_by_id(const UnitId& id);
   Range cstr_by_val(const BaseDomain* object);
};
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* ---------------------- Template Class Instantiation ---------------------- */
EXTERN_FLAG_UNIT
EXTERN_FLAG_DOMAIN
EXTERN_CSTR_DOMAIN
#endif