/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "domain.h"
#include "insn.h"

using namespace SBA;
/* -------------------------------------------------------------------------- */
string const BaseLH::NAME = string("BaseLH");
string const TaintDomain::NAME = string("TaintDomain");
BaseDomain* const BaseDomain::TOP = new BaseDomain(-1);
BaseDomain* const BaseDomain::BOT = new BaseDomain(-1);
BaseDomain* const BaseLH::NOTLOCAL = new BaseLH();
uint8_t const TaintDomain::MAX_SIZE = 32;
/* ------------------------------- BaseDomain ------------------------------- */
BaseDomain* BaseDomain::abs_union(const BaseDomain* object) {
   if (top())  /* TOP */
      return BaseDomain::TOP;
   else        /* BOT */
      return (BaseDomain*)object;
}


BaseDomain* BaseDomain::abs_intersect(const BaseDomain* object) {
   if (bot())  /* BOT */
      return BaseDomain::BOT;
   else        /* TOP */
      return (BaseDomain*)object;
}


void BaseDomain::safe_delete(BaseDomain* object) {
   if (object != nullptr && object->ref_ == 0)
      delete object;
}


void BaseDomain::save(BaseDomain* object) {
   if (object != nullptr && object->ref_ != -1)
      ++(object->ref_);
}


void BaseDomain::discard(BaseDomain* object) {
   if (object != nullptr && object->ref_ != -1) {
      --(object->ref_);
      BaseDomain::safe_delete(object);
   }
}
/* --------------------------------- BaseLH --------------------------------- */
Range BaseLH::cstr_val(const Range& baseCstr) {
   return baseCstr + r;
}


void BaseLH::use_cstr(const Range& cstr) {
   b = 0;
   r = cstr;
}


string BaseLH::to_string(ComparableType v) {
   return string("base_").append(get_id(v).to_string());
}


BaseLH* BaseLH::create(const Range& range) {
   return (BaseLH*)((new BaseLH(range))->norm());
}


BaseLH* BaseLH::create(IMM base, const Range& range) {
   return (BaseLH*)((new BaseLH(base,range))->norm());
}


BaseDomain* BaseLH::clone() const {
   return (BaseLH::notlocal(this))?
          (BaseDomain*)this: (new BaseLH(*this))->norm();
}


BaseDomain* BaseLH::mode(uint8_t bytes) {
   /* only applied to concrete values */
   if (b == 0) {
      /* do not modify stored ptr */
      if (ref() > 0) {
         auto val = (BaseLH*)(this->clone());
         val->r.contract(bytes);
         return val->norm();
      }
      /* apply mode if not special node */
      else if (ref() == 0)
         r.contract(bytes);
   }
   return this;
}


BaseDomain* BaseLH::abs_union(const BaseDomain* object) {
   if (object->top()) {
      BaseDomain::safe_delete(this);
      return BaseDomain::TOP;
   }
   else if (object->bot())
      return this;
   else if (BaseLH::notlocal(this))
      return BaseLH::excludeLocal(object)? BaseLH::NOTLOCAL: BaseDomain::TOP;
   else if (BaseLH::notlocal(object)) {
      auto res = BaseLH::excludeLocal(this)? BaseLH::NOTLOCAL: BaseDomain::TOP;
      BaseDomain::safe_delete(this);
      return res;
   }
   else {
      const BaseLH* obj = (const BaseLH*)object;
      /* (b + r1) U (b + r2) --> (b + r1|r2) */
      if (b == obj->b) {
         r = r | obj->r;
         return this->norm();
      }
      /* (b1 + r1) U (b2 + r2) --> NOTLOCAL if b1 != baseSP ^ b2 != baseSP */
      /* (b1 + r1) U (b2 + r2) --> TOP      if b1 == baseSP ^ b2 != baseSP */
      /*                                    if b1 != baseSP ^ b2 == baseSP */
      else {
         auto res = (BaseLH::excludeLocal(this)&&BaseLH::excludeLocal(object))?
                     BaseLH::NOTLOCAL: BaseDomain::TOP;
         BaseDomain::safe_delete(this);
         return res;
      }
   }
}


BaseDomain* BaseLH::abs_intersect(const BaseDomain* object) {
   if (object->bot()) {
      BaseDomain::safe_delete(this);
      return BaseDomain::BOT;
   }
   else if (object->top())
      return this;
   /* NOTLOCAL */
   else if (BaseLH::notlocal(this))
      return BaseLH::excludeLocal(object)? (BaseDomain*)object: BaseDomain::BOT;
   else if (BaseLH::notlocal(object))
      return BaseLH::excludeLocal(this)? this: BaseDomain::BOT;
   else {
      const BaseLH* obj = (const BaseLH*)object;
      /* (b + r1) intersect (b + r2) --> (b + r1&r2) */
      if (b == obj->b) {
         r = r & obj->r;
         return this->norm();
      }
      /* (b1 + r1) intersect (b2 + r2)               */
      /* if b1 != b2, result is not representable    */
      /* for soundness, pick a pointer higher up     */
      /* either (b1 + r1) or (b2 + r2) is accepted   */
      else {
         /* (a) baseSP not overlap with other bases  */
         if (!BaseLH::excludeLocal(this) || !BaseLH::excludeLocal(object)) {
            BaseDomain::safe_delete(this);
            return BaseDomain::BOT;
         }
         /* (b) favor concrete over abstract value   */
         else if (b == 0)
            return this;
         else if (obj->b == 0) {
            BaseDomain::safe_delete(this);
            return (BaseDomain*)obj;
         }
         /* (c) favor smaller range distance         */
         else if (r.size() < obj->r.size())
            return this;
         else {
            BaseDomain::safe_delete(this);
            return (BaseDomain*)obj;
         }
      }
   }
}


bool BaseLH::equal(const BaseDomain* object) const {
   const BaseLH* obj = (const BaseLH*)object;
   return (object == nullptr || object->top() || object->bot() ||
          BaseLH::notlocal(this) || BaseLH::notlocal(object))?
          (this == obj): (*this == *obj);
}


BaseDomain* BaseLH::norm() {
   if (BaseLH::notlocal(this))
      return this;
   else if (r.empty()) {
      BaseDomain::safe_delete(this);
      return BaseDomain::TOP;
   }
   else if (r.lo() == _oo && r.hi() == oo) {
      auto res = !BaseLH::excludeLocal(this)? BaseDomain::TOP: BaseLH::NOTLOCAL;
      BaseDomain::safe_delete(this);
      return res;
   }
   else
      return this;
}


string BaseLH::to_string() const {
   if (BaseLH::notlocal(this))
      return string("NOTLOCAL");
   else if (b == 0)
      return r.to_string();
   else if (r == Range::ZERO)
      return (b > 0? string("(base_"): string("(-base_"))
             .append(get_id(std::abs(b)).to_string()).append(")");
   else
      return (b > 0? string("(base_"): string("(-base_"))
             .append(get_id(std::abs(b)).to_string())
             .append(" + ").append(r.to_string()).append(")");
}


bool BaseLH::notlocal(const BaseDomain* object) {
   return !object->top() && !object->bot() && object == BaseLH::NOTLOCAL;
}


bool BaseLH::excludeLocal(const BaseDomain* object) {
   return !object->top() && !object->bot() && (BaseLH::notlocal(object) ||
          ((const BaseLH*)object)->b != get_base(REGION::STACK));
}


void BaseLH::abs_plus(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top() || obj2->top())
      obj = obj->abs_union(obj2);
   else if (BaseLH::notlocal(obj) || BaseLH::notlocal(obj2))
      obj = obj->abs_union(obj2);
   else {
      auto x = (BaseLH*)obj;
      auto const y = (const BaseLH*)obj2;
      /* (b + r1) + (-b + r2) --> (0 + r1+r2) */
      /* (b + r1) + (0 + r2)  --> (b + r1+r2) */
      /* (0 + r1) + (b + r2)  --> (b + r1+r2) */
      /* (0 + r1) + (0 + r2)  --> (0 + r1+r2) */
      if ((x->b + y->b == 0) || (x->b == 0 || y->b == 0)) {
         x->b = x->b + y->b;
         x->r = x->r + y->r;
         obj = x->norm();
      }
      /* (b1 + r1) + (b2 + r2) --> (b1 + r1) union (b2 + r2) */
      else
         obj = x->abs_union(y);
   }
}


void BaseLH::abs_minus(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top() || obj2->top())
      obj = obj->abs_union(obj2);
   else if (BaseLH::notlocal(obj) || BaseLH::notlocal(obj2))
      obj = obj->abs_union(obj2);
   else {
      auto x = (BaseLH*)obj;
      auto const y = (const BaseLH*)obj2;
      /* (b + r1) - (b + r2) --> (0 + r1-r2)  */
      /* (b + r1) - (0 + r2) --> (b + r1-r2)  */
      /* (0 + r1) - (b + r2) --> (-b + r1-r2) */
      /* (0 + r1) - (0 + r2) --> (0 + r1-r2)  */
      if ((x->b - y->b == 0) || (x->b == 0 || y->b == 0)) {
         x->b = x->b - y->b;
         x->r = x->r - y->r;
         obj = x->norm();
      }
      /* (b1 + r1) - (b2 + r2) --> (b1 + r1) union (b2 + r2) */
      else
         obj = x->abs_union(y);
   }
}


void BaseLH::abs_mult(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top() || obj2->top())
      obj = obj->abs_union(obj2);
   else if (BaseLH::notlocal(obj) || BaseLH::notlocal(obj2))
      obj = obj->abs_union(obj2);
   else {
      auto x = (BaseLH*)obj;
      auto const y = (const BaseLH*)obj2;
      /* multipliers in {-1, 0, 1} */
      if (*x == -1) {
         *x = *y;
         BaseLH::abs_neg(obj);
      }
      else if (*y == -1)
         BaseLH::abs_neg(obj);
      else if (*x == 0)
         return;
      else if (*y == 0)
         *x = 0;
      else if (*x == 1)
         *x = *y;
      else if (*y == 1)
         return;
      /* either has base --> abs_union */
      else if (x->b != 0 || y->b != 0)
         obj = x->abs_union(y);
      /* (0 + r1) * (0 + r2) --> (0 + r1*r2) */
      else {
         x->r = x->r * y->r;
         obj = x->norm();
      }
   }
}


void BaseLH::abs_div(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top() || obj2->top())
      obj = obj->abs_union(obj2);
   else if (BaseLH::notlocal(obj) || BaseLH::notlocal(obj2))
      obj = obj->abs_union(obj2);
   else {
      auto x = (BaseLH*)obj;
      auto const y = (const BaseLH*)obj2;
      /* division by zero */
      if (*y == 0) {
         BaseDomain::safe_delete(x);
         obj = BaseDomain::TOP;
         LOG4("error: division by zero!");
      }
      /* divisors in {-1, 1, *this, -*this} */
      else if (*y == -1)
         BaseLH::abs_neg(obj);
      else if (*y == 1)
         return;
      else if (*x == *y) {
         *x = 1;
      }
      else if (x->b == -y->b && x->r == -(y->r))
         *x = -1;
      /* either has base --> abs_union */
      else if (x->b != 0 || y->b != 0)
         obj = x->abs_union(y);
      /* (0 + r1) / (0 + r2) --> (0 + r1/r2) */
      else {
         x->r = x->r / y->r;
         obj = x->norm();
      }
   }
}


void BaseLH::abs_mod(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top() || obj2->top())
      obj = obj->abs_union(obj2);
   else if (BaseLH::notlocal(obj) || BaseLH::notlocal(obj2))
      obj = obj->abs_union(obj2);
   else {
      auto x = (BaseLH*)obj;
      auto const y = (const BaseLH*)obj2;
      /* division by zero */
      if (*y == 0) {
         BaseDomain::safe_delete(x);
         obj = BaseDomain::TOP;
         LOG4("error: division by zero!");
      }
      /* divisors in {-1, 1, *this, -*this} */
      else if (*y == -1 || *y == 1 || *x == *y ||
      (x->b == y->b && x->r == -(y->r)))
         *x = 0;
      /* either has base --> abs_union */
      else if (x->b != 0 || y->b != 0)
         obj = x->abs_union(y);
      /* (0 + r1) % (0 + r2) --> (0 + r1%r2) */
      else {
         x->r = x->r % y->r;
         obj = x->norm();
      }
   }
}


void BaseLH::abs_xor(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top() || obj2->top())
      obj = obj->abs_union(obj2);
   else if (BaseLH::notlocal(obj) || BaseLH::notlocal(obj2))
      obj = obj->abs_union(obj2);
   else {
      auto x = (BaseLH*)obj;
      auto const y = (const BaseLH*)obj2;
      /* either has base --> abs_union */
      if (x->b != 0 || y->b != 0)
         obj = x->abs_union(y);
      /* (0 + r1) ^ (0 + r2) --> (0 + r1^r2) */
      else {
         x->r = x->r ^ y->r;
         obj = x->norm();
      }
   }
}


void BaseLH::abs_ior(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top() || obj2->top())
      obj = obj->abs_union(obj2);
   else if (BaseLH::notlocal(obj) || BaseLH::notlocal(obj2))
      obj = obj->abs_union(obj2);
   else {
      auto x = (BaseLH*)obj;
      auto const y = (const BaseLH*)obj2;
      /* either has base --> abs_union */
      if (x->b != 0 || y->b != 0)
         obj = x->abs_union(y);
      /* (0 + r1) | (0 + r2) --> (0 + r1|r2) */
      else {
         x->r = x->r | y->r;
         obj = x->norm();
      }
   }
}


void BaseLH::abs_and(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top() || BaseLH::notlocal(obj)) {
      if (obj2->top() || BaseLH::notlocal(obj2))
         obj = BaseDomain::TOP;
      else {
         auto const y = (const BaseLH*)obj2;
         if (y->b == 0 && y->r.lo() > 0)
            obj = BaseLH::create(0, Range(0, y->r.hi()));
      }
   }
   else if (obj2->top() || BaseLH::notlocal(obj2)) {
      auto x = (BaseLH*)obj;
      auto r = Range(0, oo) & x->r;
      if (x->b == 0 && !r.empty()) {
         BaseDomain::safe_delete(obj);
         obj = BaseLH::create(0, Range(0, r.hi()));
      }
   }
   else {
      auto x = (BaseLH*)obj;
      auto const y = (const BaseLH*)obj2;
      /* either has base --> abs_union */
      if (x->b != 0 || y->b != 0)
         obj = x->abs_union(y);
      /* (0 + r1) & (0 + r2) --> (0 + min_range) */
      else {
         auto r1 = x->r & Range(0, oo);
         auto r2 = y->r & Range(0, oo);
         x->r = Range(0, std::min(std::max(0,r1.hi()),std::max(0,r2.hi())));
         obj = x->norm();
      }
   }
}


void BaseLH::abs_ashift(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top() || obj2->top())
      obj = obj->abs_union(obj2);
   else if (BaseLH::notlocal(obj) || BaseLH::notlocal(obj2))
      obj = obj->abs_union(obj2);
   else {
      auto x = (BaseLH*)obj;
      auto const y = (const BaseLH*)obj2;
      /* special case {0} */
      if (*x == 0 || *y == 0)
         return;
      /* either has base --> abs_union */
      else if (x->b != 0 || y->b != 0)
         obj = x->abs_union(y);
      /* (0 + r1) << (0 + r2) --> (0 + r1<<r2) */
      else {
         x->r = x->r << y->r;
         obj = x->norm();
      }
   }
}


void BaseLH::abs_abs(BaseDomain*& obj) {
   if (obj->top() || obj->bot() || BaseLH::notlocal(obj))
      return;
   else {
      auto x = (BaseLH*)obj;
      /* |(b + r)| --> TOP */
      if (x->b != 0) {
         BaseDomain::safe_delete(x);
         obj = BaseDomain::TOP;
      }
      /* |(0 + r)| --> (0 + r.abs()) */
      else {
         x->r = x->r.abs();
         obj = x->norm();
      }
   }
}


void BaseLH::abs_neg(BaseDomain*& obj) {
   /* TOP, BOT */
   if (obj->top() || obj->bot() || BaseLH::notlocal(obj))
      return;
   else {
      auto x = (BaseLH*)obj;
      /* -(b + r) --> (-b + -r) */
      x->b = -x->b;
      x->r = -x->r;
      obj = x->norm();
   }
}
/* ------------------------------ TaintDomain ------------------------------- */
BaseDomain* TaintDomain::mode(uint8_t bytes) {
   uint32_t x = ((state_ << (32-bytes)) >> (32-bytes));
   if (x == state_)
      return this;
   return TaintDomain::create(x, taint_src_);
};


BaseDomain* TaintDomain::abs_union(const BaseDomain* object) {
   if (object->top()) {
      BaseDomain::safe_delete(this);
      return BaseDomain::TOP;
   }
   if (object->bot())
      return this;
   else {
      const TaintDomain* obj = (const TaintDomain*)object;
      state_ &= obj->state_;   /* uninit if uninit in both */
      taint_src_ = (state_ != 0)? taint_src_: nullptr;
      return this;
   }
}


BaseDomain* TaintDomain::tainted_val(Insn* taint_src) {
   return TaintDomain::create(0xffffffff, taint_src);
}


bool TaintDomain::equal(const BaseDomain* object) const {
   return (object==nullptr || object->top() || object->bot() || top() || bot())?
          this == object: state_ == ((const TaintDomain*)object)->state_;
}


string TaintDomain::to_string() const {
   auto x = TaintDomain::init(this);
   if (x > 0)
      return string("UNTAINTED_").append(std::to_string(x*8))
            .append(" {").append(taint_src_ != nullptr?
                                 std::to_string(taint_src_->offset()):
                                 string("_"))
            .append("}");
   else {
      auto y = TaintDomain::uninit(this);
      return string("TAINTED_").append(std::to_string(y*8))
            .append(" {").append(taint_src_ != nullptr?
                                 std::to_string(taint_src_->offset()):
                                 string("_"))
            .append("}");
   }
}


uint8_t TaintDomain::init(const BaseDomain* object) {
   if (object->top()) return 32;
   else if (object->bot()) return 0;
   else {
      auto obj = (const TaintDomain*)object;
      if (obj->extract(0,31) == 0) return 32;
      else if (obj->extract(0,15) == 0) return 16;
      else if (obj->extract(0,7) == 0) return 8;
      else if (obj->extract(0,3) == 0) return 4;
      else if (obj->extract(0,1) == 0) return 2;
      else if (obj->extract(0,0) == 0) return 1;
      else return 0;
   }
}


uint8_t TaintDomain::uninit(const BaseDomain* object) {
   if (object->top()) return 0;
   else if (object->bot()) return 32;
   else {
      auto obj = (const TaintDomain*)object;
      if (TaintDomain::init(object) > 0) return 0;
      else if (obj->extract(1,63) == 0) return 1;
      else if (obj->extract(2,63) == 0) return 2;
      else if (obj->extract(4,63) == 0) return 4;
      else if (obj->extract(8,63) == 0) return 8;
      else if (obj->extract(16,63) == 0) return 16;
      else return 32;
   }
}


bool TaintDomain::valid(const BaseDomain* object, uint8_t mode_size) {
   return TaintDomain::init(object) >= mode_size;
}


void TaintDomain::binary_op(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top()) {
      if (!obj2->top()) {
         auto const y = (const TaintDomain*)obj2;
         obj = TaintDomain::create(y->state_!=0? 0xffffffff: 0x0, y->taint_src_);
      }
   }
   else if (!obj->top()) {
      auto x = (TaintDomain*)obj;
      if (x->state_ != 0)
         x->state_ = 0xffffffff;
      else if (!obj2->top()) {
         auto const y = (const TaintDomain*)obj2;
         x->state_ = (y->state_!=0)? 0xffffffff: 0x0;
         x->taint_src_ = (y->state_!=0)? y->taint_src_: nullptr;
      }
   }
}


void TaintDomain::unary_op(BaseDomain*& obj) {
   if (obj->top() || obj->bot())
      return;
   else {
      auto x = (TaintDomain*)obj;
      if (x->state_ != 0)
         x->state_ = 0xffffffff;
   }
}


Insn* TaintDomain::taint_src(BaseDomain* obj) {
   return (obj->top() || obj->bot())? nullptr: ((TaintDomain*)obj)->taint_src_;
}


uint32_t TaintDomain::extract(uint8_t lsb, uint8_t msb) const {
   return ((state_ << (31-msb)) >> (31-msb+lsb));
}
/* -------------------------------- ExprVal --------------------------------- */
template<class T> ExprVal<T>::ExprVal() {
   op_ = T::EXPR_VAL_OP::NONE;
   subargs_[0] = nullptr;
   subargs_[1] = nullptr;
}


template<class T> ExprVal<T>::ExprVal(T* a) {
   op_ = T::EXPR_VAL_OP::NONE;
   subargs_[0] = (T*)(a->clone());
   subargs_[1] = nullptr;
}


template<class T> ExprVal<T>::ExprVal(T::EXPR_VAL_OP op, T* a, T* b) {
   op_ = op;
   subargs_[0] = (T*)(a->clone());
   subargs_[1] = (T*)(b->clone());
}


template<class T> ExprVal<T>::ExprVal(const ExprVal<T>& obj) {
   op_ = obj.op_;
   for (int i = 0; i < 2; ++i)
      subargs_[i] = obj.subargs_[i]==nullptr? nullptr:
                    (T*)(obj.subargs_[i]->clone());
}


template<class T> ExprVal<T>::~ExprVal() {
   BaseDomain::safe_delete(subargs_[0]);
   BaseDomain::safe_delete(subargs_[1]);
}


template<class T> bool ExprVal<T>::comparable() const {
   auto const& a = subargs_[0];
   auto const& b = subargs_[1];
   return (a!=nullptr && a->comparable() && (b==nullptr || b->comparable()));
}


template<class T> void ExprVal<T>::update(typename T::EXPR_VAL_OP op, T* a,
T* b) {
   if (subargs_[0] != nullptr) BaseDomain::safe_delete(subargs_[0]);
   if (subargs_[1] != nullptr) BaseDomain::safe_delete(subargs_[1]);
   op_ = op;
   subargs_[0] = (T*)((a->ref() > 0)? a->clone(): a);
   subargs_[1] = (b == nullptr)? nullptr: ((b->ref() > 0)? (T*)(b->clone()): b);
}


template<class T> string ExprVal<T>::to_string() const {
   return string("");
}


template<class T> void ExprVal<T>::norm(ExprVal<T>* rhs) {
}


template<class T> vector<pair<typename T::ComparableType,Range>>
ExprVal<T>::get_cstr(COMPARE cmp, const ExprVal<T>* rhs) const {
   return vector<pair<typename T::ComparableType,Range>>{};
}
/* ------------------------------- FlagUnit --------------------------------- */
template<class T> FlagUnit<T>::FlagUnit(const array<ExprId*,2>& id,
const array<ExprVal<T>*,2>& val) {
   /* process id */
   if (id[0]->comparable() && id[1]->comparable()) {
      id_ = vector<ExprId*>(id.begin(), id.end());
      id_[0]->norm(id_[1]);
   }

   /* process val */
   if (val[0]->comparable() && val[1]->comparable()) {
      val_ = vector<ExprVal<T>*>(val.begin(), val.end());
      val_[0]->norm(val_[1]);
   }
}


template<class T> FlagUnit<T>::~FlagUnit() {
}


template<class T> string FlagUnit<T>::to_string() const {
   /* [(ax, stack[34] + 85); (base_ax, base_stack[34] + [85,85])] */
   auto s = string("{");
   if (!id_.empty())
      s.append(id_[0]->to_string()).append(" vs ").append(id_[1]->to_string());
   else
      s.append("...");
   s.append("; ");
   if (!val_.empty())
      s.append(val_[0]->to_string()).append(" vs ").append(val_[1]->to_string());
   else
      s.append("...");
   s.append("}");
   return s;
}


template<class T> void FlagUnit<T>::invalidate(const UnitId& id) {
   for (auto x: id_)
      if (x->subargs(0) == id || x->subargs(1) == id) {
         id_.clear();
         return;
      }
}


template<class T> void FlagUnit<T>::invalidate(REGION r) {
   for (auto x: id_)
      if (x->subargs(0).r() == r || x->subargs(1).r() == r) {
         id_.clear();
         return;
      }
}
/* ------------------------------- FlagDomain ------------------------------- */
template<class T> FlagDomain<T>::FlagDomain(const FlagUnit<T>& u) {
   units_ = u.empty()? vector<FlagUnit<T>>{}: vector<FlagUnit<T>>{u};
}


template<class T> FlagDomain<T>* FlagDomain<T>::create(const FlagUnit<T>& u) {
   return (FlagDomain<T>*)(new FlagDomain<T>(u));
}


template<class T> BaseDomain* FlagDomain<T>::clone() const {
   return new FlagDomain<T>(*this);
};


template<class T> BaseDomain* FlagDomain<T>::abs_union(const BaseDomain*
object) {
   if (object->bot())
      return this;
   else {
      const FlagDomain<T>* obj = (const FlagDomain<T>*)object;
      for (auto const& v: obj->units_)
         if (units_.size() > CSTR_LIMIT)
            break;
         else if (!v.empty())
            units_.push_back(v);
      return this;
   }
}


template<class T> string FlagDomain<T>::to_string() const {
   if (units_.empty())
      return string("{}");
   else {
      string s = "{";
      for (int i = 0; i < (int)(units_.size()) - 1; ++i)
         s.append(units_[i].to_string()).append("; ");
      s.append(units_.back().to_string()).append("}");
      return s;
   }
}


template<class T> void FlagDomain<T>::invalidate(BaseDomain* flags,
const UnitId& dst, const ExprId& src_expr) {
   if (!flags->bot())
      if (src_expr.empty() || src_expr.subargs(0) != dst ||
      !src_expr.subargs(1).zero()) {
         auto f = (FlagDomain<T>*)flags;
         for (auto& u: f->units_)
            u.invalidate(dst);
      }
};


template<class T> void FlagDomain<T>::invalidate(BaseDomain* flags, REGION r) {
   if (!flags->bot()) {
      auto f = (FlagDomain<T>*)flags;
      for (auto& u: f->units_)
         u.invalidate(r);
   }
};
/* ------------------------------- CstrDomain ------------------------------- */
template<class T> CstrDomain<T>::CstrDomain(COMPARE cmp, const BaseDomain* f) {
   if (cmp == COMPARE::OTHER || cmp == COMPARE::NONE || f->bot())
      return;

   auto const flag = (const FlagDomain<T>*)f;

   /* compute cstrId_ */
   auto firstUnit = true;
   for (auto const& u: flag->units()) {
      if (!u.args_id().empty()) {
         auto const& x = u.args_id()[0];
         auto const& y = u.args_id()[1];
         for (auto [b, r]: x->get_cstr(cmp, y)) {
            cstrId_[b] = firstUnit? r: (cstrId_.contains(b)?
                                       (cstrId_[b] | r): Range::UNIVERSAL);
         }
      }
      else {
         cstrId_.clear();
         break;
      }
      firstUnit = false;
   }

   /* compute cstrVal_ */
   firstUnit = true;
   for (auto const& u: flag->units()) {
      if (!u.args_val().empty()) {
         auto const& x = u.args_val()[0];
         auto const& y = u.args_val()[1];
         for (auto [b,r]: x->get_cstr(cmp, y))
            cstrVal_[b] = firstUnit? r: (cstrVal_.contains(b)?
                                        (cstrVal_[b] | r): Range::UNIVERSAL);
      }
      else {
         cstrVal_.clear();
         break;
      }
      firstUnit = false;
   }
}


template<class T> CstrDomain<T>::CstrDomain(const CstrDomain<T>& obj) {
   if (!obj.bot()) {
      cstrId_ = obj.cstrId_;
      cstrVal_ = obj.cstrVal_;
      exprEq_ = obj.exprEq_;
   }
}


template<class T> CstrDomain<T>* CstrDomain<T>::create(COMPARE cmp,
const BaseDomain* f) {
   return (CstrDomain<T>*)(new CstrDomain<T>(cmp, f));
}


template<class T> BaseDomain* CstrDomain<T>::clone() const {
   return new CstrDomain<T>(*this);
}


template<class T> string CstrDomain<T>::to_string() const {
   auto s = string("{");
   if (!cstrId_.empty()) {
      for (auto const& [sym, r]: cstrId_)
         s.append(get_id(sym).to_string()).append(": ")
          .append(r.to_string()).append("; ");
      s.erase(s.length()-2, 2);
   }
   if (!cstrVal_.empty()) {
      for (auto const& [val, r]: cstrVal_)
         s.append("; ").append(T::to_string(val)).append(": ")
          .append(r.to_string());
   }
   s.append("}");

   if (!exprEq_.empty()) {
      s.append(" | [");
      for (auto const& [val, args_id]: exprEq_)
         s.append(get_id(val).to_string()).append(" ~ ")
          .append(args_id.to_string()).append("; ");
      s.erase(s.length()-2, 2);
      s.append("]");
   }
   return s;
}


template<class T> void CstrDomain<T>::abs_and(BaseDomain*& object,
const BaseDomain* object2) {
   if (object->bot())
      object = (BaseDomain*)object2;
   else if (object2->bot())
      return;
   else {
      auto obj = (CstrDomain<T>*)object;
      auto const obj2 = (const CstrDomain<T>*)object2;
      /* propagate constraint from equivalent expression -> condition branch */
      /* compute new cstrs from cstrId_ in object + exprEq_ in object2 */
      if (!obj2->exprEq_.empty()) {
         for (auto const& [sym, r]: obj->cstrId_) {
            /* sym_a = sym_b + c */
            for (auto const& [sym_a, expr]: obj2->exprEq_) {
               auto sym_b = get_sym(expr.subargs(0));
               auto c = expr.subargs(1).i();
               /* sym = sym_a -> sym_b = r - c */
               if (sym == sym_a) {
                  if (obj->cstrId_.contains(sym_b))
                     obj->cstrId_[sym_b] = obj->cstrId_[sym_b] & (r-Range(c,c));
                  else
                     obj->cstrId_[sym_b] = r - Range(c,c);
               }
               /* sym = sym_b -> sym_a = r + c */
               else if (sym == sym_b) {
                  if (obj->cstrId_.contains(sym_a))
                     obj->cstrId_[sym_a] = obj->cstrId_[sym_a] & (r+Range(c,c));
                  else
                     obj->cstrId_[sym_a] = r + Range(c,c);
               }
            }
         }
         /* pass equivalent expressions */
         obj->exprEq_ = obj2->exprEq_;
      }
      /* cstrId_ */
      for (auto const& [sym, r]: obj2->cstrId_)
         if (obj->cstrId_.contains(sym))
            obj->cstrId_[sym] = (obj->cstrId_[sym] & r);
         else
            obj->cstrId_[sym] = r;
      /* cstrVal_ */
      for (auto const& [val, r]: obj2->cstrVal_)
         if (obj->cstrVal_.contains(val))
            obj->cstrVal_[val] = (obj->cstrVal_[val] & r);
         else
            obj->cstrVal_[val] = r;
   }
}


template<class T> void CstrDomain<T>::abs_ior(BaseDomain*& object,
const BaseDomain* object2) {
   /* constraint can never be TOP */
   if (object->bot())
      object = (BaseDomain*)object2;
   else if (object2->bot())
      return;
   else {
      auto obj = (CstrDomain<T>*)object;
      auto const obj2 = (const CstrDomain<T>*)object2;
      /* cstrId_ */
      for (auto const& [sym, r]: obj->cstrId_) {
         auto it = obj2->cstrId_.find(sym);
         obj->cstrId_[sym] = (it != obj2->cstrId_.end())? (r | it->second):
                                                          Range::UNIVERSAL;
      }
      /* cstrVal_ */
      for (auto const& [val, r]: obj->cstrId_) {
         auto it = obj2->cstrVal_.find(val);
         obj->cstrVal_[val] = (it != obj2->cstrVal_.end())? (r | it->second):
                                                            Range::UNIVERSAL;
      }
      /* remove constraints of UNIVERSAL */
      for (auto it = obj->cstrId_.begin(); it != obj->cstrId_.end();)
         if (it->second == Range::UNIVERSAL)
            it = obj->cstrId_.erase(it);
         else
            ++it;
      for (auto it = obj->cstrVal_.begin(); it != obj->cstrVal_.end();)
         if (it->second == Range::UNIVERSAL)
            it = obj->cstrVal_.erase(it);
         else
            ++it;
      /* exprEq_ */
      for (auto it = obj->exprEq_.begin(); it != obj->exprEq_.end();) {
         auto sym = it->first;
         if (!obj2->exprEq_.contains(sym))
            it = obj->exprEq_.erase(it);
         else {
            auto const& expr1 = it->second;
            auto const& expr2 = obj2->exprEq_.at(sym);
            if (expr1 != expr2)
               it = obj->exprEq_.erase(it);
            else
               ++it;
         }
      }
   }
}


template<class T> void CstrDomain<T>::use_cstr(const BaseDomain* constraint,
BaseDomain*& value, const UnitId& id) {
   if (!value->bot()) {
      auto obj = (T*)value;
      auto cstr = (CstrDomain<T>*)constraint;
      auto r1 = cstr->get_cstr(id);
      auto r2 = value->abstract()? Range::UNIVERSAL:
                                   obj->cstr_val(cstr->get_cstr(obj));
      auto r = r1 & r2;

      if (!r.empty() && !r.universal()) {
         if (value->abstract())
            value = T::create(r);
         else
            obj->use_cstr(r);
      }
   }
}


template<class T> void CstrDomain<T>::assign_cstr(BaseDomain* constraint,
const UnitId& dst, const ExprId& src_expr) {
   if (!constraint->bot()) {
      auto sym_dst = get_sym(dst);
      auto cstr = (CstrDomain<T>*)constraint;
      /* invalidate any equivalent expression related to dst */
      for (auto it = cstr->exprEq_.begin(); it != cstr->exprEq_.end();)
         if (it->first == sym_dst || get_sym(it->second.subargs(0)) == sym_dst)
            it = cstr->exprEq_.erase(it);
         else
            ++it;
      /* propagate constraint from equivalent expression -> assignment */
      /* compute cstr of dst from cstr of src */
      if (!src_expr.empty() && !src_expr.constant() &&
      src_expr.op()==ExprId::OP::PLUS && src_expr.subargs(1).constant()
      && get_sym(src_expr.subargs(0)) != sym_dst) {
         cstr->exprEq_[sym_dst] = src_expr;
         auto sym_src = get_sym(src_expr.subargs(0));
         auto c = src_expr.subargs(1).i();
         if (cstr->cstrId_.contains(sym_src))
            cstr->cstrId_[sym_dst] = cstr->cstrId_[sym_src] + Range(c,c);
         else
            cstr->cstrId_.erase(sym_dst);
      }
      else
         cstr->cstrId_.erase(sym_dst);
   }
}


template<class T> void CstrDomain<T>::invalidate(BaseDomain* constraint,
REGION r) {
   if (!constraint->bot()) {
      auto cstr = (CstrDomain<T>*)constraint;
      auto collect = unordered_set<IMM>{};
      for (auto const& [sym, range]: cstr->cstrId_)
         if (get_id(sym).r() == r)
            collect.insert(sym);
      for (auto sym: collect)
         cstr->cstrId_.erase(sym);
   }
}


template<class T> Range CstrDomain<T>::get_cstr(const UnitId& id) {
   auto sym = get_sym(id);
   return cstrId_.contains(sym)? cstrId_[sym]: Range::UNIVERSAL;
}


template<class T> Range CstrDomain<T>::get_cstr(const BaseDomain* object) {
   if (object->comparable()) {
      auto v = ((T*)object)->comparable_sym();
      return cstrVal_.contains(v)? cstrVal_[v]: Range::UNIVERSAL;
   }
   else
      return Range::UNIVERSAL;
}


DOMAIN_VAR
DOMAIN_CPP
EXPR_VAL_CPP
FLAG_UNIT_INSTANT
FLAG_DOMAIN_INSTANT
CSTR_DOMAIN_INSTANT
EXPR_VAL_INSTANT
