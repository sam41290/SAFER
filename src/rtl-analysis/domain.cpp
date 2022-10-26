/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "domain.h"
/* -------------------------------------------------------------------------- */
string const BaseLH::NAME = string("BaseLH");
string const InitDomain::NAME = string("InitDomain");
BaseDomain* const BaseDomain::TOP = new BaseDomain(true);
BaseDomain* const BaseDomain::BOT = new BaseDomain(true);
BaseDomain* const BaseLH::NOTLOCAL = new BaseLH();
uint8_t InitDomain::uninit_allowed = 0;
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
Range BaseLH::val_with_cstr(const Range& baseCstr) {
   return baseCstr + r;
}


void BaseLH::use_cstr(const Range& cstr) {
   b = 0;
   r = cstr;
}


string BaseLH::to_string(ComparableType v) {
   return string("base_").append(UnitId::symbolId(v).to_string());
}


BaseLH* BaseLH::create_instance(const Range& range) {
   return (BaseLH*)((new BaseLH(range))->norm());
}


BaseLH* BaseLH::create_instance(int64_t base, const Range& range) {
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
   else if (r.lo() <= norm_min && r.hi() >= norm_max) {
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
             .append(UnitId::symbolId(std::abs(b)).to_string()).append(")");
   else
      return (b > 0? string("(base_"): string("(-base_"))
             .append(UnitId::symbolId(std::abs(b)).to_string())
             .append(" + ").append(r.to_string()).append(")");
}


bool BaseLH::notlocal(const BaseDomain* object) {
   return !object->top() && !object->bot() && object == BaseLH::NOTLOCAL;
}


bool BaseLH::excludeLocal(const BaseDomain* object) {
   return !object->top() && !object->bot() && (BaseLH::notlocal(object) ||
          ((const BaseLH*)object)->b != baseRegion(REGION::STACK));
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
         LOG(4, "error: division by zero!");
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
         LOG(4, "error: division by zero!");
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
            obj = BaseLH::create_instance(0, Range(0, y->r.hi()));
      }
   }
   else if (obj2->top() || BaseLH::notlocal(obj2)) {
      auto x = (BaseLH*)obj;
      auto r = Range(0, oo) & x->r;
      if (x->b == 0 && !r.empty()) {
         BaseDomain::safe_delete(obj);
         obj = BaseLH::create_instance(0, Range(0, r.hi()));
      }
   }
   else {
      auto x = (BaseLH*)obj;
      auto const y = (const BaseLH*)obj2;
      /* either has base --> abs_union */
      if (x->b != 0 || y->b != 0)
         obj = x->abs_union(y);
      /* (0 + r1) & (0 + r2) --> (0 + r1&r2) */
      else {
         x->r = x->r & y->r;
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
/* ------------------------------- InitDomain ------------------------------- */
BaseDomain* InitDomain::mode(uint8_t bytes) {
   uint32_t x = ((state_ << (32-bytes)) >> (32-bytes));
   if (x == state_)
      return this;
   return InitDomain::create_instance(x);
};


BaseDomain* InitDomain::abs_union(const BaseDomain* object) {
   if (object->top()) {
      BaseDomain::safe_delete(this);
      return BaseDomain::TOP;
   }
   if (object->bot())
      return this;
   else {
      const InitDomain* obj = (const InitDomain*)object;
      state_ &= obj->state_;   /* uninit if uninit in both */
      return this;
   }
}


bool InitDomain::equal(const BaseDomain* object) const {
   return (object==nullptr || object->top() || object->bot() || top() || bot())?
          this == object: state_ == ((const InitDomain*)object)->state_;
}


string InitDomain::to_string() const {
   auto x = InitDomain::init(this);
   if (x > 0)
      return string("INIT_").append(std::to_string(x*8));
   else {
      auto y = InitDomain::uninit(this);
      return string("UNINIT_").append(std::to_string(y*8));
   }
}


uint8_t InitDomain::init(const BaseDomain* object) {
   if (object->top()) return 32;
   else if (object->bot()) return 0;
   else {
      auto obj = (const InitDomain*)object;
      if (obj->extract(0,31) == 0) return 32;
      else if (obj->extract(0,15) == 0) return 16;
      else if (obj->extract(0,7) == 0) return 8;
      else if (obj->extract(0,3) == 0) return 4;
      else if (obj->extract(0,1) == 0) return 2;
      else if (obj->extract(0,0) == 0) return 1;
      else return 0;
   }
}


uint8_t InitDomain::uninit(const BaseDomain* object) {
   if (object->top()) return 0;
   else if (object->bot()) return 32;
   else {
      auto obj = (const InitDomain*)object;
      if (InitDomain::init(object) > 0) return 0;
      else if (obj->extract(1,63) == 0) return 1;
      else if (obj->extract(2,63) == 0) return 2;
      else if (obj->extract(4,63) == 0) return 4;
      else if (obj->extract(8,63) == 0) return 8;
      else if (obj->extract(16,63) == 0) return 16;
      else return 32;
   }
}


bool InitDomain::valid(const BaseDomain* object, int8_t mode_size) {
   return InitDomain::init(object) >= mode_size;
}


void InitDomain::binary_op(BaseDomain*& obj, const BaseDomain* obj2) {
   if (obj->bot() || obj2->bot()) {
      BaseDomain::safe_delete(obj);
      obj = BaseDomain::BOT;
   }
   else if (obj->top()) {
      if (!obj2->top()) {
         auto const y = (const InitDomain*)obj2;
         obj = InitDomain::create_instance(y->state_ > 0? -1: 0);
      }
   }
   else if (!obj->top()) {
      auto x = (InitDomain*)obj;
      if (x->state_ > 0)
         x->state_ = -1;
      else if (!obj2->top()) {
         auto const y = (const InitDomain*)obj2;
         x->state_ = (y->state_ > 0? -1: 0);
      }
   }
}


void InitDomain::unary_op(BaseDomain*& obj) {
   if (obj->top() || obj->bot())
      return;
   else {
      auto x = (InitDomain*)obj;
      if (x->state_ > 0)
         x->state_ = -1;
   }
}


uint32_t InitDomain::extract(uint8_t lsb, uint8_t msb) const {
   return ((state_ << (31-msb)) >> (31-msb+lsb));
}
/* ------------------------------- FlagDomain ------------------------------- */
template<class T> FlagUnit<T>::FlagUnit(const array<CompareArgsId*,2>& id,
const array<CompareArgsVal<T>*,2>& val) {
   /* process id */
   if (id[0]->comparable() && id[1]->comparable()) {
      id_ = vector<CompareArgsId*>(id.begin(), id.end());
      id_[0]->norm(id_[1]);
   }

   /* process val */
   if (val[0]->comparable() && val[1]->comparable()) {
      val_ = vector<CompareArgsVal<T>*>(val.begin(), val.end());
      val_[0]->norm(val_[1]);
   }
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
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
template<class T> FlagDomain<T>::FlagDomain(const FlagUnit<T>& u) {
   units_ = u.empty()? vector<FlagUnit<T>>{}: vector<FlagUnit<T>>{u};
}


template<class T> FlagDomain<T>* FlagDomain<T>::create_instance(
const FlagUnit<T>& u) {
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
         if (units_.size() > CSTR_CNT_LIMIT)
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
const UnitId& dst, const CompareArgsId& src_expr) {
   if (!flags->bot())
      if (src_expr.is_empty() || src_expr.subargs(0) != dst ||
      !src_expr.subargs(1).is_zero()) {
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

   auto flag = (FlagDomain<T>*)f;

   /* compute cstrId_ */
   auto firstUnit = true;
   for (auto const& u: flag->units()) {
      if (!u.args_id().empty()) {
         auto const& x = u.args_id()[0];
         auto const& y = u.args_id()[1];
         for (auto [b, r]: x->get_cstr(cmp, y))
            cstrId_[b] = firstUnit? r: (cstrId_.contains(b)?
                                       (cstrId_[b] | r): Range::UNIVERSAL);
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


template<class T> CstrDomain<T>* CstrDomain<T>::create_instance(COMPARE cmp,
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
         s.append(UnitId::symbolId(sym).to_string()).append(": ")
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
         s.append(UnitId::symbolId(val).to_string()).append(" ~ ")
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
               auto sym_b = expr.subargs(0).symbol();
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
      for (auto const& [sym, r]: obj2->cstrId_)
         if (obj->cstrId_.contains(sym))
            obj->cstrId_[sym] = (obj->cstrId_[sym] | r);
         else
            obj->cstrId_[sym] = Range::UNIVERSAL;
      /* cstrVal_ */
      for (auto const& [val, r]: obj2->cstrVal_)
         if (obj->cstrVal_.contains(val))
            obj->cstrVal_[val] = (obj->cstrVal_[val] | r);
         else
            obj->cstrVal_[val] = Range::UNIVERSAL;
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
      auto r1 = cstr->cstr_by_id(id);
      auto r2 = value->top()? Range::UNIVERSAL:
                               obj->val_with_cstr(cstr->cstr_by_val(obj));
      auto r = r1 & r2;
      if (!r.empty() && !r.universal()) {
         if (value->top())
            value = T::create_instance(r);
         else
            obj->use_cstr(r);
      }
   }
}


template<class T> void CstrDomain<T>::propagate(BaseDomain* constraint,
const UnitId& dst, const CompareArgsId& src_expr) {
   if (!constraint->bot()) {
      auto sym_dst = dst.symbol();
      auto cstr = (CstrDomain<T>*)constraint;
      /* invalidate any equivalent expression related to dst */
      for (auto it = cstr->exprEq_.begin(); it != cstr->exprEq_.end();)
         if (it->first == sym_dst || it->second.subargs(0).symbol() == sym_dst)
            it = cstr->exprEq_.erase(it);
         else
            ++it;
      /* propagate constraint from equivalent expression -> assignment */
      /* compute cstr of dst from cstr of src */
      if (!src_expr.is_empty() && !src_expr.is_const() &&
      src_expr.op()==CompareArgsId::OP::PLUS && src_expr.subargs(1).is_const()
      && src_expr.subargs(0).symbol() != sym_dst) {
         cstr->exprEq_[sym_dst] = src_expr;
         auto sym_src = src_expr.subargs(0).symbol();
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
      auto collect = unordered_set<int64_t>{};
      for (auto const& [sym, range]: cstr->cstrId_)
         if (UnitId::symbolId(sym).r() == r)
            collect.insert(sym);
      for (auto sym: collect)
         cstr->cstrId_.erase(sym);
   }
}


template<class T> Range CstrDomain<T>::cstr_by_id(const UnitId& id) {
   auto sym = id.symbol();
   return cstrId_.contains(sym)? cstrId_[sym]: Range::UNIVERSAL;
}


template<class T> Range CstrDomain<T>::cstr_by_val(const BaseDomain* object) {
   if (object->comparable()) {
      auto v = ((T*)object)->comparable_val();
      return cstrVal_.contains(v)? cstrVal_[v]: Range::UNIVERSAL;
   }
   else
      return Range::UNIVERSAL;
}
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* ----------------------------- CompareArgsVal ----------------------------- */
template<class T> CompareArgsVal<T>::CompareArgsVal() {
   op_ = T::COMPARE_ARGS_OP::NONE;
   subargs_[0] = nullptr;
   subargs_[1] = nullptr;
}


template<class T> CompareArgsVal<T>::CompareArgsVal(T* a) {
   op_ = T::COMPARE_ARGS_OP::NONE;
   subargs_[0] = (T*)((a->ref() > 0)? a->clone(): a);
   subargs_[1] = nullptr;
}


template<class T> CompareArgsVal<T>::CompareArgsVal(T::COMPARE_ARGS_OP op, T* a, 
T* b) {
   op_ = op;
   subargs_[0] = (T*)((a->ref() > 0)? a->clone(): a);
   subargs_[1] = (T*)((b->ref() > 0)? b->clone(): b);
}


template<class T> CompareArgsVal<T>::CompareArgsVal(const CompareArgsVal<T>& obj) {
   op_ = obj.op_;
   for (int i = 0; i < 2; ++i)
      subargs_[i] = obj.subargs_[i]==nullptr? nullptr:
                    (T*)(obj.subargs_[i]->clone());
}


template<class T> CompareArgsVal<T>::~CompareArgsVal() {
   BaseDomain::safe_delete(subargs_[0]);
   BaseDomain::safe_delete(subargs_[1]);
}


template<class T> bool CompareArgsVal<T>::comparable() const {
   auto const& a = subargs_[0];
   auto const& b = subargs_[1];
   return (a!=nullptr && a->comparable() && (b==nullptr || b->comparable()));
}


template<> string CompareArgsVal<BaseLH>::to_string() const {
   if (subargs_[0] == nullptr && subargs_[1] == nullptr)
      return string("");
   switch (op_) {
      case BaseLH::COMPARE_ARGS_OP::AND:
         return subargs_[0]->to_string().append(" & ")
               .append(subargs_[1]->to_string());
      default:
         return subargs_[0]->to_string();
   }
}


template<> void CompareArgsVal<BaseLH>::norm(CompareArgsVal<BaseLH>* rhs) {
   if (comparable() && rhs->comparable() &&
   op_==BaseLH::COMPARE_ARGS_OP::NONE && rhs->op_==BaseLH::COMPARE_ARGS_OP::NONE) {
      auto b1 = subargs_[0]->base();
      auto r1 = subargs_[0]->range();
      auto b2 = rhs->subargs_[0]->base();
      auto r2 = rhs->subargs_[0]->range();
      auto r = r2-r1;
      /* (b1 + r1, 0 + r2) --> (b1 + 0, 0 + r2-r1) */
      if (subargs_[0]->abstract() && !rhs->subargs_[0]->abstract()) {
         update(BaseLH::create_instance(b1, Range::ZERO));
         rhs->update(BaseLH::create_instance(r));
      }
      /* (0 + r1, b2 + r2) --> (0 + r1-r2, b2 + 0) */
      else if (!subargs_[0]->abstract() && rhs->subargs_[0]->abstract()) {
         update(BaseLH::create_instance(-r));
         rhs->update(BaseLH::create_instance(b2, Range::ZERO));
      }
      /* (b1 + r1, b2 + r2) --> (b1 + 0, b2 + r2-r1) */
      else if (subargs_[0]->abstract() && rhs->subargs_[0]->abstract()) {
         update(BaseLH::create_instance(b1, Range::ZERO));
         rhs->update(BaseLH::create_instance(b2, r));
      }
      /* (0 + r1, 0 + r2) --> (0 + 0, 0 + r2-r1) */
      else {
         update(BaseLH::create_instance(Range::ZERO));
         rhs->update(BaseLH::create_instance(r));
      }
   }
}


template<> vector<pair<BaseLH::ComparableType,Range>>
CompareArgsVal<BaseLH>::get_cstr(COMPARE cmp, const CompareArgsVal<BaseLH>* rhs)
const {
   vector<pair<BaseLH::ComparableType,Range>> res;
   if (comparable() && rhs->comparable() && op_==BaseLH::COMPARE_ARGS_OP::NONE &&
   rhs->op_==BaseLH::COMPARE_ARGS_OP::NONE) {
      auto const& x = subargs_[0];
      auto const& y = rhs->subargs_[0];
      /* (0 + r < b + 0) --> (b > r) --> b in [r+1,oo] */
      if (!x->abstract() && y->base() != 0 && y->range() == Range::ZERO) {
         auto b = y->base();
         auto r = x->range();
         res.push_back(make_pair(b, Range(Util::opposite(cmp),r)));
      }
      /* (b + 0 < 0 + r) --> (b < r) --> b in [-oo,r-1] */
      else if (!y->abstract() && x->base() != 0 && x->range() == Range::ZERO) {
         auto b = x->base();
         auto r = y->range();
         res.push_back(make_pair(b, Range(cmp,r)));
      }
   }
   return res;
}


template<class T> void CompareArgsVal<T>::update(typename T::COMPARE_ARGS_OP op,
T* a, T* b) {
   if (subargs_[0] != nullptr) BaseDomain::safe_delete(subargs_[0]);
   if (subargs_[1] != nullptr) BaseDomain::safe_delete(subargs_[1]);
   op_ = op;
   subargs_[0] = (T*)((a->ref() > 0)? a->clone(): a);
   subargs_[1] = (b == nullptr)? nullptr: ((b->ref() > 0)? (T*)(b->clone()): b);
}


template<> string CompareArgsVal<InitDomain>::to_string() const {return string("");}
template<> void CompareArgsVal<InitDomain>::norm(CompareArgsVal<InitDomain>* rhs) {}
template<> vector<pair<InitDomain::ComparableType,Range>>
           CompareArgsVal<InitDomain>::get_cstr(COMPARE cmp,
           const CompareArgsVal<InitDomain>* rhs) const {
               return vector<pair<InitDomain::ComparableType,Range>>{};
           }
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* ---------------------- Template Class Instantiation ---------------------- */
INSTANTIATE_COMPARE_ARGS
INSTANTIATE_FLAG_UNIT
INSTANTIATE_FLAG_DOMAIN
INSTANTIATE_CSTR_DOMAIN