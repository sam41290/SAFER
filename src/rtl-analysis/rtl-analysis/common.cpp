/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "common.h"
#include "expr.h"
/* --------------------------------- UnitId --------------------------------- */
UnitId const UnitId::ZERO = UnitId(REGION::NONE,0);
UnitId const UnitId::FLAGS = UnitId(ARCH::compareFlags);
UnitId const UnitId::CF_FLAGS = UnitId(ARCH::controlFlags);
int64_t const flagSym = UnitId::FLAGS.symbol();
int64_t const ctrlSym = UnitId::CF_FLAGS.symbol();
int64_t const stackSym = UnitId(ARCH::stackPtr).symbol();
int64_t const staticSym = UnitId(ARCH::insnPtr).symbol();
Range const Range::ZERO = Range(0,0);
Range const Range::ONE = Range(1,1);
Range const Range::EMPTY = Range();
Range const Range::UNIVERSAL = Range(false);
CompareArgsId const CompareArgsId::EMPTY = CompareArgsId();
/* --------------------------------- UnitId --------------------------------- */
UnitId UnitId::outBoundId(REGION r) {
   return (r == REGION::STACK)? UnitId(REGION::STACK, _oo):
                                UnitId(REGION::STATIC, _oo);
}


UnitId UnitId::symbolId(int64_t c) {
  /*-----------------------------------------------------------------------+
   |  0   initReg[]   baseStack   initStack[]   baseStatic   initStatic[]  |
   |                                                                       |
   |  initReg[stackPtr] = baseStack                                        |
   |  initReg[insnPtr]  = baseStatic                                       |
   *-----------------------------------------------------------------------*/
   if (c == -1) return UnitId::outBoundId(REGION::STACK);
   else if (c == -2) return UnitId::outBoundId(REGION::STATIC);
   else if (c == 0) return UnitId::ZERO;
   else if (c < baseRegion(REGION::STACK)) return UnitId((ARCH::REG)c);
   else if (c == baseRegion(REGION::STACK)) return UnitId(ARCH::stackPtr);
   else if (c < baseRegion(REGION::STATIC))
      return UnitId(REGION::STACK,  c - baseRegion(REGION::STACK) - 1 +
                                    boundRange(REGION::STACK,0));
   else if (c == baseRegion(REGION::STATIC)) return UnitId(ARCH::insnPtr);
   else
      return UnitId(REGION::STATIC, c - baseRegion(REGION::STATIC) - 1 +
                                    boundRange(REGION::STATIC,0));
}


UnitId UnitId::operator-() const {
   if (is_bad())
      return UnitId();
   return is_const()? UnitId(REGION::NONE,-i_): UnitId(-sgn_,r_,i_);
}


bool UnitId::operator==(const UnitId& obj) const {
   if (is_bad())
      return false;
   return sgn_==obj.sgn_ && r_==obj.r_ && i_==obj.i_;
}


int64_t UnitId::symbol() const {
  /*-----------------------------------------------------------------------+
   |  0   initReg[]   baseStack   initStack[]   baseStatic   initStatic[]  |
   |                                                                       |
   |  initReg[stackPtr] = baseStack                                        |
   |  initReg[insnPtr]  = baseStatic                                       |
   *-----------------------------------------------------------------------*/
   switch (r_) {
      case REGION::REGISTER:
         if (i_ == (int)ARCH::stackPtr)
            return baseRegion(REGION::STACK);
         else if (i_ == (int)ARCH::insnPtr)
            return baseRegion(REGION::STATIC);
         else
            return i_;
      case REGION::STACK:
         if (i_ == _oo) return -1;
         else return baseRegion(r_) + 1 + i_ - boundRange(r_,0);
      case REGION::STATIC:
         if (i_ == _oo) return -2;
         else return baseRegion(r_) + 1 + i_ - boundRange(r_,0);
      case REGION::NONE:
         return 0;
      default:
         return -3;
   }
}


bool UnitId::bounds_check() const {
   if (is_bad())
      return false;
   return (r_ == REGION::NONE)? true:
          (i_ >= boundRange(r_,0) && i_ <= boundRange(r_,1));
}


string UnitId::to_string() const {
   string s = (sgn_ == -1)? string("-"): string("");
   switch (r_) {
      case REGION::REGISTER:
         s = ARCH::to_string((ARCH::REG)i_);
         break;
      case REGION::STACK:
         s.append((i_ == _oo)? string("stack[outBound]"):
                  string("stack[").append(std::to_string(i_)).append("]"));
         break;
      case REGION::STATIC:
         s.append((i_ == _oo)? string("static[outBound]"):
                  string("static[").append(std::to_string(i_)).append("]"));
         break;
      case REGION::NONE:
         s = s.append(std::to_string(i_));
         break;
      default:
         s = string("bad");
         break;
   }
   return s;
}
/* --------------------------------- Range ---------------------------------- */
Range::Range(COMPARE cmp, int64_t i) {
   c = false;
   auto c_add_1 = (i < oo)? i + 1: i;
   auto c_sub_1 = (i > _oo)? i - 1: i;
   switch (cmp) {
      case COMPARE::EQ: l = i;        h = i;                   break;
      case COMPARE::NE: l = i;        h = i;        c = true;  break;
      case COMPARE::GT: l = c_add_1;  h = oo;                  break;
      case COMPARE::GE: l = i;        h = oo;                  break;
      case COMPARE::LT: l = _oo;      h = c_sub_1;             break;
      case COMPARE::LE: l = _oo;      h = i;                   break;
      default:          l = _oo;      h = oo;                  break;
   }
   norm();
}


Range::Range(COMPARE cmp, const Range& obj) {
   c = false;
   auto h_add_1 = (obj.h < oo)?  obj.h + 1: obj.h;
   auto l_sub_1 = (obj.l > _oo)? obj.l - 1: obj.l;
   switch (cmp) {
      case COMPARE::EQ: l = obj.l;    h = obj.h;               break;
      case COMPARE::NE: l = obj.l;    h = obj.h;    c = true;  break;
      case COMPARE::GT: l = h_add_1;  h = oo;                  break;
      case COMPARE::GE: l = obj.h;    h = oo;                  break;
      case COMPARE::LT: l = _oo;      h = l_sub_1;             break;
      case COMPARE::LE: l = _oo;      h = obj.l;               break;
      default:          l = _oo;      h = oo;                  break;
   }
   norm();
}


Range& Range::operator=(const Range& obj) {
   l = obj.l;
   h = obj.h;
   c = obj.c;
   return *this;
}


Range Range::operator-() const {
   return (!empty() && !universal())? Range(-h,-l,c): Range(*this);
}


Range Range::operator!() const {
   return Range(l, h, !c);
}


Range Range::operator+(const Range& obj) const {
   /* zero */
   if (obj == Range::ZERO)
      return *this;
   else if (*this == Range::ZERO)
      return obj;
   /* empty */
   else if (empty() || obj.empty())
      return Range::EMPTY;
   /* universal or NE-constraint */
   else if (universal() || obj.universal() || c || obj.c)
      return Range::UNIVERSAL;
   else
      return Range(Util::plus(l,obj.l), Util::plus(h,obj.h));
}


Range Range::operator-(const Range& obj) const {
   if (obj == Range::ZERO)
      return *this;
   else if (*this == Range::ZERO)
      return obj;
   else if (empty() || obj.empty())
      return Range::EMPTY;
   else if (universal() || obj.universal() || c || obj.c)
      return Range::UNIVERSAL;
   else
      return Range(Util::minus(l,obj.h), Util::minus(h,obj.l));
}


Range Range::operator*(const Range& obj) const {
   /* one */
   if (obj == Range::ONE)
      return *this;
   else if (*this == Range::ONE)
      return obj;
   /* empty */
   else if (empty() || obj.empty())
      return Range::EMPTY;
   /* universal or NE-constraint */
   else if (universal() || obj.universal() || c || obj.c)
      return Range::UNIVERSAL;
   else {
      auto t1 = Util::mult(l, obj.l);
      auto t2 = Util::mult(l, obj.h);
      auto t3 = Util::mult(h, obj.l);
      auto t4 = Util::mult(h, obj.h);
      auto val_l = std::min(t1, std::min(t2, std::min(t3, t4)));
      auto val_h = std::max(t1, std::max(t2, std::max(t3, t4)));
      return Range(val_l, val_h);
   }
}


Range Range::operator/(const Range& obj) const {
   /* divisor: one */
   if (obj == Range::ONE)
      return *this;
   else if (empty() || obj.empty())
      return Range::EMPTY;
   else if (universal() || obj.universal() || c || obj.c)
      return Range::UNIVERSAL;
   else if (obj.contains(Range::ZERO))
      return Range::UNIVERSAL;
   else {
      auto t1 = l / obj.l;
      auto t2 = l / obj.h;
      auto t3 = h / obj.l;
      auto t4 = h / obj.h;
      auto val_l = std::min(t1, std::min(t2, std::min(t3, t4)));
      auto val_h = std::max(t1, std::max(t2, std::max(t3, t4)));
      return Range(val_l, val_h);
   }
}


Range Range::operator%(const Range& obj) const {
   /* divisor: one */
   if (obj == Range::ONE)
      return *this;
   /* empty */
   if (empty() || obj.empty()) return Range::EMPTY;
   /* divisor: universal or NE-constraint */
   else if (obj.universal() || obj.c) return Range::UNIVERSAL;
   /* division by Range::ZERO */
   else if (obj.contains(Range::ZERO)) return Range::UNIVERSAL;
   /* dividend: universal or NE-constraint */
   else if (universal() || c) return Range(0, std::abs(obj.h));
   else return Range(0, std::max(std::abs(h),std::abs(obj.h)));
}


Range Range::operator<<(const Range& obj) const {
   if (empty() || obj.empty())
      return Range::EMPTY;
   else if (universal() || obj.universal() || c || obj.c)
      return Range::UNIVERSAL;
   /* definitely positive range */
   else if (*this > Range::ZERO && obj > Range::ZERO)
      return Range(l << obj.l, h << obj.h);
   /* contains negative range */
   else
      return Range::UNIVERSAL;
}


Range Range::operator&(const Range& obj) const {
   /* empty */
   if (empty() || obj.empty()) return Range::EMPTY;
   /* universal */
   else if (universal()) return obj;
   else if (obj.universal()) return Range(*this);
   /* normal & normal */
   else if (!c && !obj.c) return Range(std::max(l,obj.l), std::min(h,obj.h));
   /* normal & NE-constraint */
   else if (!c && obj.c) {
      auto l_range = (*this) & Range(COMPARE::LT, obj.l);
      auto h_range = (*this) & Range(COMPARE::GT, obj.h);
      return l_range | h_range;
   }
   else if (c && !obj.c) {
      auto l_range = Range(COMPARE::LT, l) & obj;
      auto h_range = Range(COMPARE::GT, h) & obj;
      return l_range | h_range;
   }
   /* NE-constraint & NE-constraint */
   else {
      if (l<=obj.l && obj.l<=h) return Range(l, std::max(h,obj.h), true);
      if (obj.l<=l && l<=obj.h) return Range(obj.l, std::max(h,obj.h), true);
      else return Range::UNIVERSAL;
   }
}


Range Range::operator|(const Range& obj) const {
   /* universal */
   if (universal() || obj.universal()) return Range::UNIVERSAL;
   /* empty */
   else if (empty()) return obj;
   else if (obj.empty()) return Range(*this);
   /* normal & normal */
   else if (!c && !obj.c) return Range(std::min(l,obj.l), std::max(h,obj.h));
   /* normal & NE-constraint */
   else if (!c && obj.c) {
      if (l <= obj.l && obj.l <= h)
         return (h < obj.h)? Range(h+1, obj.h, true): Range::UNIVERSAL;
      if (l <= obj.h && obj.h <= h)
         return (obj.l < l)? Range(obj.l, l-1, true): Range::UNIVERSAL;
      if (obj.l < l && h < obj.h)
         return Range::UNIVERSAL;
      return obj;
   }
   else if (c && !obj.c) {
      if (obj.l <= l && l <= obj.h)
         return (obj.h < h)? Range(obj.h+1, h, true): Range::UNIVERSAL;
      if (obj.l <= h && h <= obj.h)
         return (l < obj.l)? Range(l, obj.l-1, true): Range::UNIVERSAL;
      if (l < obj.l && obj.h < h)
         return Range::UNIVERSAL;
      return Range(*this);
   }
   /* NE-constraint & NE-constraint */
   else {
      if (l<=obj.l && obj.l<=h) return Range(obj.l, std::min(h,obj.h), true);
      if (obj.l<=l && l<=obj.h) return Range(l, std::min(h,obj.h), true);
      else return Range::UNIVERSAL;
   }
}


Range Range::operator^(const Range& obj) const {
   if (empty() || obj.empty())
      return Range::EMPTY;
   else if (universal() || obj.universal() || c || obj.c)
      return Range::UNIVERSAL;
   /* definitely positive range */
   else if (*this > Range::ZERO && obj > Range::ZERO) {
      int64_t res = (1LL << (int)(std::log(std::max(h, obj.h)) + 1)) - 1;
      return Range(0, res);
   }
   /* contains negative range */
   else
      return Range::UNIVERSAL;
}


bool Range::operator==(const Range& obj) const {
   return l == obj.l && h == obj.h && c == obj.c;
}


bool Range::operator!=(const Range& obj) const {
   return l != obj.l || h != obj.h || c != obj.c;
}


bool Range::operator>=(const Range& obj) const {
   /* incomparable: E, U, NE-constraint */
   if (universal() || obj.universal() || c || obj.c) return false;
   return l >= obj.h;
}


bool Range::operator<=(const Range& obj) const {
   if (universal() || obj.universal() || c || obj.c) return false;
   return h <= obj.l;
}


bool Range::operator>(const Range& obj) const {
   if (universal() || obj.universal() || c || obj.c) return false;
   return l > obj.h;
}


bool Range::operator<(const Range& obj) const {
   if (universal() || obj.universal() || c || obj.c) return false;
   return h < obj.l;
}


bool Range::contains(const Range& obj) const {
   /* empty */
   if (obj.empty()) return true;
   /* universal */
   else if (obj.universal()) return universal();
   /* NE-constraint */
   else if (obj.c) return universal() || (c && obj.l <= l && h <= obj.h);
   else return l <= obj.l && obj.h <= h;
}


Range Range::abs() const {
   /* empty */
   if (empty()) return Range::EMPTY;
   /* universal */
   else if (universal()) return Range::UNIVERSAL;
   else if (!c) {
      if (l <= 0 && 0 <= h)
         return Range(0, std::max(std::abs(l),std::abs(h)));
      else if (h <= 0)
         return Range(std::abs(h),std::abs(l));
      else
         return Range(*this);
   }
   else {
      if (l <= 0 && 0 <= h)
         return Range(std::min(std::abs(l),std::abs(h))+1, oo);
      else
         return Range(0, oo);
   }

}


void Range::contract(int bytes) {
   /* empty */
   if (empty())
      return;
   l = std::min(std::max(l, Util::min(bytes)), Util::max(bytes));
   h = std::max(std::min(h, Util::max(bytes)), Util::min(bytes));
   norm();
}


string Range::to_string() const {
   if (empty())
      return string("[]");
   else {
      auto s = c? string("!"): string("");
      if (l == _oo) s.append("[-oo, ");
      else s.append("[").append(std::to_string(l)).append(", ");
      if (h == oo) s.append("+oo]");
      else s.append(std::to_string(h)).append("]");
      return s;
   }
}


void Range::norm() {
   /* skip set E and U */
   if (empty() || universal())
      return;
   /* bad range --> E */
   if (l > h) {
      *this = Range::EMPTY;
      return;
   }

   /* standardize constraint sets (except NE) */
   /* U\[-oo,3] --> [4,oo]  */
   /* U\[4,oo]  --> [-oo,3] */
   if (c && (l==_oo || h==oo)) {
      c = false;
      if (l==_oo) {
         l = h + 1;
         h = oo;
      }
      else {
         h = l - 1;
         l = _oo;
      }
   }

   /*   (_oo       norm_min     norm_max  [ ]  oo) --> E */
   /*   (_oo  [ ]  norm_min     norm_max       oo) --> E */
   /* U\(_oo       norm_min     norm_max  [ ]  oo) --> U */
   /* U\(_oo       norm_min     norm_max  [ ]  oo) --> U */
   if (l > norm_max || h < norm_min) {
      *this = Range(!c);
      return;
   }

   /* normalize range */
   l = (l != _oo)? std::max(l, (int64_t)norm_min): _oo;
   h = (h !=  oo)? std::min(h, (int64_t)norm_max):  oo;
}
/* ------------------------------ CompareArgsId ----------------------------- */
CompareArgsId::CompareArgsId() {
   empty_ = true;
   constant_ = false;
   op_ = OP::PLUS;
   subargs_[0] = UnitId::ZERO;
   subargs_[1] = UnitId::ZERO;
}


CompareArgsId::CompareArgsId(const UnitId& a) {
   update(a);
}


CompareArgsId::CompareArgsId(OP op, const UnitId& a, const UnitId& b) {
   update(op, a, b);
}


CompareArgsId::CompareArgsId(const CompareArgsId& obj) {
   op_ = obj.op_;
   subargs_ = obj.subargs_;
   empty_ = obj.empty_;
   constant_ = obj.constant_;
}


bool CompareArgsId::comparable() const {
   return (!empty_ && (subargs_[0].is_const() || subargs_[0].bounds_check()) &&
                      (subargs_[1].is_const() || subargs_[1].bounds_check()));
}


bool CompareArgsId::operator==(const CompareArgsId& obj) const {
   if (!empty_ && !obj.empty_ && op_ == obj.op_ &&
   ((subargs_[0]==obj.subargs_[0] && subargs_[1]==obj.subargs_[1]) ||
   (subargs_[0]==obj.subargs_[1] && subargs_[1]==obj.subargs_[0])))
      return true;
   return false;
}


string CompareArgsId::to_string() const {
   if (empty_)
      return string("∅");
   auto s0 = subargs_[0].to_string();
   auto s1 = subargs_[1].to_string();
   switch (op_) {
      case OP::AND:
         return s0.append(" & ").append(s1);
      default:
         return (!subargs_[1].is_zero())? s0.append(" + ").append(s1): s0;
   }
}


vector<pair<int64_t,Range>> CompareArgsId::get_cstr(COMPARE cmp,
const CompareArgsId* rhs) const {
   vector<pair<int64_t,Range>> res;
   if (comparable() && rhs->comparable() && op_==OP::PLUS && rhs->op_==OP::PLUS
   && subargs_[1].is_zero() && rhs->subargs_[1].is_zero()) {
      auto const& x = subargs_[0];
      auto const& y = rhs->subargs_[0];
      /* (c + 0 < x + 0) --> x > c --> x in [c+1,oo] */
      if (x.is_const() && !y.is_const())
         res.push_back(make_pair(y.symbol(), Range(Util::opposite(cmp),x.i())));
      /* (x + 0 < c + 0) --> x < c --> x in [-oo,c-1] */
      else if (!x.is_const() && y.is_const())
         res.push_back(make_pair(x.symbol(), Range(cmp,y.i())));
   }
   return res;
}


void CompareArgsId::norm(CompareArgsId* rhs) {
   auto c1 = subargs_[1];
   auto c2 = rhs->subargs_[1];
   if (comparable() && rhs->comparable() && c1.is_const() && c2.is_const() &&
   op_ == OP::PLUS && rhs->op_ == OP::PLUS) {
      auto x = subargs_[0];
      auto y = rhs->subargs_[0];
      auto c = UnitId(REGION::NONE, c2.i()-c1.i());
      /* (-x + c1, -y + c2) --> (y + c1, x + c2) --> (y + 0, x + c2-c1) */
      if (x.sgn() == -1 && y.sgn() == -1) {
         update(-y);
         rhs->update(OP::PLUS, -x, c);
      }
      /* (-x + c1, y + c2) --> (c1 - c2, x + y) */
      else if (x.sgn() == -1 && y.sgn() == 1) {
         update(-c);
         rhs->update(OP::PLUS, -x, y);
      }
      /* (x + c1, -y + c2) --> (x + y, c2 - c1) */
      else if (x.sgn() == 1 && y.sgn() == -1) {
         update(OP::PLUS, x, -y);
         rhs->update(c);
      }
      /* (x + c1, y + c2) --> (x + 0, y + c2-c1) */
      /* (c + c1, y + c2) --> (c + c1-c2, y + 0) */
      else {
         if (!x.is_const()) {
            update(x);
            rhs->update(OP::PLUS, y, c);
         }
         else {
            update(OP::PLUS, x, -c);
            rhs->update(y);
         }
      }
   }
}


void CompareArgsId::update(const UnitId& a) {
   if (a.is_bad() || !a.bounds_check()) {
      empty_ = true;
      constant_ = false;
      op_ = OP::PLUS;
      subargs_[0] = UnitId::ZERO;
      subargs_[1] = UnitId::ZERO;
   }
   else {
      empty_ = false;
      constant_ = a.is_const();
      op_ = OP::PLUS;
      subargs_[0] = a;
      subargs_[1] = UnitId::ZERO;
   }
}


void CompareArgsId::update(OP op, const UnitId& a, const UnitId& b) {
   if (a.is_bad() || b.is_bad() || !a.bounds_check() || !b.bounds_check()) {
      empty_ = true;
      constant_ = false;
      op = OP::PLUS;
      subargs_[0] = UnitId::ZERO;
      subargs_[1] = UnitId::ZERO;
   }
   else {
      /* MINUS is converted to PLUS */
      if (op == OP::PLUS || op == OP::MINUS) {
         /* c1 + c2 --> c + 0 */
         /* c1 - c2 --> c + 0 */
         if (a.is_const() && b.is_const()) {
            empty_ = false;
            constant_ = true;
            op_ = OP::PLUS;
            subargs_[0] = (op==OP::PLUS)? UnitId(REGION::NONE, a.i()+b.i()):
                                          UnitId(REGION::NONE, a.i()-b.i());
            subargs_[1] = UnitId::ZERO;
         }
         /* x - y --> x + (-y) */
         else if (op == OP::MINUS) {
            empty_ = false;
            constant_ = false;
            op_ = OP::PLUS;
            subargs_[0] = a;
            subargs_[1] = -b;
         }
         /* x + y */
         else {
            empty_ = false;
            constant_ = false;
            op_ = op;
            subargs_[0] = a;
            subargs_[1] = b;
         }
      }
      /* x & y */
      else {
         empty_ = false;
         constant_ = false;
         op_ = op;
         subargs_[0] = a;
         subargs_[1] = b;
      }

      /* c + x -> x + c       */
      /* c + (-x) -> (-x) + c */
      /* c & (-x) -> (-x) & c */
      if (subargs_[0].is_const() && !subargs_[1].is_const()) {
         auto tmp = subargs_[0];
         subargs_[0] = subargs_[1];
         subargs_[1] = tmp;
      }
   }
}
/* -------------------------------- ExprLoc --------------------------------- */
RTL* ExprLoc::rtl() const {
   return (RTL*)(expr->simplify());
};
/* ---------------------------------- Util ---------------------------------- */
int64_t Util::to_int(const string& s) {
   string s2 = s;
   if (s2.at(0) == '.')
      s2.erase(0,1);
   if (s2.substr(0, 2).compare("0x") == 0)
      return stoll(s2, nullptr, 16); 
   return stoll(s2, nullptr, 10);
}


double Util::to_double(const string& s) {
   return stod(s, nullptr);
}


int64_t Util::max(int bytes) {
   switch (bytes) {
      case 1:
         return std::numeric_limits<int8_t>::max();
      case 2:
         return std::numeric_limits<int16_t>::max();
      case 4:
         return std::numeric_limits<int32_t>::max();
      case 8:
         return std::numeric_limits<int64_t>::max();
      default:
         return -1;
   }
}


int64_t Util::min(int bytes) {
   switch (bytes) {
      case 1:
         return std::numeric_limits<int8_t>::min();
      case 2:
         return std::numeric_limits<int16_t>::min();
      case 4:
         return std::numeric_limits<int32_t>::min();
      case 8:
         return std::numeric_limits<int64_t>::min();
      default:
         return -1;
   }
}


int64_t Util::plus(int64_t x, int64_t y) {
   if (x == _oo)
      return _oo;
   else if (x == oo)
      return oo;
   else if (y == _oo)
      return _oo;
   else if (y == oo)
      return oo;
   else
      return x + y;
}


int64_t Util::minus(int64_t x, int64_t y) {
   if (x == _oo)
      return _oo;
   else if (x == oo)
      return oo;
   else if (y == _oo)
      return oo;
   else if (y == oo)
      return _oo;
   else
      return x - y;
}


int64_t Util::mult(int64_t x, int64_t y) {
   if (x == _oo) {
      if (y < 0) return oo;
      else if (y == 0) return 0;
      else return _oo;
   }
   else if (x == oo) {
      if (y < 0) return _oo;
      else if (y == 0) return 0;
      else return oo;
   }
   else if (y == _oo) {
      if (x < 0) return oo;
      else if (x == 0) return 0;
      else return _oo;
   }
   else if (y == oo) {
      if (x < 0) return _oo;
      else if (x == 0) return 0;
      else return oo;
   }
   else
      return x * y;
}


COMPARE Util::opposite(COMPARE cmp) {
   switch (cmp) {
      case COMPARE::EQ: return COMPARE::NE;
      case COMPARE::NE: return COMPARE::EQ;
      case COMPARE::GT: return COMPARE::LE;
      case COMPARE::GE: return COMPARE::LT;
      case COMPARE::LT: return COMPARE::GE;
      case COMPARE::LE: return COMPARE::GT;
      case COMPARE::OTHER: return COMPARE::OTHER;
      default: return COMPARE::NONE;
   }
}