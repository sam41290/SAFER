/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "utility.h"
#include "expr.h"
#include "domain.h"

using namespace SBA;

fstream f_log;
/* -------------------------------------------------------------------------- */
array<UnitId,ARCH::NUM_REG+1> const UnitId::REG = []() {
   auto a = array<UnitId,ARCH::NUM_REG+1>{};
   for (int i = 1; i < ARCH::NUM_REG; ++i)
      a[i] = UnitId(REGION::REGISTER, i);
   return a;
}();

array<UnitId,get_size(REGION::STACK)+2> const UnitId::STACK = []() {
   auto a = array<UnitId,get_size(REGION::STACK)+2>{};
   constexpr int lo = get_bound(REGION::STACK, 0);
   constexpr int hi = get_bound(REGION::STACK, 1);
   for (int i = lo; i <= hi; ++i)
      a[i - lo] = UnitId(REGION::STACK, i);
   a[get_size(REGION::STACK)] = UnitId(REGION::STACK, _oo);
   a[get_size(REGION::STACK)+1] = UnitId(REGION::STACK, oo);
   return a;
}();

UnitId const UnitId::ZERO = UnitId(REGION::NONE, 0);
UnitId const UnitId::FLAG = UnitId::REG[(int)(ARCH::flags)];
UnitId const UnitId::CFLAG = UnitId(REGION::SPECIAL, 1);
UnitId const UnitId::BAD = UnitId(REGION::SPECIAL, 0);
UnitId UnitId::TEMP = UnitId();
/*-----------------------------------------------+
|   0   initReg[]   initStack[]   initStatic[]   |
*-----------------------------------------------*/
const IMM SBA::get_sym(REGION r, IMM i) {
   switch (r) {
      case REGION::REGISTER:
         return i;
      case REGION::STACK:
         return (i < get_bound(REGION::STACK,0))?
                     get_base(REGION::STACK)+get_size(REGION::STACK):
               ((i > get_bound(REGION::STACK,1))?
                     get_base(REGION::STACK)+get_size(REGION::STACK)+1:
                     get_base(REGION::STACK)+i-get_bound(REGION::STACK,0));
      case REGION::STATIC:
         return (i < get_bound(REGION::STATIC,0))?
                     get_base(REGION::STATIC)+get_size(REGION::STATIC):
               ((i > get_bound(REGION::STATIC,1))?
                     get_base(REGION::STATIC)+get_size(REGION::STATIC)+1:
                     get_base(REGION::STATIC)+i-get_bound(REGION::STATIC,0));
      case REGION::NONE:
         return 0;
      default:
         return -1 - i;
   }
}


const IMM SBA::get_sym(ARCH::REG r) {
   return get_sym(REGION::REGISTER, (IMM)r);
}


const IMM SBA::get_sym(const UnitId& id) {
   return get_sym(id.r(), id.i());
}


const UnitId& SBA::get_id(REGION r, IMM i) {
   switch (r) {
      case REGION::STACK:
         return (i < get_bound(REGION::STACK,0))?
                     UnitId::STACK[get_size(REGION::STACK)]:
               ((i > get_bound(REGION::STACK,1))?
                     UnitId::STACK[get_size(REGION::STACK)+1]:
                     UnitId::STACK[i-get_bound(REGION::STACK,0)]);
      case REGION::STATIC:
         UnitId::TEMP = (i < get_bound(REGION::STATIC,0))?
                           UnitId(REGION::STATIC, _oo):
                       ((i > get_bound(REGION::STATIC,1))?
                           UnitId(REGION::STATIC, oo):
                           UnitId(REGION::STATIC, i));
         return UnitId::TEMP;
      case REGION::REGISTER:
         return UnitId::REG[i];
      case REGION::SPECIAL:
         return (i == 0)? UnitId::BAD: UnitId::CFLAG;
      default:
         return UnitId::BAD;
   }
}


const UnitId& SBA::get_id(ARCH::REG r) {
   return UnitId::REG[(IMM)r];
}


const UnitId& SBA::get_id(IMM sym) {
   if (sym == -2)
      return UnitId::CFLAG;
   else if (sym == -1)
      return UnitId::BAD;
   else if (sym == 0)
      return UnitId::ZERO;
   else if (sym < get_base(REGION::STACK))
      return get_id((ARCH::REG)sym);
   else if (sym < get_base(REGION::STATIC))
      return get_id(REGION::STACK, sym - get_base(REGION::STACK)
                                 + get_bound(REGION::STACK,0));
   else
      return get_id(REGION::STATIC, sym - get_base(REGION::STATIC)
                                  + get_bound(REGION::STATIC,0));
}


const IMM SBA::flagSym = get_sym(ARCH::flags);
const IMM SBA::stackSym = get_sym(ARCH::stack_pointer);
const IMM SBA::staticSym = get_sym(ARCH::insn_pointer);
const IMM SBA::cflagSym = -2;
/* -------------------------------------------------------------------------- */
UnitId UnitId::operator-() const {
   return bad()? UnitId::BAD:
          (constant()? UnitId(REGION::NONE,-i_): UnitId(-sign_,r_,i_));
}


bool UnitId::operator==(const UnitId& obj) const {
   if (bad())
      return false;
   return sign_==obj.sign_ && r_==obj.r_ && i_==obj.i_;
}


bool UnitId::operator!=(const UnitId& obj) const {
   return !bad() && !(*this==obj);
};
/* --------------------------------- Range ---------------------------------- */
Range const Range::ZERO = Range(0,0);
Range const Range::ONE = Range(1,1);
Range const Range::EMPTY = Range();
Range const Range::UNIVERSAL = Range(false);


Range::Range(COMPARE cmp, IMM i) {
   c = false;
   switch (cmp) {
      case COMPARE::EQ: l = i;        h = i;                      break;
      case COMPARE::NE: l = i;        h = i;        c = true;     break;
      case COMPARE::GT: l = (i < oo)? i + 1: oo;
                        h = oo;                                   break;
      case COMPARE::GE: l = i;        h = oo;                     break;
      case COMPARE::LT: l = _oo;
                        h = (i > _oo)? i - 1: _oo;                break;
      case COMPARE::LE: l = _oo;      h = i;                      break;
      default:          l = _oo;      h = oo;                     break;
   }
   norm();
}


Range::Range(COMPARE cmp, const Range& obj) {
   c = false;
   switch (cmp) {
      case COMPARE::EQ: l = obj.l;    h = obj.h;               break;
      case COMPARE::NE: l = obj.l;    h = obj.h;    c = true;  break;
      case COMPARE::GT: l = (obj.h < oo)? obj.h + 1: oo;
                        h = oo;                                break;
      case COMPARE::GE: l = obj.h;    h = oo;                  break;
      case COMPARE::LT: l = _oo;
                        h = (obj.l > _oo)? obj.l - 1: _oo;     break;
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
      IMM res = (1LL << (int)(std::log(std::max(h, obj.h)) + 1)) - 1;
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


void Range::contract(uint8_t bytes) {
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

   if (l > h) {
      c = true;
      l = _oo;
      h = oo;
      return;
   }

   /* standardize constraint sets (except NE) */
   /* U\[-oo,3] --> [4,oo]  */
   /* U\[4,oo]  --> [-oo,3] */
   if (c) {
      if (l == _oo) {
         c = false;
         l = h + 1;
         h = oo;
      }
      else if (h == oo) {
         c = false;
         h = l - 1;
         l = _oo;
      }
   }
}
/* ------------------------------ ExprId ----------------------------- */
ExprId const ExprId::EMPTY = ExprId();


ExprId::ExprId() {
   empty_ = true;
   constant_ = false;
   op_ = OP::PLUS;
   subargs_[0] = UnitId::ZERO;
   subargs_[1] = UnitId::ZERO;
}


ExprId::ExprId(const UnitId& a) {
   update(a);
}


ExprId::ExprId(OP op, const UnitId& a, const UnitId& b) {
   update(op, a, b);
}


ExprId::ExprId(const ExprId& obj) {
   op_ = obj.op_;
   subargs_ = obj.subargs_;
   empty_ = obj.empty_;
   constant_ = obj.constant_;
}


bool ExprId::comparable() const {
   return (!empty_ && (subargs_[0].boundness()==0)
                   && (subargs_[1].boundness()==0));
}


bool ExprId::operator==(const ExprId& obj) const {
   if (!empty_ && !obj.empty_ && op_ == obj.op_ &&
   ((subargs_[0]==obj.subargs_[0] && subargs_[1]==obj.subargs_[1]) ||
   (subargs_[0]==obj.subargs_[1] && subargs_[1]==obj.subargs_[0])))
      return true;
   return false;
}


string ExprId::to_string() const {
   if (empty_)
      return string("∅");
   auto s0 = subargs_[0].to_string();
   auto s1 = subargs_[1].to_string();
   switch (op_) {
      case OP::AND:
         return s0.append(" & ").append(s1);
      default:
         return (!subargs_[1].zero())? s0.append(" + ").append(s1): s0;
   }
}


vector<pair<IMM,Range>> ExprId::get_cstr(COMPARE cmp,
const ExprId* rhs) const {
   vector<pair<IMM,Range>> res;
   if (comparable() && rhs->comparable() && op_==OP::PLUS && rhs->op_==OP::PLUS
   && subargs_[1].zero() && rhs->subargs_[1].zero()) {
      auto const& x = subargs_[0];
      auto const& y = rhs->subargs_[0];
      /* (c + 0 < x + 0) --> x > c --> x in [c+1,oo] */
      if (x.constant() && !y.constant())
         res.push_back(make_pair(get_sym(y), Range(Util::opposite(cmp),x.i())));
      /* (x + 0 < c + 0) --> x < c --> x in [-oo,c-1] */
      else if (!x.constant() && y.constant())
         res.push_back(make_pair(get_sym(x), Range(cmp,y.i())));
   }
   return res;
}


void ExprId::norm(ExprId* rhs) {
   auto c1 = subargs_[1];
   auto c2 = rhs->subargs_[1];
   if (comparable() && rhs->comparable() && c1.constant() && c2.constant() &&
   op_ == OP::PLUS && rhs->op_ == OP::PLUS) {
      auto x = subargs_[0];
      auto y = rhs->subargs_[0];
      auto c = UnitId(REGION::NONE, c2.i()-c1.i());
      /* (-x + c1, -y + c2) --> (y + c1, x + c2) --> (y + 0, x + c2-c1) */
      if (x.sign() == -1 && y.sign() == -1) {
         update(-y);
         rhs->update(OP::PLUS, -x, c);
      }
      /* (-x + c1, y + c2) --> (c1 - c2, x + y) */
      else if (x.sign() == -1 && y.sign() == 1) {
         update(-c);
         rhs->update(OP::PLUS, -x, y);
      }
      /* (x + c1, -y + c2) --> (x + y, c2 - c1) */
      else if (x.sign() == 1 && y.sign() == -1) {
         update(OP::PLUS, x, -y);
         rhs->update(c);
      }
      /* (x + c1, y + c2) --> (x + 0, y + c2-c1) */
      /* (c + c1, y + c2) --> (c + c1-c2, y + 0) */
      else {
         if (!x.constant()) {
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


void ExprId::update(const UnitId& a) {
   if (a.bad() || a.boundness() != 0) {
      empty_ = true;
      constant_ = false;
      op_ = OP::PLUS;
      subargs_[0] = UnitId::ZERO;
      subargs_[1] = UnitId::ZERO;
   }
   else {
      empty_ = false;
      constant_ = a.constant();
      op_ = OP::PLUS;
      subargs_[0] = a;
      subargs_[1] = UnitId::ZERO;
   }
}


void ExprId::update(OP op, const UnitId& a, const UnitId& b) {
   if (a.bad() || b.bad() || a.boundness() != 0 || b.boundness() != 0) {
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
         if (a.constant() && b.constant()) {
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
      if (subargs_[0].constant() && !subargs_[1].constant()) {
         auto tmp = subargs_[0];
         subargs_[0] = subargs_[1];
         subargs_[1] = tmp;
      }
   }
}
/* -------------------------------- ExprLoc --------------------------------- */
RTL* ExprLoc::rtl() const {
   return (expr != nullptr)? (RTL*)(expr->simplify()): nullptr;
};
/* --------------------------------- Value ---------------------------------- */
Value::Value() {
   owner.fill(true);
   val.fill(BaseDomain::TOP);
};

Value::~Value() {
   for (int k = 0; k < DOMAIN_NUM; ++k)
      if (owner[k])
         BaseDomain::safe_delete(val[k]);
};

void Value::set_val(int index, BaseDomain* v) {
   auto tmp = val[index];
   val[index] = v;
   if (tmp != v)
      BaseDomain::safe_delete(tmp);
}
/* ---------------------------------- Util ---------------------------------- */
IMM Util::to_int(const string& s) {
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


auto g1 = Util::max(1);
auto g2 = Util::max(2);
auto g4 = Util::max(4);
auto g8 = Util::max(8);
constexpr IMM Util::max(uint8_t bytes) {
   switch (bytes) {
      case 1:
         return (IMM)((CHAR_MAX < oo)? CHAR_MAX: oo);
      case 2:
         return (IMM)((SHRT_MAX < oo)? SHRT_MAX: oo);
      case 4:
         return (IMM)((INT_MAX < oo)? INT_MAX: oo);
      default:
         return (IMM)((LONG_MAX < oo)? LONG_MAX: oo);
   }
}


auto s1 = Util::min(1);
auto s2 = Util::min(2);
auto s4 = Util::min(4);
auto s8 = Util::min(8);
constexpr IMM Util::min(uint8_t bytes) {
   switch (bytes) {
      case 1:
         return (IMM)((CHAR_MIN > _oo)? CHAR_MIN: _oo);
      case 2:
         return (IMM)((SHRT_MIN > _oo)? SHRT_MIN: _oo);
      case 4:
         return (IMM)((INT_MIN > _oo)? INT_MIN: _oo);
      default:
         return (IMM)((LONG_MIN > _oo)? LONG_MIN: _oo);
   }
}


IMM Util::plus(IMM x, IMM y) {
   if (x == _oo || x == oo)
      return x;
   else if (y == _oo || y == oo)
      return y;
   else
      return x + y;
}


IMM Util::minus(IMM x, IMM y) {
   if (x == _oo || x == oo)
      return x;
   else if (y == _oo)
      return oo;
   else if (y == oo)
      return _oo;
   else
      return x - y;
}


IMM Util::mult(IMM x, IMM y) {
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


IMM Util::int_cast(uint64_t val, uint8_t bytes, bool sign) {
   switch (bytes) {
      case 1:
         return (IMM)(sign? int8_t(val): uint8_t(val));
      case 2:
         return (IMM)(sign? int16_t(val): uint16_t(val));
      case 4:
         return (IMM)(sign? int32_t(val): uint32_t(val));
      case 8:
         return (IMM)(sign? int64_t(val): uint64_t(val));
      default:
         return 0;
   }
}
