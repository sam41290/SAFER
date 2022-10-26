/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "arithmetic.h"
#include "state.h"
#include "domain.h"
// --------------------------------- Arithmetic --------------------------------
Arithmetic::Arithmetic(ARITH_TYPE _typeArith, EXPR_MODE _mode):
Expr(EXPR_TYPE::ARITHMETIC, _mode) {
   typeArith_ = _typeArith;
}
// ----------------------------------- Unary ---------------------------------
Unary::Unary(OP typeOp, EXPR_MODE mode, Expr* operand):
Arithmetic(ARITH_TYPE::UNARY, mode) {
   op_ = typeOp;
   operand_ = operand;
}


Unary::~Unary() {
   if (op_ != OP::ANY)
      delete operand_;
}


string Unary::to_string() const {
   if (op_ == OP::ANY)
      return string("");
   return string("(").append(Unary::OP_STR[(int)op_])
                     .append(mode_string()).append(" ")
                     .append(operand_->to_string()).append(")");
}


bool Unary::equal(RTL_EQUAL typeEq, RTL* _v) const {
   if (_v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v = (Unary*)(*_v);
   if (v == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return (op_ == v->op_ || op_ == OP::ANY);
      case RTL_EQUAL::PARTIAL:
         return (op_ == v->op_ &&
                (operand_ == nullptr || operand_->equal(typeEq, v->operand_)));
      case RTL_EQUAL::RELAXED:
         return (op_ == v->op_ &&
                 operand_->equal(typeEq, v->operand()));
      case RTL_EQUAL::STRICT:
         return (op_ == v->op_ &&
                 operand_->equal(typeEq, v->operand()) &&
                 expr_mode() == v->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> Unary::find(RTL_EQUAL typeEq, RTL* _v) {
   vector<RTL*> vList;
   if (equal(typeEq, _v))
      vList.push_back(this);
   operand_->find_helper(typeEq, _v, vList);
   return vList;
}


Expr* Unary::clone() {
   return new Unary(op_, expr_mode(), operand_->clone());
}


array<BaseDomain*,domainCnt> Unary::eval(const array<State*,domainCnt>& s) {
   array<BaseDomain*,domainCnt> res;
   auto opVec = operand_->eval(s);
   for (int k = 0; k < domainCnt; ++k)
      res[k] = (opVec[k]->ref() > 0)? opVec[k]->clone(): opVec[k];

   switch (op_) {
      case OP::NEG:
         BaseLH::abs_neg(res[0]);
         BaseLH::abs_neg(res[1]);
         InitDomain::unary_op(res[2]);
         cachedId_ = -operand_->id();
         break;
      case OP::ABS:
         BaseLH::abs_abs(res[0]);
         BaseLH::abs_abs(res[1]);
         InitDomain::unary_op(res[2]);
         break;
      default:
         BaseDomain::safe_delete(res[0]);
         BaseDomain::safe_delete(res[1]);
         res[0] = BaseDomain::TOP;
         res[1] = BaseDomain::TOP;
         InitDomain::unary_op(res[2]);
         break;
   }

   for (int k = 0; k < domainCnt; ++k)
      res[k] = res[k]->mode(mode_size());
   return res;
}


bool Unary::include(RTL* subExpr) const {
   return this == subExpr || operand_->include(subExpr);
}
// ----------------------------------- Binary ----------------------------------
Binary::Binary(OP typeOp, EXPR_MODE mode, Expr* a, Expr* b):
Arithmetic(ARITH_TYPE::BINARY, mode) {
   op_ = typeOp;
   operands_[0] = a;
   operands_[1] = b;
}


Binary::~Binary() {
   if (op_ != OP::ANY) {
      delete operands_[0];
      delete operands_[1];
   }
}


string Binary::to_string() const {
   if (op_ == OP::ANY)
      return string("");
   return string("(").append(Binary::OP_STR[(int)op_])
                     .append(mode_string()).append(" ")
                     .append(operands_[0]->to_string()).append(" ")
                     .append(operands_[1]->to_string()).append(")");
}


bool Binary::equal(RTL_EQUAL typeEq, RTL* _v) const {
   if (_v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v = (Binary*)(*_v);
   if (v == nullptr)
      return false;
   
   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return (op_ == v->op_ || op_ == OP::ANY);
      case RTL_EQUAL::PARTIAL:
         return (op_ == v->op_ &&
                (operands_[0] == nullptr ||
                 operands_[0]->equal(typeEq, v->operands_[0])) &&
                (operands_[1] == nullptr ||
                 operands_[1]->equal(typeEq, v->operands_[1])));
   case RTL_EQUAL::RELAXED:
         return (op_ == v->op_ &&
                 operands_[0]->equal(typeEq, v->operands_[0]) &&
                 operands_[1]->equal(typeEq, v->operands_[1]));
      case RTL_EQUAL::STRICT:
         return (op_ == v->op_ &&
                 operands_[0]->equal(typeEq, v->operands_[0]) &&
                 operands_[1]->equal(typeEq, v->operands_[1]) &&
                 expr_mode() == v->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> Binary::find(RTL_EQUAL typeEq, RTL* _v) {
   vector<RTL*> vList;
   if (equal(typeEq, _v))
      vList.push_back(this);
   operands_[0]->find_helper(typeEq, _v, vList);
   operands_[1]->find_helper(typeEq, _v, vList);
   return vList;
}


Expr* Binary::clone() {
   return new Binary(op_, expr_mode(),
                     operands_[0]->clone(), operands_[1]->clone());
}


array<BaseDomain*,domainCnt> Binary::eval(const array<State*,domainCnt>& s) {
   array<BaseDomain*,domainCnt> res;
   auto op1Vec = operands_[0]->eval(s);
   auto op2Vec = operands_[1]->eval(s);
   for (int k = 0; k < domainCnt; ++k)
      res[k] = (op1Vec[k]->ref() > 0)? op1Vec[k]->clone(): op1Vec[k];

   InitDomain::binary_op(res[2], op2Vec[2]);
   switch (op_) {
      case OP::PLUS:
         BaseLH::abs_plus(res[0], op2Vec[0]);
         BaseLH::abs_plus(res[1], op2Vec[1]);
         break;
      case OP::MINUS:
         BaseLH::abs_minus(res[0], op2Vec[0]);
         BaseLH::abs_minus(res[1], op2Vec[1]);
         break;
      case OP::MULT:
         BaseLH::abs_mult(res[0], op2Vec[0]);
         BaseLH::abs_mult(res[1], op2Vec[1]);
         break;
      case OP::DIV:
         BaseLH::abs_div(res[0], op2Vec[0]);
         BaseLH::abs_div(res[1], op2Vec[1]);
         break;
      case OP::MOD:
         BaseLH::abs_mod(res[0], op2Vec[0]);
         BaseLH::abs_mod(res[1], op2Vec[1]);
         break;
      case OP::XOR:
         BaseLH::abs_xor(res[0], op2Vec[0]);
         BaseLH::abs_xor(res[1], op2Vec[1]);
         break;
      case OP::IOR:
         BaseLH::abs_ior(res[0], op2Vec[0]);
         BaseLH::abs_ior(res[1], op2Vec[1]);
         break;
      case OP::AND:
         BaseLH::abs_and(res[0], op2Vec[0]);
         BaseLH::abs_and(res[1], op2Vec[1]);
         break;
      case OP::ASHIFT:
         BaseLH::abs_ashift(res[0], op2Vec[0]);
         BaseLH::abs_ashift(res[1], op2Vec[1]);
         break;
      case OP::COMPARE: {
         array<Binary*,2> bin = {(Binary*)(*operands_[0]),
                                 (Binary*)(*operands_[1])};
         /* CompareArgsId */
         array<CompareArgsId*,2> args_id;
         for (int i = 0; i < 2; ++i) {
            auto tmp = (bin[i] != nullptr)? bin[i]->eval_expr():
                       CompareArgsId(operands_[i]->id());
            args_id[i] = tmp.clone();
         }
         /* CompareArgs */
         array<array<CompareArgsVal<BaseLH>*,2>,domainCnt> args_val;
         for (int i = 0; i < 2; ++i)
         if (bin[i] != nullptr && bin[i]->op_ == OP::AND) {
            auto and0 = bin[i]->operands_[0]->eval(s);
            auto and1 = bin[i]->operands_[1]->eval(s);
            for (int k = 0; k < domainCnt; ++k)
            if (s[k]->cstr_mode())
               args_val[k][i] = new CompareArgsVal<BaseLH>(
               BaseLH::COMPARE_ARGS_OP::AND, (BaseLH*)and0[k], (BaseLH*)and1[k]);
            else {
               BaseDomain::safe_delete(and0[k]);
               BaseDomain::safe_delete(and1[k]);
            }
         }
         else {
            for (int k = 0; k < domainCnt; ++k)
            if (s[k]->cstr_mode()) {
               auto subargs = (i == 0)? res[k]: op2Vec[k];
               args_val[k][i] = new CompareArgsVal<BaseLH>((BaseLH*)subargs);
            }
         }
         /* FlagDomain */
         for (int k = 0; k < domainCnt; ++k)
         if (s[k]->cstr_mode()) {
            auto fUnit = FlagUnit<BaseLH>(args_id, args_val[k]);
            res[k] = new FlagDomain<BaseLH>(fUnit);
         }
         break;
      }
      default:
         BaseDomain::safe_delete(res[0]);
         BaseDomain::safe_delete(res[1]);
         res[0] = BaseDomain::TOP;
         res[1] = BaseDomain::TOP;
         break;
   }

   for (int k = 0; k < domainCnt; ++k)
      res[k] = res[k]->mode(mode_size());
   return res;
}


bool Binary::include(RTL* subExpr) const {
   return this == subExpr || operands_[0]->include(subExpr) ||
          operands_[1]->include(subExpr);
}


CompareArgsId Binary::eval_expr() const {
   auto const& a = operands_[0];
   auto const& b = operands_[1];
   switch (op_) {
      case OP::AND:
         return CompareArgsId(CompareArgsId::OP::AND, a->id(), b->id());
      case OP::PLUS:
         return CompareArgsId(CompareArgsId::OP::PLUS, a->id(), b->id());
      case OP::MINUS:
         return CompareArgsId(CompareArgsId::OP::MINUS, a->id(), b->id());
      default:
         return CompareArgsId();
   }
}
// ---------------------------------- Compare ----------------------------------
Compare::Compare(OP op, EXPR_MODE mode, Expr* a):
Arithmetic(ARITH_TYPE::COMPARE, mode) {
   op_ = op;
   expr_ = a;
}


Compare::~Compare() {
   if (expr_ != nullptr)
      delete expr_;
}


string Compare::to_string() const {
   if (op_ == OP::ANY)
      return string("");
   return string("(").append(Compare::OP_STR[(int)op_])
          .append(mode_string()).append(" ")
          .append(expr_->to_string())
          .append(" (const_int 0))");
}


bool Compare::equal(RTL_EQUAL typeEq, RTL* _v) const {
   if (_v == nullptr)
      return (typeEq == RTL_EQUAL::PARTIAL);

   auto v = (Compare*)(*_v);
   if (v == nullptr)
      return false;

   switch (typeEq) {
      case RTL_EQUAL::OPCODE:
         return (op_ == v->op_ || op_ == Compare::OP::ANY);
      case RTL_EQUAL::PARTIAL:
         return (op_ == v->op_ &&
                (expr_ == nullptr || expr_->equal(typeEq, v->expr())));
      case RTL_EQUAL::RELAXED:
         return (op_ == v->op_ && expr_->equal(typeEq, v->expr()));
      case RTL_EQUAL::STRICT:
         return (op_ == v->op_ && expr_mode() == v->expr_mode());
      default:
         return false;
   }
}


vector<RTL*> Compare::find(RTL_EQUAL typeEq, RTL* _v) {
   if (equal(typeEq, _v))
      return vector<RTL*>{this};
   return vector<RTL*>{};
}


Expr* Compare::clone() {
   return new Compare(op_, expr_mode(), expr_->clone());
}


array<BaseDomain*,domainCnt> Compare::eval(const array<State*,domainCnt>& s) {
   array<BaseDomain*,domainCnt> res;
   for (int k = 0; k < domainCnt; ++k)
      res[k] = BaseDomain::TOP;
   return res;
}


bool Compare::include(RTL* subExpr) const {
   return this == subExpr || expr_->include(subExpr);
}