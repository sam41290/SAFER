/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "arithmetic.h"
#include "state.h"
#include "domain.h"

using namespace SBA;
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


Value Unary::eval(const array<AbsState*,DOMAIN_NUM>& s) {
   EVAL_UNARY(s);
}


bool Unary::contains(RTL* subExpr) const {
   return this == subExpr || operand_->contains(subExpr);
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


Value Binary::eval(const array<AbsState*,DOMAIN_NUM>& states) {
//   EVAL_BINARY(s);
   auto res = operand(0)->eval(states);                                        
   auto op2 = operand(1)->eval(states);                                        
   FOR_STATE(states, k, res[k]->ref() > 0, {                                   
      res.set_val(k, res[k]->clone());                                         
   });                                                                         
                                                                               
   switch (op_) {                                                              
      case OP::PLUS:                                                           
         if (states[0]->enable_analysis())                                     
            BaseLH::abs_plus(res[0], op2[0]);                                  
         if (states[1]->enable_analysis())                                     
            BaseLH::abs_plus(res[1], op2[1]);                                  
         if (states[2]->enable_analysis())                                     
            TaintDomain::binary_op(res[2], op2[2]);                             
         break;                                                                
      case OP::MINUS:                                                          
         if (states[0]->enable_analysis())                                     
            BaseLH::abs_minus(res[0], op2[0]);                                 
         if (states[1]->enable_analysis())                                     
            BaseLH::abs_minus(res[1], op2[1]);                                 
         if (states[2]->enable_analysis())                                     
            TaintDomain::binary_op(res[2], op2[2]);                             
         break;                                                                
      case OP::MULT:                                                           
         if (states[0]->enable_analysis())                                     
            BaseLH::abs_mult(res[0], op2[0]);                                  
         if (states[1]->enable_analysis())                                     
            BaseLH::abs_mult(res[1], op2[1]);                                  
         if (states[2]->enable_analysis())                                     
            TaintDomain::binary_op(res[2], op2[2]);                             
         break;                                                                
      case OP::DIV:                                                            
         if (states[0]->enable_analysis())                                     
            BaseLH::abs_div(res[0], op2[0]);                                   
         if (states[1]->enable_analysis())                                     
            BaseLH::abs_div(res[1], op2[1]);                                   
         if (states[2]->enable_analysis())                                     
            TaintDomain::binary_op(res[2], op2[2]);                             
         break;                                                                
      case OP::MOD:                                                            
         if (states[0]->enable_analysis())                                     
            BaseLH::abs_mod(res[0], op2[0]);                                   
         if (states[1]->enable_analysis())                                     
            BaseLH::abs_mod(res[1], op2[1]);                                   
         if (states[2]->enable_analysis())                                     
            TaintDomain::binary_op(res[2], op2[2]);                             
         break;                                                                
      case OP::XOR:                                                            
         if (states[0]->enable_analysis())                                     
            BaseLH::abs_xor(res[0], op2[0]);                                   
         if (states[1]->enable_analysis())                                     
            BaseLH::abs_xor(res[1], op2[1]);                                   
         if (states[2]->enable_analysis())                                     
            TaintDomain::binary_op(res[2], op2[2]);                             
         break;                                                                
      case OP::IOR:                                                            
         if (states[0]->enable_analysis())                                     
            BaseLH::abs_ior(res[0], op2[0]);                                   
         if (states[1]->enable_analysis())                                     
            BaseLH::abs_ior(res[1], op2[1]);                                   
         if (states[2]->enable_analysis())                                     
            TaintDomain::binary_op(res[2], op2[2]);                             
         break;                                                                
      case OP::AND:                                                            
         if (states[0]->enable_analysis())                                     
            BaseLH::abs_and(res[0], op2[0]);                                   
         if (states[1]->enable_analysis())                                     
            BaseLH::abs_and(res[1], op2[1]);                                   
         if (states[2]->enable_analysis())                                     
            TaintDomain::binary_op(res[2], op2[2]);                             
         break;                                                                
      case OP::ASHIFT:                                                         
         if (states[0]->enable_analysis())                                     
            BaseLH::abs_ashift(res[0], op2[0]);                                
         if (states[1]->enable_analysis())                                     
            BaseLH::abs_ashift(res[1], op2[1]);                                
         if (states[2]->enable_analysis())                                     
            TaintDomain::binary_op(res[2], op2[2]);                             
         break;                                                                
      case OP::COMPARE: {                                                      
         /* FlagDomain for CstrDomain<BaseLH> */                               
         res.set_val(0, BaseDomain::TOP);                                      
         res.set_val(1, BaseDomain::TOP);                                      
         res.set_val(2, BaseDomain::TOP);                                      
         if (states[1]->enable_analysis()) {                                   
            /* ExprId */                                                       
            array<ExprId*,2> args_id = {nullptr, nullptr};                     
            array<ExprVal<BaseLH>*,2> args_val = {nullptr, nullptr};           
            for (int i = 0; i < 2; ++i) {                                      
               IF_RTL_TYPE(Binary, operand(i), bin, {                          
                  args_id[i] = operand(i)->eval_expr().clone();                
                  if (bin->op() == OP::AND) {                                  
                     auto v0 = bin->operand(0)->eval(states);                  
                     auto v1 = bin->operand(1)->eval(states);                  
                     args_val[i]=new ExprVal<BaseLH>(BaseLH::EXPR_VAL_OP::AND, 
                                              (BaseLH*)v0[1], (BaseLH*)v1[1]); 
                  }                                                            
               }, {                                                            
                  args_id[i] = ExprId(operand(i)->id()).clone();               
               });                                                             
               if (args_val[i] == nullptr) {                                   
                  auto args = (i == 0)? res[1]: op2[1];                        
                  args_val[i] = new ExprVal<BaseLH>((BaseLH*)args);            
               }                                                               
            }                                                                  
            res.set_val(1, new FlagDomain<BaseLH>(                             
                               FlagUnit<BaseLH>(args_id,args_val)));           
         }                                                                     
         break;                                                                
      }                                                                        
      default:                                                                 
         FOR_STATE(states, k, true, {                                          
            res.set_val(k, BaseDomain::TOP);                                   
         });                                                                   
         break;                                                                
   }                                                                           
                                                                               
   FOR_STATE(states, k, true, {                                                
      res.set_val(k, res[k]->mode(mode_size()));                               
   });                                                                         
   return res;
}


bool Binary::contains(RTL* subExpr) const {
   return this == subExpr || operands_[0]->contains(subExpr) ||
          operands_[1]->contains(subExpr);
}


ExprId Binary::eval_expr() const {
   auto const& a = operands_[0];
   auto const& b = operands_[1];
   switch (op_) {
      case OP::AND:
         return ExprId(ExprId::OP::AND, a->id(), b->id());
      case OP::PLUS:
         return ExprId(ExprId::OP::PLUS, a->id(), b->id());
      case OP::MINUS:
         return ExprId(ExprId::OP::MINUS, a->id(), b->id());
      default:
         return ExprId();
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


Value Compare::eval(const array<AbsState*,DOMAIN_NUM>& s) {
   EVAL_COMPARE(s);
}


bool Compare::contains(RTL* subExpr) const {
   return this == subExpr || expr_->contains(subExpr);
}
