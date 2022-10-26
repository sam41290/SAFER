/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef ARITHMETIC_H
#define ARITHMETIC_H

#include "expr.h"
#include "common.h"
// -----------------------------------------------------------------------------
class State;
// -----------------------------------------------------------------------------
class Arithmetic: public Expr {
 public:
   enum class ARITH_TYPE: char {UNARY, BINARY, COMPARE};

 private:
   ARITH_TYPE typeArith_;

 public:
   Arithmetic(ARITH_TYPE _typeArith, EXPR_MODE _mode);
   virtual ~Arithmetic() {};
   ARITH_TYPE arith_type() const {return typeArith_;};
};
// -----------------------------------------------------------------------------
class Unary: public Arithmetic {
 public:
   enum class OP: char {NEG, NOT, ABS, SQRT, CLZ, CTZ, BSWAP, ANY};
   static inline const string OP_STR[8] =
                       {"neg", "not", "abs", "sqrt", "clz", "ctz", "bswap", ""};

 private:
   Expr* operand_;
   OP op_;

 public:
   Unary(OP typeOp, EXPR_MODE mode, Expr* operand);
   ~Unary();

   /* Read accessors */
   string to_string() const override;
   bool equal(RTL_EQUAL typeEq, RTL* _v) const override;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* _v) override;
   Expr* operand() const {return operand_;};
   OP op() const {return op_;};

   /* Methods related to parser */
   Expr* clone() override;

   /* Methods related to static analysis */
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) override;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;
};                   
// -----------------------------------------------------------------------------
class Binary: public Arithmetic {
 public:
   enum class OP: char {PLUS, MINUS, MULT, DIV, UDIV, MOD, UMOD, AND, IOR,
                        XOR, ASHIFT, ASHIFTRT, LSHIFTRT, ROTATE, ROTATERT,
                        COMPARE, ANY};
   static inline const string OP_STR[17] =
         {"plus", "minus", "mult", "div", "udiv", "mod", "umod", "and", "ior",
          "xor", "ashift", "ashiftrt", "lshiftrt", "rotate", "rotatert",
          "compare", ""};

 private:
   array<Expr*,2> operands_;
   OP op_;

 public:
   Binary(OP typeOp, EXPR_MODE mode, Expr* a, Expr* b);
   ~Binary();

   /* Read accessors */
   string to_string() const override;
   bool equal(RTL_EQUAL typeEq, RTL* _v) const override;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* _v) override;
   Expr* operand(int idx) const {return operands_[idx];};
   OP op() const {return op_;};

   /* Methods related to parser */
   Expr* clone() override;

   /* Methods related to static analysis */
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) override;
   CompareArgsId eval_expr() const override;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;

 private:
   /* Methods related to helper methods */
};
// -----------------------------------------------------------------------------
class Compare: public Arithmetic {
 public:
   enum class OP: char {EQ, NE, GT, GTU, GE, GEU, LT, LTU, LE, LEU,
                             UNLE, UNLT, UNEQ, LTGT, ORDERED, UNORDERED, ANY};
   static inline const string OP_STR[17] = 
                     {"eq","ne","gt","gtu","ge","geu","lt","ltu","le","leu",
                      "unle","unlt","uneq","ltgt","ordered","unordered",""};

 private:
   OP op_;
   Expr* expr_;

 public:
   Compare(OP op, EXPR_MODE mode, Expr* a);
   ~Compare();

   /* Read accessors */
   string to_string() const override;
   bool equal(RTL_EQUAL typeEq, RTL* _v) const override;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* _v) override;
   OP op() const {return op_;};
   Expr* expr() {return expr_;};

   /* Methods related to parser */
   Expr* clone() override;

   /* Methods related to static analysis */
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) override;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;
};
// -----------------------------------------------------------------------------
#endif