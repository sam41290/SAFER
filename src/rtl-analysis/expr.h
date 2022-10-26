/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef EXPR_H
#define EXPR_H

#include "rtl.h"
#include "common.h"
// -----------------------------------------------------------------------------
class State;
class BaseDomain;
class Compare;
// -----------------------------------------------------------------------------
class Expr: public RTL {
 public:
   enum class EXPR_TYPE: char {CONSTANT, VAR, ARITHMETIC, SUBREG,
                               IF_ELSE, CONVERSION, NOTYPE};
   enum class EXPR_MODE: char {QI, HI, SI, DI, TI,
                               SF, DF, XF, TF,
                               BLK, BLKQI, BLKHI, BLKSI, BLKDI,
                               CC, CCZ, CCC, CCO, CCNO, CCGC, CCGOC, CCFP,
                               V1DI, V1TI, V2DF, V2DI, V2SF, V2SI,
                               V4DI, V4SF, V4SI, V8HI, V8QI, V8SF, V8SI,
                               V16HI, V16QI, V32QI, NONE};
   static inline const uint8_t MODE_SZ[39] = { 1,  2,  4,  8, 16,
                                               4,  8, 10, 16,
                                               8,  1,  2,  4,  8,
                                               8,  8,  8,  8,  8,  8, 8, 8,
                                               8, 16, 16, 16,  8,  8,
                                              32, 16, 16, 16,  8, 32, 32,
                                              32, 16, 32, 0};
   static inline const string MODE_STR[39] = {":QI", ":HI", ":SI", ":DI", ":TI",
                                             ":SF", ":DF", ":XF", ":TF",
             ":BLK", ":BLKQI", ":BLKHI", ":BLKSI", ":BLKDI",
             ":CC", ":CCZ", ":CCC", ":CCO", ":CCNO", ":CCGC", ":CCGOC", ":CCFP",
             ":V1DI" , ":V1TI" , ":V2DF", ":V2DI", ":V2SF", ":V2SI",
             ":V4DI" , ":V4SF" , ":V4SI", ":V8HI", ":V8QI", ":V8SF", ":V8SI",
             ":V16HI", ":V16QI", ":V32QI", ""};

 private:
   EXPR_TYPE typeExpr_;
   EXPR_MODE modeExpr_;

 protected:
   UnitId cachedId_;

 public:
   Expr(EXPR_TYPE type, EXPR_MODE mode);

   /* Read accessors */
   EXPR_TYPE expr_type() const {return typeExpr_;};
   EXPR_MODE expr_mode() const {return modeExpr_;};
   uint8_t mode_size() const {return Expr::MODE_SZ[(int)modeExpr_];};
   string mode_string() const {return Expr::MODE_STR[(int)modeExpr_];}
   virtual Expr* simplify() const {return (Expr*)this;};

   /* Methods related to parser */
   virtual Expr* clone() = 0;

   /* Methods related to static analysis */
   virtual array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) = 0;

   /* Methods related to helper methods */
   UnitId id() const {return cachedId_;};
   virtual CompareArgsId eval_expr() const {return CompareArgsId(id());};
};
// -----------------------------------------------------------------------------
class Const: public Expr {
 public:
   enum class CONST_TYPE: char {INTEGER, DOUBLE, LABEL, VECTOR, ANY};

 private:
   int64_t i_;
   double d_;
   CONST_TYPE typeConst_;

 public:
   Const(int64_t i);
   Const(CONST_TYPE typeConst, Expr* expr);

   /* Read accessors */
   string to_string() const override;
   bool equal(RTL_EQUAL typeEq, RTL* v) const override;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v) override;
   CONST_TYPE const_type() const {return typeConst_;};
   int64_t to_int() const {return i_;};
   double to_double() const {return d_;};

   /* Methods related to parser */
   Expr* clone() override;

   /* Methods related to static analysis */
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) override;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override {return this == subExpr;};
};
// -----------------------------------------------------------------------------
class Var: public Expr {
 public:
   enum class VAR_TYPE: char {MEM, REG};

 private:
   VAR_TYPE typeVar_;

 public:
   Var(VAR_TYPE typeVar, EXPR_MODE mode);

   /* Read accessors */
   VAR_TYPE var_type() const {return typeVar_;};
};


class Mem: public Var {
 private:
   Expr* addr_;

 public:
   Mem(EXPR_MODE mode, Expr* addr);
   ~Mem();

   /* Read accessors */
   string to_string() const override;
   bool equal(RTL_EQUAL typeEq, RTL* v) const override;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v) override;
   Expr* addr() const {return addr_;};

   /* Methods related to parser */
   Expr* clone() override;

   /* Methods related to static analysis */
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) override;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;
};


class Reg: public Var {
 private:
   ARCH::REG r_;

 public:
   Reg(EXPR_MODE mode, Expr* r);
   Reg(EXPR_MODE mode, ARCH::REG r);
   ~Reg();

   /* Read accessors */
   string to_string() const override;
   bool equal(RTL_EQUAL typeEq, RTL* v) const override;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v) override;
   ARCH::REG reg() const {return r_;};

   /* Methods related to parser */
   Expr* clone() override;

   /* Methods related to static analysis */
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) override;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override {return this == subExpr;};
};
// -----------------------------------------------------------------------------
class SubReg: public Expr {
 private:
   Expr* expr_;
   int byteNum_;

 public:
   SubReg(EXPR_MODE mode, Expr* expr, Expr* byteNum);
   SubReg(EXPR_MODE mode, Expr* expr, int byteNum);
   ~SubReg();

   /* Read accessors */
   string to_string() const override;
   bool equal(RTL_EQUAL typeEq, RTL* v) const override;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v) override;
   Expr* expr() const {return expr_;};
   int bytenum() const {return byteNum_;};

   /* Methods related to parser */
   Expr* clone() override;

   /* Methods related to static analysis */
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) override;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;
};
// -----------------------------------------------------------------------------
class IfElse: public Expr {
 private:
   Compare* cmp_;
   Expr* if_;
   Expr* else_;

 public:
   IfElse(EXPR_MODE mode, Compare* cmp, Expr* if_expr, Expr* else_expr);
   ~IfElse();

   /* Read accessors */
   string to_string() const override;
   bool equal(RTL_EQUAL typeEq, RTL* v) const override;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v) override;
   Compare* cmp() const {return cmp_;};
   Expr* if_expr() const {return if_;};
   Expr* else_expr() const {return else_;};

   /* Methods related to parser */
   Expr* clone() override;

   /* Methods related to static analysis */
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) override;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;
};
// -----------------------------------------------------------------------------
class Conversion: public Expr {
 public:
   enum class OP: char {ZERO_EXTRACT, SIGN_EXTRACT, TRUNCATE,
                        STRUNCATE, UTRUNCATE, SFLOAT, UFLOAT,
                        FIX, UFIX, ZERO_EXTEND, SIGN_EXTEND,
                        FLOAT_EXTEND, STRICT_LOW_PART, ANY};
   static inline const string OP_STR[14] =
                     {"zero_extract", "sign_extract", "truncate",
                      "ss_truncate", "us_truncate", "float", "unsigned_float",
                      "fix", "unsigned_fix", "zero_extend", "sign_extend",
                      "float_extend", "strict_low_part", ""};

 private:
   Expr* expr_;
   Expr* size_;
   Expr* pos_;
   OP typeOp_;

 public:
   Conversion(OP typeOp, EXPR_MODE mode, Expr* expr);
   Conversion(OP typeOp, EXPR_MODE mode, Expr* expr, Expr* size, Expr* pos);
   ~Conversion();

   /* Read accessors */
   string to_string() const override;
   bool equal(RTL_EQUAL typeEq, RTL* v) const override;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v) override;
   OP conv_type() const {return typeOp_;};
   Expr* expr() const {return expr_;};
   Expr* size() const {return size_;};
   Expr* pos() const {return pos_;};
   Expr* simplify() const override;

   /* Methods related to parser */
   Expr* clone() override;

   /* Methods related to static analysis */
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) override;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;
};
// -----------------------------------------------------------------------------
class NoType: public Expr {
 private:
   string s_;

 public:
   NoType(const string& s);
   ~NoType();

   /* Read accessors */
   string to_string() const override;
   bool equal(RTL_EQUAL typeEq, RTL* v) const override;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v) override;

   /* Methods related to parser */
   Expr* clone() override;

   /* Methods related to static analysis */
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s) override;
};
// -----------------------------------------------------------------------------
#endif