/*
   Copyright (C) 2018 - 2024 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef EXPR_H
#define EXPR_H

#include "rtl.h"
#include "state.h"
#include "common.h"

namespace SBA {
   /* forward declaration */
   class BaseDomain;
   class Compare;
   /* -------------------------------- Expr --------------------------------- */
   class Expr: public RTL {
    public:
      enum class EXPR_TYPE: char {CONSTANT, VAR, ARITHMETIC, SUBREG,
                                  IFELSE, CONVERSION, NOTYPE};
      enum class EXPR_MODE: char {QI, HI, SI, DI, TI, SF, DF, XF, TF,
                                  FSQI, FSHI, FSSI, FSDI,
                                  BLK, BLKQI, BLKHI, BLKSI, BLKDI,
                                  CC, CCZ, CCC, CCO, CCNO, CCGC, CCGOC, CCFP,
                                  V1DI, V1TI, V2DF, V2DI, V2SF, V2SI,
                                  V4DI, V4SF, V4SI, V8HI, V8QI, V8SF, V8SI,
                                  V16HI, V16QI, V32QI, NONE};
      static inline const uint8_t MODE_SZ[43] = {
                                  1,  2,  4,  8, 16, 4,  8, 10, 16,
                                  1,  2,  4,  8,
                                  8,  1,  2,  4,  8,
                                  8,  8,  8,  8,  8,  8, 8, 8,
                                  8, 16, 16, 16,  8,  8,
                                 32, 16, 16, 16,  8, 32, 32,
                                 32, 16, 32, 0};
      static inline const string MODE_STR[43] = {
            ":QI", ":HI", ":SI", ":DI", ":TI", ":SF", ":DF", ":XF", ":TF",
            ":FSQI", ":FSHI", ":FSSI", ":FSDI",
            ":BLK", ":BLKQI", ":BLKHI", ":BLKSI", ":BLKDI",
            ":CC", ":CCZ", ":CCC", ":CCO", ":CCNO", ":CCGC", ":CCGOC", ":CCFP",
            ":V1DI" , ":V1TI" , ":V2DF", ":V2DI", ":V2SF", ":V2SI",
            ":V4DI" , ":V4SF" , ":V4SI", ":V8HI", ":V8QI", ":V8SF", ":V8SI",
            ":V16HI", ":V16QI", ":V32QI", ""};

    private:
      EXPR_TYPE typeExpr_;
      EXPR_MODE modeExpr_;

    protected:
      #if ENABLE_SUPPORT_CONSTRAINT == true
         AbsId expr_id_;
         bool run_expr_id_ = true;
      #endif

    public:
      Expr(EXPR_TYPE type, EXPR_MODE mode): RTL(RTL_TYPE::EXPR),
                                            typeExpr_(type), modeExpr_(mode) {}; 

      /* accessor */
      EXPR_TYPE expr_type() const {return typeExpr_;};
      EXPR_MODE expr_mode() const {return modeExpr_;};
      uint8_t mode_size() const {return Expr::MODE_SZ[(int)modeExpr_];};
      string mode_string() const {return Expr::MODE_STR[(int)modeExpr_];}
      virtual Expr* simplify() const {return (Expr*)this;};

      /* analysis */
      virtual AbsVal eval(State& s) = 0;
      void execute(State& s) override {};
      #if ENABLE_SUPPORT_CONSTRAINT == true
         virtual const AbsId& expr_id(const State& s) {return expr_id_;};
      #endif

      /* helper */
      virtual Expr* clone() = 0;
      RTL* find_container(RTL* subExpr, const function<bool(const RTL*)>&
                          select) const override {
                             return select(this) && contains(subExpr)?
                                    (RTL*)this: nullptr;
                          };
   };
   /* ------------------------------- Const --------------------------------- */
   class Const: public Expr {
    public:
      enum class CONST_TYPE: char {INTEGER, DOUBLE, VECTOR, ANY};

    private:
      CONST_TYPE typeConst_;
      IMM i_;

    public:
      Const(IMM i): Expr(EXPR_TYPE::CONSTANT, EXPR_MODE::NONE),
                    typeConst_(CONST_TYPE::INTEGER), i_(i) {};
      Const(CONST_TYPE typeConst, Expr* expr);

      /* accessor */
      IMM to_int() const {return i_;};
      CONST_TYPE const_type() const {return typeConst_;};
      string to_string() const override;

      /* analysis */
      AbsVal eval(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         const AbsId& expr_id(const State& s);
      #endif

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
   };
   /* -------------------------------- Var ---------------------------------- */
   class Var: public Expr {
    public:
      enum class VAR_TYPE: char {MEM, REG};

    private:
      VAR_TYPE typeVar_;

    public:
      Var(VAR_TYPE type, EXPR_MODE mode): Expr(EXPR_TYPE::VAR, mode),
                                          typeVar_(type) {};
      VAR_TYPE var_type() const {return typeVar_;};
   };


   class Mem: public Var {
    private:
      Expr* addr_;

    public:
      Mem(EXPR_MODE mode, Expr* addr): Var(VAR_TYPE::MEM, mode),
                                       addr_(addr) {};
      ~Mem();

      /* accessor */
      Expr* addr() const {return addr_;};
      string to_string() const override;

      /* analysis */
      AbsVal eval(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         const AbsId& expr_id(const State& s);
      #endif

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
      bool contains(RTL* subExpr) const override;
   };


   class Reg: public Var {
    private:
      ARCH::REG r_;

    public:
      Reg(EXPR_MODE mode, ARCH::REG r): Var(VAR_TYPE::REG, mode),
                                        r_(r) {};
      Reg(EXPR_MODE mode, Expr* r);
      ~Reg() {};

      /* accessor */
      ARCH::REG reg() const {return r_;};
      string to_string() const override;

      /* analysis */
      AbsVal eval(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         const AbsId& expr_id(const State& s);
      #endif

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
   };
   /* ------------------------------- SubReg -------------------------------- */
   class SubReg: public Expr {
    private:
      Expr* expr_;
      int byteNum_;

    public:
      SubReg(EXPR_MODE mode, Expr* expr, int byteNum):
                                         Expr(EXPR_TYPE::SUBREG, mode),
                                         expr_(expr), byteNum_(byteNum) {};
      SubReg(EXPR_MODE mode, Expr* expr, Expr* byteNum);
      ~SubReg();

      /* accessor */
      Expr* expr() const {return expr_;};
      int bytenum() const {return byteNum_;};
      string to_string() const override;

      /* analysis */
      AbsVal eval(State& s) override;

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
      bool contains(RTL* subExpr) const override;
   };
   /* ------------------------------- IfElse -------------------------------- */
   class IfElse: public Expr {
    private:
      Compare* cmp_;
      Expr* if_;
      Expr* else_;

    public:
      IfElse(EXPR_MODE mode, Compare* cmp, Expr* if_expr, Expr* else_expr);
      ~IfElse();

      /* accessor */
      Compare* cmp_expr() const {return cmp_;};
      Expr* if_expr() const {return if_;};
      Expr* else_expr() const {return else_;};
      string to_string() const override;

      /* analysis */
      AbsVal eval(State& s) override;

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
      bool contains(RTL* subExpr) const override;
   };
   /* ----------------------------- Conversion ------------------------------ */
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
      OP typeOp_;
      Expr* expr_;
      Expr* size_;
      Expr* pos_;

    public:
      Conversion(OP type, EXPR_MODE mode, Expr* expr):
                 Expr(EXPR_TYPE::CONVERSION, mode),
                 typeOp_(type), expr_(expr), size_(nullptr), pos_(nullptr) {};
      Conversion(OP type, EXPR_MODE mode, Expr* expr, Expr* size, Expr* pos):
                 Expr(EXPR_TYPE::CONVERSION, mode),
                 typeOp_(type), expr_(expr), size_(size), pos_(pos) {};
      ~Conversion();

      /* accessor */
      OP conv_type() const {return typeOp_;};
      Expr* expr() const {return expr_;};
      Expr* size() const {return size_;};
      Expr* pos() const {return pos_;};
      string to_string() const override;
      Expr* simplify() const override;

      /* analysis */
      AbsVal eval(State& s) override;
      #if ENABLE_SUPPORT_CONSTRAINT == true
         const AbsId& expr_id(const State& s);
      #endif

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
      bool contains(RTL* subExpr) const override;
   };
   /* ------------------------------- NoType -------------------------------- */
   class NoType: public Expr {
    private:
      string s_;

    public:
      NoType(const string& s): Expr(EXPR_TYPE::NOTYPE, EXPR_MODE::NONE),
                               s_(s) {};
      ~NoType() {};

      /* accessor */
      string to_string() const override {return s_;};

      /* analysis */
      AbsVal eval(State& s) override;

      /* helper */
      bool equal(RTL_EQUAL eq, RTL* v) const override;
      vector<RTL*> find(RTL_EQUAL eq, RTL* v) override;
      Expr* clone() override;
   };

}

#endif
