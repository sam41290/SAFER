/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

/* ----------------------------- RTL -----------------------------
   RTL
    | --- Statement
    |         | --- Parallel
    |         | --- Sequence
    |         | --- Assign
    |         | --- Call
    |         | --- Ret
    |         | --- Clobber
    |         | --- Exit
    |          
    | --- Expr
    |         | --- Const
    |         | --- Var
    |         |      | --- Mem
    |         |      | --- Reg
    |         | --- Arithmetic
    |         |      | --- UnaryOp
    |         |      | --- BinaryOp
    |         |      | --- Compare
    |         | --- SubReg
    |         | --- IfElse
    |         | --- Conversion
    |         | --- NoType

    These tree structures keep RTL contents. They are not
    associated to any specific abstract domains, which are
    given by users. Since RTL subclasses cannot reason what
    input abstract domains take and the implementation of
    Expr subclasses is fixed, it is the user's responsibility
    to support input from as many Expr subclasses as possible.
   --------------------------------------------------------------- */

#ifndef RTL_H
#define RTL_H

#include "common.h"
// -----------------------------------------------------------------------------
class State;
class BaseDomain;
// -----------------------------------------------------------------------------
class Statement;
class Parallel;
class Sequence;
class Assign;
class Call;
class Clobber;
class Exit;
class Nop;
class Expr;
class Const;
class Var;
class Mem;
class Reg;
class Arithmetic;
class Unary;
class Binary;
class SubReg;
class IfElse;
class Conversion;
class Compare;
class NoType;
// -----------------------------------------------------------------------------
enum class RTL_TYPE: char {STATEMENT, EXPR};
enum class RTL_EQUAL: char {STRICT, RELAXED, PARTIAL, OPCODE};
// -----------------------------------------------------------------------------
class RTL {
 private:
   RTL_TYPE typeRTL_;

 public:
   RTL(RTL_TYPE _typeRTL);
   virtual ~RTL() = 0;
   virtual string to_string() const = 0;
   RTL_TYPE rtl_type() const {return this->typeRTL_;}
   // check if current RTL matches v under matching condition typeEq:
   // (a) STRICT:  identical
   // (b) RELAXED: same as (a), but ignore Expr mode
   // (c) PARTIAL: same as (b), but allow some parts to be arbitrary (nullptr)
   // (d) OPCODE:  either identical opcode or v opcode is ANY
   virtual bool equal(RTL_EQUAL typeEq, RTL* v) const = 0;
   // return self and all its parts equal to v under typeEq
   // (a) Insn::process_transfer() looks for Assign(pc,const) for unconditional
   //     direct jump, Assign(pc,Var) for indirect jump, Call(nullptr) for call
   // (b) Domain's substitute() takes ARCH::REG and create a map from Reg*
   //     to BaseDomain*, so it needs to look for Reg* within the main expr_
   virtual vector<RTL*> find(RTL_EQUAL typeEq, RTL* v) = 0;
   // find v in current RTL under typeEq and add results to vList
   // the goal is to reduce code size in find() methods
   // ::note:: a hidden rule in C++ is that subclasses don't recognize methods
   //          sharing same name regardless arguments; doing that means we have
   //          to add "using RTL::find" in every subclass (verified)
   void find_helper(RTL_EQUAL typeEq, RTL* v, vector<RTL*>& vList);
   virtual bool include(RTL* subExpr) const {return false;};
   // custom typecast
   operator Statement*() const;
   operator Parallel*() const;
   operator Sequence*() const;
   operator Assign*() const;
   operator Call*() const;
   operator Clobber*() const;
   operator Exit*() const;
   operator Nop*() const;
   operator Expr*() const;
   operator Const*() const;
   operator Var*() const;
   operator Mem*() const;
   operator Reg*() const;
   operator Arithmetic*() const;
   operator Unary*() const;
   operator Binary*() const;
   operator Compare*() const;
   operator SubReg*() const;
   operator IfElse*() const;
   operator Conversion*() const;
   operator NoType*() const;
};
// -----------------------------------------------------------------------------
class Statement: public RTL {
 public:
   enum class STATEMENT_TYPE: char {ASSIGN, CALL, SEQUENCE, PARALLEL, CLOBBER,
                                    EXIT, NOP};

 private:
   Statement::STATEMENT_TYPE typeStatement_;

 public:
   Statement(STATEMENT_TYPE type);
   virtual ~Statement() {};

   /* Read accessors */
   STATEMENT_TYPE stmt_type() const {return typeStatement_;};

   /* Methods related to static analysis */
   virtual void execute(const array<State*,domainCnt>& s) const {};
   virtual void preset(const array<State*,domainCnt>& s) const {};
   virtual array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s, Expr* subExpr) const;
};
// -----------------------------------------------------------------------------
class Parallel: public Statement {
 private:
   vector<Statement*> stmts_;

 public:
   Parallel(const vector<Statement*>& _stmts);
   ~Parallel();

   /* Read accessors */
   string to_string() const;
   bool equal(RTL_EQUAL typeEq, RTL* v) const;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
   const vector<Statement*>& stmts() const {return stmts_;};

   /* Methods related to static analysis */
   void execute(const array<State*,domainCnt>& s) const;
   void preset(const array<State*,domainCnt>& s) const;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;
};
// -----------------------------------------------------------------------------
class Sequence: public Statement {
 private:
   vector<Statement*> stmts_;

 public:
   Sequence(const vector<Statement*>& stmts);
   ~Sequence();

   /* Read accessors */
   string to_string() const;
   bool equal(RTL_EQUAL typeEq, RTL* v) const;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
   const vector<Statement*>& stmts() const {return stmts_;};

   /* Methods related to static analysis */
   void execute(const array<State*,domainCnt>& s) const;
   void preset(const array<State*,domainCnt>& s) const;
   array<BaseDomain*,domainCnt> eval(const array<State*,domainCnt>& s, Expr* subExpr) const;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;
};
// -----------------------------------------------------------------------------
class Assign: public Statement {
 private:
   Expr* dst_;
   Expr* src_;

 public:
   Assign(Expr* dst, Expr* src);
   ~Assign();

   /* Read accessors */
   string to_string() const;
   bool equal(RTL_EQUAL typeEq, RTL* v) const;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
   Expr* dst() const {return dst_;};
   Expr* src() const {return src_;};

   /* Methods related to static analysis */
   void execute(const array<State*,domainCnt>& s) const;
   void preset(const array<State*,domainCnt>& s) const;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;
};
// -----------------------------------------------------------------------------
class Call: public Statement {
 private:
   Mem* target_;

 public:
   Call(Mem* target): Statement(STATEMENT_TYPE::CALL) {target_ = target;};
   ~Call();

   /* Read accessors */
   string to_string() const;
   bool equal(RTL_EQUAL typeEq, RTL* v) const;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
   Mem* target() const {return target_;};

   /* Methods related to static analysis */
   void execute(const array<State*,domainCnt>& s) const;
   void preset(const array<State*,domainCnt>& s) const;

   /* Methods related to helper methods */
   bool include(RTL* subExpr) const override;
};
// -----------------------------------------------------------------------------
class Clobber: public Statement {
 private:
   Expr* expr_;

 public:
   Clobber(Expr* expr): Statement(STATEMENT_TYPE::CLOBBER) {expr_ = expr;};
   ~Clobber();

   /* Read accessors */
   string to_string() const;
   bool equal(RTL_EQUAL typeEq, RTL* v) const;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
   Expr* expr() const {return expr_;};

   /* Methods related to static analysis */
   void execute(const array<State*,domainCnt>& s) const;
   void preset(const array<State*,domainCnt>& s) const;
};
// -----------------------------------------------------------------------------
class Exit: public Statement {
 public:
   enum class EXIT_TYPE: char {RET, HALT};

 private:
   EXIT_TYPE typeExit_;

 public:
   Exit(EXIT_TYPE type): Statement(STATEMENT_TYPE::EXIT) {typeExit_ = type;};
   ~Exit() {};

   /* Read accessors */
   string to_string() const;
   bool equal(RTL_EQUAL typeEq, RTL* v) const;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
   EXIT_TYPE exit_type() {return typeExit_;};
};
// -----------------------------------------------------------------------------
class Nop: public Statement {
 public:
   Nop(): Statement(STATEMENT_TYPE::NOP) {};
   ~Nop() {};
   /* Read accessors */
   string to_string() const {return string("nop");};
   bool equal(RTL_EQUAL typeEq, RTL* v) const;
   vector<RTL*> find(RTL_EQUAL typeEq, RTL* v);
};
// -----------------------------------------------------------------------------
#endif