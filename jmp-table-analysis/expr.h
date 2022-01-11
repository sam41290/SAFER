/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef EXPR_H
#define EXPR_H

#include "mathexpr.h"
#include "const.h"

using namespace std;

class Expr {
    public:
        string s;
        string op;
        string mode;
        char type;
        char isInvalidExpr;
        vector<Expr*> subExpr;
        Expr(const string& x);
        ~Expr();
        // essential functions
        Expr* get_expr(int index);
        Expr* find_opcode(const string& op);
        Expr* find_opcode(const string& op, Expr* argv, int argId);
        Expr* find_opcode_2(const string& op1, const string& op2, Expr* argv, int argId1, int argId2);
        vector<Expr*> find_opcode_all(const string& op);
        // get list of required regs to track some regs
        virtual set<string> get_regs_to_track(const string& _reg);
        set<string> get_regs_to_track(const vector<string> &_regs);
        // update value of regs using given input {regs, vals}
        virtual vector<MathExpr*> update_val_of_regs(const string& _reg,
                const vector<string> &fromRegs, const vector<vector<MathExpr*>> &fromVals);
        vector<vector<MathExpr*>> update_val_of_regs(const vector<string> &_regs,
                const vector<string> &fromRegs, const vector<vector<MathExpr*>> &fromVals);
        // tools for other purposes
        void print();
        void print(vector<int> pos);
        MathExpr* estimate_val();
        virtual char equivalent(Expr *v);
        virtual void adjust_assigned_value(const vector<MathExpr*> &oldVal, vector<MathExpr*> &newVal);
    protected:
        void add_expr(const string& x);
        void extract_operands();
        static string get_opcode(const string& x);
        static string get_mode(const string& x);
        static char get_type(const string& x);
};

class Reg: public Expr {
    public:
        string reg;
        char equivalent(Expr *v);
        Reg(const string& x);
};

class SubReg: public Expr {
    public:
        int byteNum;
        SubReg(const string& x);
        void adjust_assigned_value(const vector<MathExpr*> &oldVal, vector<MathExpr*> &newVal);
};

class StrictLowPart: public Expr {
    public:
        StrictLowPart(const string& x);
        void adjust_assigned_value(const vector<MathExpr*> &oldVal, vector<MathExpr*> &newVal);
};

class Extract: public Expr {
    public:
        int size;
        int pos;
        char isSignExtract;
        Extract(const string& x);
        void adjust_assigned_value(const vector<MathExpr*> &oldVal, vector<MathExpr*> &newVal);
};

class Ref: public Expr {        // either symbol_ref or label_ref
    public:                     // remove .L at beginning to extract offset
        int64 offset;
        Ref(const string& x);
};

class Mem: public Expr {
    public:
        char accessType;
        int64 directTarget;
        MathExpr* indirectTarget;
        Mem(const string& x);
        ~Mem();
};

class Const: public Expr {
    public:
        char constType;           // either INT_TYPE or DOUBLE_TYPE
        int64 val;                // we only care about int64 values
        string doubleVal;         // either a double or Inf
        Const(const string& x);
        Const(int64 x);
};

class IfElse: public Expr {
    public:
        Expr* target_if;
        Expr* target_else;
        IfElse(const string& x);
};

class Parallel: public Expr {
    public:
        Parallel(const string& x);
        set<string> get_regs_to_track(const string& _reg);
        vector<MathExpr*> update_val_of_regs(const string& _reg,
                const vector<string> &fromRegs, const vector<vector<MathExpr*>> &fromVals);
};

class GeneralType: public Expr {
    public:
        string val;
        GeneralType(const string& x);
};

#endif