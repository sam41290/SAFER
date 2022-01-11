/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef MATHEXPR_H
#define MATHEXPR_H
#include "const.h"
#include <map>
#include <vector>
#include <list>
#include <set>
#include <string>

using namespace std;

struct StringCompare {
    public:
    bool operator() (const string x, const string y) {
         return x.compare(y) < 0;
    }
};

class Expr;

class MathExpr {
    public:
        char isMathExpr;
        list<string> mathExpr;
        MathExpr(Expr* expr);
        MathExpr(MathExpr* expr);
        MathExpr(const list<string> &_mathExpr);
        ~MathExpr();
        // features for analysis
        vector<string> get_all_regs();
        MathExpr* substitute(const string& reg, MathExpr* val);
        MathExpr* substitute(const vector<string> &regs, const vector<MathExpr*> &vals);
        vector<MathExpr*> substitute(const vector<string> &regs, const vector<vector<MathExpr*>> &vals);
        list<string>::iterator next_element(list<string>::iterator it);
        char find_non_ext_op(list<string>::iterator &it);
        // useful features
        void print();
        void print_no_mode();
        static char str_to_int64(const string& s, int64 &v);
        static char extract_offset(const string &label, int64 &v);
        static char extract_op(const string& op_size, string &op, int &opSize);
        static char extract_reg(const string& reg_size, string &reg, int &regSize);
        static uint64 fill_set_bit(int64 nBit);
        // clone and clear functions
        static MathExpr* clone(MathExpr* v);
        static vector<MathExpr*> clone(const vector<MathExpr*> &v);
        static vector<vector<MathExpr*>> clone(const vector<vector<MathExpr*>> &v);
        static void clear(vector<MathExpr*> &v);
        static void clear(vector<vector<MathExpr*>> &v);
        // useful static data
        static vector<string> sideEffectOpList;
        static map<string,string,StringCompare> modeLenMap;
    private:
        static char is_initialized;
        static map<string,string,StringCompare> opMap1;
        static map<string,string,StringCompare> opMap2;
        static map<string,string,StringCompare> opMap3;
        static set<string> opList1;
        static set<string> opList2;
        static set<string> opList3;
        static set<string> regList;
        // optimization features
        void add_expr(Expr* expr);
        char get_op_args_1(list<string>::iterator it, string &op, int &opSize,
                           int64 &x, int64 &y, int64 &z);
        char get_op_args_2(list<string>::iterator it, string &op, int &opSize,
                           int64 &x, int64 &y, string &reg, char &regPos, char &innerOpFirst);
        void add_to_mathExpr(list<string>::iterator &it, const string& s);
        void add_to_mathExpr(list<string>::iterator &it, MathExpr* _mathExpr);
        vector<MathExpr*> substitute(const vector<string> &regs, const vector<vector<MathExpr*>> &vals,
                                     vector<MathExpr*> &v, int index);
        char compute_const(const string& op, int opSize, int64 x, int64 y, int64 z, int64 &v);
        char simplify_const(list<string>::iterator it);
        void optimize_const();
        // useful features
        static void init();
        static char is_reg(const string &s);
        static char is_op(const string &s);
        static char is_number(const string &s);
        static void scale_opSize(int64 &v, int opSize);
};

#endif