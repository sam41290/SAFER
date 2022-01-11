/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include "mathexpr.h"
#include "expr.h"

using namespace std;

char MathExpr::is_initialized;
map<string,string,StringCompare> MathExpr::opMap1;
map<string,string,StringCompare> MathExpr::opMap2;
map<string,string,StringCompare> MathExpr::opMap3;
map<string,string,StringCompare> MathExpr::modeLenMap;
set<string> MathExpr::opList1;
set<string> MathExpr::opList2;
set<string> MathExpr::opList3;
set<string> MathExpr::regList;
vector<string> MathExpr::sideEffectOpList;

MathExpr::MathExpr(Expr* expr) {
    if (MathExpr::is_initialized == 0)
        MathExpr::init();
    isMathExpr = 1;
    add_expr(expr);
    if (isMathExpr)
        optimize_const();
}

MathExpr::MathExpr(const list<string> &_mathExpr) {
    if (_mathExpr.size() == 0) {
        isMathExpr = 0;
        return;
    }
    // assume that this constructor can only be used by legitimate code
    if (MathExpr::is_initialized == 0)
        MathExpr::init();
    isMathExpr = 1;
    for (list<string>::const_iterator it = _mathExpr.begin(); it != _mathExpr.end(); ++it)
        mathExpr.push_back(*it);
    optimize_const();
}

MathExpr::MathExpr(MathExpr* _mexpr) {
    if (_mexpr == NULL) {
        isMathExpr = 0;
        return;
    }
    // assume that this constructor can only be used by legitimate code
    if (MathExpr::is_initialized == 0)
        MathExpr::init();
    isMathExpr = 1;
    for (list<string>::const_iterator it = _mexpr->mathExpr.begin(); it != _mexpr->mathExpr.end(); ++it)
        mathExpr.push_back(*it);
    optimize_const();
}

MathExpr::~MathExpr() {
    mathExpr.clear();
}

MathExpr* MathExpr::substitute(const string& reg, MathExpr* val) {
    string r;
    int rSize;
    list<string>::iterator it;
    MathExpr* v = MathExpr::clone(this);

    // if empty val for reg "r", keep it as original reg, stop searching
    if (val == NULL || !val->isMathExpr)
        return v;
    // otherwise, use corresponding val
    for (it = v->mathExpr.begin(); it != v->mathExpr.end(); ++it)
        if (MathExpr::extract_reg(*it, r, rSize) && (r.compare(reg) == 0)) {
            it = v->mathExpr.erase(it);
            v->add_to_mathExpr(it, val);
            if (it == v->mathExpr.end())
                break;
        }

    v->optimize_const();

    return v;
}

MathExpr* MathExpr::substitute(const vector<string> &regs, const vector<MathExpr*> &vals) {
    string r;
    int rSize;

    MathExpr* v = MathExpr::clone(this);
    list<string>::iterator it = v->mathExpr.begin();
    vector<string>::const_iterator it2;
    vector<MathExpr*>::const_iterator it3;

    for (; it != v->mathExpr.end(); ++it)
        if (MathExpr::extract_reg(*it, r, rSize)) {
            it2 = regs.begin();
            it3 = vals.begin();
            for (; it2 != regs.end(); ++it2, ++it3)
                if (*it3 != NULL && (*it3)->isMathExpr && r.compare(*it2) == 0) {
                    it = v->mathExpr.erase(it);
                    v->add_to_mathExpr(it, *it3);
                    --it;
                }
        }

    v->optimize_const();
    return v;
}

vector<MathExpr*> MathExpr::substitute(const vector<string> &regs,
const vector<vector<MathExpr*>> &vals, vector<MathExpr*> &v, int index) {
    vector<MathExpr*> result;
    // if already go over all registers
    if (index == regs.size()) {
        result.push_back(substitute(regs, v));
        return result;
    }
    // otherwise, handle reg at position index
    vector<string>::const_iterator it = regs.begin();
    vector<vector<MathExpr*>>::const_iterator it2 = vals.begin();
    for (int i = 0; i < index; ++i, ++it, ++it2);    
    vector<MathExpr*>::const_iterator it3 = (*it2).begin();
    // for each reg, if at least 1 value go over each choice of value
    if ((*it2).size() > 0)
        for (; it3 != (*it2).end(); ++it3) {
            MathExpr* tt = MathExpr::clone(*it3);
            v.push_back(tt);
            vector<MathExpr*> t = substitute(regs, vals, v, index + 1);
            result.insert(result.end(), t.begin(), t.end());
            v.pop_back();
            // clear tt because add_to_mathExpr will use a copy of tt's content
            delete tt;
            // t holds a vector of ptr passed into "result", ptrs should not be destroyed
            t.clear();
        }
    // otherwise, use empty value which is then intepreted as original reg
    else {
        v.push_back(NULL);
        vector<MathExpr*> t = substitute(regs, vals, v, index + 1);
        result.insert(result.end(), t.begin(), t.end());
        v.pop_back();
        // t holds a vector of ptr passed into "result", ptrs should not be destroyed
        t.clear();
    }
    return result;
}

vector<MathExpr*> MathExpr::substitute(const vector<string> &regs, const vector<vector<MathExpr*>> &vals) {
    vector<MathExpr*> v;
    return substitute(regs, vals, v, 0);
}

vector<string> MathExpr::get_all_regs() {
    string r;
    int rSize;
    set<string> v;
    for (list<string>::iterator it = mathExpr.begin(); it != mathExpr.end(); ++it)
        if (MathExpr::extract_reg(*it, r, rSize))
            v.insert(r);

    vector<string> regs;
    regs.assign(v.begin(), v.end());
    return regs;
}

void MathExpr::print() {
    for (list<string>::iterator it = mathExpr.begin(); it != mathExpr.end(); ++it)
        cout << (*it) << " ";
}

void MathExpr::print_no_mode() {
    string t;
    int tSize;
    for (list<string>::iterator it = mathExpr.begin(); it != mathExpr.end(); ++it) {
        if (extract_op(*it, t, tSize))
            cout << t << " ";
        else if (extract_reg(*it, t, tSize))
            cout << t << " ";
        else
            cout << *it << " ";
    }
}

// get the next element that is not within the scope held by the iterator
list<string>::iterator MathExpr::next_element(list<string>::iterator it) {
    string op;
    int opSize;
    // ignore out of range
    if (it == mathExpr.end())
        return it;
    // opcode
    if (MathExpr::extract_op(*it, op, opSize)) {
        // unary opcode
        if (MathExpr::opList1.find(op) != MathExpr::opList1.end())
            return next_element(++it);
        // binary opcode
        else if (MathExpr::opList2.find(op) != MathExpr::opList2.end())
            return next_element(next_element(++it));
        // ternary opcode
        else if (MathExpr::opList3.find(op) != MathExpr::opList3.end())
            return next_element(next_element(next_element(++it)));
    }
    // reg or const
    else
        return ++it;

    return mathExpr.end();
}

// skip consecutive _extend/_extract insn and find the first following opcode
// reg or value in between is NOT allowed
// used for checking is_jump_table_target
char MathExpr::find_non_ext_op(list<string>::iterator &it) {
    string op;
    int opSize;
    while (it != mathExpr.end()) {
        if (!MathExpr::extract_op(*it, op, opSize))
            return 0;
        if (op.compare("sext") == 0 || op.compare("zext") == 0 ||
            op.compare("sextr") == 0 || op.compare("zextr") == 0) {
                ++it;
                continue;
            }
        break;
    }
    return 1;
}

void MathExpr::add_expr(Expr* expr) {
    string size;
    map<string,string,StringCompare>::iterator it;

    // find (op/reg) size, set default to 64 if not specified
    // NOTE: currently, unsupported mode (e.g. "float") is marked as NOT a mathExpr
    it = MathExpr::modeLenMap.find(expr->mode);
    if (it != MathExpr::modeLenMap.end())
        size = it->second;
    else if (expr->mode.compare("") == 0)
        size = "64";
    else {
        isMathExpr = 0;
        return;
    }

    switch (expr->type) {
        case V_EXPR:
            // special case: -34 = 0 - 34
            if (expr->op.compare("neg") == 0) {
                mathExpr.push_back("-_" + size);
                mathExpr.push_back("0");
                add_expr(expr->get_expr(0));
                break;
            }
            // unary opcodes
            it = MathExpr::opMap1.find(expr->op); 
            if (it != MathExpr::opMap1.end()) {
                mathExpr.push_back(it->second + "_" + size);
                add_expr(expr->get_expr(0));
                break;
            }
            // binary opcodes
            it = MathExpr::opMap2.find(expr->op);
            if (it != MathExpr::opMap2.end()) {
                mathExpr.push_back(it->second + "_" + size);
                add_expr(expr->get_expr(0));
                add_expr(expr->get_expr(1));
                break;
            }
            // ternary opcodes
            it = MathExpr::opMap3.find(expr->op);
            if (it != MathExpr::opMap3.end()) {
                mathExpr.push_back(it->second + "_" + size);
                add_expr(expr->get_expr(0));
                add_expr(expr->get_expr(1));
                add_expr(expr->get_expr(2));
                break;
            }
            // not marked as a mathExpr if no match
            isMathExpr = 0;
            break;
        case V_REF:
            mathExpr.push_back("L" + to_string(((Ref*)expr)->offset));
            break;
        case V_REG:
            mathExpr.push_back(((Reg*)expr)->reg + "_" + size);
            break;
        case V_SUBREG:
            mathExpr.push_back(MathExpr::opMap2["subreg"] + "_" + size);
            add_expr(expr->get_expr(0));
            mathExpr.push_back(to_string(((SubReg*)expr)->byteNum));
            break;
        case V_CONST:
            mathExpr.push_back(to_string(((Const*)expr)->val));
            break;
        case V_MEM:
            mathExpr.push_back(MathExpr::opMap1["mem"] + "_" + size);
            add_expr(expr->get_expr(0));
            break;
        case V_STRICT_LOW_PART:
            it = MathExpr::modeLenMap.find(expr->mode);
            if (it != MathExpr::modeLenMap.end()) {
                size = it->second;
                mathExpr.push_back(MathExpr::opMap1["strict_low_part"] + "_" + size);
                add_expr(expr->get_expr(0));
            }
            else
                isMathExpr = 0;
            break;
        case V_EXTRACT:
            mathExpr.push_back(MathExpr::opMap3[expr->op] + "_" + size);
            add_expr(expr->get_expr(0));
            mathExpr.push_back(to_string(((Extract*)expr)->size));
            mathExpr.push_back(to_string(((Extract*)expr)->pos));
            break;
        case V_GENERALTYPE:
            mathExpr.push_back(((GeneralType*)expr)->val);
            break;
        default:
            isMathExpr = 0;
            break;
    }
}

void MathExpr::add_to_mathExpr(list<string>::iterator &it, const string& s) {
    if (it != mathExpr.end())
        mathExpr.insert(it, s);
    else {
        mathExpr.push_back(s);
        it = mathExpr.end();
    }
}

void MathExpr::add_to_mathExpr(list<string>::iterator &it, MathExpr* _expr) {
    list<string>::iterator it2;
    for (it2 = _expr->mathExpr.begin(); it2 != _expr->mathExpr.end(); ++it2) {
        string s = *it2;
        add_to_mathExpr(it, s);
    }
}

char MathExpr::get_op_args_1(list<string>::iterator it, string &op, int &opSize, int64 &x, int64 &y, int64 &z) {
    // extract and check if op is not an opcode
    if (!MathExpr::extract_op(*it, op, opSize))
        return 0;
    // if op is an opcode
    char t = 1;

    ++it;
    if (MathExpr::str_to_int64(*it, x) == 0)
        // if (MathExpr::extract_offset(*it, x) == 0)
            t = 0;
    
    if (MathExpr::opList2.find(op) != MathExpr::opList2.end()) {
        ++it;
        if (MathExpr::str_to_int64(*it, y) == 0)
            // if (MathExpr::extract_offset(*it, y) == 0)
                t = 0;
    }

    if (MathExpr::opList3.find(op) != MathExpr::opList3.end()) {
        ++it;
        if (MathExpr::str_to_int64(*it, y) == 0)
            // if (MathExpr::extract_offset(*it, y) == 0)
                t = 0;
        ++it;
        if (MathExpr::str_to_int64(*it, z) == 0)
            // if (MathExpr::extract_offset(*it, z) == 0)
                t = 0;
    }
    // t == 0 if at least 1 failed conversion
    return t;
}

char MathExpr::get_op_args_2(list<string>::iterator it, string &op, int &opSize,
int64 &x, int64 &y, string &reg, char &regPos, char &innerOpFirst) {
    // extract and check if op is not an opcode
    if (!MathExpr::extract_op(*it, op, opSize))
        return 0;
    // if op is not a binary opcode
    if (MathExpr::opList2.find(op) == MathExpr::opList2.end())
        return 0;

    int64 z;
    string op2;
    int opSize2;
    char successX = 1, successY = 1, successZ = 1;
    list<string>::iterator it2 = it;

    // op op x y z
    if (MathExpr::extract_op(*(++it), op2, opSize2)) {
        if (op.compare(op2) != 0 || opSize != opSize2)
            return 0;
        if (op.compare("+") == 0 || op.compare("-") == 0 ||
            op.compare("&") == 0 || op.compare("|") == 0 ||
            op.compare("*") == 0 || op.compare("<<") == 0) {
                ++it;
                if ((successX = MathExpr::str_to_int64(*it, x)) == 0)
                    // if ((successX = MathExpr::extract_offset(*it, x)) == 0)
                        reg = *it;
                ++it;
                if ((successY = MathExpr::str_to_int64(*it, y)) == 0)
                    // if ((successY = MathExpr::extract_offset(*it, y)) == 0)
                        reg = *it;
                ++it;
                if ((successZ = MathExpr::str_to_int64(*it, z)) == 0)
                    // if ((successZ = MathExpr::extract_offset(*it, z)) == 0)
                        reg = *it;
            }
        innerOpFirst = 1;
    }
    // op x op y z
    else {
        ++it2;
        it = it2;
        if (MathExpr::extract_op(*(++it), op2, opSize2)) {
            if (op.compare(op2) != 0 || opSize != opSize2)
                return 0;
            if (op.compare("+") == 0 || op.compare("-") == 0 ||
                op.compare("&") == 0 || op.compare("|") == 0 ||
                op.compare("*") == 0 || op.compare("<<") == 0) {
                    if ((successX = MathExpr::str_to_int64(*it2, x)) == 0)
                        // if ((successX = MathExpr::extract_offset(*it2, x)) == 0)
                            reg = *it;
                ++it;
                if ((successY = MathExpr::str_to_int64(*it, y)) == 0)
                    // if ((successY = MathExpr::extract_offset(*it, y)) == 0)
                        reg = *it;
                ++it;
                if ((successZ = MathExpr::str_to_int64(*it, z)) == 0)
                    // if ((successZ = MathExpr::extract_offset(*it, z)) == 0)
                        reg = *it;
            }
            innerOpFirst = 0;
        }
        else
            return 0;
    }

    string r;
    int rSize;
    if (successX + successY + successZ != 2 || !MathExpr::extract_reg(reg, r, rSize))
        return 0;

    if (!successX && successZ) {
        regPos = 0;
        x = z;
    }
    else if (!successY && successZ) {
        regPos = 1;
        y = z;
    }
    else
        regPos = 2;

    return 1;
}

char MathExpr::compute_const(const string& op, int opSize, int64 x, int64 y, int64 z, int64 &v) {
    // unary opcodes
    if      (op.compare("~") == 0)   v = ~x;
    else if (op.compare("abs") == 0) v = abs(x);
    else if (op.compare("trunc") == 0) v = x;
    else if (op.compare("clz") == 0 && x != 0) { // undefined behavior if x == 0
        v = 0;
        int64 t2 = 0;
        for (uint64 t = (uint64)x; t != 0; t >>= 1, ++t2)
            if ((t & 1) == 1) v = t2;
    }
    else if (op.compare("ctz") == 0 && x != 0) { // undefined behavior if x == 0
        v = 0;
        for (uint64 t = (uint64)x; (t & 1) == 0; t >>= 1, ++v);
    }
    else if (op.compare("rev") == 0) {
        uint64 t = (uint64)x;
        uint64 v2 = 0;
        int nRound = opSize >> 4;
        for (int i = 0; i < nRound; ++i, t >>= 8)
            v2 = (v2 << 8) + (t & MathExpr::fill_set_bit(8));
        v = (int64)v2;
    }
    else if (op.compare("slp") == 0) v = x;     // slp in src = cast into mode

    // unary side-effect opcodes
    else if (op.compare("++i") == 0) v = x + (int64)(opSize >> 3);
    else if (op.compare("i++") == 0) v = x;
    else if (op.compare("--i") == 0) v = x - (int64)(opSize >> 3);
    else if (op.compare("i--") == 0) v = x;

    // binary opcodes
    else if (op.compare("+") == 0)   v = x + y;
    else if (op.compare("-") == 0)   v = x - y;
    else if (op.compare("*") == 0)   v = x * y;
    else if (op.compare("/") == 0)   v = x / y;
    else if (op.compare("u/") == 0)  v = (int64)((uint64)x / (uint64)y);
    else if (op.compare("%") == 0)   v = x % y;
    else if (op.compare("u%") == 0)  v = (int64)((uint64)x % (uint64)y);
    else if (op.compare("^") == 0)   v = (int64)((uint64)x ^ (uint64)y);
    else if (op.compare("&") == 0)   v = (int64)((uint64)x & (uint64)y);
    else if (op.compare("|") == 0)   v = (int64)((uint64)x | (uint64)y);
    else if (op.compare(">>>") == 0) v = (int64)((uint64)x >> y);
    else if (op.compare(">>") == 0)  v = x >> y;
    else if (op.compare("<<") == 0)  v = x << y;
    else if (op.compare("<-") == 0) {
        uint64 t = (uint64)x;
        uint64 pow2 = fill_set_bit(opSize - 1) + 1;
        for (; y > 0; --y)
            if ((t & pow2) != 0)
                t = (t << 1) + 1;
            else
                t <<= 1;
        v = (int64)t;
    }
    else if (op.compare("->") == 0) {
        uint64 t = (uint64)x;
        uint64 pow2 = fill_set_bit(opSize - 1) + 1;
        for (; y > 0; --y)
            if ((t & 1) == 0)
                t >>= 1;
            else
                t = pow2 + (t >> 1);
        v = (int64)t;
    }
    else if (op.compare("sreg") == 0) v = ((uint64)x >> (y * 8)) & MathExpr::fill_set_bit(opSize);
    // binary side-effect opcodes
    else if (op.compare("rmod") == 0) v = x;
    else if (op.compare("modr") == 0) v = y;

    // ternary operators
    else if (op.compare("*+") == 0)  v = x * y + z;
    else if (op.compare("zextr") == 0) v = (int64) (((uint64)x >> z) & MathExpr::fill_set_bit(y));
    else if (op.compare("sextr") == 0) {
        // sign = 111..1111 or 000..0000
        uint64 sign = (((uint64)x >> (SYSTEM_ARCH_BIT - 1)) << 8) - 1;
        if (sign == 1)
            sign = MathExpr::fill_set_bit(SYSTEM_ARCH_BIT);
        uint64 tmp = ((uint64)x >> z) & MathExpr::fill_set_bit(y);
        v = (int64) (((sign >> z) << z) + tmp);
    }
    else
        return 0;
    // perform operator within opSize
    scale_opSize(v, opSize);

    return 1;
}

char MathExpr::simplify_const(list<string>::iterator it) {
    // (op reg val) OR (op val reg)
    // extract value of reg, val
    int64 val;
    int opSize;
    char regFirst;
    string op, reg;

    // check if opcode is found
    if (!MathExpr::extract_op(*it, op, opSize))
        return 0;

    // get next 2 elements
    list<string>::iterator it2 = it;
    if (++it2 == mathExpr.end())
        return 0;
    list<string>::iterator it3 = it2;
    if (++it3 == mathExpr.end())
        return 0;

    // if combination (val, reg) is found
    string r;
    int rSize;
    if (MathExpr::str_to_int64(*it2, val) && MathExpr::extract_reg(*it3, r, rSize)) {
        reg = *it3;
        regFirst = 0;
    }
    else if (MathExpr::str_to_int64(*it3, val) && MathExpr::extract_reg(*it2, r, rSize)) {
        reg = *it2;
        regFirst = 1;
    }
    else
        return 0;

    // handle special cases: result = 0 or reg
    if (val == 0) {
        // result = reg
        // (+ x 0) OR (| x 0)
        if ((regFirst && (op.compare("<<") == 0
                       || op.compare(">>") == 0 || op.compare(">>>") == 0)) ||
            (op.compare("+") == 0 || op.compare("-") == 0 || op.compare("|") == 0)) {
                it = mathExpr.erase(it);
                it = mathExpr.erase(it);
                it = mathExpr.erase(it);
                add_to_mathExpr(it, reg);
                return 1;
        }
        // result = 0
        // (* x 0) OR (& x 0)
        else if (op.compare("*") == 0 || op.compare("&") == 0) {
            it = mathExpr.erase(it);
            it = mathExpr.erase(it);
            it = mathExpr.erase(it);
            add_to_mathExpr(it, "0");
            return 1;
        }
    }
    // result = reg
    // (* x 1)
    if (val == 1 && op.compare("*") == 0) {
        it = mathExpr.erase(it);
        it = mathExpr.erase(it);
        it = mathExpr.erase(it);
        add_to_mathExpr(it, reg);
        return 1;
    }
    return 0;
}

void MathExpr::optimize_const() {
    char update = 0;
    list<string>::iterator it, it2;
    for (it = mathExpr.begin(); it != mathExpr.end(); ++it) {
        // extract op and args
        string op, reg;
        int opSize;
        int64 v, x, y, z;
        char regPos, innerOpFirst;

        // v = (op x)
        // v = (op x y)
        // v = (op x y z)
        if (get_op_args_1(it, op, opSize, x, y, z) && compute_const(op, opSize, x, y, z, v)) {
            // replace old elements ...
            update = 1;
            it = mathExpr.erase(it);                     // remove operator
            it = mathExpr.erase(it);                     // remove x
            if (MathExpr::opList2.find(op) != MathExpr::opList2.end())
                it = mathExpr.erase(it);                 // remove y
            if (MathExpr::opList3.find(op) != MathExpr::opList3.end()) {
                it = mathExpr.erase(it);                 // remove y
                it = mathExpr.erase(it);                 // remove w
            }
            // ... by new elements
            add_to_mathExpr(it, to_string(v));
        }
        //   (op (op x y) z)
        //   (op x (op y z))
        // with opcode in {+, -, *, <<, &, |}
        // and exactly 1 of {x, y, z} is reg
        else if (get_op_args_2(it, op, opSize, x, y, reg, regPos, innerOpFirst)) {
            // can't do anything with 3 << (ax << 4) or (3 << ax) << 4
            if (op.compare("<<") == 0 && regPos != 0)
                continue;
            // otherwise, replace old elements ...
            update = 1;
            ++it;                                        // skip the 1st operator
            it = mathExpr.erase(it);                     // remove 2nd operator
            it = mathExpr.erase(it);                     //        and x, y, z
            it = mathExpr.erase(it);
            it = mathExpr.erase(it);
            // ... by new elements
            // op op x y z
            if (innerOpFirst) {
                if (regPos == 0) {
                    add_to_mathExpr(it, reg);
                    // - - ax 3 2 = - ax + 3 2 = - ax 5
                    if (op.compare("-") == 0 || op.compare("<<") == 0)
                        compute_const("+", opSize, x, y, 0, v);
                    else
                        compute_const(op, opSize, x, y, 0, v);
                    add_to_mathExpr(it, to_string(v));
                }
                else {
                    compute_const(op, opSize, x, y, 0, v);
                    add_to_mathExpr(it, to_string(v));
                    add_to_mathExpr(it, reg);
                }
            }
            // op x op y z
            else {
                // - 3 - ax 4 = - + 3 4 ax
                if (regPos == 1 && op.compare("-") == 0) {
                    compute_const("+", opSize, x, y, 0, v);
                    add_to_mathExpr(it, to_string(v));
                    add_to_mathExpr(it, reg);
                }
                // - 3 - 4 ax = + - 3 4 ax
                else if (regPos == 2 && op.compare("-") == 0) {
                    // remove 1st operator
                    --it;
                    mathExpr.erase(it);
                    // add new operator
                    add_to_mathExpr(it, "+" + opSize);
                    // and more
                    compute_const("-", opSize, x, y, 0, v);
                    add_to_mathExpr(it, to_string(v));
                    add_to_mathExpr(it, reg);
                }
                else {
                    compute_const(op, opSize, x, y, 0, v);
                    add_to_mathExpr(it, reg);
                    add_to_mathExpr(it, to_string(v));
                }
            }
        }
        // (op x 0) OR (op 0 x)
        else if (simplify_const(it))
            update = 1;

        // start from beginning, update until no change
        if (update == 1) {
            optimize_const();
            return;
        }
    }
}

void MathExpr::init() {
    MathExpr::is_initialized = 1;
    // op to short version mapping
    string op_rtl_1[] = {"not", "abs", "mem", "zero_extend", "sign_extend", "truncate",
                         "post_inc", "pre_inc", "post_dec", "pre_dec", "clz", "ctz",
                         "bswap", "strict_low_part"};
    string op_short_1[] = {"~", "abs", "M", "zext", "sext", "trunc",
                           "i++", "++i", "i--", "--i", "clz", "ctz",
                           "rev", "slp"};
    string op_rtl_2[] = {"plus", "minus", "mult", "div", "udiv", "mod", "umod",
                         "xor", "and", "ior", "lshiftrt", "ashiftrt", "ashift",
                         "rotate", "rotatert", "post_modify", "pre_modify", "subreg"};
    string op_short_2[] = {"+", "-", "*", "/", "u/", "%", "u%",
                           "^", "&", "|", ">>>", ">>", "<<",
                           "<-", "->", "rmod", "modr", "sreg"};
    string op_rtl_3[] = {"fma", "zero_extract", "sign_extract"};
    string op_short_3[] = {"*+", "zextr", "sextr"};

    for (int i = 0; i < 14; ++i) {
        MathExpr::opMap1[op_rtl_1[i]] = op_short_1[i];
        MathExpr::opList1.insert(op_short_1[i]);
    }
    for (int i = 0; i < 18; ++i) {
        MathExpr::opMap2[op_rtl_2[i]] = op_short_2[i];
        MathExpr::opList2.insert(op_short_2[i]);
    }
    for (int i = 0; i < 3; ++i) {
        MathExpr::opMap3[op_rtl_3[i]] = op_short_3[i];
        MathExpr::opList3.insert(op_short_3[i]);
    }
    // mode to bit length mapping
    MathExpr::modeLenMap["QI"] = "8";
    MathExpr::modeLenMap["HI"] = "16";
    MathExpr::modeLenMap["SI"] = "32";
    MathExpr::modeLenMap["DI"] = "64";
    // list of register
    string reg_list[] = {"ax", "bx", "cx", "dx", "si", "di", "sp", "bp", "r8",
                         "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    for (int i = 0; i < 16; ++i)
        MathExpr::regList.insert(reg_list[i]);
    // list of side effect RTL opcodes
    MathExpr::sideEffectOpList.push_back("pre_dec");
    MathExpr::sideEffectOpList.push_back("pre_inc");
    MathExpr::sideEffectOpList.push_back("pre_modify");
    MathExpr::sideEffectOpList.push_back("post_dec");
    MathExpr::sideEffectOpList.push_back("post_inc");
    MathExpr::sideEffectOpList.push_back("post_modify");
    // *** NOTE ***
    // not support due to operating on float registers:
    // ... ss_truncate, us_truncate, fix

}


char MathExpr::is_reg(const string& s) {
    return MathExpr::regList.find(s) != MathExpr::regList.end();
}

char MathExpr::str_to_int64(const string& s, int64 &v) {
    try {
        v = stoll(s, nullptr, 10);
        return 1;
    }
    catch (invalid_argument &e) {
        return 0;
    }
}

char MathExpr::is_number(const string& s) {
    int64 v;
    return MathExpr::str_to_int64(s, v);
}

char MathExpr::is_op(const string& s) {
    if (MathExpr::opList1.find(s) == MathExpr::opList1.end() &&
        MathExpr::opList2.find(s) == MathExpr::opList2.end() &&
        MathExpr::opList3.find(s) == MathExpr::opList3.end())
            return 0;
    return 1;
}

// op_size: -_64, +_64, >>>_32, +*_16, u/_8
char MathExpr::extract_op(const string &op_size, string &op, int &opSize) {
    size_t t = op_size.find('_');
    if (t != string::npos) {
        string t1 = op_size.substr(0,t);
        string t2 = op_size.substr(t+1);
        if (!MathExpr::is_op(t1) || !MathExpr::is_number(t2))
            return 0;
        op = t1;
        opSize = stoi(t2);
        return 1;
    }
    op = "";
    opSize = -1;
    return 0;
}

// reg_size: ax_32, r10_64
char MathExpr::extract_reg(const string &reg_size, string &reg, int &regSize) {
    size_t t = reg_size.find('_');
    if (t != string::npos) {
        string t1 = reg_size.substr(0,t);
        string t2 = reg_size.substr(t+1);
        if (!MathExpr::is_reg(t1) || !MathExpr::is_number(t2))
            return 0;
        reg = t1;
        regSize = stoi(t2);
        return 1;
    }
    reg = "";
    regSize = -1;
    return 0;
}

char MathExpr::extract_offset(const string &label, int64 &v) {
    if (label.at(0) == 'L') {
        string t = label;
        t.erase(0, 1);
        if (str_to_int64(t, v))
            return 1;
    }

    return 0;
}

void MathExpr::scale_opSize(int64 &v, int opSize) {
    v = (int64) ((uint64)v & MathExpr::fill_set_bit(opSize));
}

uint64 MathExpr::fill_set_bit(int64 nBit) {
    if (nBit == SYSTEM_ARCH_BIT)
        return (uint64)((int64)-1);
    return ((uint64)1 << nBit) - 1;
}

// clone and clear functions
MathExpr* MathExpr::clone(MathExpr* v) {
    return new MathExpr(v);
}

vector<MathExpr*> MathExpr::clone(const vector<MathExpr*> &v) {
    vector<MathExpr*> result;
    for (vector<MathExpr*>::const_iterator it = v.begin(); it != v.end(); ++it)
        result.push_back(MathExpr::clone(*it));
    return result;
}

vector<vector<MathExpr*>> MathExpr::clone(const vector<vector<MathExpr*>> &v) {
    vector<vector<MathExpr*>> result;
    for (vector<vector<MathExpr*>>::const_iterator it = v.begin(); it != v.end(); ++it)
        result.push_back(MathExpr::clone(*it));
    return result;
}

void MathExpr::clear(vector<MathExpr*> &v) {
    vector<MathExpr*>::iterator it = v.begin();
    for (; it != v.end(); ++it)
        if (*it != NULL)
            delete (*it);
    v.clear();
}

void MathExpr::clear(vector<vector<MathExpr*>> &v) {
    vector<vector<MathExpr*>>::iterator it = v.begin();
    for (; it != v.end(); ++it)
        MathExpr::clear(*it);
    v.clear();
}