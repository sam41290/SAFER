/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#ifndef ANALYSIS_INTERFACE_H
#define ANALYSIS_INTERFACE_H

#include "basicblock.h"
using namespace std;

class Interface {
    public:
        vector<int64> transferOffset;             // list of offset of transfer insns
        vector<int64> directTargets;              // list of direct transfer targets
        vector<MathExpr*> indirectTargets;      // list of indirect transfer targets

        void analyze(const string &asmFile);
        void check_transfer_insn();
        // Jump Table Target 
        vector<pair<pair<int64,int64>,int>> get_jump_table_target_base_entrysize(int windowSize, char trackType);
        vector<MathExpr*> get_jump_table_target(int windowSize, char trackType);
        // C-Ocaml interface
        static void ocaml_train_imap(const string &imapFile1, const string &imapFile2);
        static void ocaml_load_auto(const string &autoFile);
	static void ocaml_end();
        Interface();
        ~Interface();
    private:
	static int pid;
        vector<Insn*> insnList;
        map<int,Insn*> offset_insn;
        map<int,BasicBlock*> offset_bb;
        void clear();
        static vector<MathExpr*> track_value(MathExpr* v, Insn* insn, int windowSize);
        static vector<vector<MathExpr*>> track_value(const vector<string> &regs, Insn* insn, int windowSize);
        static char is_jump_table_target(MathExpr* _mathExpr, int64 &base, int64 &jmptbl, int &entrySize);
        static string extract_op(const string &op_size);
        static void print_ptr(vector<vector<MathExpr*>> &v);
        // C-Ocaml interface
        static int fileNum;
        static void ocaml_lift_asm(string &asmFile, string &rtlFile);
        static void prepare_file(const string &fileName, int id);
};

#endif
