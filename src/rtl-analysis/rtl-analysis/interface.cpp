/*
   Copyright (C) 2018 - 2021 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "interface.h"
#include "program.h"

#include <cstdio>
#include <unistd.h>
#include <caml/mlvalues.h>
#include <caml/callback.h>
// -------------------------------- Interface ----------------------------------
Interface::Interface(const string& autoFile) {
   char** argv = (char**)malloc(4*sizeof(char*));
   char t0[] = "interface";
   char t1[] = "-itf";
   char t2[] = "on";
   argv[0] = t0;
   argv[1] = t1;
   argv[2] = t2;
   argv[3] = nullptr;
   // start ocaml code and load auto
   caml_main(argv);
   Interface::ocaml_load_auto(autoFile);
}

Interface::~Interface() {
   for (auto p: progList_)
      delete p;
}
// -----------------------------------------------------------------------------
Program* Interface::add(const string& asmFile, const vector<int64_t>& entry,
const unordered_map<int64_t,vector<int64_t>>& jumpTable) {
   auto p = new Program(asmFile, entry, jumpTable);
   if (!p->corrupted()) {
      progList_.push_back(p);
      return p;
   }
   else {
      LOG(1, "error: " << asmFile << " is corrupted!");
      delete p;
      return nullptr;
   }
}


void Interface::remove(Program* p) {
   for (auto it = progList_.begin(); it != progList_.end(); ++it)
      if (*it == p) {
         progList_.erase(it);
         break;
      }
   delete p;
}
// ----------------------------- Helper Methods --------------------------------
void Interface::format_asm(const string& asmFile, const string& outFile) {
   string s;
   size_t p1 = 0;
   size_t p2 = 0;
   size_t p3 = 0;

   fstream fin(asmFile, fstream::in);
   fstream fout(outFile, fstream::out);

   unordered_set<int64_t> label_set;

   while (getline(fin, s)) {
      // st(1) --> st1
      // %st(0)  -->  %st
      for (int i = 0; i < 8; ++i) {
         string t1 = string("st(").append(std::to_string(i)).append(")");
         string t2 = (i==0)?string("st"):string("st").append(std::to_string(i));
         p1 = s.find(t1);
         while (p1 != string::npos) {
            s.replace(p1, t1.length(), t2);
            p1 = s.find(t1);
         }
      }

      /* ignore duplicate code */
      int64_t label = Util::to_int(s.substr(1, s.find(":")-1));
      if (label_set.find(label) != label_set.end())
         continue;
      label_set.insert(label);

      /* replace label */
      p1 = s.find(".");
      while (p1 != string::npos) {
         s.insert(p1+1, "L");
         p1 = s.find(".", p1+1);
      }

      /* replace opcode */
      // drop one suffix character if the pattern match the start of opcode
      string drop_1[3] = {"cmov", "cvttss2si", "bswap"};
      for (int i = 0; i < 3; ++i) {
         p1 = s.find(drop_1[i]);
         if (p1 != string::npos) {
            p1 = s.find(" ", p1 + drop_1[i].length());
            s.erase(p1-1, 1);
            break;
         }
      }
      // replace (partially) one with another
      string s_old[12] = {"callq","jmpq","retq","lretl", "iretl","jae","shl",
                          "repz cmpsb (%rdi), (%rsi)",
                          "movsq (%rsi), (%rdi)",
                          "cmpsb (%rdi), (%rsi)",
                          "scasb (%rdi), %al",
                          "bnd"};
      string s_new[12] = {"call","jmp","ret","ret","ret","jnb","sal",
                          "repz cmpsb",
                          "movsq",
                          "cmpsb",
                          "scasb",
                          ""};

      for (int i = 0; i < 12; ++i) {
         p1 = s.find(s_old[i]);
         if (p1 != string::npos)
            s.replace(p1, s_old[i].length(), s_new[i]);
      }

      // remove parameters of opcode
      string rm_param[1] = {"ret"};
      for (int i = 0; i < 1; ++i) {
         p1 = s.find(rm_param[i]);
         if (p1 != string::npos)
            s.erase(p1+3, string::npos);
      }

      // replace "movd" with "movq" if all operands are 8 bytes
      string r8b[16] = {"%rax","%rbx","%rcx","%rdx","%rsi","%rdi","%rsp","%rbp",
                        "%r8","%r9","%r10","%r11","%r12","%r13","%r14","%r15"};
      p1 = s.find("movd ");
      while (p1 != string::npos) {
         p2 = s.find(";", p1);
         for (int i = 0; i < 16; ++i) {
            p3 = s.find(r8b[i], p1);
            while (p3 < p2) {
               char c = s.at(p3+1);
               if (c == ')' || c == ',' || c == ';') {
                  s.replace(p1, 4, string("movq"));
                  break;
               }
               p3 = s.find(r8b[i], p3+1);
            }
         }
         p1 = s.find("movd ", p2);
      }

      /* clean up */
      s.erase(s.find(":"), 1);
      s.erase(s.find_last_not_of(" ")+1, string::npos);
      fout << s << ";" << std::endl;
   }

   fin.close();
   fout.close();
}
// ---------------------------- Ocaml/C Interface ------------------------------
void Interface::ocaml_lift_asm(string& asmFile, string& rtlFile) {
   static const value* closure_f = nullptr;
   
   string s = asmFile;
   asmFile = "/tmp/sbr2/tmp_2";
   rtlFile = "/tmp/sbr2/tmp_3";
   std::remove(asmFile.c_str());
   std::remove(rtlFile.c_str());

   Interface::format_asm(s, asmFile);

   if (closure_f == nullptr)
      closure_f = caml_named_value("Lift callback");
   caml_callback2(*closure_f, Val_int(2), Val_int(3));
}


void Interface::ocaml_load_auto(const string& autoFile) {
   static const value * closure_f = nullptr;

   string s = "/tmp/sbr2/tmp_1";
   std::remove(s.c_str());
   symlink(autoFile.c_str(), s.c_str());

   if (closure_f == nullptr)
      closure_f = caml_named_value("Load callback");
   caml_callback(*closure_f, Val_int(1));
}