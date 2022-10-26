#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <cassert>
using namespace std;

string label;
/* -------------------------------------------------------------------------- */
void detect_bracket(const string& s, size_t curr, const string& open_str,
char open, char close, int cnt_target, size_t& start, size_t& end) {
   size_t p1, p2, p3;

   p1 = s.find(open_str, curr);

   if (cnt_target == -1 && s.find(close, curr) < p1) {
      start = curr;
      end = s.find(close, curr)-1;
   }
   else if (p1 != string::npos) {
      int cnt = 1;
      p3 = p1;
      while (cnt != cnt_target) {
         p2 = s.find(open, p3+1);
         p3 = s.find(close, p3+1);
         cnt = (p2 < p3) ? (cnt+1) : (cnt-1);
         p3 = (p2 < p3) ? p2 : p3;
      }
      start = p1;
      end = p3 + cnt_target;
      p1 = s.find(open_str, p1);
   }
   else {
      start = -1;
      end = -1;
   }
}
/* -------------------------------------------------------------------------- */
void refine_asm(string& s) {
   size_t p1 = 0;
   size_t p2 = 0;

   // call func@plt  -->  call func
   p1 = s.find("@");
   while (p1 != string::npos) {
      p2 = s.find_first_of("(;, \t", p1+1);
      s.erase(p1, p2-p1);
      p1 = s.find("@");
   }

   // %st(1)  -->  %st1
   // %st(0)  -->  %st
   for (int i = 0; i < 8; ++i) {
      string tmp1 = string("st(").append(to_string(i)).append(")");
      string tmp2 = (i == 0) ? string("st") : string("st").append(to_string(i));
      p1 = s.find(tmp1);
      while (p1 != string::npos) {
         s.replace(p1, tmp1.length(), tmp2);
         p1 = s.find(tmp1);
      }
   }

   // scan for label, assume that no more than one label,
   // otherwise, don't know how to match it with label_ref
   p1 = s.find(".L");
   while (p1 != string::npos) {
      p2 = s.find_first_of("(;, \t", p1);
      string tmp = s.substr(p1, p2-p1);
      for (int i = 2; i < tmp.length(); ++i)
         if (tmp.at(i) < '0' || tmp.at(i) > '9') {
            tmp = string("");
            break;
         }
      if (!tmp.empty()) {
         label = tmp;
         break;
      }
      p1 = s.find(".L", p1+1);
   }

   // remove tab at the end, append semi-colon
   if (s.at(s.length()-1) == '\t')
      s.erase(s.length()-1, 1);
   s.append(";");
}
/* -------------------------------------------------------------------------- */
void refine_rtl(string& s) {
   int cnt;
   size_t p1 = 0;
   size_t p2 = 0;
   size_t p3 = 0;
   size_t start = 0;
   size_t end = 0;

   // extract insn
   detect_bracket(s, 1, "(", '(', ')', 0, start, end);
   s = s.substr(start, end-start+1);

   // remove cancel-character "\"
   string special[7] = {"\\\"", "\\(", "\\)", "\\[", "\\]", "\\<", "\\>"};
   for (int i = 0; i < 7; ++i)
      while (true) {
         p1 = s.find(special[i]);
         if (p1 == string::npos)
            break;
         s.erase(p1, 2);
      }

   // remove (use ...)
   while (true) {
      detect_bracket(s, 0, "(use", '(', ')', 0, start, end);
      if (start == -1 && end == -1)
         break;
      s.erase(start, end-start+1);
   }

   // (reg/f:DI ...)  -->  (reg:DI ...)
   // (mem/f:DI ...)  -->  (mem:DI ...)
   // (symbol_ref/f:DI ...)  -->  (mem:DI ...)
   string slash[3] = {"reg/", "mem/", "symbol_ref/"};
   for (int i = 0; i < 3; ++i) {
      p1 = s.find(slash[i]);
      while (p1 != string::npos) {
         s.erase(p1+slash[i].length()-1, 2);
         p1 = s.find(slash[i], p1);
      }
   }

   // (reg:DI 0 ax)  -->  (reg:DI ax)
   p1 = s.find("(reg:");
   while (p1 != string::npos) {
      p2 = s.find(" ", p1);
      p3 = s.find_first_of("abcdefghijklmnopqrstuvwxyz", p2);
      s.erase(p2, p3-p2-1);
      p1 = s.find("(reg:", p1+1);
   }

   // remove mode
   string no_mode[3] = {"(parallel:", "(symbol_ref:", "(label_ref:"};
   for (int i = 0; i < 3; ++i) {
      p1 = s.find(no_mode[i]);
      int len = no_mode[i].length();
      while (p1 != string::npos) {
         p2 = s.find(" ", p1);
         s.erase(p1+len-1, p2-p1-len+1);
         p1 = s.find(no_mode[i]);
      }
   }

   // (symbol_ref ("func"))  -->  (symbol_ref func)
   // (symbol_ref ("*.L1"))  -->  (symbol_ref .L1)
   p1 = s.find("(symbol_ref");
   while (p1 != string::npos) {
      p2 = s.find("(\"", p1);
      s.erase(p2, 2);
      if (s.at(p2) == '*')
         s.erase(p2, 1);
      p2 = s.find("\")", p1);
      s.erase(p2, 2);
      p1 = s.find("(symbol_ref", p1+1);
   }

   // (reg:DI ax [orig:157 MEM])  -->  (reg:DI ax)
   // (symbol_ref ... [flags 0x3] <function_decl>)  -->  (symbol_ref ...)
   // (const_int 3485 [12])  -->  (const_int 3485)
   string ext[4] = {"(reg:", "(symbol_ref", "(const_int", "(const_double"};
   for (int i = 0; i < 4; ++i) {
      p1 = s.find(ext[i]);
      while (p1 != string::npos) {
         p1 = s.find(" ", p1);
         if (s.find(" ", p1+1) < s.find(")", p1+1)) {
            p1 = s.find(" ", p1+1);
            // (reg:DI ax [orig:157 MEM])  -->  (reg:DI ax)
            //           ^
            //           |
            //           p1
            detect_bracket(s, p1, "(", '(', ')', -1, start, end);
            s.erase(p1, end-p1+1);
         }
         p1 = s.find(ext[i], p1);
      }
   }

   // (mem:SI (...) [2 exit_failure+0 S4 A32])  -->  (mem:SI (...))
   p1 = s.find("(mem:");
   while (p1 != string::npos) {
      detect_bracket(s, p1+1, "(", '(', ')', 0, start, end);
      p1 = end + 1;
      // (mem:SI (...) [2 MEM[(struct [1] *)&args].fp_offset+0 S4 A32])
      //              ^
      //              |
      //              p1
      detect_bracket(s, p1, "(", '(', ')', -1, start, end);
      s.erase(p1, end-p1+1);
      p1 = s.find("(mem:", p1);
   }

   // st(1)  -->  st1
   // st(0)  -->  st
   for (int i = 0; i < 8; ++i) {
      string tmp1 = string("st(").append(to_string(i)).append(")");
      string tmp2 = (i == 0) ? string("st") : string("st").append(to_string(i));
      p1 = s.find(tmp1);
      while (p1 != string::npos) {
         s.replace(p1, tmp1.length(), tmp2);
         p1 = s.find(tmp1);
      }
   }

   // (label_ref 3485)  -->  (label_ref .L1)
   p1 = s.find("(label_ref");
   while (p1 != string::npos) {
      p2 = s.find(" ", p1);
      p3 = s.find(")", p1);
      s.replace(p2+1, p3-p2-1, label);
      p1 = s.find("(label_ref", p1+1);
   }

   // remove redundant spaces
   string spc[6] = {"  ", "  ", " )", " ]", "( [", "[ ("};
   size_t off[6] = {   0,    0,    0,    0,     1,     1};
   for (int i = 0; i < 6; ++i) {
      p1 = s.find(spc[i]);
      while (p1 != string::npos) {
         s.erase(p1+off[i], 1);
         p1 = s.find(spc[i]);
      }
   }

   // rtl bracket validation
   string brk_open[2]  = {"(", "["};
   string brk_close[2] = {")", "]"};
   for (int i = 0; i < 2; ++i) {
      cnt = 0;
      p1 = s.find(brk_open[i]);
      if (p1 != string::npos) {
         cnt = 1;
         while (true) {
            p2 = s.find(brk_open[i], p1+1);
            p3 = s.find(brk_close[i], p1+1);
            if (p2 == string::npos && p3 == string::npos)
               break;
            cnt = (p2 < p3) ? (cnt+1) : (cnt-1);
            p1 = (p2 < p3) ? p2 : p3;
         }
      }
      assert(cnt == 0);
   }
}
/* -------------------------------------------------------------------------- */
bool preprocess(string& asm_s, string& rtl_s) {
   size_t p1 = 0;
   size_t p2 = 0;
   string s;

   /* preprocessing rule 1                                                 */
   /* filter out instructions that never appear in the disassembled output */
   // (1.1) ignore empty asm
   if (asm_s.compare("") == 0)
      return false;

   // (1.2) remove movsbl -28+yypgoto(%rip), %edi;
   if (asm_s.find("+") != string::npos)
      return false;
   p1 = asm_s.find("-");
   while (p1 != string::npos) {
      char c = asm_s.at(p1-1);
      if (c != '\t' && c != ' ' && c != '(' && c != ',')
         return false;
      p1 = asm_s.find("-", p1+1);
   }

   // (1.3) remove movl $.L3485, %r8d; 
   p1 = asm_s.find("$");
   while (p1 != string::npos) {
      char c = asm_s.at(p1+1);
      if (c == '.')
         return false;
      p1 = asm_s.find("$", p1+1);
   }

   /* preprocessing rule 2                                                 */
   /* remove pairs in training where the compiler has more information     */
   /* than what is available at assembly                                   */
   // (2.1) function call returns a value
   if (asm_s.find("\tcall") != string::npos && rtl_s.find("(set (reg:") == 0)
      return false;

   /* preprocessing rule 3                                                 */
   /* replacement to improve consistency                                   */
   // (3.1) "symbol_ref" --> "label_ref"
   p1 = rtl_s.find("(symbol_ref");
   while (p1 != string::npos) {
      rtl_s.replace(p1, 11, string("(label_ref"));
      p1 = rtl_s.find("(symbol_ref");
   }

   // (3.1.1) use same label everywhere
   p1 = rtl_s.find("(label_ref ");
   while (p1 != string::npos) {
      p2 = rtl_s.find(")", p1);
      s = rtl_s.substr(p1+11, p2-p1-11);
      // replace rtl_s
      rtl_s.replace(p1, p2-p1+1, "(label_ref .L3485)");
      // replace asm_s starting from first operand
      p2 = asm_s.find_first_not_of("\t ");
      p2 = asm_s.find("\t", p2+1);
      p2 = asm_s.find_first_not_of("\t ");
      p2 = asm_s.find(s, p2);
      while (p2 != string::npos) {
         asm_s.replace(p2, s.length(), ".L3485");
         p2 = asm_s.find(s, p2+1);
      }

      p1 = rtl_s.find("(label_ref", p1+1);
   }

   // (3.2) leaq  abc(%rip), %rdi;
   //       (set (reg:DI di) (plus:DI (reg:DI ip) (const_int abc)))
   //   --> leaq  3485(%rip), %rdi;
   //   --> (set (reg:DI di) (plus:DI (reg:DI ip) (const_int 3485)))
   p1 = rtl_s.find("(const_int");
   while (p1 != string::npos) {
      // extract "abc"
      p1 = rtl_s.find(" ", p1);
      p2 = rtl_s.find(")", p1);
      s = rtl_s.substr(p1+1, p2-p1-1);
      if (s.find_first_not_of("-0123456789") != string::npos) {
         // replace "abc" with "3485" in asm_s
         p2 = asm_s.find(s);
         if (p2 != string::npos)
            asm_s.replace(p2, s.length(), "3485");
         // replace "(const int abc)" with "(const_int 3485)" in rtl_s
         s = string("(const_int ").append(s).append(")");
         p2 = rtl_s.find(s);
         if (p2 != string::npos)
            rtl_s.replace(p2, s.length(), "(const_int 3485)");
      }
      p1 = rtl_s.find("(const_int", p1+1);
   }

   // (3.3) convert label_ref to const_int if not .L3485 or .L3485(%rip)
   // movb  $1, .L3485(%r12);
   // (set (mem:QI (plus:DI (reg:DI r12) (label_ref .L3485))) (const_int 1))
   // --> movb  $1, 3485(%r12);
   // --> (set (mem:QI (plus:DI (reg:DI r12) (const_int 3485))) (const_int 1))
   p1 = asm_s.find(".L3485(");
   while (p1 != string::npos) {
      p2 = asm_s.find(")", p1);
      s = asm_s.substr(p1+7, p2-p1-7);
      if (s.compare("%rip") != 0) {
         asm_s.replace(p1, 6, string("3485"));
         p2 = rtl_s.find("(label_ref .L3485)");
         while (p2 != string::npos) {
            rtl_s.replace(p2, 18, string("(const_int 3485)"));
            p2 = rtl_s.find("(label_ref .L3485)", p2);
         }
      }
      p1 = asm_s.find(".L3485(", p1+1);
   }

   // (3.4) remove suffix
   string no_suff[1] = {"cvttsd2si"};
   for (int i = 0; i < 1; ++i) {
      p1 = asm_s.find(no_suff[i]);
      while (p1 != string::npos) {
         p2 = asm_s.find(" ", p1);
         asm_s.replace(p1, p2-p1, no_suff[i]);
         p1 = asm_s.find(no_suff[i], p1+1);
      }
   }

   /* preprocessing rule 4                                                 */
   /* remove pairs that cause confusion                                    */
   // (4.1) remove pairs .L3485(%rip) with unspec
   if (asm_s.find(".L3485(%rip)") != string::npos &&
   rtl_s.find("unspec") != string::npos)
      return false;

   // (4.2) remove some of the unspec
   string unspec[5] = {"UNSPEC_STA", "UNSPEC_DTPOFF", "UNSPEC_NTPOFF",
                       "UNSPEC_TLS_LD_BASE", "UNSPECV_NOP_ENDBR"};
   for (int i = 0; i < 5; ++i)
      if (rtl_s.find(unspec[i]) != string::npos)
         return false;

   // (4.3) remove movq/movl/movd/movb with const_double or const_vector
   string mov[4] = {"movq", "movl", "movd", "movb"};
   string cst[2] = {"const_double", "const_vector"};
   for (int i = 0; i < 4; ++i)
      if (asm_s.find(mov[i]) != string::npos)
         for (int j = 0; j < 2; ++j)
            if (rtl_s.find(cst[j]) != string::npos)
               return false;

   // (4.4) remove nop instructions
   if (asm_s.find("nop")!=string::npos || asm_s.find("endbr64")!=string::npos)
      return false;

   return true;
}
/* -------------------------------------------------------------------------- */
int main(int argc, char **argv) {
   string out_fname = string(argv[argc-1]);
   fstream f_out(out_fname, fstream::out | fstream::trunc);

   for (int idx = 1; idx < argc-1; ++idx) {
      fstream f_in(string(argv[idx]), fstream::in);
      int64_t line = 0;
      int64_t progress = 0;
      string s = string("");
      string asm_s = string("");
      string rtl_s = string("");
      bool reading_asm = true;

      // get number of lines
      FILE *f_tmp = NULL;
      string cmd = string("wc -l ").append(string(argv[idx]));
      f_tmp = popen(cmd.c_str(), "r");
      fscanf(f_tmp, "%ld", &line);
      pclose(f_tmp);

      for (int64_t i = 0; i < line; ++i) {
         getline(f_in, s);

         // read asm
         if (reading_asm) {
            // skip label at the begin of asm (rare!)
            if (s.at(s.find_first_not_of("\t ")) == '.') {
               getline(f_in, s);
               ++i;
            }
            if (s.at(0) == '\t') {
               refine_asm(s);
               asm_s.append(s);
            }
            else {
               reading_asm = false;
               rtl_s = s;
            }
         }
         // read rtl
         else if (s.compare("------------") != 0)
            rtl_s.append(s);
         // done
         else {
            refine_rtl(rtl_s);
            if (preprocess(asm_s, rtl_s)) {
               f_out << asm_s << endl;
               f_out << rtl_s << endl;
            }
            asm_s = string("");
            rtl_s = string("");
            reading_asm = true;
         }

         // update progress
         int64_t curr_progress = (int64_t)(100*i/line);
         if (curr_progress != progress && curr_progress % 3 == 0) {
            cout << "\rProcessing " << string(argv[idx]) << ": "
                 << 100*(i+1)/line << "% ...";
            cout.flush();
            progress = curr_progress;
         }
      }

      f_in.close();
      cout << "\rProcessing " << string(argv[idx]) << ": 100%     " << endl;
   }

   f_out.close();

   // sorting and eliminating duplicates
   cout << "\rSorting and eliminating duplicates ...";
   string cmd=string("cat ").append(string(argv[argc-1]))
      .append(" | paste -d\"#\" - - | sort -u -t\'#\' -k1,1 | sed \'/+/d\' >")
      .append("/tmp/tmp.txt");
   system(cmd.c_str());
   cmd=string("tr \'#\' \'\n\' < /tmp/tmp.txt >").append(string(argv[argc-1]));
   system(cmd.c_str());

   // finish
   cout << "\rGenerated " << out_fname << "!          " << endl;
   return 0;
}