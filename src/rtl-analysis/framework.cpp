/*
   Copyright (C) 2018 - 2022 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "framework.h"
#include "program.h"
#include "rtl.h"
#include "parser.h"

#include <unistd.h>
#include <caml/mlvalues.h>
#include <caml/callback.h>
/* -------------------------------------------------------------------------- */
static string asmFile = "";
static string objFile = "";
static string errFile = "";
static string errFile2 = "";
static string tmp_1 = "";
static string tmp_2 = "";
static string tmp_3 = "";
/* -------------------------------------------------------------------------- */
int Framework::sessionId;
double Framework::time_format;
double Framework::time_lift;
double Framework::time_parse;
double Framework::time_cfg;
double Framework::time_analysis;
double Framework::time_track;
double Framework::time_jump_table;
int64_t Framework::total_file;
int64_t Framework::total_insn;
/* -------------------------------------------------------------------------- */
static void refine_itc(string& itc) {
   size_t p;

   /* (0) xor  eax,DWORD PTR [r13+r15*1+0x0] */
   /* --> xor  eax,DWORD PTR [r13+r15]       */
   static array<string,4> rm_pattern = {"*1]", "*1-", "*1+", "+0x0]"};
   for (auto const& x: rm_pattern)
      while (true) {
         p = itc.find(x);
         if (p != string::npos)
            itc.erase(p, x.length()-1);
         else
            break;
      }

   /* (1) (a) loop  c   */
   /*     --> loop  0xc */
   static array<string,3> op_add_0x = {"loop", "loope", "loopne"};
   for (auto const& x: op_add_0x)
      if (itc.find(x) != string::npos) {
         p = itc.find_last_of(" ");
         itc.insert(p+1, string("0x"));
      }
   /*     (b) rol rdx,1   */
   /*     --> rol rdx,0x1 */
   if (itc.substr(itc.length()-2,2).compare(",1") == 0)
      itc.insert(itc.length()-1, string("0x"));

   /* (2) cs nop WORD PTR [rax+rax] --> nop WORD PTR cs:[rax+rax] */
   if (itc.compare("cs nop WORD PTR [rax+rax]") == 0)
      itc = string("nop WORD PTR cs:[rax+rax]");
}


static void format_asm(const string& attFile, const string& itcFile,
const unordered_map<int64_t,int64_t>& insnSize) {
   std::filesystem::remove(asmFile);
   std::filesystem::remove(objFile);
   std::filesystem::remove(errFile);
   std::filesystem::remove(errFile2);

   string s;
   vector<string> label;
   static unordered_set<string> branch = {
         "jo","jno", "js", "jns", "je", "jne", "jz", "jnz", "jb", "jnb",
         "jae", "jnae", "jc", "jnc", "jbe", "jnbe", "ja", "jna", "jl", "jnl",
         "jge", "jnge", "jg", "jng", "jle", "jnle", "jp", "jnp", "jpe", "jpo",
         "jcxz", "jecxz", "jrcxz", "jmp", "jmpq", "call", "callq"
   };
   static array<string,6> rm_prefix = {"bnd", "lock", "notrack", "data16",
                                       "rex.W", "rex.X"};
   static array<string,6> to_nop = {"data16 addb", "addr32",
                                    "loopq", "loop", "loope", "loopne"};
   static array<string,3> to_hlt = {"int1", "int3", "icebp"};

   /* handle direct transfer instructions separately */
   {
      fstream fatt(attFile, fstream::in);
      fstream fasm(asmFile, fstream::out);
      while (getline(fatt, s)) {
         Framework::total_insn += 1;
         /* replace with nop */
         for (auto const& x: to_nop) {
            auto it = s.find(x);
            if (it != string::npos)
               s.replace(s.find(":")+2, string::npos, "nop");
         }
         /* replace with hlt */
         for (auto const& x: to_hlt) {
            auto it = s.find(x);
            if (it != string::npos)
               s.replace(s.find(":")+2, string::npos, "hlt");
         }
         /* remove prefixes */
         for (auto const& x: rm_prefix) {
            auto it = s.find(x);
            if (it != string::npos)
               s.erase(it, x.length()+1);
         }
         auto p1 = s.find(":");
         auto p2 = p1 + 2;
         auto p3 = s.find_first_of("*%.(", p2);
         auto offset = s.substr(1, p1-1);
         auto opcode = s.substr(p2, p3-p2-1);
         /* .1234: callq .3485 --> .L1234 call 3485 */
         if (branch.contains(opcode) && s[p3] == '.') {
            fasm << s << "\n";
            s.erase(p3, 1);
            if (opcode.compare("callq") == 0)
               s.replace(p2, 5, string("call"));
            s.erase(p1, 1);
            label.push_back(string(".L").append(s.substr(1,string::npos)));
         }
         /* .1234: addb %al, (%rax) --> .L1234 add BYTE PTR [rax],al */
         else if (opcode.compare("addb") == 0) {
            auto p4 = s.find("%al,");
            if (p4 != string::npos) {
               auto p5 = s.find("(%rax)",p4);
               if (p5 != string::npos) {
                  fasm << "." << offset << ": nop\n";
                  label.push_back(string(".L").append(offset)
                                 .append(" add BYTE PTR [rax],al"));
               }
               else {
                  fasm << s << "\n";
                  label.push_back(string(".L").append(offset));
               }
            }
            else {
               fasm << s << "\n";
               label.push_back(string(".L").append(offset));
            }
         }
         /* .10: leaq .40(%rip), %r8 --> .L10 lea r8, DWORD PTR[rip+25] */
         /* .10: jmpq *.40(%rip)     --> .L10 jmp QWORD PTR [rip+25]    */
         /* .10: callq *.40(%rip)    --> .L10 call QWORD PTR [rip+25]   */
         else if (s.find("(%rip") != string::npos) {
            auto ioffset = Util::to_int(offset);
            auto pc = ioffset + insnSize.at(ioffset);
            auto p5 = s.find("(%rip", p3);
            auto p4 = s.rfind('.',p5);
            auto target = s.substr(p4+1, p5-p4-1);
            if (target.length() < 15) {
               auto itarget = Util::to_int(target);
               auto repl = std::to_string(itarget - pc);
               s.replace(p4, p5-p4, repl);
               fasm << s << "\n";
            }
            else
               fasm << "." << offset << ": nop\n";
            label.push_back(string(".L").append(offset));
         }
         /* .1234: movq %eax, %ebx --> .L1234 */
         else {
            fasm << s << "\n";
            label.push_back(string(".L").append(offset));
         }
      }
      fatt.close();
      fasm.close();
   }

   /* convert AT&T syntax to Intel syntax */
   {
      /* assemble to object file */
      auto cmd = string("as ").append(asmFile).append(" -o ").append(objFile)
                .append(" 2> ").append(errFile2)
                .append(" ; grep \": Error:\" ").append(errFile2)
                .append(" > ").append(errFile);
      system(cmd.c_str());

      /* check if failed to assemble */
      vector<int64_t> line_skip;
      fstream ferr(errFile, fstream::in);
      while (getline(ferr, s)) {
         auto p1 = s.find("proc.s")+7;
         line_skip.push_back(Util::to_int(s.substr(p1, s.find(":",p1)-p1)));
      }

      /* replace errornous lines with nop, assemble again */
      if (!line_skip.empty()) {
         auto tmpFile = asmFile + ".tmp";
         std::filesystem::copy(asmFile, tmpFile,
                          std::filesystem::copy_options::overwrite_existing);

         auto it = line_skip.begin();
         fstream ftmp(tmpFile, fstream::in);
         fstream fasm(asmFile, fstream::out);
         for (int i = 1; i <= (int)(label.size()); ++i) {
            getline(ftmp, s);
            if (it != line_skip.end() && i == *it) {
               ++it;
               auto p1 = s.find(" ");
               s.replace(p1+1, string::npos, "nop");
            }
            fasm << s << "\n";
         }
         ftmp.close();
         fasm.close();

         cmd = string("as ").append(asmFile).append(" -o ").append(objFile);
         system(cmd.c_str());
      }

      /* disassemble to intel syntax */
      cmd = string("objdump -d ").append(objFile).append(" -M intel")
           .append(" | cut -d\'\t\' -f3-")
           .append(" | grep \"^\\s*[a-z]\"")
           .append(" | cut -d\'#\' -f1 > ")
           .append(asmFile);
      if (!WIFEXITED(system(cmd.c_str())))
         LOG(1, "error: failed to translate AT&T syntax to Intel syntax");
   }

   /* generate itcFile */
   {
      fstream fasm(asmFile, fstream::in);
      fstream fitc(itcFile, fstream::out | fstream::trunc);
      for (auto const& l: label) {
         getline(fasm, s);
         /* special insn: label already store complete intel syntax */
         if (l.find(' ') != string::npos)
            fitc << l << "\n";
         /* normal insn: label contains only label */
         else {
            if (!s.empty()) refine_itc(s);
            fitc << l << " " << s << "\n";
         }
      }
      fasm.close();
      fitc.close();
   }
}


static void ocaml_load(const string& autoFile) {
   static const value * closure_f = nullptr;
   std::remove(tmp_1.c_str());
   std::filesystem::create_symlink(autoFile, tmp_1);
   if (closure_f == nullptr)
      closure_f = caml_named_value("Load callback");
   caml_callback2(*closure_f, Val_int(Framework::sessionId), Val_int(1));
}


static void ocaml_lift(const string& attFile,
const unordered_map<int64_t,int64_t>& insnSize) {
   static const value* closure_f = nullptr;
   time_start(start1);
   format_asm(attFile, tmp_2, insnSize);
   time_stop(Framework::time_format,start1);
   time_start(start2);
   if (closure_f == nullptr)
      closure_f = caml_named_value("Lift callback");
   caml_callback3(*closure_f, Val_int(Framework::sessionId),
                  Val_int(2), Val_int(3));
   time_stop(Framework::time_lift,start2);
}


static vector<pair<int64_t,RTL*>> lift(const string& attFile,
const unordered_map<int64_t,int64_t>& insnSize, bool& corrupted) {
   string att, rtl;
   vector<pair<int64_t,RTL*>> pairList;

   Framework::total_file += 1;
   ocaml_lift(attFile, insnSize);

   time_start(start1);
   fstream fatt(attFile, fstream::in);
   fstream frtl(tmp_3, fstream::in);
   while (getline(fatt, att) && getline(frtl, rtl)) {
      int offset = Util::to_int(att.substr(1, att.find(':')-1));
      RTL* object = Parser::process(rtl);
      pairList.push_back(make_pair(offset,object));

      /* if failed to lift, report error */
      if (object == nullptr) {
         LOG(1, "error: failed to lift at " << offset << ":"
            << att.substr(att.find(':')+1, string::npos));
         corrupted |= flag_unlifted_insn;
         if (corrupted)
            break;
      }
   }
   time_stop(Framework::time_parse,start1);

   fatt.close();
   frtl.close();
   corrupted |= pairList.empty();
   return pairList;
}
/* ------------------------------- Framework -------------------------------- */
void Framework::setup(const string& autoFile) {
   /* setup lifter */
   char** argv = (char**)malloc(5*sizeof(char*));
   char t0[] = "interface";
   char t1[] = "-c";
   char t2[] = "on";
   char t3[] = "-p";
   argv[0] = t0;
   argv[1] = t1;
   argv[2] = t2;
   argv[3] = t3;
   argv[4] = nullptr;

   /* setup session, filename */
   Framework::sessionId = getpid();
   auto sessionStr = std::to_string(Framework::sessionId);
   auto path = string("/tmp/sbr2/").append(sessionStr).append("/");
   std::filesystem::create_directories(path);
   tmp_1 = path + string("tmp_1");
   tmp_2 = path + string("tmp_2");;
   tmp_3 = path + string("tmp_3");;
   asmFile = path + string("proc.s");
   objFile = path + string("proc.o");
   errFile = path + string("err.log");
   errFile2 = path + string("err.log.tmp");

   /* setup stats */
   Framework::reset_stats();
   time_start(start1);
   caml_main(argv);
   ocaml_load(autoFile);
   time_stop(Framework::time_lift, start1);
}


void Framework::reset_stats() {
   Framework::time_format = 0;
   Framework::time_lift = 0;
   Framework::time_parse = 0;
   Framework::time_cfg = 0;
   Framework::time_analysis = 0;
   Framework::time_track = 0;
   Framework::time_jump_table = 0;
   Framework::total_file = 0;
   Framework::total_insn = 0;
}


Program* Framework::create_prog(const string& attFile,
const unordered_map<int64_t,int64_t>& insnSize,
const unordered_map<int64_t,vector<int64_t>>& jumpTable,
const vector<int64_t>& entry) {
   auto corrupted = false;
   auto pairList = lift(attFile, insnSize, corrupted);

   /* lift error or empty program */
   if (corrupted) {
      LOG(1, "error: " << attFile << " is corrupted! (lifting issue)");
      for (auto [offset, rtl]: pairList)
         delete rtl;
      return nullptr;
   }
   /* create program */
   else {
      time_start(start1);
      auto p = new Program(pairList, insnSize, jumpTable, entry, corrupted);
      time_stop(Framework::time_cfg, start1);

      /* create successfully */
      if (!corrupted)
         return p;
      /* corrupted program */
      else {
         LOG(1, "error: " << attFile << " is corrupted! (graph issue)");
         delete p;
         return nullptr;
      }
   }
}