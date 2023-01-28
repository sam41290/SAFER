/*
   Copyright (C) 2018 - 2023 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "framework.h"
#include "program.h"
#include "rtl.h"
#include "parser.h"

#include <unistd.h>
#include <caml/mlvalues.h>
#include <caml/callback.h>

using namespace SBA;
/* -------------------------------------------------------------------------- */
static string asmFile = "";
static string objFile = "";
static string errFile = "";
static string errFile2 = "";
static string tmp_1 = "";
static string tmp_2 = "";
static string tmp_3 = "";
/* -------------------------------------------------------------------------- */
int Framework::session_id;
double Framework::t_syntax;
double Framework::t_lift;
double Framework::t_parse;
double Framework::t_cfg;
double Framework::t_analyse;
double Framework::t_track;
double Framework::t_jtable;
int64_t Framework::num_prog;
int64_t Framework::num_func;
int64_t Framework::num_insn;
/* -------------------------------------------------------------------------- */
static void refine(string& itc) {
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


static void format(const string& attFile, const string& itcFile,
const unordered_map<IMM,uint8_t>& insnSize) {
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
            auto p4 = s.find(" + 1");
            if (p4 != string::npos)
               s.erase(p4, string::npos);
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
      (void)!system(cmd.c_str());

      /* check if failed to assemble */
      vector<IMM> line_skip;
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
         (void)!system(cmd.c_str());
      }

      /* disassemble to intel syntax */
      cmd = string("objdump -d ").append(objFile).append(" -M intel")
           .append(" | cut -d\'\t\' -f3-")
           .append(" | grep \"^\\s*[a-z]\"")
           .append(" | cut -d\'#\' -f1 > ")
           .append(asmFile);
      if (!WIFEXITED(system(cmd.c_str())))
         LOG1("error: failed to translate AT&T syntax to Intel syntax");
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
            if (!s.empty()) refine(s);
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
   caml_callback2(*closure_f, Val_int(Framework::session_id), Val_int(1));
}


static void ocaml_lift(const string& attFile,
const unordered_map<IMM,uint8_t>& insnSize) {
   static const value* closure_f = nullptr;
   {
      TIME_START(start_t);
      format(attFile, tmp_2, insnSize);
      TIME_STOP(Framework::t_syntax, start_t);
   }
   {
      TIME_START(start_t);
      if (closure_f == nullptr)
         closure_f = caml_named_value("Lift callback");
      caml_callback3(*closure_f, Val_int(Framework::session_id),
                     Val_int(2), Val_int(3));
      TIME_STOP(Framework::t_lift, start_t);
   }
}


static vector<pair<IMM,RTL*>> load(const string& att_fpath,
const string& rtl_fpath) {
   string att, rtl;
   vector<pair<IMM,RTL*>> offset_rtl;

   fstream fatt(att_fpath, fstream::in);
   fstream frtl(rtl_fpath, fstream::in);
   TIME_START(start_t);
   while (getline(fatt, att) && getline(frtl, rtl)) {
      int offset = Util::to_int(att.substr(1, att.find(':')-1));
      RTL* object = Parser::process(rtl);
      offset_rtl.push_back(make_pair(offset,object));
      if (object == nullptr) {
         LOG1("error: failed to lift at " << offset << ":"
            << att.substr(att.find(':')+1, string::npos));
         #if ABORT_UNLIFTED_INSN == true
            for (auto [offset, rtl]: offset_rtl)
               delete rtl;
            offset_rtl.clear();
         #endif
      }
   }
   TIME_STOP(Framework::t_parse, start_t);
   fatt.close();
   frtl.close();

   Framework::num_prog += 1;
   Framework::num_insn = offset_rtl.size();
   return offset_rtl;
}
/* ------------------------------- Framework -------------------------------- */
void Framework::config(const string& autoFile) {
   /* filename */
   Framework::session_id = getpid();
   auto sessionStr = std::to_string(Framework::session_id);
   auto path = string("/tmp/sbr2/").append(sessionStr).append("/");
   std::filesystem::create_directories(path);
   tmp_1 = path + string("tmp_1");
   tmp_2 = path + string("tmp_2");
   tmp_3 = path + string("tmp_3");
   asmFile = path + string("proc.s");
   objFile = path + string("proc.o");
   errFile = path + string("err.log");
   errFile2 = path + string("err.log.tmp");

   /* lifter */
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

   /* stats */
   Framework::t_syntax = 0;
   Framework::t_lift = 0;
   Framework::t_parse = 0;
   Framework::t_cfg = 0;
   Framework::t_analyse = 0;
   Framework::t_track = 0;
   Framework::t_jtable = 0;
   Framework::num_prog = 0;
   Framework::num_func = 0;
   Framework::num_insn = 0;
   TIME_START(start_t);
   caml_startup(argv);
   ocaml_load(autoFile);
   TIME_STOP(Framework::t_lift, start_t);
}


void Framework::print_stats() {
   #if PERF_STATS == 1
      LOG2("_____________________________________________________ ");
      LOG2("--> num_prog:   " << Framework::num_prog  << " programs");
      LOG2("--> num_func:   " << Framework::num_func  << " functions");
      LOG2("--> num_insn:   " << Framework::num_insn  << " instructions");
      LOG2("--> format:     " << Framework::t_syntax  << " seconds");
      LOG2("--> lift:       " << Framework::t_lift    << " seconds");
      LOG2("--> parse:      " << Framework::t_parse   << " seconds");
      LOG2("--> cfg:        " << Framework::t_cfg     << " seconds");
      LOG2("--> analysis:   " << Framework::t_analyse << " seconds");
      LOG2("--> track:      " << Framework::t_track   << " seconds");
      LOG2("--> jump_table: " << Framework::t_jtable  << " seconds");
   #endif
}


Program* Framework::create_program(
const vector<pair<IMM,RTL*>>& offset_rtl,
const unordered_map<IMM,uint8_t>& insn_size,
const unordered_map<IMM,vector<IMM>>& jump_tables,
const vector<IMM>& func_entries) {
   if (offset_rtl.empty()) {
      LOG1("error: program is corrupted! (lifting issue)");
      return nullptr;
   }
   else {
      TIME_START(start_t);
      auto p = new Program(offset_rtl, insn_size, jump_tables, func_entries);
      TIME_STOP(Framework::t_cfg, start_t);
      if (!p->corrupted())
         return p;
      else {
         LOG1("error: program is corrupted! (graph issue)");
         delete p;
         return nullptr;
      }
   }
}


void Framework::update_program(Program* p,
const vector<pair<IMM,RTL*>>& offset_rtl,
const unordered_map<IMM,uint8_t>& insn_size,
const unordered_map<IMM,vector<IMM>>& jump_tables,
const vector<IMM>& func_entries) {
   TIME_START(start_t);
   p->update_graph(offset_rtl, insn_size, jump_tables, func_entries);
   TIME_STOP(Framework::t_cfg, start_t);
   if (p->corrupted())
      LOG1("error: program is corrupted! (graph issue)");
}


vector<pair<IMM,RTL*>> Framework::offset_rtl(const string& att_fpath,
const string& rtl_fpath) {
   return load(att_fpath, rtl_fpath);
}


vector<pair<IMM,RTL*>> Framework::offset_rtl(const string& att_fpath,
const unordered_map<IMM,uint8_t>& insn_size) {
   ocaml_lift(att_fpath, insn_size);
   return load(att_fpath, tmp_3);
}
