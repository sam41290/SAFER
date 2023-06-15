/*
   Copyright (C) 2018 - 2024 by Huan Nguyen in Secure Systems Lab,
   Stony Brook University, Stony Brook, NY 11794.
*/

#include "framework.h"
#include "program.h"
#include "rtl.h"
#include "parser.h"
#include <unistd.h>
#if ENABLE_LIFT_ENGINE
   #include <caml/mlvalues.h>
   #include <caml/callback.h>
#endif

using namespace SBA;
/* -------------------------------------------------------------------------- */
static string tmp_1 = "";
static string tmp_2 = "";
static string tmp_3 = "";
static string tmp_4 = "";
/* -------------------------------------------------------------------------- */
uint8_t Framework::thread_id = 0;
int Framework::session_id;
double Framework::t_syntax;
double Framework::t_lift;
double Framework::t_parse;
double Framework::t_cfg;
double Framework::t_analyse;
double Framework::t_track;
double Framework::t_target;
int64_t Framework::num_prog;
int64_t Framework::num_func;
int64_t Framework::num_insn;
/* -------------------------------------------------------------------------- */
#if ENABLE_LIFT_ENGINE
   static void ocaml_load(const string& auto_path) {
      static const value * closure_f = nullptr;
      std::remove(tmp_1.c_str());
      std::filesystem::create_symlink(auto_path, tmp_1);
      if (closure_f == nullptr)
         closure_f = caml_named_value("Load callback");
      caml_callback2(*closure_f, Val_int((int)Framework::thread_id),
                                 Val_int(Framework::session_id));
   }
   
   
   static void ocaml_lift() {
      static const value* closure_f = nullptr;
      TIME_START(start_t);
      if (closure_f == nullptr)
         closure_f = caml_named_value("Lift callback");
      caml_callback2(*closure_f, Val_int((int)Framework::thread_id),
                                 Val_int(Framework::session_id));
      TIME_STOP(Framework::t_lift, start_t);
   }
#endif


static vector<tuple<IMM,RTL*,vector<uint8_t>>> load(const string& itc_path,
const string& rtl_path, const string& raw_path, const unordered_set<IMM>&
noreturn_calls = {}) {
   TIME_START(start_t);
   string itc, rtl, raw;
   vector<tuple<IMM,RTL*,vector<uint8_t>>> res;
   string one_byte;
   vector<uint8_t> raw_bytes;

   fstream f_itc(itc_path, fstream::in);
   fstream f_rtl(rtl_path, fstream::in);
   fstream f_raw(raw_path, fstream::in);

   while (getline(f_itc, itc) && getline(f_rtl,rtl) && getline(f_raw,raw)) {
      RTL* object = nullptr;
      IMM offset = Util::to_int(itc.substr(2, itc.find(" ")-2));
      auto it = noreturn_calls.find(offset);
      if (it == noreturn_calls.end())
         object = Parser::process(rtl);
      else {
         object = new Exit(Exit::EXIT_TYPE::HALT);
         raw = ARCH::raw_bytes_hlt;
         LOG2("fix: instruction " << offset << " is a non-returning call");
      }
      raw_bytes.clear();
      for (IMM i = 0; i < (IMM)(raw.length()); i += 3)
         raw_bytes.push_back((uint8_t)Util::to_int("0x" + raw.substr(i,2)));

      res.push_back({offset, object, raw_bytes});
      if (object == nullptr) {
         LOG2("error: failed to lift at " << offset << ": "
            << itc.substr(itc.find(" ")+1, string::npos));
         #if ABORT_UNLIFTED_INSN == true
            for (auto [offset, object, raw_bytes]: res)
               delete object;
            break;
         #endif
      }
   }
   f_itc.close();
   f_rtl.close();

   Framework::num_prog += 1;
   Framework::num_insn = res.size();
   TIME_STOP(Framework::t_parse, start_t);
   return res;
}
/* ------------------------------- Framework -------------------------------- */
void Framework::config(const string& auto_path, uint8_t thread_id) {
   /* filename */
   Framework::session_id = getpid();
   Framework::thread_id = thread_id;
   auto session_dir = WORKING_DIR + std::to_string(Framework::thread_id)
                    + "/lift/" + std::to_string(Framework::session_id) + "/";
   std::filesystem::create_directories(session_dir);
   tmp_1 = session_dir + string("tmp_1");
   tmp_2 = session_dir + string("tmp_2");
   tmp_3 = session_dir + string("tmp_3");
   tmp_4 = session_dir + string("tmp_4");

   /* stats */
   Framework::t_syntax = 0;
   Framework::t_lift = 0;
   Framework::t_parse = 0;
   Framework::t_cfg = 0;
   Framework::t_analyse = 0;
   Framework::t_track = 0;
   Framework::t_target = 0;
   Framework::num_prog = 0;
   Framework::num_func = 0;
   Framework::num_insn = 0;
   
   /* lifter */
   #if ENABLE_LIFT_ENGINE
      TIME_START(start_t);
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
      caml_startup(argv);
      ocaml_load(auto_path);
      TIME_STOP(Framework::t_lift, start_t);
   #endif
}


void Framework::print_stats() {
   #if PLEVEL >= 1
      LOG1("_____________________________________________________ ");
      LOG1("--> num_prog:   " << Framework::num_prog  << " programs");
      LOG1("--> num_func:   " << Framework::num_func  << " functions");
      LOG1("--> num_insn:   " << Framework::num_insn  << " instructions");
      LOG1("--> format:     " << Framework::t_syntax  << " seconds");
      LOG1("--> lift:       " << Framework::t_lift    << " seconds");
      LOG1("--> parse:      " << Framework::t_parse   << " seconds");
      LOG1("--> cfg:        " << Framework::t_cfg     << " seconds");
      LOG1("--> analysis:   " << Framework::t_analyse << " seconds");
      LOG1("--> track:      " << Framework::t_track   << " seconds");
      LOG1("--> target:     " << Framework::t_target  << " seconds");
   #endif
}


Program* Framework::create_program(const string& bin_path, const vector<IMM>&
fptr_list, const unordered_map<IMM,unordered_set<IMM>>& icfs, IMM session_id) {
   if (session_id != -1) {
      auto dir = WORKING_DIR + std::to_string(Framework::thread_id) + "/lift/"
                             + std::to_string(Framework::session_id) + "/";
      tmp_2 = dir + "tmp_2";
      tmp_3 = dir + "tmp_3";
      tmp_4 = dir + "tmp_4";
      auto noreturn_calls = BINARY::noreturn_calls(bin_path);
      auto vec = load(tmp_2, tmp_3, tmp_4, noreturn_calls);
      return Framework::create_program(bin_path, vec, fptr_list, icfs);
   }
   #if ENABLE_LIFT_ENGINE
      else {
         Framework::disassemble(bin_path);
         ocaml_lift();
         auto noreturn_calls = BINARY::noreturn_calls(bin_path);
         auto vec = load(tmp_2, tmp_3, tmp_4, noreturn_calls);
         return Framework::create_program(bin_path, vec, fptr_list, icfs);
      }
   #else
      else
         return nullptr;
   #endif
}
/* -------------------------------------------------------------------------- */
Program* Framework::create_program(const string& bin_path,
const vector<tuple<IMM,RTL*,vector<uint8_t>>>& offset_rtl_raw,
const vector<IMM>& fptr_list, const unordered_map<IMM,unordered_set<IMM>>& icfs) {
   if (offset_rtl_raw.empty())
      return nullptr;
   else {
      auto p = new Program(offset_rtl_raw, fptr_list, icfs, bin_path);
      if (!p->faulty)
         return p;
      else {
         delete p;
         return nullptr;
      }
   }
}
