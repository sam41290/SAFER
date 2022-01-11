/*
    Copyright (C) 2018 - 2019 by Huan Nguyen in Secure Systems
    Lab, Stony Brook University, Stony Brook, NY 11794.
*/

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include "gcc-plugin.h"
#include "insn-config.h"
#include "context.h"
#include "tree-pass.h"
#include "rtl.h"
#include "recog.h"
#include "output.h"
#include "toplev.h"
using namespace std;

int plugin_is_GPL_compatible;
static FILE* rtlFile;
extern FILE* asm_out_file;
static long prevPos, currPos;
static bool is_initialized = false;

const pass_data dump_pass_data = {
  RTL_PASS,         /* type */
  "my_dump_pass",   /* name */
  OPTGROUP_NONE,    /* optinfo_flags */
  TV_NONE,          /* tv_id */
  0,                /* properties_required */
  0,                /* properties_provided */
  0,                /* properties_destroyed */
  0,                /* todo_flags_start */
  0                 /* todo_flags_finish */
};

/* ------------------------------------------------------ */
/*                  Plugin Initialization                 */
/* ------------------------------------------------------ */
void gcc_init() {
  int n;
  string s, OUTPUT_DIR;

  // gcc plugin initialization
  init_adjust_machine_modes();
  ggc_protect_identifiers = true;
  init_emit();
  init_final(main_input_filename);
  init_recog();
  // -----
  reload_completed = 1;
  is_initialized = true;
  prevPos = 0;

  // get OUTPUT_DIR, add '/' to the end if necessary
  OUTPUT_DIR = string(getenv("PLUGIN_OUTPUT_DIR"));
  if (OUTPUT_DIR[OUTPUT_DIR.length()-1] != '/')
    OUTPUT_DIR.push_back('/');

  // open temp file to store rtl instructions
  s = OUTPUT_DIR + "tmpRtl.txt";
  rtlFile = fopen(s.c_str(), "w+");

  // get asm_out_file's file path
  const int MAXLEN = 200;
  char procPath[MAXLEN + 1];
  char filePath[MAXLEN + 1];
  memset(filePath, 0, MAXLEN + 1);
  snprintf(procPath, MAXLEN, "/proc/self/fd/%d", fileno(asm_out_file));
  readlink(procPath, filePath, (size_t) MAXLEN);
  
  // retrieve index, increase index
  fstream countFile;
  s = OUTPUT_DIR + "tmpCount.txt";
  countFile.open(s.c_str(), fstream::in);
  countFile >> n;
  countFile.close();
  // -----
  countFile.open(s.c_str(), fstream::out | fstream::trunc);
  countFile << n + 1;
  countFile.close();

  // create a hard link to asm_out_file: tmp_[index].txt
  s = OUTPUT_DIR + "tmp_" + to_string(n) + ".txt";
  link(filePath, s.c_str());
}

/* ------------------------------------------------------ */
/*               Print ASM to "asm_out_file"              */
/* ------------------------------------------------------ */
void generate_asm(rtx_insn *insn) {
  int id = recog(PATTERN(insn), insn, NULL);
  if (id != -1) {
    which_alternative = -1;
    extract_constrain_insn_cached(insn);
    const char* templ = get_insn_template(id, insn);
    output_asm_insn(templ, recog_data.operand);
  }
}

/* ------------------------------------------------------ */
/* Print RTL with '#' added to the beginning of each line */
/* ------------------------------------------------------ */
void generate_rtl(rtx_insn *insn) {
  // print RTL to rtlFile
  print_rtl_single(rtlFile, insn);
  // get currPos, get RTL's length, allocate buffer
  currPos = ftell(rtlFile);
  size_t len = currPos - prevPos;
  char* cStr = (char*) xmalloc(len+1);
  memset(cStr, 0, len+1);
  // seek to prevPos, read the RTL, update prevPos
  fseek(rtlFile, -len, SEEK_CUR);
  fread(cStr, len, 1, rtlFile);
  prevPos = currPos;
  // insert '#' to 1st line, remove last '\n'
  // insert '#' after each '\n'
  string rtl = string(cStr);
  rtl.insert(0, "#");
  rtl.pop_back();
  size_t pos = rtl.find('\n');
  while (pos != string::npos) {
    rtl.insert(pos+1, "#");
    pos = rtl.find('\n', pos+1);
  }
  // print modified RTL to asm_out_file
  fprintf(asm_out_file, "%s\n", rtl.c_str());
}

/* ------------------------------------------------------ */
/*                       RTL-OPT-PASS                     */
/* ------------------------------------------------------ */
struct my_dump_pass : rtl_opt_pass {
  my_dump_pass(gcc::context *ctx): rtl_opt_pass(dump_pass_data, ctx) {}

  virtual unsigned int execute(function * fun) override {
    rtx_insn *insn;

    if (!is_initialized)
      gcc_init();

    for (insn = get_first_nonnote_insn(); insn != NULL; insn = next_insn(insn))
      if (GET_CODE(insn) == INSN || GET_CODE(insn) == JUMP_INSN ||
          GET_CODE(insn) == CALL_INSN) {
        generate_rtl(insn);
        generate_asm(insn);
      }

    return 0;
  }

  virtual my_dump_pass *clone() override {
    return this;
  }
};

/* ------------------------------------------------------ */
/*                      Register Pass                     */
/* ------------------------------------------------------ */
int plugin_init(struct plugin_name_args *plugin_info,
                struct plugin_gcc_version *version) {

  struct register_pass_info pass_info;
  pass_info.pass = new my_dump_pass(g);
  pass_info.reference_pass_name = "final";
  pass_info.ref_pass_instance_number = 1;
  pass_info.pos_op = PASS_POS_INSERT_AFTER;

  register_callback(plugin_info->base_name,
                    PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

  return 0;
}