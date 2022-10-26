/*
   Copyright (C) 2018 - 2021 by Huan Nguyen in Secure Systems
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
#include "print-rtl.h"
#include "recog.h"
#include "output.h"
#include "toplev.h"
using namespace std;

int plugin_is_GPL_compatible;
static FILE* mapping_out_file;
extern FILE* asm_out_file;


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


void generate_mapping(rtx_insn *insn) {
   int id = recog(PATTERN(insn), insn, NULL);
   if (id != -1) {
      /* ------------------------- print asm ------------------------- */
      /* observations:                                                 */
      /* (1) assembly is printed out to an extern FILE* asm_out_file   */
      /*     via output_asm_insn(template, operands) found in gcc      */
      /*     sources, particularly [output.h, final.c]                 */
      /* (2) asm_out_file is continuously set to different temporary   */
      /*     streams outside this function, it could be a file with    */
      /*     random name in /tmp/ or an unnamed pipe, and they are     */
      /*     going to be erased right after; fortunately, we can       */
      /*     intercept right after they are generated and before they  */
      /*     disappear                                                 */
      /* (3) redirect asm_out_file to a chosen file may affect the     */
      /*     compilation's constraint, e.g., compiler needs to write   */
      /*     all asms to a file for each object before combining; thus */
      /*     any change to asm_out_file will split two parts of an     */
      /*     object to two separate files and compiler does not know   */
      /*     where the first part is stored, so it will fail           */
      /*                                                               */
      /* there are a few failed approaches:                            */
      /* (a) hard link asm_out_file to a chosen file                   */
      /*     problem: link() requires file path arguments, but pipe    */
      /*              does not have file path                          */
      /*     result: some training data cannot be captured             */
      /* (b) keep asm_out_file intact, but extract the asm directly    */
      /*     from it using ftell/fseek/fread/fwrite                    */
      /*     problem: same code that works for other files fail with   */
      /*              asm_out_file, suggesting that the gcc's internal */
      /*              specially handles the indicated stream position. */
      /*     result: unable to extract any asm                         */
      /* (c) redirect asm_out_file with care:                          */
      /*        fopen()   -> PASS_POS_INSERT_BEFORE                    */
      /*        fclose()  -> PASS_POS_INSERT_AFTER                     */
      /*     problem: beside problem (3), compiler complains against   */
      /*              using PASS_POS_INSERT_BEFORE, unknown reason!    */
      /*                                                               */
      /* current approach:                                             */
      /*     (+) mapping_out_file points to same file every time the   */
      /*         plugin is associated, so less files                   */
      /*     (+) asm_out_file is backed up first, and redirected to    */
      /*         mapping_out_file, then output_asm_insn(), and finally */
      /*         restored back to the original, so avoid issue of too  */
      /*         many files left open                                  */
      /*     (+) mapping_out_file is small because here it only emits  */
      /*         what could be an insn/jump_insn/call_insn, with an    */
      /*         additional check regarding corrupted asm; e.g., it    */
      /*         omits all directive asm and static data, save space   */
      /*         and ease postprocesses                                */
      /*     (+) mapping_out_file needs to repeatedly open a file and  */
      /*         without closing it, it is possible to catch the error */
      /*         of too many open files; fortunately, we can close it  */
      /*         via intercepting pass PLUGIN_FINISH when gcc is about */
      /*         to exit                                               */
      /* ------------------------------------------------------------- */
      auto t = asm_out_file;
      asm_out_file = mapping_out_file;
      which_alternative = -1;
      extract_constrain_insn_cached(insn);
      const char* templ = get_insn_template(id, insn);
      output_asm_insn(templ, recog_data.operand);
      asm_out_file = t;
      /* ------------------------- print rtl ------------------------- */
      /* RTL is printed via print_rtl_single(FILE*, rtx_insn*) found   */
      /* in gcc sources, particularly [rtl.h, print-rtl.c]             */
      /* ------------------------------------------------------------- */
      print_rtl_single(mapping_out_file, insn);
      fprintf(mapping_out_file, "------------\n");
   }
}

/* ------------------------------------------------------ */
/*                       RTL-OPT-PASS                     */
/* ------------------------------------------------------ */
struct my_dump_pass : rtl_opt_pass {
my_dump_pass(gcc::context *ctx): rtl_opt_pass(dump_pass_data, ctx) {}

   virtual unsigned int execute(function * fun) override {
      for (auto i = get_first_nonnote_insn(); i != NULL; i = next_insn(i))
      if (GET_CODE(i)==INSN || GET_CODE(i)==JUMP_INSN || GET_CODE(i)==CALL_INSN)
         generate_mapping(i);
      return 0;
   }

   virtual my_dump_pass *clone() override {
      return this;
   }
};

void close_file(void *gcc_data, void *user_data) {
   fclose(mapping_out_file);
}
/* ------------------------------------------------------ */
/*                      Register Pass                     */
/* ------------------------------------------------------ */
int plugin_init(struct plugin_name_args *plugin_info,
                struct plugin_gcc_version *version) {

   // get the output file path from env
   // open the file each time the plugin is invoked
   string out = string(getenv("OUT"));
   mapping_out_file = fopen(out.c_str(), "a");

   struct register_pass_info pass_info;
   pass_info.pass = new my_dump_pass(g);
   pass_info.reference_pass_name = "final";
   pass_info.ref_pass_instance_number = 1;
   pass_info.pos_op = PASS_POS_INSERT_AFTER;

   register_callback(plugin_info->base_name,
                    PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

   // close the file after gcc is about to exit
   register_callback(plugin_info->base_name,
                    PLUGIN_FINISH, close_file, NULL);

  return 0;
}