#ifndef _CFI_TBL_H
#define _CFI_TBL_H
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <vector>

/* class cfi_table stores the unwinding metadata/ stack unwinding instructions
 * for a given function.
 */

using namespace std;

struct unwinding_op
{

  //Represents one unwinding op.
  //Since one unwinding op can be inheritted by subsequent unwinding blocks,
  //we assign id to operations and then map the ids to unwinding blocks,
  //rather than creating a op everytime.

  int id;
  int opcode;
  int op_cnt;
  uint64_t op1;
  uint64_t op2;
  int8_t is_expr;
  vector < uint8_t > instructions;
};

struct unwinding_record
{
  //Represents one unwinding record or one unwinding block.
  //One record can have multiple unwinding ops.

  uint64_t frame;
  uint64_t PC;
  map < uint64_t, int >reg_state; //REG and corresponding OP ID.
  uint64_t cfa_state = 0;	//holds latest op id for cfa state change
  uint64_t cfa_reg_state = 0;	//holds latest op id for cfa reg state change
  int8_t is_cfa_exp = 0;
  map < uint64_t, int >restored_reg;	
  //queue<int> remember_state;
  int remember_point = 0;	//for DW_CFA_restore_state
  int restore_point = 0;
};

class cfi_table
{

  uint64_t frame;
  int op_id_ctr = 1;
  map < int, vector < int >>op_tree;
  map < int, unwinding_op > operations;
  map < uint64_t, unwinding_record > CFI; //The unwinding blocks table.
  unwinding_record initial_CFI;
  map < uint64_t, unwinding_record > restore;
  int cur_op_id;
  stack < unwinding_record > remember_state;

  /* Variables used for Printing unwinding instructions.
   * cur_cfa = current CFA offset
   * is_cur_cfa_exp = if expression is used to calculate current CFA.
   * cur_cfa_reg = REG used to calculate current CFA.
   * cur_reg_state = REG states defined by last printed instructions.
   * last_rec = last printed unwinding block.
   */
  uint64_t cur_cfa = 0;
  int8_t is_cur_cfa_exp = 0;
  uint64_t cur_cfa_reg = 0;
  map < uint64_t, int >cur_reg_state;
  uint64_t last_rec = 0;

  string last_pc = "";
  uint64_t distance = 0;
public:
  int print_cfi (uint64_t addrs, string fname, int ins_sz, string label);
  void read_cfi_table (uint8_t * fde_tbl, uint64_t pc_begin, uint64_t pc_range,
		       int length, int init_cfi_length);
  int op_exists (unwinding_op op);
  int create_op (int opcode, int op_cnt, uint64_t op1, uint64_t op2, int8_t
		 is_expr, uint8_t * start, uint64_t length);

  uint64_t create_unwind_record (uint64_t prev_unwind_rec, uint64_t PC, uint64_t
				 pc_begin);
  map < uint64_t, int8_t > return_cfi_ranges ();
  string encode_cfa (map < uint64_t, unwinding_record >::iterator & cfi_it);
  void remove_unwinding_blk (uint64_t addrs);
  set <uint64_t> get_all_unwinding_blks ();
  void merge_unwinding_blocks (uint64_t start, uint64_t end, uint64_t effective_blk);
};


#endif
