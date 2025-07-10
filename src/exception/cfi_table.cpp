#include "cfi_table.h"
#include <iostream>
#include <fstream>
#include <bits/stdc++.h>
#include<stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <vector>
#include <regex>
#include <map>
#include "elf64.h"
//#include "disassem.h"
#include "elf_class.h"
#include "exception_handler.h"
#include "libutils.h"

using namespace std;


//extern map < uint64_t, cfi_table > unwinding_info;
//extern set<uint64_t> address_taken;

void 
cfi_table::remove_unwinding_blk (uint64_t addrs)
{
  CFI.erase(addrs);
}

void
cfi_table::merge_unwinding_blocks (uint64_t start, uint64_t end, uint64_t
    effective_blk)
{
  /* Merge all unwinding blocks between start and end. New block address
   * = start.
   * New block unwinding OPS = unwinding OPS of block at effective_blk.
   */

  auto it_start = CFI.lower_bound (start);

  if (it_start == CFI.end () || it_start->first > end)
    return;

  auto it_end = CFI.lower_bound (end);

  auto effective_blk_it = is_within (effective_blk, CFI);

  unwinding_record rec = effective_blk_it->second;

  LOG("Merged unwinding block: "<<hex<<it_start->first<<" - "<<it_end->first);

  CFI.erase(it_start, it_end);
  CFI[start] = rec;

}

set <uint64_t> 
cfi_table::get_all_unwinding_blks ()
{
  set <uint64_t> all_unwinding_blks;
  auto it = CFI.begin ();
  while (it != CFI.end ())
  {
    all_unwinding_blks.insert (it->first);
    it ++;
  }
  return all_unwinding_blks;
}

int
cfi_table::op_exists (unwinding_op op)
{

  //Check if the given op already exists. If yes, return the corresponding ID

  /* op_tree is a map of vectors where key = opcode.
   * the vector is a vector of OP IDs that use the given opcode.
   */

  map < int, vector < int >>::iterator op_tree_it;
  op_tree_it = op_tree.find (op.opcode);
  if (op_tree_it != op_tree.end ())
    {
      map < int, unwinding_op >::iterator op_it;
      for (int i = 0; i < op_tree_it->second.size (); i++)
	    {
	      op_it = operations.find (op_tree_it->second[i]);
	      if (op.instructions.size () == op_it->second.instructions.size ())
	        {
              /* op.instructions is a vector of bytes.
               * If instructions.size () is same, compare each byte.
               * If they are equal return the ID.
               */
	          int j = 0;
	          for (j = 0; j < op_it->second.instructions.size (); j++)
	    	    {
	    	      if (op.instructions[j] != op_it->second.instructions[j])
	    	        break;
	    	    }
	          if (j == op.instructions.size ())
	    	    return op_it->second.id;
	        }
	    }

    }
  return 0;
}

int
cfi_table::create_op (int opcode, int op_cnt, uint64_t op1, uint64_t op2, int8_t
		      is_expr, uint8_t * start, uint64_t length)
{

  /* creates and unwinding_op object for the given opcode and operands.
   */

  EH_LOG ("creating ops: ");
  unwinding_op op;
  op.opcode = opcode;
  op.op_cnt = op_cnt;
  op.op1 = op1;
  op.op2 = op2;
  op.is_expr = is_expr;
  for (int i = 0; i < length; i++)
    {
      /* Insert the corresponding bytes into op.instructions vector.
       * We do not need to re-create the OPs while re-creating the EH metadata.
       * Just put the hex bytes using .byte directive and it will serve the
       * purpose. Hence, we store the original bytes of a given op.
       */

      EH_LOG (hex << (uint32_t) (*(start + i)) << " ");
      op.instructions.push_back (*(start + i));
    }
  int x = op_exists (op);
  if (x != 0)
    {
      /* If OP already exists, no need to recreate.
       */

      EH_LOG ("op exists: " << x << "\n");
      return x;

    }
  op.id = op_id_ctr;
  op_id_ctr++;
  operations[op.id] = op;
  op_tree[opcode].push_back (op.id);
  EH_LOG ("new op id: " << op.id << "\n");
  return op.id;

}

uint64_t
cfi_table::create_unwind_record (uint64_t prev_unwind_rec, uint64_t
				 PC, uint64_t pc_begin)
{

  /* A new unwinding record inherits all the properties of its previous
   * unwinding record.
   * Hence, just copy the previous record and return.
   * Any further additions will be added on top of this.
   */

  unwinding_record rec = CFI[prev_unwind_rec];
  rec.frame = pc_begin;
  rec.PC = PC;
  rec.remember_point = 0;
  rec.restore_point = 0;
  CFI[PC] = rec;
  return PC;
}


string
cfi_table::encode_cfa (map < uint64_t, unwinding_record >::iterator & cfi_it)
{
  /* Generates ASM directives to encode CFA state.
   * CFA = canonical frame address. That is start of stack frame for the current
   * function.
   */

  string cfa = "";
  if (cfi_it->second.is_cfa_exp == 1)
    {
      /* Current cfa state is computed using an expression. */

      if (is_cur_cfa_exp == 1 && cur_cfa == cfi_it->second.cfa_state)
	    return cfa;
      map < int, unwinding_op >::iterator op_it;
      op_it = operations.find (cfi_it->second.cfa_state);
      EH_LOG ("op size: " << op_it->second.instructions.size () << "\n");
      for (int i = 0; i < op_it->second.instructions.size (); i++)
	    {
          /* Put out the bytes of the expression. */

	      EH_LOG ((uint32_t) (op_it->second.instructions[i]) << " ");
	      cfa += ".byte "
	        + to_string ((uint32_t) (op_it->second.instructions[i])) + "\n";
	    }
      cur_cfa = cfi_it->second.cfa_state;

      if (cfi_it->second.cfa_reg_state == cfi_it->second.cfa_state)
	    cur_cfa_reg = cur_cfa;
      is_cur_cfa_exp = 1;
      EH_LOG ("new cfa state: " << cur_cfa << "\n");

    }
  else
    {
      /* If not expression, CFA is defined as a REG + offset. */

      if (is_cur_cfa_exp == 1 || (cur_cfa != cfi_it->second.cfa_state &&
				  cur_cfa_reg != cfi_it->second.cfa_reg_state))
	    {
          //Opcode DW_CFA_def_cfa
	      cfa += ".byte " + to_string ((uint32_t) DW_CFA_def_cfa) + "\n";
          //CFA register
	      cfa += ".uleb128 " + to_string (cfi_it->second.cfa_reg_state) + "\n";
          //Offset
	      cfa += ".uleb128 " + to_string (cfi_it->second.cfa_state) + "\n";
	    }
      else if (cur_cfa == cfi_it->second.cfa_state && cur_cfa_reg !=
	       cfi_it->second.cfa_reg_state)
	    {
          //Offset remains same, only REG changes.
	      cfa += ".byte " + to_string ((uint32_t) DW_CFA_def_cfa_register)
	        + "\n";
	      cfa += ".uleb128 " + to_string (cfi_it->second.cfa_reg_state) + "\n";
	    }
      else if (cur_cfa != cfi_it->second.cfa_state && cur_cfa_reg ==
	       cfi_it->second.cfa_reg_state)
	    {
          //REG remains same, offset changes.
	      cfa += ".byte " + to_string ((uint32_t) DW_CFA_def_cfa_offset) + "\n";
	      cfa += ".uleb128 " + to_string (cfi_it->second.cfa_state) + "\n";
	    }
    }

  //Store the current CFA state.

  is_cur_cfa_exp = cfi_it->second.is_cfa_exp;
  cur_cfa = cfi_it->second.cfa_state;
  cur_cfa_reg = cfi_it->second.cfa_reg_state;
  return cfa;
}

//uint64_t extra_jump = 0;

int
cfi_table::print_cfi (uint64_t addrs, string fname, int ins_sz, string label)
{

  /* Prints ASM directives to encode new unwinding instructions.
   * Input: 
   *    1. code address for which unwinding instructions are to be generated.
   *    2. label of the code address.
   *    3. ins_sz: expected size of unwinding block.
   *    4. fname: file onto which ASM directives are to be written.
   */

  if (CFI.size () > 0) {
    //Find the unwinding block to which the address belongs.

    auto cfi_it = is_within(addrs, CFI);
    EH_LOG ("address: " << addrs << " CFI block: " << hex << cfi_it->
        first << "\n");


    EH_LOG ("last rec: " << hex << last_rec << " last pc: " << last_pc <<
        "\n");


    EH_LOG ("required cfa state || cfa : " << cfi_it->second.
        cfa_state << " cfa_reg: " << cfi_it->second.
        cfa_reg_state << "\n");
    uint32_t distance_op;
    string op_size;
    //uint64_t alignment = 0;
    /*
       if(ins_sz < 0xff)
       {
       distance_op = DW_CFA_advance_loc1;
       op_size = ".byte ";
       }
       else if(ins_sz < 0xffff)
       {
       distance_op = DW_CFA_advance_loc2;
       op_size = ".2byte ";
       }
       else if(ins_sz <= 0xffffffff)
       {
       distance_op = DW_CFA_advance_loc4;
       op_size = ".long ";
       }
     */

    distance_op = DW_CFA_advance_loc4;
    op_size = ".long ";


    if (cfi_it->first == last_rec) {
      //Stack or Reg states haven't changed. No need to print new
      //instructions.

      //distance += ins_sz + alignment;
      return 0;
    }
    ofstream unwind_file;
    unwind_file.open (fname, ofstream::out | ofstream::app);

    string pc_symbol = label;
    /*
       if(trampoline_blocks.find(addrs) != trampoline_blocks.end())
       pc_symbol = "." + to_string(addrs) + "_tramp";
       else
       pc_symbol = "." + to_string(addrs);
     */
    if (last_pc.length () == 0) {

      /* First instruction of the function. No need to mark unwinding block
       * start.
       */
      //unwind_file<<".byte "<<distance_op<<"\n";
      //unwind_file<<op_size<<pc_symbol<<" - .frame_"<<frame<<"\n";
    }
    else {
      unwind_file << ".byte " << distance_op << "\n";
      unwind_file << op_size << pc_symbol << " - " << last_pc << "\n";
    }

    map <int, unwinding_op>::iterator op_it;


    EH_LOG ("current cfa state: " << dec << cur_cfa << "\n");
    string cfa = encode_cfa (cfi_it);
    unwind_file << cfa;
    map < uint64_t, int >::iterator reg_it1;
    map < uint64_t, int >::iterator reg_it2;

    EH_LOG ("register state size: " << cfi_it->second.reg_state.size () << "\n");
    reg_it1 = cfi_it->second.reg_state.begin ();
    EH_LOG ("new reg states: \n");
    while (reg_it1 != cfi_it->second.reg_state.end ()) {
      /* Map cur_reg_state holds the state of a REG in the last printed
       * instruction.
       */

      reg_it2 = cur_reg_state.find (reg_it1->first);
      if (reg_it2 == cur_reg_state.end () || reg_it2->second != reg_it1->second) {
        //Change in state. Print corresponding unwinding instruction.

        EH_LOG ("reg: " << reg_it1->first << " new state: "<< reg_it1->second << "\n");
        op_it = operations.find (reg_it1->second);
        EH_LOG ("op size: " << op_it->second.instructions.size () << "\n");
        if (op_it->second.opcode == DW_CFA_restore || op_it->second.opcode == DW_CFA_restore_extended) {
          //If a REG is being restored, then put the instructions for
          //previous state to avoid any side effects.

    	  map < uint64_t, int >::iterator reg_it3;;
    	  reg_it3 = cfi_it->second.restored_reg.find (reg_it1->first);
    	  if (reg_it3 != cfi_it->second.restored_reg.end () &&
    	      reg_it3->second != reg_it2->second) {
    	    map < int, unwinding_op >::iterator op_it2;
    	    op_it2 = operations.find (reg_it3->second);
    	    for (int i = 0; i < op_it->second.instructions.size (); i++) {
    	      unwind_file << ".byte "<< (uint32_t) (op_it->second.instructions[i]) << "\n";
    	    }
          }
    	}
        //Put out the bytes of the unwinding instructions.
        for (int i = 0; i < op_it->second.instructions.size (); i++) {
    	  unwind_file << ".byte " << (uint32_t) (op_it->second.instructions[i]) << "\n";
    	}
      }
      reg_it1++;
    }

    /* Due to randomization and reordering of blocks, few REG states might
     * have been defined in the previous unwinding instruction, but do not
     * need to be defined in this unwinding instruction.
     * We need to undefine those.
     */
    //Undefine registers

    reg_it1 = cur_reg_state.begin ();
    while (reg_it1 != cur_reg_state.end ()) {
      reg_it2 = cfi_it->second.reg_state.find (reg_it1->first);
      if (reg_it2 == cfi_it->second.reg_state.end ()) {
        EH_LOG ("undefining register: " << reg_it1->first << "\n");
        vector < uint8_t > reg =
    	  encode_unsigned_leb128 (reg_it1->first, 0);

        unwind_file << ".byte " << DW_CFA_undefined << "\n";
        for (int i = 0; i < reg.size (); i++)
    	  unwind_file << ".byte " << (uint32_t) reg[i] << "\n";
      }
      reg_it1++;
    }

    /* Update the current REG state and last printed unwinding block
     */

    cur_reg_state = cfi_it->second.reg_state;
    last_rec = cfi_it->first;
    if (last_pc.length () == 0)
      last_pc = ".frame_" + to_string (frame);
    else
      last_pc = label;

    unwind_file.close ();
    return 1;
  }

  return 0;

}

map < uint64_t, int8_t > cfi_table::return_cfi_ranges ()
{
  map < uint64_t, int8_t > ranges;
  map < uint64_t, unwinding_record >::iterator cfi_it;
  cfi_it = CFI.begin ();
  while (cfi_it != CFI.end ())
    {
      ranges[cfi_it->first] = 1;
      cfi_it++;
    }
  return ranges;
}


void
cfi_table::read_cfi_table (uint8_t * fde_tbl, uint64_t pc_begin, uint64_t
			   pc_range, int length, int init_cfi_length)
{

  //Reads cfi table (call frame instruction table) for a given function
  //pointer by pc_begin.
  //cfi table holds stack unwidning operations.

  //int index = 0;
  EH_LOG ("call frame instructions: " << "\n");
  frame = pc_begin;
  unwinding_record rec;
  rec.frame = pc_begin;
  rec.PC = pc_begin;
  //map<uint64_t,unwinding_record> unwind_rec_map;
  CFI[rec.frame] = rec;
  uint64_t cur_unwind_rec = pc_begin;
  uint64_t op_cnt = 0;
  uint64_t shift = 0;
  uint64_t adv = 0;
  int cfa_expr = 0;
  int expr = 0;
  int skip_bytes = 0;
  for (int index = 0; index < length; index++)
    {
      uint8_t c = fde_tbl[index];
      if (skip_bytes > 0)
	    {
	      skip_bytes--;
	    }
      else if (op_cnt > 0)
	    {
	      adv = adv + ((uint64_t) c << shift);
	      shift += 8;
	      op_cnt--;
	      if (op_cnt == 0)
	        {
	          shift = 0;
	          cur_unwind_rec
	    	    = create_unwind_record (cur_unwind_rec, cur_unwind_rec
	    				+ adv, pc_begin);
	          EH_LOG (hex << cur_unwind_rec << "\n");
	        }
	    }
      else if ((c & 0xc0) == DW_CFA_advance_loc)
	    {
	      EH_LOG ("\nDW_CFA_advance_loc: ");
	      uint64_t adv = c & 0x3f;
	      cur_unwind_rec = create_unwind_record (cur_unwind_rec, cur_unwind_rec
	    					 + adv, pc_begin);
	      EH_LOG (hex << cur_unwind_rec << "\n");
	    }
      else if ((c & 0xc0) == DW_CFA_offset)
	    {
	      EH_LOG ("\tDW_CFA_offset: ");
	      uint64_t reg = c & 0x3f;
	      uint64_t offt;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &offt);
	      int op_id = create_op (DW_CFA_offset, 1, offt, 0, 0, fde_tbl
	    			 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      if (index < init_cfi_length)
	        initial_CFI.reg_state[reg] = op_id;
	      EH_LOG ("reg - " << dec << reg << " offset: " << offt << "\n");
	    }
      else if ((c & 0xc0) == DW_CFA_restore)
	    {
	      EH_LOG ("\tDW_CFA_restore :");
	      uint64_t reg = c & 0x3f;
	      int op_id =
	        create_op (DW_CFA_restore, 0, 0, 0, 0, fde_tbl + index, 1);
	      CFI[cur_unwind_rec].restored_reg[reg] =
	        CFI[cur_unwind_rec].reg_state[reg];
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      EH_LOG ("reg -" << dec << reg << "\n");
	    }
      else if (c == DW_CFA_register)
	    {
	      EH_LOG ("\tDW_CFA_register :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      uint64_t offt;
	      skip_bytes += read_unsigned_leb128 (fde_tbl + index
	    				      + 1 + skip_bytes, &offt);
	      int op_id = create_op (DW_CFA_register, 2, reg, offt, 0, fde_tbl
	    			 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      if (index < init_cfi_length)
	        initial_CFI.reg_state[reg] = op_id;
	      EH_LOG ("reg - " << dec << reg << " offset: " << offt << "\n");

	    }
      else if (c == DW_CFA_offset_extended)
	    {
	      EH_LOG ("\tDW_CFA_offset_extended :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      uint64_t offt;
	      skip_bytes += read_unsigned_leb128 (fde_tbl + index
	    				      + 1 + skip_bytes, &offt);
	      int op_id =
	        create_op (DW_CFA_offset_extended, 2, reg, offt, 0, fde_tbl + index,
	    	       skip_bytes + 1);
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      if (index < init_cfi_length)
	        initial_CFI.reg_state[reg] = op_id;
	      EH_LOG ("reg - " << dec << reg << " offset: " << offt << "\n");
	    }
      else if (c == DW_CFA_restore_extended)
	    {
	      EH_LOG ("\tDW_CFA_restore_extended :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      int op_id = create_op (DW_CFA_restore_extended, 1, reg, 0, 0, fde_tbl
	    			 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].restored_reg[reg]
	        = CFI[cur_unwind_rec].reg_state[reg];
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      EH_LOG ("reg -" << dec << reg << "\n");
	    }
      else if (c == DW_CFA_undefined)
	    {
	      EH_LOG ("\tDW_CFA_undefined :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      int op_id = create_op (DW_CFA_undefined, 1, reg, 0, 0, fde_tbl
	    			 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      if (index < init_cfi_length)
	        initial_CFI.reg_state[reg] = op_id;
	      EH_LOG ("reg -" << dec << reg << "\n");
	    }
      else if (c == DW_CFA_def_cfa)
	    {
	      EH_LOG ("\tDW_CFA_def_cfa :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      uint64_t offt;
	      skip_bytes += read_unsigned_leb128 (fde_tbl + index + 1 + skip_bytes,
	    				      &offt);
	      int op_id = create_op (DW_CFA_def_cfa, 2, reg, offt, 0, fde_tbl
	    			 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].cfa_state = offt;
	      if (index < init_cfi_length)
	        initial_CFI.cfa_state = offt;
	      CFI[cur_unwind_rec].cfa_reg_state = reg;
	      if (index < init_cfi_length)
	        {
	          initial_CFI.cfa_reg_state = reg;
	          initial_CFI.is_cfa_exp = 0;
	        }
	      CFI[cur_unwind_rec].is_cfa_exp = 0;

	      EH_LOG ("reg - " << dec << reg << " offset: " << offt << "\n");
	    }
      else if (c == DW_CFA_def_cfa_sf)
	    {
	      EH_LOG ("\tDW_CFA_def_cfa_sf :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      uint64_t offt;
	      skip_bytes += read_unsigned_leb128 (fde_tbl + index + 1 + skip_bytes,
	    				      &offt);
	      int op_id = create_op (DW_CFA_def_cfa_sf, 2, reg, offt, 0, fde_tbl
	    			 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].cfa_state = offt;
	      if (index < init_cfi_length)
	        initial_CFI.cfa_state = offt;
	      CFI[cur_unwind_rec].cfa_reg_state = reg;
	      if (index < init_cfi_length)
	        {
	          initial_CFI.cfa_reg_state = reg;
	          initial_CFI.is_cfa_exp = 0;
	        }
	      CFI[cur_unwind_rec].is_cfa_exp = 0;

	      EH_LOG ("reg - " << dec << reg << " offset: " << offt << "\n");
	    }
      else if (c == DW_CFA_def_cfa_register)
	    {
	      EH_LOG ("\tDW_CFA_def_cfa_register :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      int op_id = create_op (DW_CFA_def_cfa_register, 1, reg, 0, 0, fde_tbl
	    			 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].cfa_reg_state = reg;
	      if (index < init_cfi_length)
	        initial_CFI.cfa_reg_state = reg;
	      EH_LOG ("reg -" << dec << reg << "\n");
	    }
      else if (c == DW_CFA_def_cfa_offset)
	    {
	      EH_LOG ("\tDW_CFA_def_cfa_offset :");
	      uint64_t offt;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &offt);
	      int op_id = create_op (DW_CFA_def_cfa_offset, 1, offt, 0, 0, fde_tbl
	    			 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].cfa_state = offt;
	      if (index < init_cfi_length)
	        initial_CFI.cfa_state = offt;
	      EH_LOG ("offset -" << dec << offt << "\n");
	    }
      else if (c == DW_CFA_def_cfa_offset_sf)
	    {
	      EH_LOG ("\tDW_CFA_def_cfa_offset_sf :");
	      uint64_t offt;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &offt);
	      int op_id =
	        create_op (DW_CFA_def_cfa_offset_sf, 1, offt, 0, 0, fde_tbl + index,
	    	       skip_bytes + 1);
	      CFI[cur_unwind_rec].cfa_state = offt;
	      if (index < init_cfi_length)
	        initial_CFI.cfa_state = offt;
	      EH_LOG ("offset -" << dec << offt << "\n");
	    }
      else if (c == DW_CFA_def_cfa_expression)
	    {
	      EH_LOG ("\tDW_CFA_def_cfa_expression :");
	      uint64_t expr_len;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &expr_len);
	      skip_bytes += expr_len;
	      int op_id
	        = create_op (DW_CFA_def_cfa_expression, 1, expr_len, 0, 1, fde_tbl
	    		 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].cfa_state = op_id;
	      if (index < init_cfi_length)
	        initial_CFI.cfa_state = op_id;
	      CFI[cur_unwind_rec].cfa_reg_state = op_id;
	      CFI[cur_unwind_rec].is_cfa_exp = 1;
	      if (index < init_cfi_length)
	        {
	          initial_CFI.cfa_reg_state = op_id;
	          initial_CFI.is_cfa_exp = 1;
	        }

	      EH_LOG ("expr length -" << dec << expr_len << "\n");
	    }
      else if (c == DW_CFA_expression)
	    {
	      EH_LOG ("\tDW_CFA_expression :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      uint64_t expr_len;
	      skip_bytes += read_unsigned_leb128 (fde_tbl + index
	    				      + 1 + skip_bytes, &expr_len);
	      skip_bytes += expr_len;
	      int op_id = create_op (DW_CFA_expression, 2, reg, expr_len, 1, fde_tbl
	    			 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      EH_LOG ("reg - " << reg << "expr length -" << dec << expr_len <<
	    	  "\n");
	    }
      else if (c == DW_CFA_offset_extended_sf)
	    {
	      EH_LOG ("\tDW_CFA_offset_extended_sf :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      int64_t offset;
	      skip_bytes += read_signed_leb128 (fde_tbl + index + 1 + skip_bytes,
	    				    &offset);

	      int op_id
	        = create_op (DW_CFA_offset_extended_sf, 2, reg, offset, 0, fde_tbl
	    		 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      if (index < init_cfi_length)
	        initial_CFI.reg_state[reg] = op_id;
	      EH_LOG ("reg - " << dec << reg << " offset: " << offset << "\n");
	    }
      else if (c == DW_CFA_val_offset)
	    {
	      EH_LOG ("\tDW_CFA_val_offset :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      int64_t offset;
	      skip_bytes += read_signed_leb128 (fde_tbl + index + 1 + skip_bytes,
	    				    &offset);
	      int op_id = create_op (DW_CFA_val_offset, 2, reg, offset, 0, fde_tbl
	    			 + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      if (index < init_cfi_length)
	        initial_CFI.reg_state[reg] = op_id;
	      EH_LOG ("reg - " << dec << reg << " offset: " << offset << "\n");
	    }
      else if (c == DW_CFA_val_offset_sf)
	    {
	      EH_LOG ("\tDW_CFA_val_offset_sf :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      int64_t offset;
	      skip_bytes += read_signed_leb128 (fde_tbl + index + 1 + skip_bytes,
	    				    &offset);
	      int op_id =
	        create_op (DW_CFA_val_offset_sf, 2, reg, offset, 0, fde_tbl + index,
	    	       skip_bytes + 1);
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      if (index < init_cfi_length)
	        initial_CFI.reg_state[reg] = op_id;
	      EH_LOG ("reg - " << dec << reg << " offset: " << offset << "\n");
	    }
      else if (c == DW_CFA_GNU_args_size)
	    {
	      EH_LOG ("\tDW_CFA_GNU_args_size (Not doing anything for now):");
	      uint64_t offset;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &offset);
	      EH_LOG ("offset -" << dec << offset << "\n");
	    }
      else if (c == DW_CFA_GNU_negative_offset_extended)
	    {
	      EH_LOG ("\tDW_CFA_GNU_negative_offset_extended :");
	      uint64_t reg;
	      skip_bytes = read_unsigned_leb128 (fde_tbl + index + 1, &reg);
	      uint64_t offset;
	      skip_bytes += read_unsigned_leb128 (fde_tbl + index + 1 + skip_bytes,
	    				      &offset);
	      int op_id
	        =
	        create_op (DW_CFA_GNU_negative_offset_extended, 2, reg, offset, 0,
	    	       fde_tbl + index, skip_bytes + 1);
	      CFI[cur_unwind_rec].reg_state[reg] = op_id;
	      EH_LOG ("reg - " << dec << reg << " offset: " << offset << "\n");
	    }
      else if (c == DW_CFA_remember_state)
	    {
	      EH_LOG ("\tDW_CFA_remember_state\n");
	      remember_state.push (CFI[cur_unwind_rec]);
	      int op_id = create_op (DW_CFA_remember_state, 0, 0, 0, 0, fde_tbl
	    			 + index, 1);
	    }
      else if (c == DW_CFA_restore_state)
	    {
	      EH_LOG ("\tDW_CFA_restore_state\n");
	      int op_id = create_op (DW_CFA_restore_state, 0, 0, 0, 0, fde_tbl
	    			 + index, 1);
	      restore[cur_unwind_rec] = remember_state.top ();
	      CFI[cur_unwind_rec] = restore[cur_unwind_rec];
	      remember_state.pop ();
	    }
      else if (c == DW_CFA_advance_loc1)
	    {
	      EH_LOG ("DW_CFA_advance_loc1 :");
	      op_cnt = 1;
	      shift = 0;
	      adv = 0;
	    }
      else if (c == DW_CFA_advance_loc2)
	    {
	      EH_LOG ("DW_CFA_advance_loc2 :");
	      op_cnt = 2;
	      shift = 0;
	      adv = 0;
	    }
      else if (c == DW_CFA_advance_loc4)
	    {
	      EH_LOG ("DW_CFA_advance_loc4 :");
	      op_cnt = 4;
	      shift = 0;
	      adv = 0;
	    }
      else if (c == 0)
	    {
	      EH_LOG ("Nop byte found\n");
	    }
      else
	    {
	      int op_id = create_op (c, 0, 0, 0, 0, fde_tbl + index, 1);
	      //operations[cur_op_id].next_op = op_id;
	      EH_LOG ("unmapped byte: " << hex << (uint32_t) c << "\n");
	    }
    }

  cur_cfa = initial_CFI.cfa_state;
  cur_cfa_reg = initial_CFI.cfa_reg_state;

  cur_reg_state = initial_CFI.reg_state;
  is_cur_cfa_exp = initial_CFI.is_cfa_exp;
  //last_pc = ".frame_" + to_string (pc_begin);
}
