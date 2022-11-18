#ifndef _FDE_H
#define _FDE_H
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <vector>

using namespace std;

/* Represents an FDE structure in the EH_FRAME section.
 * There is one FDE structure for every function in the program.
 */

struct my_cie_data
{
  // Few data present in the FDE's parent CIE and needs to be frequently
  // accessed by the FDE.

  uint64_t location;
  uint8_t fde_ptr_enc;
  uint8_t lsda_ptr_enc;
  uint8_t is_aug_data;
  vector < uint8_t > initial_instructions;
};

class fde_class
{
  struct my_cie_data my_cie;
  uint64_t location;
  uint32_t length;		//      Required
  uint64_t extended_length;	//  Optional
  uint32_t cie_pointer;		//          Required
  vector < uint8_t > encoded_pc_begin;	//  Required
  uint64_t pc_begin = 0;
  vector < uint8_t > encoded_pc_range;	//  Required
  uint64_t pc_range = 0;
  vector < uint8_t > encoded_aug_data_length;	//      Optional
  uint64_t aug_data_length;
  vector < uint8_t > aug_data;	//  Optional
  uint64_t lsda_ptr = 0;
  uint64_t lsda_ptr_padding;
  vector < uint8_t > call_frame_insn;	//      Required
  string bname_;

public:
  fde_class (uint64_t p_length, uint64_t p_extended_length,
	       uint64_t p_location);

  void set_my_cie (uint64_t cie_loc, uint8_t fde_enc, uint8_t lsda_enc, uint8_t
		   is_aug_data, vector < uint8_t > init_ins);
  void read_fde (string bname, uint8_t * fde_ptr, uint64_t length, uint64_t
		 offset);
  uint64_t get_pc_begin ();
  uint64_t get_pc_range ();
  string print_fde ();
  uint64_t get_lsda_ptr ();
};

#endif
