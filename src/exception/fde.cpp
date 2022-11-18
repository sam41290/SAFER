#include "fde.h"
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
#include <string>

using namespace std;

extern map < uint64_t, cfi_table > unwinding_info;

fde_class::fde_class (uint64_t p_length, uint64_t p_extended_length,
		      uint64_t p_location)
{
  length = p_length;
  location = p_location;
  extended_length = p_extended_length;
}

void
fde_class::read_fde (string bname, uint8_t * fde_ptr, uint64_t length, uint64_t
		     offset)
{
  bname_ = bname;
  EH_LOG
    ("---------------------------------------------------------------------------\n");
  uint64_t cie_ptr;
  uint64_t i = 0;
  EH_LOG (hex << offset << ":" << "CIE ID: " << hex << my_cie.location << "\n");

  int size_enc = my_cie.fde_ptr_enc & 0x0f;

  int byte_count = get_encoded_value(bname, my_cie.fde_ptr_enc, offset, fde_ptr + i,
      &pc_begin);

  offset += byte_count;
  i += byte_count;

  EH_LOG ("PC begin: " << hex << pc_begin << "\n");

  byte_count = get_encoded_value (bname, size_enc, offset, fde_ptr + i,
      &pc_range);


  offset += byte_count;
  i += byte_count;

  EH_LOG ("PC range: " << hex << pc_range << "\n");
  if (my_cie.is_aug_data == 1 /*&& is_lsda_ptr == 1 */ )
    {
      int sz = read_unsigned_leb128 (fde_ptr + i, &aug_data_length);
      for (int j = 0; j < sz; j++)
	    {
	      encoded_aug_data_length.push_back (*(fde_ptr + i));
	      i++;
	    }
      EH_LOG ("aug data length: " << hex << aug_data_length << "\n");
      offset += sz;
      if (aug_data_length > 0)
	    {
	      for (int j = 0; j < aug_data_length; j++)
	        {
	          aug_data.push_back (*(fde_ptr + i));
	          i++;
	        }
	      int sz =
	        decode_ptr (bname, my_cie.lsda_ptr_enc, aug_data, 0, offset,
	    		&lsda_ptr);

	      lsda_ptr_padding = sz;
	    }
      EH_LOG ("LSDA pointer: " << hex << lsda_ptr << "\n");

    }
  uint8_t *fde_tbl;
  while (i < length)
  {
    call_frame_insn.push_back (*(fde_ptr + i));
    i++;
  }

  fde_tbl = (uint8_t *) malloc (my_cie.initial_instructions.size ()
				+ call_frame_insn.size ());

  int k = 0;
  for (k = 0; k < my_cie.initial_instructions.size (); k++)
    fde_tbl[k] = my_cie.initial_instructions[k];

  int init_cfi_length = k;
  for (int j = 0; j < call_frame_insn.size (); k++, j++)
    fde_tbl[k] = call_frame_insn[j];

  cfi_table cfi;
  cfi.read_cfi_table (fde_tbl, pc_begin, pc_range,
		      my_cie.initial_instructions.size () +
		      call_frame_insn.size (), init_cfi_length);
  unwinding_info[pc_begin] = cfi;

  EH_LOG
    ("---------------------------------------------------------------------------\n");

}

uint64_t
fde_class::get_pc_begin ()
{
  return pc_begin;
}

uint64_t
fde_class::get_pc_range ()
{
  return pc_range;
}

void
fde_class::set_my_cie (uint64_t loc, uint8_t fde_enc, uint8_t lsda_enc, uint8_t
		       is_aug_data, vector < uint8_t > init_ins)
{
  my_cie.location = loc;
  my_cie.fde_ptr_enc = fde_enc;
  my_cie.lsda_ptr_enc = lsda_enc;
  my_cie.is_aug_data = is_aug_data;
  my_cie.initial_instructions = init_ins;
}

string
fde_class::print_fde ()
{
  string fde = "";
  uint64_t addrs = utils::GET_ADDRESS(bname_, location);
  fde += "." + to_string(addrs) + "_FDE:\n";
  fde += "." + to_string (location) + "_fde_struct:\n";
  
  if (length == 0xffffffff)
  {
    fde += ".long 0xffffffff\n";
    fde += ".quad ." + to_string (location) + "_fde_end - ."
         + to_string (location) + "_fde_start\n";
  }
  else
    fde += ".long ." + to_string (location) + "_fde_end - ."
      + to_string (location) + "_fde_start\n";


  fde += "." + to_string (location) + "_fde_start:\n";

  fde += ".long ." + to_string (location) + "_fde_start - ."
    + to_string (my_cie.location) + "_cie_struct\n";


  fde += "." + to_string (location) + "_pc_begin:\n";

  fde += print_encoded_ptr ("." + to_string (location) + "_pc_begin", ".frame_"
			    + to_string (pc_begin), my_cie.fde_ptr_enc);

  fde += print_encoded_ptr_lvl2 (my_cie.fde_ptr_enc & 0x0f, ".frame_"
				 + to_string (pc_begin) + "_end - .frame_" +
				 to_string (pc_begin) + "\n");

  if (my_cie.is_aug_data == 1 /*&& my_cieis_lsda_ptr == 1 */ )
  {
    fde += ".uleb128 ." + to_string (location) + "_aug_data_end - ."
        + to_string (location) + "_aug_data_start\n";
    fde += "." + to_string (location) + "_aug_data_start:\n";
    if (aug_data_length > 0) {
      fde += print_encoded_ptr ("." + to_string (location)
    			                    + "_aug_data_start", "."
    			                    + to_string (lsda_ptr) + "_LSDA",
    			                    my_cie.lsda_ptr_enc);
    }
    fde += "." + to_string (location) + "_aug_data_end:\n";
  }
  ifstream ifile;
  ifile.open ("tmp/" + to_string (pc_begin) + "_unwind.s");

  string str;
  while (getline (ifile, str))
    fde += str + "\n";

  ifile.close ();

  //for(int i = 0;i<call_frame_insn.size();i++)
  //  fde += ".byte " + to_string((uint32_t)call_frame_insn[i]) + "\n";
  fde += ".align 8,0x0\n";
  fde += "." + to_string (location) + "_fde_end:\n";

  return fde;

}

uint64_t
fde_class::get_lsda_ptr ()
{
  return lsda_ptr;
}
