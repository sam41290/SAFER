#include "cie.h"
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

//extern set<uint64_t> keep_eh_data;

cie_class::cie_class (uint64_t p_length, uint64_t p_extended_length,
		      uint64_t p_location)
{
  length = p_length;
  extended_length = p_extended_length;
  location = p_location;
}

uint8_t
cie_class::get_lsda_enc ()
{
  return lsda_ptr_enc;
}

int
cie_class::read_cie_augmentation_str (uint8_t * aug_ptr)
{
  char *str = (char *) aug_ptr;
  int i = 0;

  if (str[0] == 'z' || str[0] == 'Z')
    is_aug_data = 1;
  if (strncmp (str, "eh", 2) == 0)
    is_eh_data = 1;
  EH_LOG ("Augmentation string: \n");
  while (str[i] != '\0')
    {
      aug_string.push_back (str[i]);
      EH_LOG (str[i]);
      i++;
    }
  if (is_aug_data == 1)
    {
      if (aug_string.find ("L") != string::npos)
	    is_lsda_ptr = 1;
      if (aug_string.find ("P") != string::npos)
	    is_personality_ptr = 1;
      if (aug_string.find ("R") != string::npos)
	    is_fde_ptr_enc = 1;

    }
  EH_LOG ("\n");
  return i;
}


void
cie_class::decode_cie_aug_data (string bname, uint64_t offset)
{

  if (is_aug_data == 1)
    {
      int aug_data_index = 0;
      for (int i = 1; i < aug_string.length (); i++)
	    {
	      if (aug_string[i] == 'L')
	        {
	          lsda_ptr_enc = aug_data[aug_data_index];
	          aug_data_index++;
	        }
	      else if (aug_string[i] == 'R')
	        {
	          fde_ptr_enc = aug_data[aug_data_index];
	          aug_data_index++;

	        }
	      else if (aug_string[i] == 'P')
	        {
	          personality_rtn_ptr_enc = aug_data[aug_data_index];
	          aug_data_index++;
	          personality_ptr_padding =
	    	    decode_ptr (bname, personality_rtn_ptr_enc, aug_data,
	    	    	    aug_data_index, offset + aug_data_index,
	    	    	    &(personality_rtn_ptr));
	          aug_data_index += personality_ptr_padding;

	        }
	    }
    }
}


void
cie_class::read_cie (string bname, uint8_t * cie_ptr, uint64_t length, uint64_t
		     offset)
{
  EH_LOG
    ("----------------------------------------------------------------------\n");
  int i = 0;
  cie_id = *((uint32_t *) (cie_ptr + i));
  i = i + sizeof (uint32_t);
  EH_LOG (hex << offset << ":CIE ID: " << cie_id << "\n");
  offset = offset + sizeof (uint32_t);


  version = *(cie_ptr + i);
  EH_LOG (hex << offset << ":version: " << (uint32_t) version << "\n");
  i++;
  offset++;
  int augmentation_str_length = read_cie_augmentation_str (cie_ptr + i);
  i = i + augmentation_str_length + 1;
  offset = offset + augmentation_str_length + 1;

  if (is_eh_data)
    {
      for (int j = 0; j < 8; j++)
	    {
	      eh_data[j] = *(cie_ptr + i);
	      i++;
	      offset++;
	    }
    }

  int sz = read_unsigned_leb128 (cie_ptr + i, &(code_align));
  EH_LOG (hex << offset << ":code align: " << code_align << "\n");
  for (int j = 0; j < sz; j++)
    {
      encoded_code_align.push_back (*(cie_ptr + i));
      i++;
    }
  offset = offset + sz;

  sz = read_unsigned_leb128 (cie_ptr + i, &(data_align));
  EH_LOG (hex << offset << ":data align: " << data_align << "\n");
  for (int j = 0; j < sz; j++)
    {
      encoded_data_align.push_back (*(cie_ptr + i));
      i++;
    }
  offset = offset + sz;
  if (version == 1)
    {
      uint8_t ret_reg = *(cie_ptr + i);
      i++;
      offset++;
      EH_LOG ("return address register: " << hex << (uint32_t) ret_reg << "\n");
      return_reg.push_back (ret_reg);
    }
  else
    {
      uint64_t ret_reg;
      EH_LOG (hex << offset << ":return address register: \n");

      int sz = read_unsigned_leb128 (cie_ptr + i, &ret_reg);
      for (int j = 0; j < sz; j++)
	    {
	      return_reg.push_back (*(cie_ptr + i));
	      i++;
	    }

      offset = offset + sz;

    }
  if (is_aug_data == 1)
    {
      //EH_LOG(hex<<offset<<":aug data length: \n");
      int sz = read_unsigned_leb128 (cie_ptr + i, &(aug_data_length));
      EH_LOG (hex << offset << ":aug data length: " << aug_data_length << "\n");
      for (int j = 0; j < sz; j++)
	    {
	      encoded_aug_data_length.push_back (*(cie_ptr + i));
	      i++;
	    }

      offset = offset + sz;
      EH_LOG ("augmentation data: \n");
      uint64_t aug_data_offset = offset;
      uint64_t data_len = aug_data_length;
      for (int ctr = 0; ctr < data_len; ctr++)
	    {
	      uint8_t c = *(cie_ptr + i);
	      //EH_LOG(hex<<offset<<":"<<hex<<(uint32_t)c<<" ");
	      aug_data.push_back (c);
	      i++;
	      offset++;
	    }
      EH_LOG ("\n");
      decode_cie_aug_data (bname, aug_data_offset);
      EH_LOG ("personality routine enc:"
	      << hex << (uint32_t) (personality_rtn_ptr_enc) << "personality \
				routine: " << hex << personality_rtn_ptr << "\n");
      EH_LOG ("FDE pointer enc: " << hex << (uint32_t) (fde_ptr_enc) << "\n");
      EH_LOG ("LSDA pointer enc: " << hex << (uint32_t) (lsda_ptr_enc) << "\n");
    }
  EH_LOG ("bytes read: " << i << "\n");
  EH_LOG ("initial instructions: " << "\n");
  while (i < length)
    {
      uint8_t c = *(cie_ptr + i);
      initial_instructions.push_back (c);
      EH_LOG (hex << offset << ":" << hex << (uint32_t) c << " ");
      i++;
      offset++;
    }
  EH_LOG ("\n");
  EH_LOG
    ("-----------------------------------------------------------------------\n");
}


void
cie_class::print_cie (uint64_t data_segment, string print_file, set <uint64_t>
    fde_to_remove)
{
  ofstream ofile;
  ofile.open (print_file, ofstream::out | ofstream::app);
  ofile << "." << location << "_cie_struct:" << "\n";
  if (length != 0xffffffff)
    ofile << ".long .cie_" << location << "_end - .cie_" << location << "_start"
      << "\n";
  else
    {
      ofile << ".long " << length << "\n";
      ofile << ".quad .cie_" << location << "_end - .cie_" << location <<
	"_start" << "\n";
    }
  ofile << ".cie_" << location << "_start:" << "\n";
  ofile << ".long " << cie_id << "\n";
  ofile << ".byte " << (uint32_t) version << "\n";
  ofile << ".cie_" << location << "_aug_string:\n";

  for (int j = 0; j < aug_string.length (); j++)
    {
      ofile << ".byte " << (uint32_t) aug_string[j] << "\n";
    }

  ofile << ".byte " << (uint32_t) '\0' << "\n";

  ofile << ".cie_" << location << "_eh_data:\n";
  if (is_eh_data == 1)
    {
      for (int j = 0; j < 8; j++)
	    {
	      ofile << ".byte " << (uint32_t) eh_data[j] << "\n";
	    }
    }

  for (int j = 0; j < encoded_code_align.size (); j++)
    ofile << ".byte " << (uint32_t) encoded_code_align[j] << "\n";

  for (int j = 0; j < encoded_data_align.size (); j++)
    ofile << ".byte " << (uint32_t) encoded_data_align[j] << "\n";

  for (int j = 0; j < return_reg.size (); j++)
    ofile << ".byte " << (uint32_t) return_reg[j] << "\n";


  ofile << ".cie_" << location << "_aug_data_length:\n";

  if (is_aug_data == 1)
    {
      for (int j = 0; j < encoded_aug_data_length.size (); j++)
	    {
	      ofile << ".byte " << (uint32_t) encoded_aug_data_length[j] << "\n";
	    }

      ofile << ".cie_" << location << "_aug_data:\n";

      ofile << print_cie_aug_data (data_segment);
    }
  ofile << ".cie_" << location << "_initial_ins:\n";

  for (int j = 0; j < initial_instructions.size (); j++)
    ofile << ".byte " << (uint32_t) initial_instructions[j] << "\n";

  ofile << ".align 8,0x0\n";
  ofile << ".cie_" << location << "_end:" << "\n";
  for (int j = 0; j < fde_list.size (); j++)
    {
      if(fde_to_remove.find(fde_list[j].get_pc_begin()) == fde_to_remove.end())
      {
        string fde = fde_list[j].print_fde ();	//change the params
        ofile << fde << "\n";
      }
    }
  ofile.close ();

}

string
cie_class::print_cie_aug_data (uint64_t data_segment)
{
  int aug_data_index = 0;
  string aug_str = "";
  for (int i = 1; i < aug_string.length (); i++)
    {
      if (aug_string[i] == 'L')
	    {
          aug_str += ".byte " + to_string ((uint32_t) lsda_ptr_enc) + "\n";
	      aug_data_index++;
	    }
      else if (aug_string[i] == 'R')
	    {
	      aug_str += ".byte " + to_string ((uint32_t) fde_ptr_enc) + "\n";
	      aug_data_index++;

	    }
      else if (aug_string[i] == 'P')
	    {
	      aug_str += ".byte "
	        + to_string ((uint32_t) personality_rtn_ptr_enc) + "\n";
	      aug_data_index++;
	      aug_str += "." + to_string (location) + "_prsnlty:\n";
	      string ptr_str;
          bool data_seg_rltv = false;
	      if (personality_rtn_ptr >= data_segment) {
	        ptr_str = ".datasegment_start";// + " + to_string (personality_rtn_ptr - data_segment);
            data_seg_rltv = true;
          }
	      else
	        ptr_str = to_string (personality_rtn_ptr);
          string loc_lbl = "." + to_string (location) + "_prsnlty";
          if(data_seg_rltv)
            loc_lbl += " + " + to_string(personality_rtn_ptr - data_segment);
	      aug_str += print_encoded_ptr (loc_lbl, ptr_str, personality_rtn_ptr_enc);

	    }
    }
  return aug_str;
}

uint64_t
cie_class::get_location ()
{
  return location;
}

uint8_t
cie_class::get_fde_enc ()
{
  return fde_ptr_enc;
}


uint8_t
cie_class::get_is_aug_data ()
{
  return is_aug_data;
}

vector < uint8_t > cie_class::get_initial_instructions ()
{
  return initial_instructions;
}

map < uint64_t, uint64_t > cie_class::get_frames ()
{
  map < uint64_t, uint64_t > frames;
  for (int i = 0; i < fde_list.size (); i++)
    {
      frames[fde_list[i].get_pc_begin ()] = fde_list[i].get_pc_begin ()
	+ fde_list[i].get_pc_range ();
    }
  return frames;
}

void
cie_class::add_fde (fde_class f)
{
  fde_list.push_back (f);
}

uint8_t
cie_class::get_is_lsda ()
{
  return is_lsda_ptr;
}
