#include "lsda.h"
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

//extern map <uint64_t,int> targets;
extern map < uint64_t, call_site_info > all_call_sites;

lsda_class::lsda_class (uint64_t p_pc_begin)
{
  pc_begin = p_pc_begin;
}

void
lsda_class::read_lsda (string fname, uint64_t lsda_location)
{
  EH_LOG ("------------------LSDA data-------------------" << "\n");
  location = lsda_location;
  EH_LOG ("location: " << hex << lsda_location << "\n");

  //int act_index = 0;
  uint8_t *gcc_except_table;
  ElfClass elf_obj (fname.c_str ());
  Elf64_Shdr *sh = elf_obj.elfSectionHdr (".gcc_except_table").sh;
  uint64_t section_offset = sh->sh_offset;
  uint64_t section_size = sh->sh_size;
  gcc_except_table = (uint8_t *) malloc (section_size);
  utils::READ_FROM_FILE (fname, gcc_except_table, section_offset, section_size);

  int index = lsda_location - sh->sh_addr;


  EH_LOG ("index: " << index << "\n");

  vector < uint8_t > data;

  base_enc = gcc_except_table[index];
  index++;
  lsda_location++;

  EH_LOG ("base encoding: " << hex << (uint32_t) base_enc << "\n");

  if (base_enc != DW_EH_PE_omit)
    {
      base_padding =
	    get_encoded_value (fname, base_enc, lsda_location,
			   gcc_except_table + index, &base);
      for (int i = 0; i < base_padding; i++)
	    {
	      encoded_base.push_back (gcc_except_table[index]);
	      index++;
	    }
      lsda_location += base_padding;
      EH_LOG ("landing pad base: " << hex << base << "\n");
    }
  else
    {
      base = pc_begin;
      EH_LOG ("landing pad base same as pc begin: " << hex << pc_begin << "\n");
    }

  type_table_enc = gcc_except_table[index];
  EH_LOG ("type table enc: " << hex << (uint32_t) type_table_enc << "\n");
  index++;
  lsda_location++;
  if (type_table_enc != DW_EH_PE_omit)
    {
      type_table_ptr_padding = read_unsigned_leb128 (gcc_except_table
						     + index, &type_table_ptr);
      for (int i = 0; i < type_table_ptr_padding; i++)
	    {
	      encoded_type_table_ptr.push_back (gcc_except_table[index]);
	      index++;
	      lsda_location++;
	    }
      EH_LOG ("PC: " << hex << lsda_location << " type table offset from pc: "
	      << hex << type_table_ptr << "\n");
      type_table_ptr += lsda_location;
    }

  call_site_table_enc = gcc_except_table[index];
  index++;
  lsda_location++;

  EH_LOG ("call site encoding: " << hex << (uint32_t) call_site_table_enc <<
	  "\n");

  uint64_t call_site_length;
  call_site_table_length_padding = read_unsigned_leb128 (gcc_except_table
							 + index,
							 &call_site_length);
  call_site_table_length = call_site_length;
  for (int i = 0; i < call_site_table_length_padding; i++)
    {
      encoded_call_site_table_length.push_back (gcc_except_table[index]);
      index++;
      lsda_location++;
    }
  EH_LOG ("call site table length: " << hex << call_site_table_length << "\n");
  read_call_site_table (fname, gcc_except_table, index, lsda_location);
  index += call_site_table_length;
  lsda_location += call_site_table_length;

  //read action table
  //

  int max_tt_index = 0;
  EH_LOG ("\naction table:\n");
  //while(act_index)
  uint64_t act_tbl_size = 0;
  for (int i = 0; i < call_site_table.size (); i++)
    {
      if (call_site_table[i].action_index != 0)
	    {
	      int act_offt = call_site_table[i].action_index - 1;
	      while (1)
	        {
	          action_table_entry act;
	          int cnt = read_signed_leb128 (gcc_except_table + index
	    				    + act_offt, &act.index);
	          act_offt += cnt;
	          cnt = read_signed_leb128 (gcc_except_table + index
	    				+ act_offt, &act.offt);
	          if ((act_offt + cnt) > act_tbl_size)
	    	    act_tbl_size = act_offt + cnt;

	          act_offt += act.offt;
	          action_table.push_back (act);
	          EH_LOG (dec << (int) act.index << " - " << (int) act.
	    	      offt << "\n");
	          if (act.index > max_tt_index)
	    	    max_tt_index = act.index;
	          if (act.offt == 0)
	    	    break;
	        }
	    }
    }

  for (int i = 0; i < act_tbl_size; i++, index++, lsda_location++)
    encoded_action_table.push_back (*(gcc_except_table + index));


  //read type table
  uint64_t type_tbl_index = type_table_ptr - sh->sh_addr;

  //Assuming that type table encoding is always 0x9b or 0x1b
  uint64_t tt_start = type_table_ptr;
  EH_LOG ("\nType table:\n");
  while (max_tt_index > 0)
    {
      tt_start -= 4;
      EH_LOG (tt_start << ":");
      uint64_t tt_entry;
      int cnt =
	    get_encoded_value (fname, 0x9b, tt_start,
			   gcc_except_table + type_tbl_index - 4, &tt_entry);
      type_tbl_index -= cnt;
      type_table.push (tt_entry);
      EH_LOG (hex << tt_entry << "\n");
      max_tt_index--;
    }
  free (gcc_except_table);

}

void
lsda_class::read_call_site_table (string bname, uint8_t * gcc_except_table, int
				  index, uint64_t offset)
{
  EH_LOG ("------------call site info---------------" << "\n");
  int byte_count = 0;
  while (byte_count < call_site_table_length)
    {
      call_site_info call_site;
      call_site_entry c;
      /*start value needs to be recalculated as offset from lnding pad base
       * while rewriting lsda*/
      c.start_padding =
	    get_encoded_value (bname, call_site_table_enc, offset,
			   gcc_except_table + index, &(c.start));
      call_site.start = base + c.start;
      for (int i = 0; i < c.start_padding; i++)
	    {
	      c.encoded_start.push_back (gcc_except_table[index]);
	      index++;
	      offset++;
	      byte_count++;
	    }
      EH_LOG ("call site instruction start: " << hex << c.start << "\n");

      uint64_t length;

      int sz = get_encoded_value (bname, call_site_table_enc & 0x0f, offset,
          gcc_except_table + index, &length);
      for (int j = 0; j < sz; j++)
      {
        c.encoded_length.push_back (*(gcc_except_table + index));
        index++;
      }
      offset += sz;

      c.length = length;
      call_site.length = length;


      EH_LOG ("instruction length: " << hex << c.length << "\n");
      c.length_padding = sz;

      byte_count += sz;
      c.landing_pad_ptr_padding =
	    get_encoded_value (bname, call_site_table_enc, offset,
			   gcc_except_table + index, &(c.landing_pad_ptr));
      for (int i = 0; i < c.landing_pad_ptr_padding; i++)
	    {
	      c.encoded_landing_pad_ptr.push_back (gcc_except_table[index]);
	      index++;
	      offset++;
	      byte_count++;
	    }
      if (c.landing_pad_ptr != 0)
	    {
	      call_site.landing_pad = c.landing_pad_ptr + base;
	      //targets[call_site.landing_pad] = 1;
	    }
      all_call_sites[call_site.start] = call_site;
      EH_LOG ("landing pad pointer: " << hex << c.landing_pad_ptr << "\n");

      sz = read_unsigned_leb128 (gcc_except_table + index, &(c.action_index));
      c.action_index_padding = sz;
      for (int i = 0; i < sz; i++)
	    {
	      c.encoded_action_index.push_back (gcc_except_table[index]);
	      index++;
	      offset++;
	      byte_count++;
	    }
      EH_LOG ("action table index: " << hex << c.action_index << "\n");
      call_site_table.push_back (c);
    }

}

void
lsda_class::print_lsda (uint64_t data_segment)
{

  ofstream lsda_file;
  lsda_file.open ("gcc_except_table.s", ofstream::out | ofstream::app);
  lsda_file << "." << location << ":\n";
  lsda_file << ".byte " << (uint32_t) base_enc << "\n";

  if (base_enc != 0xff)
    {
      string cur_location = ".lsda_" + to_string (location) + "_base";
      lsda_file << cur_location << ":\n";
      lsda_file << print_encoded_ptr (cur_location, "."
				      + to_string (base), base_enc);
    }
  lsda_file << ".byte " << (uint32_t) type_table_enc << "\n";

  if (type_table_enc != 0xff)
    {
      lsda_file << ".uleb128 ." << location << "_tt_end - ."
	<< location << "_tt_base\n";
    }
  lsda_file << "." << location << "_tt_base:\n";
  lsda_file << ".byte " << (uint32_t) call_site_table_enc << "\n";
  lsda_file << ".uleb128 ." << location << "_call_site_tbl_end - ."
    << location << "_call_site_tbl_start\n";
  ifstream ifile;
  ifile.open ("tmp/call_site_tbl_" + to_string (pc_begin) + ".s");
  string str;
  lsda_file << "." << location << "_call_site_tbl_start:\n";
  while (getline (ifile, str))
    {
      lsda_file << str << "\n";
    }
  lsda_file << "." << location << "_call_site_tbl_end:\n";
  ifile.close ();

  lsda_file << "." << location << "_action_table:\n";
  for (int j = 0; j < encoded_action_table.size (); j++)
    lsda_file << ".byte " << (uint32_t) encoded_action_table[j] << "\n";

  lsda_file << ".align 4\n";
  lsda_file << "." << location << "_tt_start:\n";
  int tt_ctr = 0;
  while (!type_table.empty ())
    {
      string cur_location = "." + to_string (location) + "_tt_entry_"
	+ to_string (tt_ctr);
      lsda_file << "." << location << "_tt_entry_" << tt_ctr << ":\n";
      uint64_t tt_entry = type_table.top ();
      string tt_entry_str;
      if (tt_entry >= data_segment)
	tt_entry_str = ".datasegment_start + " + to_string (tt_entry
							    - data_segment);
      else
	tt_entry_str = "." + to_string (tt_entry);
      tt_entry_str
	= print_encoded_ptr (cur_location, tt_entry_str, type_table_enc);
      lsda_file << tt_entry_str << "\n";
      type_table.pop ();
      tt_ctr++;
    }
  lsda_file << "." << location << "_tt_end:\n";
  lsda_file.close ();
}



void
lsda_class::print_call_site_tbl (uint64_t addrs, uint64_t start)
{
  ofstream lsda_file;
  lsda_file.open ("tmp/call_site_tbl_" + to_string (pc_begin)
		  + ".s", ofstream::out | ofstream::app);
  for (int j = 0; j < call_site_table.size (); j++)
    {
      uint64_t call_site_start = call_site_table[j].start + base;
      if (call_site_start == start)
	    {
	      EH_LOG ("::::rewriting call site tbl - call_site found:"
	    	  << hex << start << "\n");
	      string ptr_str
	        = print_encoded_ptr_lvl2 (call_site_table_enc, ".call_site_"
	    			      + to_string (addrs) + " - .frame_"
	    			      + to_string (pc_begin));
	      lsda_file << ptr_str << "\n";

	      ptr_str = print_encoded_ptr_lvl2 (call_site_table_enc, ".call_site_"
	    				    + to_string (addrs) +
	    				    "_end - .call_site_" +
	    				    to_string (addrs));

	      lsda_file << ptr_str << "\n";

	      EH_LOG ("::::rewriting call site tbl - landing pad: "
	    	  << hex << call_site_table[j].landing_pad_ptr << "\n");

	      if (call_site_table[j].landing_pad_ptr == 0)
	        lsda_file << ".uleb128 0\n";
	      else
	        {
	          uint64_t pad = call_site_table[j].landing_pad_ptr + base;
	          EH_LOG ("old pad: " << hex << pad << "\n");
	          ptr_str = "." + to_string (pad) + " - .frame_"
	    	+ to_string (pc_begin);
	          ptr_str = print_encoded_ptr_lvl2 (call_site_table_enc, ptr_str);

	          lsda_file << ptr_str << "\n";
	        }
	      for (int k = 0; k < call_site_table[j].encoded_action_index.size ();
	           k++)
	        lsda_file << ".byte " << (uint32_t) call_site_table[j].
	          encoded_action_index[k] << "\n";

	      break;
	    }
    }

  lsda_file.close ();

}

uint64_t
lsda_class::get_pc_begin ()
{
  return pc_begin;
}
