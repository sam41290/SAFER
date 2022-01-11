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

/* Global counters used while reading EH_FRAME.*/
int cie_ctr = 0;
int cur_cie = 0;

//Info regarding try/catch blocks and corresponding launch pads. EH terminology
//names them as call sites, so we will also call them the same.
map < uint64_t, call_site_info > all_call_sites;

//unwinding metadata per function. Function address is the key
map < uint64_t, cfi_table > unwinding_info;	

uint64_t frame_hdr_offset;
uint64_t frame_offset;
uint64_t frame_hdr_addr;
uint64_t frame_addr;


//set<uint64_t> keep_eh_data;

/* Generic function definitions.
 * Used for encoding and decoding pointers in EH metadata.
 */

int
read_unsigned_leb128 (uint8_t * leb128_start, uint64_t * data)
{
  uint64_t result = 0;
  uint64_t shift = 0;
  int i = 0;
  while (true)
    {
      uint8_t byte = leb128_start[i];
      uint8_t decoded_byte = (byte & 0b01111111);
      //cout<<hex<<(uint32_t)decoded_byte<<"\n";
      result |= (byte & 0b01111111) << shift;
      if (((byte & 0b10000000) >> 7) == 0)
	    break;
      shift += 7;
      i++;
    }
  //EH_LOG(hex<<result<<"\n");
  *data = result;
  return i + 1;
}


vector < uint8_t > encode_unsigned_leb128 (uint64_t data, int padding = 0)
{
  vector < uint8_t > byte_array;
  uint8_t byte = 0;
  int count = 0;
  while (1)
    {
      byte = data & 0x7f;
      data = data >> 7;
      count++;
      EH_LOG ("byte: " << hex << (uint32_t) byte << "\n");
      if (data == 0)
	    break;
      else
	    {
	      byte = byte | 0b10000000;
	      byte_array.push_back (byte);
	      //count++;
	    }
    }
  if (count < padding)
    {
      byte = byte | 0b10000000;
      byte_array.push_back (byte);
      count++;
      while (count < padding)
	    {
	      byte_array.push_back (0x80);
	      count++;
	    }
      byte_array.push_back (0x00);
    }
  else
    byte_array.push_back (byte);
  return byte_array;
}

vector < uint8_t > encode_signed_leb128 (int64_t data, int padding = 0)
{
  vector < uint8_t > byte_array;
  uint8_t byte = 0;
  int count = 0;
  while (1)
    {
      byte = data & 0x7f;
      data = data >> 7;
      count++;
      if ((data == 0 && (byte & 0x40 == 0))
	  || (data == -1 && (byte & 0x40 == -1)))
	    break;
      else
	    {
	      byte = byte | 0b10000000;
	      byte_array.push_back (byte);
	    }
    }
  if (count < padding)
    {
      byte = byte | 0b10000000;
      byte_array.push_back (byte);
      count++;
      while (count < padding)
	    {
	      byte_array.push_back (0x80);
	      count++;
	    }
      byte_array.push_back (0x00);
    }
  else
    byte_array.push_back (byte);
  return byte_array;
}

int
read_signed_leb128 (uint8_t * leb128_start, int64_t * data)
{
  int result = 0;
  uint64_t shift = 0;
  int i = 0;
  uint8_t byte;
  while (true)
    {
      byte = leb128_start[i];
      uint8_t decoded_byte = (byte & 0b01111111);
      //cout<<hex<<(uint32_t)decoded_byte<<"\n";
      result |= (byte & 0b01111111) << shift;
      shift += 7;
      if (((byte & 0b10000000) >> 7) == 0)
	break;
      //shift += 7;
      i++;
    }
  int num_bits = 8 * sizeof (result);
  //cout<<"num bits: "<<dec<<num_bits<<"\n";
  if ((shift < num_bits) && (byte & 0x40))
    result |= (-1 << shift);
  //cout<<hex<<result<<"\n";
  *data = result;
  return i + 1;
}


int
decode_ptr2 (uint8_t size_enc, vector < uint8_t > data, int index,
	     uint64_t * ptr)
{
  /* Given a vector of bytes and encoding format (size_enc), function decodes
   * the value and fills *ptr.
   */
  uint64_t addend_u64;
  uint16_t addend_u16;
  uint32_t addend_u32;
  int64_t addend_64;
  int16_t addend_16;
  int32_t addend_32;

  uint8_t uleb_data[data.size () - index];

  int sz;
  string addr = "";
  switch (size_enc)
    {
    case DW_EH_PE_omit:
      return 0;
      break;
    case DW_EH_PE_uleb128:
      for (int i = index; i < data.size (); i++)
	    uleb_data[i] = data[i];
      sz = read_unsigned_leb128 (&(uleb_data[0]), &addend_u64);
      *ptr = *(ptr) + addend_u64;
      return sz;
    case DW_EH_PE_udata2:
      //string addr = "";
      for (int i = index; i < (index + 2); i++)
	    {
	      string byte = utils::decToHexa ((int) data[i]);
	      if (byte.length () == 1)
	        byte = "0" + byte;
	      addr = byte + addr;
	    }
      //uint16_t addend;
      addend_u16 = stol (addr, 0, 16);
      *ptr = *ptr + addend_u16;
      return 2;
    case DW_EH_PE_udata4:
      //string addr = "";
      for (int i = index; i < (index + 4); i++)
	    {
	      //string byte = to_string(data[i]);
	      string byte = utils::decToHexa ((int) data[i]);
	      if (byte.length () == 1)
	        byte = "0" + byte;
	      addr = byte + addr;
	    }
      addend_u32 = stol (addr, 0, 16);
      *ptr = *ptr + addend_u32;
      return 4;
    case DW_EH_PE_udata8:
      //string addr = "";
      for (int i = index; i < (index + 8); i++)
	    {
	      //string byte = to_string(data[i]);
	      string byte = utils::decToHexa ((int) data[i]);
	      if (byte.length () == 1)
	        byte = "0" + byte;
	      addr = byte + addr;
	    }
      addend_u64 = stol (addr, 0, 16);
      *ptr = *ptr + addend_u64;
      return 8;
    case DW_EH_PE_sleb128:
      //uint8_t uleb_data[data.size() - index];
      for (int i = index; i < data.size (); i++)
	uleb_data[i] = data[i];
      //int64_t ptr;
      addend_64;
      sz = read_signed_leb128 (&(uleb_data[0]), &addend_64);
      *ptr = (uint64_t) ((int64_t) (*ptr) + addend_64);
      return sz;
    case DW_EH_PE_sdata2:
      //string addr = "";
      for (int i = index; i < (index + 2); i++)
	    {
	      //string byte = to_string(data[i]);
	      string byte = utils::decToHexa ((int) data[i]);
	      if (byte.length () == 1)
	        byte = "0" + byte;
	      addr = byte + addr;
	    }
      addend_16;
      addend_16 = stol (addr, 0, 16);
      *ptr = (uint64_t) ((*ptr) + addend_16);
      return 2;
    case DW_EH_PE_sdata4:
      //string addr = "";
      for (int i = index; i < (index + 4); i++)
	    {
	      //string byte = to_string(data[i]);
	      string byte = utils::decToHexa ((int) data[i]);
	      if (byte.length () == 1)
	        byte = "0" + byte;
	      addr = byte + addr;
	    }
      addend_32 = stol (addr, 0, 16);
      //cout<<"Addend: "<<hex<<addend_32<<" "<<addr<<"\n";
      *ptr = (uint64_t) ((*ptr) + addend_32);
      return 4;
    case DW_EH_PE_sdata8:
      //string addr = "";
      for (int i = index; i < (index + 8); i++)
	    {
	      //string byte = to_string(data[i]);
	      string byte = utils::decToHexa ((int) data[i]);
	      if (byte.length () == 1)
	        byte = "0" + byte;
	      addr = byte + addr;
	    }
      addend_64 = stol (addr, 0, 16);
      *ptr = (uint64_t) ((*ptr) + addend_64);
      return 8;

    }

}

/*
vector<uint8_t> encode_ptr2(uint8_t size_enc,uint64_t data, int padding)
{
	vector<uint8_t> encoded_byte;

	string addr = "";
	switch(size_enc)
	{
		case DW_EH_PE_omit:
			return encoded_byte;
			break;
		case DW_EH_PE_uleb128:
			//uint8_t uleb_data[data.size() - index];
			cout<<"unsigned leb128 encoding\n";
			encoded_byte = encode_unsigned_leb128(data,padding);
			return encoded_byte;
		case DW_EH_PE_udata2:
			//string addr = "";
			for(int i = 0 ; i<2 ;i++)
			{
				uint8_t byte = data & 0xff;
				encoded_byte.push_back(byte);
				data = data >> 8;
			}
			return encoded_byte;
		case DW_EH_PE_udata4:
			//string addr = "";
			for(int i = 0 ; i<4 ;i++)
			{
				//string byte = to_string(data[i]);
				uint8_t byte = data & 0xff;
				encoded_byte.push_back(byte);
				data = data >> 8;
			}
			return encoded_byte;
		case DW_EH_PE_udata8:
			 //string addr = "";
			 for(int i = 0 ; i<8 ;i++)
			{
				//string byte = to_string(data[i]);
				uint8_t byte = data & 0xff;
				encoded_byte.push_back(byte);
				data = data >> 8;
			}
			return encoded_byte;
		case DW_EH_PE_sleb128:
			//uint8_t uleb_data[data.size() - index];
			encoded_byte = encode_signed_leb128(data,padding);
			return encoded_byte;
		case DW_EH_PE_sdata2:
			//string addr = "";
			for(int i = 0 ; i<2 ;i++)
			{
				//string byte = to_string(data[i]);
				uint8_t byte = data & 0xff;
				encoded_byte.push_back(byte);
				data = data >> 8;
			}
			return encoded_byte;
		case DW_EH_PE_sdata4:
			//string addr = "";
			for(int i = 0 ; i<4 ;i++)
			{
				//string byte = to_string(data[i]);
				uint8_t byte = data & 0xff;
				encoded_byte.push_back(byte);
				data = data >> 8;
			}
			return encoded_byte;
		case DW_EH_PE_sdata8:
			//string addr = "";
			for(int i = 0 ; i<8 ;i++)
			{
				//string byte = to_string(data[i]);
				uint8_t byte = data & 0xff;
				encoded_byte.push_back(byte);
				data = data >> 8;
			}
			return encoded_byte;

	}

}

*/

int
decode_ptr (string bname, uint8_t enc, vector < uint8_t > data, int index,
	    uint64_t offset, uint64_t * ptr)
{

  /* Given a vector of bytes and encoding format (enc), determines whether the
   * encoded value is absolute or relative.
   * It then decodes accordingly.
   */

  uint8_t rel = enc & 0xf0;
  uint8_t ptr_size = enc & 0x0f;
  if (ptr_size == DW_EH_PE_omit)
    return 0;

  switch (rel & 0x70)
    {
    case DW_EH_PE_absptr:
      *ptr = 0;
      return decode_ptr2 (ptr_size, data, index, ptr);
      //break;
    case DW_EH_PE_pcrel:
      //EH_LOG("PC: "<<hex<<offset<<" file: "<<bname<<"\n");
      *ptr = utils::GET_ADDRESS (bname, offset);
      return decode_ptr2 (ptr_size, data, index, ptr);
      //break;
    case DW_EH_PE_datarel:
      *ptr = utils::GET_ADDRESS (bname, frame_hdr_offset);
      return decode_ptr2 (ptr_size, data, index, ptr);
      //break;
    case DW_EH_PE_omit:
      *ptr = 0;
      return 0;
    default:
      *ptr = 0;
      return decode_ptr2 (ptr_size, data, index, ptr);

      //break;

    }
  return 0;
}

/*
vector<uint8_t> encode_ptr(string bname,uint8_t enc,uint64_t data,uint64_t
		offset,uint64_t code_segment_offset,int padding)
{
	uint8_t rel = enc & 0xf0;
	uint8_t ptr_size = enc & 0x0f;
	vector<uint8_t> encoded_array;
	uint64_t new_frame_hdr_offset;
	uint64_t new_frame_hdr_addrs;
	uint64_t address;
	if(ptr_size == DW_EH_PE_omit)
		return encoded_array;	


	EH_LOG("Old ptr: "<<hex<<data<<"\n");
	uint64_t new_offset = ul.GET_OFFSET(".frame_" + to_string(data),code_segment_offset);
	if(new_offset == -1)
		new_offset = ul.GET_OFFSET(data,code_segment_offset);
	data = utils::GET_ADDRESS(bname,new_offset);
	EH_LOG("New ptr: "<<hex<<data<<" offset: "<<offset<<"\n");

	switch(rel & 0x70)
	{
		case DW_EH_PE_absptr:
			encoded_array = encode_ptr2(ptr_size,data,padding);
			return encoded_array;
		case DW_EH_PE_pcrel:
			encoded_array = encode_ptr2(ptr_size,data - offset,padding);
			return encoded_array;
		case DW_EH_PE_datarel:
			new_frame_hdr_offset = ul.GET_OFFSET(frame_hdr_offset,code_segment_offset);
			new_frame_hdr_addrs = utils::GET_ADDRESS(bname,new_frame_hdr_offset);
			encoded_array = encode_ptr2(ptr_size,data - new_frame_hdr_addrs,padding);
			return encoded_array;
		case DW_EH_PE_omit:
			return encoded_array;
		default:
			encoded_array = encode_ptr2(ptr_size,data,padding);
			return encoded_array;

	}
	return encoded_array;
}
*/
int
get_encoded_value (string bname, uint8_t enc, uint64_t offset, uint8_t * data,
		   uint64_t * ptr)
{

  int byte_count = -1;
  switch (enc & 0x0f)
    {
    case DW_EH_PE_udata2:
      byte_count = 2;
      break;
    case DW_EH_PE_udata4:
      byte_count = 4;
      break;
    case DW_EH_PE_udata8:
      byte_count = 8;
      break;
    case DW_EH_PE_sdata2:
      byte_count = 2;
      break;
    case DW_EH_PE_sdata4:
      byte_count = 4;
      break;
    case DW_EH_PE_sdata8:
      byte_count = 8;
      break;
    case DW_EH_PE_uleb128:
      byte_count = -1;
      break;
    case DW_EH_PE_sleb128:
      byte_count = -2;
      break;
    }
  uint64_t decoded_ptr = 0;
  int sz = 0;
  int index = 0;
  vector < uint8_t > byte_array;
  if (byte_count == -1)		//leb128 encoding
    {
      sz = read_unsigned_leb128 (data + index, &decoded_ptr);
      index += sz;
      if (enc & 0x70 == DW_EH_PE_pcrel)
	    {
	      decoded_ptr += offset;
	    }
      offset += sz;
      index += sz;
    }
  else if (byte_count == -2)	//leb128 encoding
    {
      sz = read_signed_leb128 (data + index, (int64_t *) & decoded_ptr);
      index += sz;
      if (enc & 0x70 == DW_EH_PE_pcrel)
	    {
	      decoded_ptr += offset;
	    }
      offset += sz;
      index += sz;

    }
  else
    {
      for (int i = 0; i < byte_count; i++)
	    {
	      byte_array.push_back (data[index]);
	      index++;
	    }
      sz = decode_ptr (bname, enc, byte_array, 0, offset, &decoded_ptr);
    }
  *ptr = decoded_ptr;
  return sz;


}


string
print_encoded_ptr_lvl2 (uint8_t enc, string ptr)
{
  string final_ptr = "";
  switch (enc)
    {
    case DW_EH_PE_uleb128:
      final_ptr += ".uleb128 " + ptr;
      break;
    case DW_EH_PE_udata2:
      final_ptr += ".2byte " + ptr;
      break;
    case DW_EH_PE_udata4:
      final_ptr += ".long " + ptr;
      break;
    case DW_EH_PE_udata8:
      final_ptr += ".quad " + ptr;
      break;
    case DW_EH_PE_sleb128:
      final_ptr += ".sleb128 " + ptr;
      break;
    case DW_EH_PE_sdata2:
      final_ptr += ".2byte " + ptr;
      break;
    case DW_EH_PE_sdata4:
      final_ptr += ".long " + ptr;
      break;
    case DW_EH_PE_sdata8:
      final_ptr += ".quad " + ptr;
      break;
    default:
      return final_ptr;
      break;

    }
  return final_ptr;
}

string
print_encoded_ptr (string cur_location, string ptr_str, uint8_t ptr_enc)
{
  string asm_ptr = "";
  //string ptr_str;

  switch (ptr_enc & 0x70)
    {
    case DW_EH_PE_absptr:
      asm_ptr += ptr_str + "\n";
      asm_ptr = print_encoded_ptr_lvl2 (ptr_enc & 0x0f, asm_ptr);
      break;
    case DW_EH_PE_pcrel:
      asm_ptr += ptr_str + " - " + cur_location + "\n";
      asm_ptr = print_encoded_ptr_lvl2 (ptr_enc & 0x0f, asm_ptr);
      break;
    case DW_EH_PE_datarel:
      asm_ptr += ptr_str + " - .eh_frame_hdr_dup\n";
      asm_ptr = print_encoded_ptr_lvl2 (ptr_enc & 0x0f, asm_ptr);
      break;
    default:
      return asm_ptr;
      break;
    }
  return asm_ptr;
}

void
exception_handler::print_lsda (uint64_t data_segment)
{
  //Print ASM for language specific data

  int i;
  for (i = 0; i < lsda_list.size (); i++)
    {
      lsda_list[i].print_lsda (data_segment);
    }
}

void
exception_handler::print_call_site_tbl (uint64_t addrs, uint64_t start,
					uint64_t pc_begin)
{

  /* Print call sites table - Metadata for try/catch block and corresponding
   * landing pads.
   * pc_begin: Function/frame start.
   *
   * start - start of call site/try-catch block region.
   *
   * addrs - address within try-catch block for which the printing of metadata
   * is triggered.
   *
   * Note: A try-catch block may be broken by randomization. In such case the
   * function will be triggered for the start address of every smaller block.
   *
   */

  EH_LOG ("::::rewriting call site tbl - addrs: " << hex << addrs <<
	  " call site: " << hex << start << "\n");
  for (int i = 0; i < lsda_list.size (); i++)
    {
      if (lsda_list[i].get_pc_begin () == pc_begin)
	    {
	      EH_LOG ("::::rewriting call site tbl - pc begin: " << hex << pc_begin
	    	  << "\n");
	      lsda_list[i].print_call_site_tbl (addrs, start);
	      break;
	    }
    }

}

void
exception_handler::print_eh_frame (uint64_t data_segment)
{
  /* Print ASM directives for every CIE in the EH_FRAME section.
   */
  ofstream ofile;
  ofile.open ("eh_frame.s", ofstream::out | ofstream::app);
  ofile<<"."<<frame_addr<<":\n"; 
  ofile.close();
  for (int i = 0; i < cie.size (); i++)
    {
      cie[i].print_cie (data_segment, "eh_frame.s", fde_to_remove);
    }
  ofile.open ("eh_frame.s", ofstream::out | ofstream::app);
  ofile << ".long 0x0\n";	//Marks end of eh frame section
  ofile.close ();
}

void
exception_handler::read_eh_frame (string fname)
{

  /* Reads the EH frame section and creates CIE and FDE structures.
   */

  ElfClass elf_obj (fname.c_str ());
  Elf64_Shdr *sh = elf_obj.elfSectionHdr (".eh_frame").sh;
  if (sh == NULL)
    {
      EH_LOG ("section eh_frame doesn't exist\n");
      return;
      //exit(0);
    }
  uint64_t eh_frame_offset = sh->sh_offset;
  uint64_t eh_frame_size = sh->sh_size;

  frame_size = eh_frame_size;
  frame_offset = eh_frame_offset;
  frame_addr = utils::GET_ADDRESS (fname, frame_offset);
  uint8_t *eh_frame_ptr = (uint8_t *) malloc (eh_frame_size);

  if (eh_frame_ptr == NULL)
    {
      EH_LOG ("Error assigning memory to eh_frame_ptr" << "\n");
      exit (0);
    }

  utils::READ_FROM_FILE(fname, eh_frame_ptr, eh_frame_offset, eh_frame_size);

  int i = 0;
  uint32_t length = 0;
  uint64_t extended_length = 0;
  uint64_t cie_length = 0;
  uint64_t cie_id = 0;

  /* Eh frame consists of a series of CIE and FDE structures.
   * Each CIE structure is followed by a series of FDE structures.
   * Each CIE and FDE structure is preceded by *LENGTH* field and CIE_ID
   * field.
   * LENGTH field indicates the length of CIE or FDE structure..
   * LENGTH == 0 indicates termination of EH frame section.
   *
   * CIE_ID = 0 implies the following structure is CIE.
   *
   * Non-zero CIE_ID implies the following structure is FDE. 
   *
   */

  while (1)
    {
      uint64_t location = eh_frame_offset;
      if (location >= (frame_offset + frame_size))
        break;
      length = *((uint32_t *) (eh_frame_ptr + i));
      i = i + sizeof (uint32_t);
      eh_frame_offset = eh_frame_offset + sizeof (uint32_t);
      if (length == 0)
	    break;
      else if (length == 0xffffffff)
	    {
	      EH_LOG ("extended length" << "\n");
	      extended_length = *((uint64_t *) (eh_frame_ptr + i));
	      cie_length = extended_length;
	      i = i + sizeof (uint64_t);
	      eh_frame_offset = eh_frame_offset + sizeof (uint64_t);
	    }
      else
	    cie_length = length;

      cie_id = *((uint32_t *) (eh_frame_ptr + i));
      if (cie_id == 0)
	    {
	      cie_class x (length, extended_length, location);
	      //cie.push_back(x);
	      EH_LOG (hex << eh_frame_offset << ":CIE structure found | length: " <<
	    	  cie_length << "\n");
	      x.read_cie (fname, eh_frame_ptr + i, cie_length, eh_frame_offset);
	      cie.push_back (x);
	      cur_cie = cie_ctr;
	      cie_ctr++;
	    }
      else
	    {
	      fde_class f (length, extended_length, location);;
	      EH_LOG (hex << eh_frame_offset << ":FDE structure found | length: " <<
	    	  cie_length << "\n");


	      uint64_t cie_ptr = *((uint32_t *) (eh_frame_ptr + i));
	      //i = i + sizeof(uint32_t);
	      int l;
	      for (l = 0; l < cie.size (); l++)
	        {
	          //Search for the parent CIE of the current FDE.

	          if (cie[l].get_location () == (eh_frame_offset - cie_ptr))
	    	    break;
	        }
	      if (l >= cie.size ())
	        {
	          EH_LOG ("cie not found for FDE at " << hex << eh_frame_offset <<
	    	      "\n");
	          exit (0);
	        }
	      //eh_frame_offset += sizeof(uint32_t);

	      //Set the parent CIE

	      f.set_my_cie (cie[l].get_location (), cie[l].get_fde_enc (),
	    		cie[l].get_lsda_enc (), cie[l].get_is_aug_data (),
	    		cie[l].get_initial_instructions ());

	      f.read_fde (fname, eh_frame_ptr + i + sizeof (uint32_t), cie_length
	    	      - sizeof (uint32_t), eh_frame_offset + sizeof (uint32_t));

	      int lsda_index = 0;

	      if (cie[l].get_is_lsda () == 1
	          && processed_lsda[f.get_lsda_ptr ()] != 1
	          && f.get_lsda_ptr () != 0)
	        {
	          //If FDE has LSDA data assosciated.

	          lsda_class l (f.get_pc_begin ());
	          l.read_lsda (fname, f.get_lsda_ptr ());
	          lsda_list.push_back (l);
	          lsda_index++;
	          processed_lsda[f.get_lsda_ptr ()] = lsda_index;
	        }
	      cie[cur_cie].add_fde (f);
	    }
      i = i + cie_length;
      eh_frame_offset = eh_frame_offset + cie_length;
      //cie_id = *((uint32_t *)(eh_frame + i))
      //i = i + sizeof(uint32_t);
    }
  free (eh_frame_ptr);

}


void
exception_handler::read_eh_frame_hdr (string fname)
{
  /* Read EH_FRAME_HDR section.
   */

  ElfClass elf_obj (fname.c_str ());
  Elf64_Shdr *sh = elf_obj.elfSectionHdr (".eh_frame_hdr").sh;
  if (sh == NULL)
    return;
  uint64_t eh_frame_hdr_offset = sh->sh_offset;
  uint64_t eh_frame_hdr_size = sh->sh_size;


  frame_hdr_offset = eh_frame_hdr_offset;
  frame_hdr_addr = utils::GET_ADDRESS (fname, frame_hdr_offset);

  uint8_t *eh_frame_hdr = (uint8_t *) malloc (eh_frame_hdr_size);

  utils::READ_FROM_FILE(fname, eh_frame_hdr, eh_frame_hdr_offset, eh_frame_hdr_size);

  int i = 0;
  uint8_t version;
  uint8_t eh_frame_ptr_enc;
  uint8_t fde_count_enc;
  uint8_t table_enc;

  version = *(eh_frame_hdr);
  eh_frame_ptr_enc = *(eh_frame_hdr + 1);
  fde_count_enc = *(eh_frame_hdr + 2);
  table_enc = *(eh_frame_hdr + 3);

  EH_LOG
    ("----------------------------eh_frame_hdr-----------------------------" <<
     "\n");
  EH_LOG (hex << eh_frame_hdr_offset << ": " << "VERSION " << hex << (uint32_t)
	  version << "\n");
  eh_frame_hdr_offset++;

  EH_LOG (hex << eh_frame_hdr_offset << ": " << "eh_frame_ptr_enc " << hex <<
	  (uint32_t) eh_frame_ptr_enc << "\n");
  eh_frame_hdr_offset++;
  EH_LOG (hex << eh_frame_hdr_offset << ": " << "fde_count_enc " << hex <<
	  (uint32_t) fde_count_enc << "\n");
  eh_frame_hdr_offset++;
  EH_LOG (hex << eh_frame_hdr_offset << ": " << "table_enc " << hex <<
	  (uint32_t) table_enc << "\n");
  eh_frame_hdr_offset++;

  i = i + 4;


  header.version = version;
  header.eh_frame_ptr_enc = eh_frame_ptr_enc;
  header.fde_count_enc = fde_count_enc;
  header.table_enc = table_enc;


  uint64_t eh_frame_ptr;
  int sz =
    get_encoded_value (fname, eh_frame_ptr_enc, eh_frame_hdr_offset,
		       eh_frame_hdr + i, &eh_frame_ptr);

  for (int j = 0; j < sz; j++)
    {
      header.eh_frame_ptr.push_back (eh_frame_hdr[i]);
      i++;
      eh_frame_hdr_offset++;
    }
  EH_LOG (hex << "eh frame pointer: " << hex << eh_frame_ptr << "\n");
  uint64_t fde_count = 0;

  sz =
    get_encoded_value (fname, fde_count_enc & 0x0f, eh_frame_hdr_offset,
		       eh_frame_hdr + i, &fde_count);
  for(int j=0;j<sz;j++)
    {
      header.fde_count.push_back(*(eh_frame_hdr + i));
      i++;
    }


  EH_LOG (hex << "FDE_COUNT: " << hex << fde_count << "\n");
  EH_LOG ("--------------------LOOK UP TABLE-----------------" << "\n");
  for (int j = 0; j < fde_count; j++)
    {
      struct fde_lookup_tbl_entry x;
      sz =
	    get_encoded_value (fname, table_enc, eh_frame_hdr_offset,
			   (eh_frame_hdr + i), &(x.fde_pc_begin));
      for (int j = 0; j < sz; j++)
	    {
	      x.enc_fde_pc_begin.push_back (eh_frame_hdr[i]);
	      i++;
	      eh_frame_hdr_offset++;
	    }
      x.fde_pc_begin_padding = sz;
      sz =
	    get_encoded_value (fname, table_enc, eh_frame_hdr_offset,
			   (eh_frame_hdr + i), &(x.fde_ptr));
      for (int j = 0; j < sz; j++)
	    {
	      x.enc_fde_ptr.push_back (eh_frame_hdr[i]);
	      i++;
	      eh_frame_hdr_offset++;
	    }
      x.enc_fde_ptr_padding = sz;
      header.lookup_tbl.push_back (x);
      EH_LOG ("entry " << j << ":frame start : " << hex << x.
	      fde_pc_begin << " FDE at: " << hex << x.fde_ptr << "\n");
    }
  free (eh_frame_hdr);		//eh_frame_hdr
  header_size = i;
  EH_LOG
    ("\n---------------------------------------------------------------\n");

}

void
exception_handler::print_bst (uint64_t frame_addrs)
{

  //Create one entry in the BST for the given function address (frame_addrs).

  if(fde_to_remove.find(frame_addrs) != fde_to_remove.end())
    return;

  uint64_t fde = 0;
  for (int i = 0; i < header.lookup_tbl.size (); i++)
    {
      if (header.lookup_tbl[i].fde_pc_begin == frame_addrs)
	    {
	      fde = header.lookup_tbl[i].fde_ptr;
	      break;
	    }
    }
  if (fde == 0)
    {
      LOG ("No FDE for frame: " << hex << frame_addrs << "\n");
      return;
    }
  new_bst_size++;

  ofstream ofile;
  ofile.open ("bst.s", ofstream::out | ofstream::app);
  ofile << ".bst_for_" << frame_addrs << ":\n";
  ofile << print_encoded_ptr (".bst_for_" + to_string (frame_addrs),
			      ".frame_" + to_string (frame_addrs),
			      header.table_enc);
  ofile << print_encoded_ptr (".bst_for_" + to_string (frame_addrs),
			      "." + to_string (fde), header.table_enc);

  //keep_eh_data.insert(frame_addrs);

  ofile.close ();

}

void
exception_handler::print_eh_frame_hdr ()
{

  //Print asm for eh_frame_hdr section.

  ofstream ofile;
  ofile.open ("eh_frame_hdr.s", ofstream::out | ofstream::app);

  ofile << "." << frame_hdr_addr << ":\n";
  ofile << ".byte " << (uint32_t) header.version << "\n";
  ofile << ".byte " << (uint32_t) header.eh_frame_ptr_enc << "\n";
  ofile << ".byte " << (uint32_t) header.fde_count_enc << "\n";
  ofile << ".byte " << (uint32_t) header.table_enc << "\n";
  ofile << ".eh_frame_ptr:\n";
  string frame_ptr =
    print_encoded_ptr (".eh_frame_ptr", ".eh_frame_dup" /*+ to_string (frame_offset)*/,
		       header.eh_frame_ptr_enc);
  ofile << frame_ptr << "\n";
  string bst_size =
    print_encoded_ptr_lvl2 (header.fde_count_enc, to_string (new_bst_size));
  ofile << bst_size << endl;
  //ofile<<".align 4,0x0\n";
  ofile << ".bst_start:\n";
  ifstream ifile;
  ifile.open ("bst.s");		//bst.s file is populated while generating asm for each function. This is done in order to maitain the order of BST entries according to the permutation of functions in new executable

  string str;
  while (getline (ifile, str))
    {
      ofile << str + "\n";
    }

  ifile.close ();
  ofile.close ();


}

/*
void exception_handler::rewrite_eh_frame_hdr(string bname,uint64_t
		code_segment_offset)
{

	//if(lsda_list.size()>0)
      //  rewrite_lsda(bname,code_segment_offset);


	EH_LOG("recreating eh_frame_hdr\n");
	utils ul;
	uint64_t new_hdr_offset = ul.GET_OFFSET(frame_hdr_offset, code_segment_offset);
	uint64_t new_hdr_addrs = utils::GET_ADDRESS(bname,new_hdr_offset);
	uint8_t * new_frame_hdr = (uint8_t *)malloc(header_size);

	int index = 0;

	new_frame_hdr[index] = header.version;
	index++;
	new_hdr_addrs++;
	new_frame_hdr[index] = header.eh_frame_ptr_enc;
	index++;
	new_hdr_addrs++;
	new_frame_hdr[index] = header.fde_count_enc;
	index++;
	new_hdr_addrs++;
	new_frame_hdr[index] = header.table_enc;
	index++;
	new_hdr_addrs++;

	for(int i=0;i<header.eh_frame_ptr.size();i++)
	{
		new_frame_hdr[index] = header.eh_frame_ptr[i];
		index++;
		new_hdr_addrs++;
	}

	for(int i=0;i<header.fde_count.size();i++)
	{
		new_frame_hdr[index] = header.fde_count[i];
		index++;
		new_hdr_addrs++;
	}

	map<uint64_t,fde_lookup_tbl_entry> lkp_tbl;
	int lkp_tbl_sz = header.lookup_tbl.size();
	for(int i=0;i<lkp_tbl_sz;i++)
	{
		uint64_t new_pc_begin
			= ul.GET_OFFSET(header.lookup_tbl[i].fde_pc_begin,code_segment_offset);
		new_pc_begin = utils::GET_ADDRESS(bname,new_pc_begin);

		fde_lookup_tbl_entry f;
		f.fde_pc_begin = new_pc_begin;
		f.enc_fde_pc_begin
			= encode_ptr(bname,header.table_enc,header.lookup_tbl[i].fde_pc_begin,new_hdr_addrs,code_segment_offset,header.lookup_tbl[i].fde_pc_begin_padding);
		uint64_t new_fde_ptr = ul.GET_OFFSET(header.lookup_tbl[i].fde_ptr,code_segment_offset);
        new_fde_ptr = utils::GET_ADDRESS(bname,new_fde_ptr);
		
		f.enc_fde_ptr = encode_ptr(bname,header.table_enc,header.lookup_tbl[i].fde_ptr,new_hdr_addrs,code_segment_offset,header.lookup_tbl[i].enc_fde_ptr_padding);
		lkp_tbl[new_pc_begin] = f;
		
	}
	map<uint64_t,fde_lookup_tbl_entry> :: iterator lkp_tbl_it;
	lkp_tbl_it = lkp_tbl.begin();
	while(lkp_tbl_it!=lkp_tbl.end())
	{
		for(int j=0;j<lkp_tbl_it->second.enc_fde_pc_begin.size();j++)
		{
			new_frame_hdr[index] = lkp_tbl_it->second.enc_fde_pc_begin[j];
			index++;
			new_hdr_addrs++;
		}

		for(int j=0;j<lkp_tbl_it->second.enc_fde_ptr.size();j++)
		{
			new_frame_hdr[index] = lkp_tbl_it->second.enc_fde_ptr[j];
			index++;
			new_hdr_addrs++;
		}
		lkp_tbl_it++;
	}

	utils::WRITE_TO_FILE(bname,new_frame_hdr,new_hdr_offset,header_size);
	free(new_frame_hdr);
}

*/

map < uint64_t, uint64_t > exception_handler::get_all_frame_address ()
{

  //Returns all EH frame start and size

  map < uint64_t, uint64_t > frames;
  int
    cie_sz = cie.size ();
  for (int i = 0; i < cie_sz; i++)
    {
      map < uint64_t, uint64_t > cie_frames = cie[i].get_frames ();
      frames.insert (cie_frames.begin (), cie_frames.end ());
    }
  return frames;
}

void exception_handler::add_fde_to_remove(uint64_t frame_addrs)
{
  fde_to_remove.insert(frame_addrs);
}

//int main(int argc, char *args[])
//{
//      string binname(args[1]);
//      eh_frame.read_eh_frame_hdr(binname);
//      eh_frame.read_eh_frame(binname);
//      map<uint64_t,uint64_t> all_frames = eh_frame.get_all_frame_address();
//      ofstream ofile;
//      ofile.open(binname + ".unwinding_info");
//      ofile<<"[eh info] Number of functions with exception handling: "<<dec<<eh_frame.lsda_list.size()<<"\n"<<"\n";
//      for(int i=0;i<eh_frame.lsda_list.size();i++)
//      {
//              ofile<<"[eh info] Function at(hex address): "<<hex<<eh_frame.lsda_list[i].pc_begin<<"|range(bytes): "<<dec<<all_frames[eh_frame.lsda_list[i].pc_begin] - eh_frame.lsda_list[i].pc_begin;
//              ofile<<"|Try/catch block count: "<<dec<<eh_frame.lsda_list[i].call_site_table.size();
//              uint64_t coverage = 0;
//              for(int j=0;j<eh_frame.lsda_list[i].call_site_table.size();j++)
//              {
//                      coverage+=eh_frame.lsda_list[i].call_site_table[j].length;
//              }
//              ofile<<"|Try/catch block coverage(bytes): "<<dec<<coverage<<"\n";
//      }
//      /*
//      map<uint64_t,map<uint64_t,unwinding_record>> :: iterator unwind_it;
//      unwind_it = uwinding_info.begin();
//      while(unwind_it!=uwinding_info.end())
//      {
//              ofile<<"[Unwinding info] frame start(hex): "<<hex<<unwind_it->first<<"|range(bytes): "<<dec<<all_frames[unwind_it->first] - unwind_it->first<<"\n";
//              map<uint64_t,unwinding_record> :: iterator it;
//              it = unwind_it->second.begin();
//              ofile<<"[Unwinding info] unwinding block count: "<<dec<<unwind_it->second.size()<<"\n";
//              uint64_t cnt = 0;
//              uint64_t avg = 0;
//              while(it!=unwind_it->second.end())
//              {
//                      if(it->second.range > 20)
//                      {
//      cnt++;
//      ofile<<"[Unwinding info] unwind block with size > 20 bytes at: "<<hex<<it->second.start<<" range: "<<dec<<it->second.range<<"\n";
//
//                      }
//                      avg+=it->second.range;
//                      it++;
//              }
//              ofile<<"[Unwinding info] unwind block with size > 20 bytes count: "<<dec<<cnt<<"\n";
//              ofile<<"[Unwinding info] average unwind block size :"<<dec<<avg/unwind_it->second.size()<<"\n";
//              unwind_it++;
//      }
//      */
//      ofile.close();
//      return 0;
//}
