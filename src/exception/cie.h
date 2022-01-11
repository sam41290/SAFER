#ifndef _CIE_H
#define _CIE_H
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <vector>
#include "fde.h"
#include <string>

using namespace std;

/* cie_class represents the CIE structure present in the EH_FRAME section.
 */

class cie_class
{
  int is_eh_data = 0;
  int is_aug_data = 0;
  int is_lsda_ptr = 0;
  int is_personality_ptr = 0;
  int is_fde_ptr_enc = 0;
  uint64_t location;
  uint32_t length;		//Required
  uint64_t extended_length;	//optional
  uint32_t cie_id;		//required
  uint8_t version;		//required
  uint8_t lsda_ptr_enc = -1;
  uint8_t fde_ptr_enc = -1;
  uint8_t personality_rtn_ptr_enc = -1;
  uint64_t personality_rtn_ptr = 0;	//part of aug data is aug string has
  //character 'P'
  uint64_t personality_ptr_padding;
  string aug_string;		//required
  uint8_t eh_data[8];		//optional
  uint64_t code_align;
  vector < uint8_t > encoded_code_align;	//required
  uint64_t data_align;
  vector < uint8_t > encoded_data_align;	//required
  vector < uint8_t > return_reg;	//required
  uint64_t aug_data_length;
  vector < uint8_t > encoded_aug_data_length;	//required
  vector < uint8_t > aug_data;	//required
  vector < uint8_t > initial_instructions;	//required

  vector < fde_class > fde_list;
  set <uint64_t> fde_to_remove;
  void decode_cie_aug_data (string bname, uint64_t offset);
  string print_cie_aug_data (uint64_t data_segment);
  int read_cie_augmentation_str (uint8_t * aug_ptr);
public:
  void read_cie (string bname, uint8_t * cie_ptr, uint64_t length, uint64_t
		 offset);
  void print_cie (uint64_t data_segment, string print_cie, set <uint64_t>
      fde_to_remove);
  cie_class (uint64_t p_length, uint64_t p_extended_length,
	       uint64_t p_location);
  uint64_t get_location ();
  uint8_t get_fde_enc ();
  uint8_t get_is_aug_data ();
  uint8_t get_lsda_enc ();
  vector < uint8_t > get_initial_instructions ();
  map < uint64_t, uint64_t > get_frames ();
  void add_fde (fde_class f);
  uint8_t get_is_lsda ();
  void add_fde_to_remove(uint64_t frame_addrs);
};

#endif
