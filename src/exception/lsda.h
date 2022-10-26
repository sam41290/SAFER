#ifndef _LSDA_H
#define _LSDA_H
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <vector>
#include "elf_class.h"

using namespace std;

/* class lsda_class represents the metadata stored in GCC_EXCEPT_TABLE section.
 * Important information stored are try/catch blocks (call_sites) and
 * corresponding landing pads.
 */

struct action_table_entry
{
  int64_t index;
  int64_t offt;
};

struct call_site_entry
{
  /*he start of the instructions for the
    current call site, a byte offset from the landing pad
    base. This is encoded using the encoding from the header.
    */

  vector < uint8_t > encoded_start;	
  int start_padding;
  uint64_t start;

   /*The length of the instructions for the
     current call site, in bytes. This is encoded using the encoding from the
     header. */

  vector < uint8_t > encoded_length;
  int length_padding;
  uint64_t length;

  /*A pointer to the landing pad for
  this sequence of instructions, or 0 if there isn’t one. This is a byte offset
  from the landing pad base. This is encoded using the encoding from the header.
  */
  vector < uint8_t > encoded_landing_pad_ptr;
  int landing_pad_ptr_padding;
  uint64_t landing_pad_ptr;

  /*The action to take, an unsigned
  LEB128. This is 1 plus a byte offset into the action table. The value zero
  means that there is no action. */
  vector < uint8_t > encoded_action_index;
  int action_index_padding;
  uint64_t action_index;
};

struct call_site_info
{
  uint64_t start;
  uint64_t landing_pad = 0;
  uint64_t length;
};


class lsda_class
{
  uint64_t pc_begin;
  uint64_t location;
  /*A 1 byte encoding of the following field (a DW_EH_PE_xxx
  value). */
  uint8_t base_enc;

  /*If the encoding is not DW_EH_PE_omit, the
  landing pad base. This is the base from which landing pad offsets are
  computed. If this is omitted, the base comes from calling
  _Unwind_GetRegionStart, which returns the beginning of the code
  described by the current FDE. In practice this field is normally
  omitted. */
  vector < uint8_t > encoded_base;
  int base_padding;
  uint64_t base;

  /*A 1 byte encoding of the entries in the type table
                   (a DW_EH_PE_xxx value). */
  uint8_t type_table_enc;	

  /*If the encoding is not
  DW_EH_PE_omit, the types table pointer. This is an unsigned LEB128 value,
  and is the byte offset from this field to the start of the types table
  used for exception matching. */
  vector < uint8_t > encoded_type_table_ptr;

  uint64_t type_table_ptr;
  int type_table_ptr_padding;

  /*A 1 byte encoding of the fields in the
                   call-site table (a DW_EH_PE_xxx value). */
  uint8_t call_site_table_enc;	

  /*An unsigned LEB128 value
    holding the length in bytes of the call-site table */
  vector < uint8_t > encoded_call_site_table_length;

  uint64_t call_site_table_length;
  int call_site_table_length_padding;
  vector < call_site_entry > call_site_table;
  vector < action_table_entry > action_table;
  vector < uint8_t > encoded_action_table;
  stack < uint64_t > type_table;

public:
  lsda_class (uint64_t p_pc_begin);
  void read_lsda (string fname, uint64_t lsda_location, ElfClass &elf_obj);
  void read_call_site_table (string bname, uint8_t * gcc_except_table, int
			     index, uint64_t offset);
  void print_lsda (uint64_t data_segment);
  void print_call_site_tbl (uint64_t addrs, uint64_t start);
  uint64_t get_pc_begin ();

};

#endif
