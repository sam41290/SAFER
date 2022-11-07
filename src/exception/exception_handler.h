#ifndef _EH_H
#define _EH_H
#include <bits/stdc++.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iterator>
#include <vector>
#include "cie.h"
#include "fde.h"
#include "lsda.h"
#include "cfi_table.h"

using namespace std;

//#define DW_EH_PE_omit 0xff;// No value is present.
#define DW_EH_PE_uleb128 0x01	// Unsigned value is encoded using the Little
                                // Endian Base 128
#define DW_EH_PE_udata2	0x02	//  A 2 bytes unsigned value.
#define DW_EH_PE_udata4	0x03	//  A 4 bytes unsigned value.
#define DW_EH_PE_udata8	0x04	//  An 8 bytes unsigned value.
#define DW_EH_PE_sleb128 0x09	// Signed value is encoded using the Little
                                // Endian Base 128 (LEB128)
#define DW_EH_PE_sdata2	0x0A	//  A 2 bytes signed value.
#define DW_EH_PE_sdata4	0x0B	//  A 4 bytes signed value.
#define DW_EH_PE_sdata8	0x0C	//  An 8 bytes signed value.

#define DW_EH_PE_absptr	0x00	//  Value is used with no modification.
#define DW_EH_PE_pcrel	0x10	//  Value is reletive to the current program
                                // counter.
#define DW_EH_PE_datarel 0x30	// Value is reletive to the beginning of the
                                // .eh_frame_hdr section.
#define DW_EH_PE_omit	0xff	//  No value is present.


//call frame instructions
//
#define DW_CFA_advance_loc	0x40
#define DW_CFA_offset		0x80
#define DW_CFA_restore		0xc0
#define DW_CFA_nop		0x00
#define DW_CFA_set_loc		0x01
#define DW_CFA_advance_loc1	0x02
#define DW_CFA_advance_loc2	0x03
#define DW_CFA_advance_loc4	0x04
#define DW_CFA_offset_extended	0x05
#define DW_CFA_restore_extended	0x06
#define DW_CFA_undefined	0x07
#define DW_CFA_same_value	0x08
#define DW_CFA_register		0x09
#define DW_CFA_remember_state	0x0a
#define DW_CFA_restore_state	0x0b
#define DW_CFA_def_cfa		0x0c
#define DW_CFA_def_cfa_register	0x0d
#define DW_CFA_def_cfa_offset	0x0e
#define DW_CFA_def_cfa_expression	0x0f
#define DW_CFA_expression	0x10
#define DW_CFA_offset_extended_sf	0x11
#define DW_CFA_def_cfa_sf	0x12
#define DW_CFA_def_cfa_offset_sf	0x13
#define DW_CFA_val_offset	0x14
#define DW_CFA_val_offset_sf	0x15
#define DW_CFA_val_expression	0x16
#define DW_CFA_lo_user		0x1c
#define DW_CFA_hi_user		0x3f
#define DW_CFA_GNU_args_size	0x2e
#define DW_CFA_GNU_negative_offset_extended 0x2f


/*
 * DWARF expression operations
 */
#define DW_OP_addr	0x03
#define DW_OP_deref	0x06
#define DW_OP_const1u	0x08
#define DW_OP_const1s	0x09
#define DW_OP_const2u	0x0a
#define DW_OP_const2s	0x0b
#define DW_OP_const4u	0x0c
#define DW_OP_const4s	0x0d
#define DW_OP_const8u	0x0e
#define DW_OP_const8s	0x0f
#define DW_OP_constu	0x10
#define DW_OP_consts	0x11
#define DW_OP_dup	0x12
#define DW_OP_drop	0x13
#define DW_OP_over	0x14
#define DW_OP_pick	0x15
#define DW_OP_swap	0x16
#define DW_OP_rot	0x17
#define DW_OP_xderef	0x18
#define DW_OP_abs	0x19
#define DW_OP_and	0x1a
#define DW_OP_div	0x1b
#define DW_OP_minus	0x1c
#define DW_OP_mod	0x1d
#define DW_OP_mul	0x1e
#define DW_OP_neg	0x1f
#define DW_OP_not	0x20
#define DW_OP_or	0x21
#define DW_OP_plus	0x22
#define DW_OP_plus_uconst	0x23
#define DW_OP_shl	0x24
#define DW_OP_shr	0x25
#define DW_OP_shra	0x26
#define DW_OP_xor	0x27
#define DW_OP_skip	0x2f
#define DW_OP_bra	0x28
#define DW_OP_eq	0x29
#define DW_OP_ge	0x2a
#define DW_OP_gt	0x2b
#define DW_OP_le	0x2c
#define DW_OP_lt	0x2d
#define DW_OP_ne	0x2e
#define DW_OP_lit0	0x30
#define DW_OP_lit1	0x31
#define DW_OP_lit2	0x32
#define DW_OP_lit3	0x33
#define DW_OP_lit4	0x34
#define DW_OP_lit5	0x35
#define DW_OP_lit6	0x36
#define DW_OP_lit7	0x37
#define DW_OP_lit8	0x38
#define DW_OP_lit9	0x39
#define DW_OP_lit10	0x3a
#define DW_OP_lit11	0x3b
#define DW_OP_lit12	0x3c
#define DW_OP_lit13	0x3d
#define DW_OP_lit14	0x3e
#define DW_OP_lit15	0x3f
#define DW_OP_lit16	0x40
#define DW_OP_lit17	0x41
#define DW_OP_lit18	0x42
#define DW_OP_lit19	0x43
#define DW_OP_lit20	0x44
#define DW_OP_lit21	0x45
#define DW_OP_lit22	0x46
#define DW_OP_lit23	0x47
#define DW_OP_lit24	0x48
#define DW_OP_lit25	0x49
#define DW_OP_lit26	0x4a
#define DW_OP_lit27	0x4b
#define DW_OP_lit28	0x4c
#define DW_OP_lit29	0x4d
#define DW_OP_lit30	0x4e
#define DW_OP_lit31	0x4f
#define DW_OP_reg0	0x50
#define DW_OP_reg1	0x51
#define DW_OP_reg2	0x52
#define DW_OP_reg3	0x53
#define DW_OP_reg4	0x54
#define DW_OP_reg5	0x55
#define DW_OP_reg6	0x56
#define DW_OP_reg7	0x57
#define DW_OP_reg8	0x58
#define DW_OP_reg9	0x59
#define DW_OP_reg10	0x5a
#define DW_OP_reg11	0x5b
#define DW_OP_reg12	0x5c
#define DW_OP_reg13	0x5d
#define DW_OP_reg14	0x5e
#define DW_OP_reg15	0x5f
#define DW_OP_reg16	0x60
#define DW_OP_reg17	0x61
#define DW_OP_reg18	0x62
#define DW_OP_reg19	0x63
#define DW_OP_reg20	0x64
#define DW_OP_reg21	0x65
#define DW_OP_reg22	0x66
#define DW_OP_reg23	0x67
#define DW_OP_reg24	0x68
#define DW_OP_reg25	0x69
#define DW_OP_reg26	0x6a
#define DW_OP_reg27	0x6b
#define DW_OP_reg28	0x6c
#define DW_OP_reg29	0x6d
#define DW_OP_reg30	0x6e
#define DW_OP_reg31	0x6f
#define DW_OP_breg0	0x70
#define DW_OP_breg1	0x71
#define DW_OP_breg2	0x72
#define DW_OP_breg3	0x73
#define DW_OP_breg4	0x74
#define DW_OP_breg5	0x75
#define DW_OP_breg6	0x76
#define DW_OP_breg7	0x77
#define DW_OP_breg8	0x78
#define DW_OP_breg9	0x79
#define DW_OP_breg10	0x7a
#define DW_OP_breg11	0x7b
#define DW_OP_breg12	0x7c
#define DW_OP_breg13	0x7d
#define DW_OP_breg14	0x7e
#define DW_OP_breg15	0x7f
#define DW_OP_breg16	0x80
#define DW_OP_breg17	0x81
#define DW_OP_breg18	0x82
#define DW_OP_breg19	0x83
#define DW_OP_breg20	0x84
#define DW_OP_breg21	0x85
#define DW_OP_breg22	0x86
#define DW_OP_breg23	0x87
#define DW_OP_breg24	0x88
#define DW_OP_breg25	0x89
#define DW_OP_breg26	0x8a
#define DW_OP_breg27	0x8b
#define DW_OP_breg28	0x8c
#define DW_OP_breg29	0x8d
#define DW_OP_breg30	0x8e
#define DW_OP_breg31	0x8f
#define DW_OP_regx	0x90
#define DW_OP_fbreg	0x91
#define DW_OP_bregx	0x92
#define DW_OP_piece	0x93
#define DW_OP_deref_size	0x94
#define DW_OP_xderef_size	0x95
#define DW_OP_nop	0x96
#define DW_OP_push_object_address	0x97
#define DW_OP_call2	0x98
#define DW_OP_call4	0x99
#define DW_OP_call_ref	0x9a
#define DW_OP_form_tls_address	0x9b
#define DW_OP_call_frame_cfa	0x9c
#define DW_OP_bit_piece	0x9d
#define DW_OP_lo_user	0xe0
#define DW_OP_hi_user	0xff

/*-----------------generic functions to be used by all eh
 * modules----------------*/

int read_unsigned_leb128 (uint8_t * leb128_start, uint64_t * data);
//int read_unsigned_leb128 (string fname, uint64_t offset, uint64_t * data);
vector < uint8_t > encode_unsigned_leb128 (uint64_t data, int padding);
vector < uint8_t > encode_signed_leb128 (int64_t data, int padding);
int read_signed_leb128 (uint8_t * leb128_start, int64_t * data);
//int read_signed_leb128 (string fname, uint64_t offset, int64_t * data);
int decode_ptr (string bname, uint8_t enc, vector < uint8_t > data, int index,
		uint64_t offset, uint64_t * ptr);
int decode_ptr2 (uint8_t size_enc, vector < uint8_t > data, int index,
		 uint64_t * ptr);
string print_encoded_ptr (string cur_location, string ptr_str, uint8_t ptr_enc);
string print_encoded_ptr_lvl2 (uint8_t enc, string ptr);
int get_encoded_value (string bname, uint8_t enc, uint64_t offset,
		       uint8_t * data, uint64_t * ptr);

/*----------------------------------------------------------*/

struct fde_lookup_tbl_entry
{
  //Each entry in the BST

  uint64_t fde_pc_begin;	//Function address
  vector < uint8_t > enc_fde_pc_begin;	//encoded function address
  int fde_pc_begin_padding;	//size of the encoded function address.
  uint64_t fde_ptr;		//Location of FDE
  vector < uint8_t > enc_fde_ptr;	//encoded location of FDE
  int enc_fde_ptr_padding;	//size of encoded location of FDE
};

struct eh_frame_hdr
{
  //Structure for EH_FRAME_HDR section.

  uint8_t version;
  uint8_t eh_frame_ptr_enc;	//encoding format of eh_frame section address
  uint8_t fde_count_enc;	//encoding format of entry count of the BST.
  uint8_t table_enc;		//encoding format of the BST
  vector < uint8_t > eh_frame_ptr;	//encoded bytes for eh_frame section address
  vector < uint8_t > fde_count;	//encoded bytes for total number of entries in
                                //BST
  vector < fde_lookup_tbl_entry > lookup_tbl;	//BST
};

/* class exception_handler represents ELF exception handling metadata.
 */

class exception_handler
{
  struct eh_frame_hdr header;
  uint64_t header_size;
  uint64_t frame_size;

  //EH frame - a vector of CIE structures
  //Each CIE structure has a vector of FDE structures.
  //One FDE for each function in whole program.

  vector < cie_class > cie;


  map < uint64_t, int >processed_lsda;
  vector < lsda_class > lsda_list;	//Language specific data

  //new BST size generated after printing all BST. Since EH optimization removes
  //entries for some functions, this value is expected to be less than the
  //original one.


  int new_bst_size = 0;	
  set <uint64_t> fde_to_remove;
public:

  void read_eh_frame_hdr (string fname);
  void read_eh_frame (string fname);
  map < uint64_t, uint64_t > get_all_frame_address ();
  void print_eh_frame (uint64_t data_segment);
  void print_lsda (uint64_t data_segment);
  void print_call_site_tbl (uint64_t addrs, uint64_t start, uint64_t pc_begin);
  //void rewrite_eh_frame_hdr(string bname,uint64_t code_segment_offset);
  void print_eh_frame_hdr ();
  void print_bst (uint64_t frame_addrs);
  void add_fde_to_remove (uint64_t frame_addrs);
  void printAllCallSiteTbls();
};
#endif
