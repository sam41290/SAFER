.align 4096
.elf_header_start:
.0: .byte 127
.1: .byte 69
.2: .byte 76
.3: .byte 70
.4: .byte 2
.5: .byte 1
.6: .byte 1
.7: .byte 0
.8: .byte 0
.9: .byte 0
.10: .byte 0
.11: .byte 0
.12: .byte 0
.13: .byte 0
.14: .byte 0
.15: .byte 0
.16: .2byte 3
.18: .2byte 62
.20: .4byte 1
.24: .8byte 26576
.32: .8byte .pheader_loc - .elf_header_start
.40: .8byte .section_header_loc - .elf_header_start
.48: .4byte 0
.52: .2byte 64
.54: .2byte 56
.56: .2byte 16
.58: .2byte 64
.60: .2byte 48
.62: .2byte 29
