.frame_16384:
.16384_16384_def_code:
	
	.byte 243
	.byte 15
	.byte 30
	.byte 250
	

.16388_16384_def_code:
	
	.byte 72
	.byte 131
	.byte 236
	.byte 8
	

.16392_16384_def_code:
	
	movq (.datasegment_start + 4040)(%rip), %rax
	

.16399_16384_def_code:
	
	.byte 72
	.byte 133
	.byte 192
	

.16402_16384_def_code:
	
	je .16406_16406_def_code
	

.16404_16404_def_code:
	
	mov %rax,-24(%rsp)
mov %rax,%rax
callq .GTF_reg

	

.16404_16404_def_code_fall:
.16406_16406_def_code:
	
	.byte 72
	.byte 131
	.byte 196
	.byte 8
	

.16410_16406_def_code:
	
	mov %rax,-8(%rsp)
pop %rax
jmp .GTF_stack

	

.frame_16384_end:
