#!/usr/bin/python3

# 
# Modified by Miro Haller <miro.haller@alumni.ethz.ch> for a simplified MICROBENCH
# attack scenario.
# 

import string
import sys

if (len(sys.argv) != 2):
    print("usage: build_asm.py expects one argument <inst_slide_len>")
    exit(1)

NB_INST     = int(sys.argv[1])
ASM_INST    = "nop"

template = string.Template('''
    /* ====== auto generated asm code from Python script ======= */

    .text
    .global asm_microbenchmark, asm_microbenchmark_end
    .align 0x1000 /* 4KiB */
    .type asm_microbenchmark, @function
    asm_microbenchmark:
    $asmCode
    asm_microbenchmark_end:
    ret

    /* 4KiB space; ensures that next page after code has no other code in it
       to make sure no false-positive page accesses happen when we are mesuring*/
    .space 0x1000
''')

asm  = "    movb $1, (%rdi) // Start counting instructions\n"
asm += (ASM_INST + '\n') * NB_INST
asm += "    movb $0, (%rdi) // Stop counting instructions\n"

code = template.substitute(asmCode=asm)

with open('asm_nop.S', 'w') as the_file:
    the_file.write(code)
