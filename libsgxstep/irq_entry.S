 /*
  * Modified by Miro Haller <miro.haller@alumni.ethz.ch> on 23.06.2020
  * (reintroducing changes from Spring 2019)
  */

#define CS 16

    .text
    .global sgx_step_irq_entry
    .type sgx_step_irq_entry,@function
sgx_step_irq_entry:
    # Check if coming from kernel space, if so just do IRET
    testb   $3, CS(%rsp)
    jz exit // Interrupt coming from kernel space, don't do anything, IRET asap

    /* Manually save rcx, rbx as cpuid overwrites them */
    mov %rcx, %r14
    mov %rbx, %r15

    // Sample timestamp _after_ all previous instructions finished executing
    rdtscp
    mov %eax, nemesis_tsc_aex(%rip)

    // Protect measurement from subsequent instructions
    cpuid

    /* restore rax, rdx, rcx, rbx, r14 and r15 from AEX synthetic register state */
    mov $3, %rax
    mov $0, %rdx
    mov %r14, %rcx
    mov %r15, %rbx
    mov $0, %r14
    mov $0, %r15

    push %rax
    mov %rsp, %rax
    add $8,%rax
    push %rbx
    push %rcx
    push %rdx
    push %rbp
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11

    mov %rax, %rdi
    /* TODO support 256 possible IRQ handlers via asm macro */
    movb sgx_step_vector_hack(%rip), %sil
    call sgx_step_irq_handler_c

    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdi
    pop %rsi
    pop %rbp
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    iretq

    .global sgx_step_irq_gate_func
sgx_step_irq_gate_func:
    call *sgx_step_irq_gate_cb(%rip)
    /* interrupt return to user space caller (this will re-enable IRQs) */
    iretq
