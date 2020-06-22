/*
 *  This file is part of the SGX-Step enclave execution control framework.
 *
 *  Copyright (C) 2017 Jo Van Bulck <jo.vanbulck@cs.kuleuven.be>,
 *                     Raoul Strackx <raoul.strackx@cs.kuleuven.be>
 *
 *  SGX-Step is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SGX-Step is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SGX-Step. If not, see <http://www.gnu.org/licenses/>.
 */

 /* Modified by Ivan Puddu <ivan.puddu@inf.ethz.ch> on 15.11.2019 */

/* 32-bit compatibility ~~following Intel SGX-SDK convention. */
#if defined(M32)
    #define xax  eax
    #define xbx  ebx
    #define xcx  ecx
    #define xdi  edi
    #define xsi  esi
    #define movx movl
#else
    #define xax  rax
    #define xbx  rbx
    #define xcx  rcx
    #define xdi  rdi
    #define xsi  rsi
    #define movx movq
#endif

#define APIC_TMICT                  0x380

/* 
 * ---------------------------------------------------------------------
 * Function: sgx_step_trampoline
 *      Code that will be returned to after interrupting an enclave.
 *
 * Registers:
 *      XAX - ERESUME leaf
 *      XBX - TSC address
 *      XCX - AEP address
 */
    .text
    .global sgx_step_aep_trampoline
    .type sgx_step_aep_trampoline, @function
sgx_step_aep_trampoline:
    mov %xbx, sgx_step_tcs(%rip)

    /* optional C function callback */
    lea sgx_step_aep_cb(%rip), %xax
    mov (%xax), %xax
    test %xax, %xax
    je .Leresume
    call *%xax

.Leresume:
    add $1, sgx_step_eresume_cnt(%rip)

    mov sgx_step_tcs(%rip), %xbx              /* TCS address */
    lea sgx_step_aep_trampoline(%rip), %xcx   /* AEP address */
    
    lea apic_base(%rip), %xsi
    mov (%xsi), %xsi
    test %xsi, %xsi 
    je .Lcheckapic          # in the unlikely case in which apic_base was not set, call apic_init
    mov %xax, %xdi          # cpuid below is going to overwrite rax, so move it to rdi
    test %xdi, %xdi
    je .Leresumebottom
    # Arm the counter if the value returned before was not 0
    movl %edi, APIC_TMICT(%xsi)

.Leresumebottom:

    prefetch nemesis_tsc_eresume(%rip)
    mfence

    rdtsc
    mov %eax, nemesis_tsc_eresume(%rip)

    mov $3, %xax                        /* ERESUME leaf */
    .byte 0x0f, 0x01, 0xd7              /* ENCLU */


.Lcheckapic:
    push %xax
    callq apic_init
    sub $1, sgx_step_eresume_cnt(%rip)
    pop %xax
    jmp .Leresume