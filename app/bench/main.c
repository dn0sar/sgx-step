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

/*
 * Modified by Miro Haller <miro.haller@alumni.ethz.ch> to both include improvements
 * (see thesis https://github.com/Miro-H/sgx-accurate-time-msrmts) and be compatible
 * with our adapted version of SGX-Step.
 *
 * This is intended as a simple example of how to use those improvements and therefore
 * only implements the MICROBENCH attack scenario.
 */

#include <sgx_urts.h>
#include "Enclave/encl_u.h"
#include <signal.h>
#include <unistd.h>
#include "libsgxstep/apic.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/config.h"
#include "libsgxstep/idt.h"
#include "libsgxstep/config.h"

#ifndef SGX_STEP_TIMER_INTERVAL
    #error The SGX_STEP_TIMER_INTERVAL variable must be defined at compile time.
    // The following line just suppresses other compile errors that derive from this
    // So that the compilation output is a bit more clean
    #define SGX_STEP_TIMER_INTERVAL 0
#endif

#ifndef NUM_RUNS
    #define NUM_RUNS 100
#endif

#define ZERO_STEP_PERCENTAGE 10



uint8_t *do_cnt_instr;
uint8_t do_cnt_instr_old;
uint64_t instr_cnt;

sgx_enclave_id_t eid = 0;
int strlen_nb_access = 0;
int irq_cnt = 0, do_irq = 1, fault_cnt = 0;
uint64_t *pte_encl = NULL;
uint64_t *pte_str_encl = NULL;
uint64_t *pmd_encl = NULL;

typedef struct measurement_t {
    uint64_t cycles;
    uint32_t page_nr;
    uint8_t accessed;
} measurement;

measurement *log_arr;

uint64_t log_arr_size;
uint64_t log_arr_idx;


/* ======================= HELPER FUNCTIONS ======================= */
void init_time_measurement() 
{
    int i;

    instr_cnt           = 0;
    do_cnt_instr_old    = 0;
    log_arr_size        = (NUM_RUNS * (100 + ZERO_STEP_PERCENTAGE) ) / 100;

    ASSERT( do_cnt_instr = (uint8_t *) calloc( 1, sizeof(uint8_t) ) );
    ASSERT( log_arr = (measurement *) calloc( log_arr_size, sizeof(measurement) ) );
}

/* ================== ATTACKER IRQ/FAULT HANDLERS ================= */

/* Called before resuming the enclave after an Asynchronous Enclave eXit. */
uint64_t aep_cb_func(void)
{
    uint64_t erip = edbgrd_erip() - (uint64_t) get_enclave_base();
    info("^^ enclave RIP=%#llx; ACCESSED=%d", erip, ACCESSED(*pte_encl));
    irq_cnt++;

    /* XXX insert custom attack-specific side-channel observation code here */

    if (do_irq && (irq_cnt > NUM_RUNS*500))
    {
        info("excessive interrupt rate detected (try adjusting timer interval " \
             "to avoid getting stuck in zero-stepping); aborting...");
	    do_irq = 0;
    }

    /*
     * NOTE: We explicitly clear the "accessed" bit of the _unprotected_ PTE
     * referencing the enclave code page about to be executed, so as to be able
     * to filter out "zero-step" results that won't set the accessed bit.
     */
    *pte_encl = MARK_NOT_ACCESSED( *pte_encl );

    /*
     * Configure APIC timer interval for next interrupt.
     *
     * On our evaluation platforms, we explicitly clear the enclave's
     * _unprotected_ PMD "accessed" bit below, so as to slightly slow down
     * ERESUME such that the interrupt reliably arrives in the first subsequent
     * enclave instruction.
     * 
     */
    if (do_irq)
    {
        *pmd_encl = MARK_NOT_ACCESSED( *pmd_encl );
        return SGX_STEP_TIMER_INTERVAL;
    }
    return 0;
}

/* Called upon SIGSEGV caused by untrusted page tables. */
void fault_handler(int signal)
{
	info("Caught fault %d! Restoring enclave page permissions..", signal);
    *pte_encl = MARK_NOT_EXECUTE_DISABLE(*pte_encl);
    ASSERT(fault_cnt++ < 10);

    // NOTE: return eventually continues at aep_cb_func and initiates
    // single-stepping mode.
}

int irq_count = 0;

void irq_handler(uint8_t *rsp)
{
    uint64_t *p = (uint64_t*) rsp;
#if 0
    printf("\n");
    info("****** hello world from user space IRQ handler with count=%d ******",
        irq_count++);

    info("APIC TPR/PPR is %d/%d", apic_read(APIC_TPR), apic_read(APIC_PPR));
    info("RSP at %p", rsp);
    info("RIP is %p", *p++);
    info("CS is %p", *p++);
    info("EFLAGS is %p", *p++);
#endif
}

/* ================== ATTACKER INIT/SETUP ================= */

/* Configure and check attacker untrusted runtime environment. */
void attacker_config_runtime(void)
{
    ASSERT( !claim_cpu(VICTIM_CPU) );
    ASSERT( !prepare_system_for_benchmark(PSTATE_PCT) );
    ASSERT(signal(SIGSEGV, fault_handler) != SIG_ERR);
	print_system_settings();

    if (isatty(fileno(stdout)))
    {
        info("WARNING: interactive terminal detected; known to cause ");
        info("unstable timer intervals! Use stdout file redirection for ");
        info("precise single-stepping results...");
    }

    register_aep_cb(aep_cb_func);
    register_enclave_info();
    print_enclave_info();
}

/* Provoke page fault on enclave entry to initiate single-stepping mode. */
void attacker_config_page_table(void)
{
    void *code_adrs;
    #if (ATTACK_SCENARIO == STRLEN)
        void *str_adrs;
        SGX_ASSERT( get_str_adrs( eid, &str_adrs) );
        info("enclave string adrs at %p", str_adrs);
        ASSERT( pte_str_encl = remap_page_table_level( str_adrs, PTE) );
    #endif

    #if (ATTACK_SCENARIO == STRLEN)
        SGX_ASSERT( get_strlen_adrs( eid, &code_adrs) );
    #elif (ATTACK_SCENARIO == ZIGZAGGER)
        SGX_ASSERT( get_zz_adrs( eid, &code_adrs) );
    #else
        SGX_ASSERT( get_nop_adrs( eid, &code_adrs) );
    #endif

    //print_page_table( code_adrs );
    info("enclave trigger code adrs at %p\n", code_adrs);
    ASSERT( pte_encl = remap_page_table_level( code_adrs, PTE) );
    #if SINGLE_STEP_ENABLE
        *pte_encl = MARK_EXECUTE_DISABLE(*pte_encl);
    #endif

    //print_page_table( get_enclave_base() );
    ASSERT( pmd_encl = remap_page_table_level( get_enclave_base(), PMD) );
}

/* ================== ATTACKER MAIN ================= */

/* Untrusted main function to create/enter the trusted enclave. */
int main( int argc, char **argv )
{
	sgx_launch_token_t token = {0};
    int apic_fd, encl_strlen = 0, updated = 0, vec=0;
    idt_t idt = {0};

   	info_event("Creating enclave...");
	SGX_ASSERT( sgx_create_enclave( "./Enclave/encl.so", /*debug=*/1,
                                    &token, &updated, &eid, NULL ) );

    /* 1. Setup attack execution environment. */
    attacker_config_runtime();
    attacker_config_page_table();

    #if USER_IDT_ENABLE
        info_event("Establishing user space APIC/IDT mappings");
        map_idt(&idt);
        install_user_irq_handler(&idt, irq_handler, IRQ_VECTOR);
        //dump_idt(&idt);
        apic_timer_oneshot(IRQ_VECTOR);
    #else
        vec = (apic_read(APIC_LVTT) & 0xff);
        info_event("Establishing user space APIC mapping with kernel space handler (vector=%d)", vec);
        apic_timer_oneshot(vec);
    #endif

    /* TODO for some reason the Dell Latitude machine first needs 2 SW IRQs
     * before the timer IRQs even fire (??) */
    #if USER_IDT_ENABLE
        info_event("Triggering user space software interrupts");
        asm("int %0\n\t" ::"i"(IRQ_VECTOR):);
        asm("int %0\n\t" ::"i"(IRQ_VECTOR):);
    #endif

    /* 2. Single-step enclaved execution. */
    info("calling enclave: attack=%d; num_runs=%d; timer=%d",
        ATTACK_SCENARIO, NUM_RUNS, SGX_STEP_TIMER_INTERVAL);

    #if (ATTACK_SCENARIO == ZIGZAGGER)
        SGX_ASSERT( do_zigzagger(eid, NUM_RUNS) );
    #elif (ATTACK_SCENARIO == STRLEN)
        SGX_ASSERT( do_strlen(eid, &encl_strlen, NUM_RUNS) );
        info("strlen returned by enclave is %d", encl_strlen);
        info("attacker counted %d", strlen_nb_access);
    #else
        SGX_ASSERT( do_nop_slide(eid) );
    #endif

    /* 3. Restore normal execution environment. */
    apic_timer_deadline();
   	SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info_event("all done; counted %d IRQs", irq_cnt);
    return 0;
}
