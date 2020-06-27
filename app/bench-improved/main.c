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
#include "libsgxstep/idt.h"
#include "libsgxstep/config.h"

#ifndef SGX_STEP_TIMER_INTERVAL
    #error The SGX_STEP_TIMER_INTERVAL variable must be defined at compile time.
    // The following line just suppresses other compile errors that derive from this
    // So that the compilation output is a bit more clean
    #define SGX_STEP_TIMER_INTERVAL 0
#endif

#ifndef ATTACK_SCENARIO
    #error ATTACK_SCENARIO must be specified (set to MICROBENCH)
#endif

// Must be the same as in Makefile.config
#define MICROBENCH 1

// Values used if Makefile.config is not used (for description, see Makefile.config)
#ifndef DEFAULT
    #define NUM_RUNS 100
    #define ZERO_STEP_PERCENTAGE 10
    #define EDBGRD 0
    #define DBIRQ 0
    #define PAGE_SIZE 4096
    #define PAGES_PER_PMD 512
#endif


// Set to one to print instruction pointer inside enclave (requires debug enclave,
// and introduces noise).
// Set to one to print debug information in the interrupt request handler


uint8_t *do_cnt_instr;
uint8_t do_cnt_instr_old;
uint64_t instr_cnt;
uint64_t zero_steps_cnt;
uint64_t cycles_cnt;
uint64_t tot_cycles_cnt;

sgx_enclave_id_t eid;
int irq_cnt, do_irq, irq_count, fault_cnt;

uint64_t *pte_encl;
uint64_t *pmd_encl;
uint64_t *curr_pte_encl;
uint64_t *next_pte_encl;

uint64_t **pte_encl_arr;
uint64_t pte_encl_len;
uint64_t pte_encl_arr_len;
uint64_t pte_encl_next_idx;

typedef struct measurement_t {
    uint64_t cycles;
    uint32_t page_nr;
    uint8_t accessed;
} measurement;

measurement *log_arr;
uint64_t log_arr_size;
uint64_t log_arr_idx;


/* ======================= HELPER FUNCTIONS ======================= */

/*
 * Initialize various variables for the time measurements and allocate
 * data structures.
 */
void init_time_measurement()
{
    int i;

    eid         = 0;
    irq_cnt     = 0;
    do_irq      = 1;
    irq_count   = 0;
    fault_cnt   = 0;

    pte_encl      = NULL;
    pmd_encl      = NULL;
    curr_pte_encl = NULL;
    next_pte_encl = NULL;

    instr_cnt           = 0;
    zero_steps_cnt      = 0;
    tot_cycles_cnt      = 0;
    do_cnt_instr_old    = 0;
    log_arr_idx         = 0;
    log_arr_size        = (NUM_RUNS * (100 + ZERO_STEP_PERCENTAGE) ) / 100;

    ASSERT( do_cnt_instr = (uint8_t *) calloc( 1, sizeof(uint8_t) ) );
    ASSERT( log_arr = (measurement *) calloc( log_arr_size, sizeof(measurement) ) );
}

/*
 * Output measurements and free allocated data structures
 */
void finish_time_measurement()
{
    int i;

    printf("Log measurement output.\ncycles, page number\n");
    for(i = 0; i < log_arr_idx; ++i) {
        if (log_arr[i].accessed) {
            if (instr_cnt == NUM_RUNS) {
                error("Trailing instructions measured, check if e.g. an init "
                      "instruction takes more than one execution step");
                exit(1);
            }

            ++instr_cnt;
            printf("%lu, %u\n", log_arr[i].cycles, log_arr[i].page_nr);
        }
        else {
            ++zero_steps_cnt;
        }
    }

    free(log_arr);
    free(do_cnt_instr);
    free(pte_encl_arr);
}

/*
 * Convenient shortcut to write constant time code using the low level assembly
 * instruction 'cmov'.
 */
static inline uint64_t cmov64(uint8_t pred, uint64_t source, uint64_t new_val)
{
    __asm__(
        "testb %1, %1;"
        "cmovnzq %2, %0;"
        : "+r"(source)
        : "r"(pred), "r"(new_val)
        : "cc");

    return source;
}


/* ================== ATTACKER IRQ/FAULT HANDLERS ================= */

/* Called before resuming the enclave after an Asynchronous Enclave eXit. */

/* Keep this function almost constant time in most cases so that it does
 * not disturb measurements. We found that measurements after shorter
 * function calls are faster. This could be due to cache lines that
 * get evicted if you do more in this function (and thus take longer).
 *
 * Some small if branchs that are only executed rarely (e.g. to throw an
 * error) are ok.
 */
uint64_t aep_cb_func(void)
{
    uint8_t accessed, accessed_next;
    uint8_t do_cnt_instr_local;

    #if EDBGRD
        uint64_t erip = edbgrd_erip() - (uint64_t) get_enclave_base();
        info("^^ enclave RIP=%#llx; ACCESSED=%d", erip,
             ACCESSED(*curr_pte_encl) || ACCESSED(*next_pte_encl));
    #endif

    irq_cnt++;

    /* Only count instructions if do_cnt_instr was set to true in the previous
     * call (not in this one, since then you count the instruction that sets it
     * to true)
     */
    do_cnt_instr_local = *do_cnt_instr && do_cnt_instr_old == *do_cnt_instr;

    /* XXX insert custom attack-specific side-channel observation code here */
    /* --- Start of custom code --- */

    if ( __builtin_expect(log_arr_size != 0 && log_arr_idx >= log_arr_size, 0) )
    {
        error("Unexpected high number of zero steps. Try increasing "
              "SGX_STEP_TIMER_INTERVAL or ZERO_STEP_PERCENTAGE  in Makefile.config");
        exit(1);
    }
    else if ( __builtin_expect( do_cnt_instr_local, 1 ) )
    {
        ASSERT( curr_pte_encl );
        ASSERT( next_pte_encl );

        accessed_next   = ACCESSED( *next_pte_encl );
        accessed        = ACCESSED( *curr_pte_encl ) || accessed_next;

        // Constant time update variables if we move to next page (instead of an if)
        curr_pte_encl       = (uint64_t *) cmov64(accessed_next,
                                            (uint64_t) curr_pte_encl,
                                            (uint64_t) next_pte_encl);
        next_pte_encl       = (uint64_t *) cmov64(accessed_next,
                                            (uint64_t) next_pte_encl,
                                            (uint64_t) pte_encl_arr[pte_encl_next_idx]);
        pte_encl_next_idx   = cmov64(accessed_next,
                                    pte_encl_next_idx,
                                    pte_encl_next_idx + 1);

        cycles_cnt      = nemesis_tsc_aex - nemesis_tsc_eresume;
        tot_cycles_cnt += cycles_cnt;

        log_arr[log_arr_idx] = (measurement) {
            cycles_cnt,
            pte_encl_next_idx - 1,
            accessed
        };

        ++log_arr_idx;
    }

    do_cnt_instr_old = *do_cnt_instr;

    /* --- End of custom code --- */

    /*
     * NOTE: We explicitly clear the "accessed" bit of the _unprotected_ PTE
     * referencing the enclave code page about to be executed, so as to be able
     * to filter out "zero-step" results that won't set the accessed bit.
     */
    *curr_pte_encl = MARK_NOT_ACCESSED( *curr_pte_encl );
    *next_pte_encl = MARK_NOT_ACCESSED( *next_pte_encl );

    /*
     * Configure APIC timer interval for next interrupt.
     *
     * On our evaluation platforms, we explicitly clear the enclave's
     * _unprotected_ PMD "accessed" bit below, so as to slightly slow down
     * ERESUME such that the interrupt reliably arrives in the first subsequent
     * enclave instruction.
     */

    // Branch always taken during measurements.
    if ( __builtin_expect(do_irq, 1) )
    {
        ASSERT(pmd_encl);
        *pmd_encl = MARK_NOT_ACCESSED( *pmd_encl );

        /*
         * Make sure currently used page is prefetched
         * (usually this is the case anyways)
         * Note: Prefetching next page is a bad idea, since this sometimes
         * evicts data used by the enclave which creates double peaks.
         */
        __asm__ __volatile__("\tprefetcht0 curr_pte_encl(%%rip)\n" ::);

        // Serializing helps to reduce variance
        __asm__ __volatile__("\tcpuid\n" ::);

        return SGX_STEP_TIMER_INTERVAL;
    }
    return 0;
}

/* Called upon SIGSEGV caused by untrusted page tables. */
void fault_handler(int signal)
{
    info("Caught fault %d! Restoring enclave page permissions..", signal);

    // initialize single stepping
    *curr_pte_encl = MARK_NOT_EXECUTE_DISABLE(*curr_pte_encl);

    *curr_pte_encl = MARK_NOT_ACCESSED( *curr_pte_encl );
    *next_pte_encl = MARK_NOT_ACCESSED( *next_pte_encl );

    ASSERT(fault_cnt++ < 10);

    // NOTE: return eventually continues at aep_cb_func and initiates
    // single-stepping mode.
}

// Interrupt request handler
void irq_handler(uint8_t *rsp)
{
    uint64_t *p = (uint64_t*) rsp;

    #if DBIRQ
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
        warning("Interactive terminal detected; known to cause "
                "unstable timer intervals! Use stdout file redirection for "
                "precise single-stepping results...");
    }

    register_aep_cb(aep_cb_func);
    register_enclave_info();
    print_enclave_info();
}

/* Provoke page fault on enclave entry to initiate single-stepping mode. */
void attacker_config_page_table(void)
{
    uint32_t i;
    void *code_adrs;
    void *code_end_adrs;

    #if (ATTACK_SCENARIO == MICROBENCH)
        SGX_ASSERT( get_nop_adrs( eid, &code_adrs) );
        SGX_ASSERT( get_nop_end_adrs( eid, &code_end_adrs) );
    #endif

    info("enclave trigger code adrs at %p\n", code_adrs);
    //print_page_table( code_adrs );

    /*
     * Initialize array for page table entries
     */
    pte_encl_len = 1 + ( (uint64_t) code_end_adrs - (uint64_t) code_adrs ) / PAGE_SIZE;

    if ( pte_encl_len > 1)
    {
        if ( pte_encl_len > PAGES_PER_PMD ) {
            warning("Test code fills more than %d pages, i.e. more than one PMD "
                    "(%lu pages)", PAGES_PER_PMD, pte_encl_len);
        }
        else {
            info("Test code fills more than one page (%lu pages)", pte_encl_len);
        }
    }

    // Last page will not contain code anymore
    pte_encl_arr_len = pte_encl_len + 1;
    ASSERT( pte_encl_arr = (uint64_t **) calloc(pte_encl_arr_len,
                                                sizeof(uint64_t *) ) );

    for (i = 0; i < pte_encl_arr_len; ++i) {
        ASSERT( pte_encl_arr[i] = (uint64_t *) remap_page_table_level(code_adrs, PTE) );
        code_adrs += PAGE_SIZE;
    }

    curr_pte_encl       = pte_encl_arr[0];
    next_pte_encl       = pte_encl_arr[1];
    pte_encl_next_idx   = 2;

    #if SINGLE_STEP_ENABLE
        *curr_pte_encl = MARK_EXECUTE_DISABLE( *curr_pte_encl );
    #endif

    //print_page_table( get_enclave_base() );
    ASSERT( pmd_encl = remap_page_table_level( get_enclave_base(), PMD) );
}

/* ================== ATTACKER MAIN ================= */

/* Untrusted main function to create/enter the trusted enclave. */
int main( int argc, char **argv )
{
	sgx_launch_token_t token = {0};
    int updated = 0, vec = 0;
    idt_t idt = {0};

    double avg_cycles_cnt;
    double avg_zero_steps;

    init_time_measurement();

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

    #if (ATTACK_SCENARIO == MICROBENCH)
        SGX_ASSERT( do_nop_slide(eid, do_cnt_instr) );
    #endif

    finish_time_measurement();

    // XXX: Take stock of your attack here
    avg_zero_steps = (double) zero_steps_cnt / NUM_RUNS;
    avg_cycles_cnt = (double) tot_cycles_cnt / NUM_RUNS;

    info("Detected %lu of %lu instructions", instr_cnt, NUM_RUNS);
    info("Avg execution time: %lf cycles\nAvg zero steps: %lf",
            avg_cycles_cnt, avg_zero_steps);

    if (instr_cnt != NUM_RUNS) {
        error(  "Instruction count does not match number the of runs. "
                "Either the benchmark is running on multiple instructions or "
                "the timer interval is too small." );
        exit(1);
    }

    /* 3. Restore normal execution environment. */
    apic_timer_deadline();
   	SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info_event("all done; counted %d IRQs", irq_cnt);
    return 0;
}
