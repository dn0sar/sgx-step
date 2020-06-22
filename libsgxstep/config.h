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

#ifndef SGX_STEP_CONFIG
#define SGX_STEP_CONFIG

#define PSTATE_PCT                  100
#define SINGLE_STEP_ENABLE          1
#define USER_IDT_ENABLE             1
#define IRQ_VECTOR                  45
#define GDT_VECTOR                  13
#if (M32 != 1)
	#define APIC_CONFIG_MSR         1
#else
	#define APIC_CONFIG_MSR         0
#endif

#define VICTIM_CPU                  1
#define NUM_CORES                   4
#define SPY_CPU                     (VICTIM_CPU + NUM_CORES)


#ifndef SGX_STEP_TIMER_INTERVAL
/*
 * XXX Configure APIC timer interval for next interrupt.
 *
 * NOTE: the exact timer interval value depends on CPU frequency, and hence
 *       remains inherently platform-specific. We empirically established
 *       suitable timer intervals on our evaluation platforms by
 *       tweaking and observing the NOP microbenchmark erip results.
 */
#define DELL_INSPIRON_7359          1
#define DELL_OPTIPLEX_7040          2
#define DELL_LATITUDE_7490          3
#define ACER_ASPIRE_V15             4
#define I9_9900K	                5
#if (SGX_STEP_PLATFORM == DELL_INSPIRON_7359)
    #define SGX_STEP_TIMER_INTERVAL 43
#elif (SGX_STEP_PLATFORM == DELL_LATITUDE_7490)
    #define SGX_STEP_TIMER_INTERVAL 36
#elif (SGX_STEP_PLATFORM == DELL_OPTIPLEX_7040)
    #define SGX_STEP_TIMER_INTERVAL 19
#elif (SGX_STEP_PLATFORM == ACER_ASPIRE_V15)
    #define SGX_STEP_TIMER_INTERVAL 28
#elif (SGX_STEP_PLATFORM == I9_9900K)
    #define SGX_STEP_TIMER_INTERVAL 21
#else
    #warning Unsupported SGX_STEP_PLATFORM; configure timer interval manually...
#endif

#endif

#endif
