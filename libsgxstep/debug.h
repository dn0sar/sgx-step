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

#ifndef SGX_STEP_DEBUG_H
#define SGX_STEP_DEBUG_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ANSI_COLOR_RED      "\x1b[31m"
#define ANSI_COLOR_ORANGE   "\x1b[33m"
#define ANSI_COLOR_RESET    "\x1b[0m"

#if !NO_SGX
#include <sgx_error.h>

extern sgx_status_t sgx_step_rv;

#define SGX_ASSERT(f)  { if ( SGX_SUCCESS != (sgx_step_rv = (f)) )      \
 {                                                                      \
       printf( "Error calling enclave at %s:%d (rv=0x%x)\n", __FILE__,  \
                                              __LINE__, sgx_step_rv);   \
        abort();                                                        \
 } }
#endif

#define ASSERT(cond)                                                    \
    do {                                                                \
        if (!(cond))                                                    \
        {                                                               \
            perror("[" __FILE__ "] assertion '" #cond "' failed");      \
            abort();                                                    \
        }                                                               \
    } while(0)

#define print_format(msg, color, ...)                                   \
    do {                                                                \
        printf("[" __FILE__ "] " color msg ANSI_COLOR_RESET "\n",       \
         ##__VA_ARGS__);                                                \
        fflush(stdout);                                                 \
    } while(0)

#define info(msg, ...) print_format(msg, "", ##__VA_ARGS__)
#define warning(msg, ...) print_format(msg,                             \
                ANSI_COLOR_ORANGE "WARNING: ", ##__VA_ARGS__)
#define error(msg, ...) print_format(msg,                               \
                ANSI_COLOR_RED "ERROR: ", ##__VA_ARGS__)

#if LIBSGXSTEP_SILENT
    #define libsgxstep_info(msg, ...)
#else
    #define libsgxstep_info(msg, ...) info(msg, ##__VA_ARGS__)
#endif

#define info_event(msg, ...)                                                                        \
do {                                                                                                \
    printf("\n--------------------------------------------------------------------------------\n"); \
    info(msg,##__VA_ARGS__);                                                                        \
    printf("--------------------------------------------------------------------------------\n\n"); \
} while(0)

void dump_hex(uint8_t *buf, int len);

#endif
