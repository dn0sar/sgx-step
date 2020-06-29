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
 * Modified by Miro Haller <miro.haller@alumni.ethz.ch> for a simplified MICROBENCH
 * attack scenario.
 */

#include <stdint.h>
#include <string.h>

// see asm_nop.S
extern void asm_microbenchmark(uint8_t *do_cnt_instr);
extern void asm_microbenchmark_end(void);

void do_nop_slide(uint8_t *do_cnt_instr)
{
    asm_microbenchmark(do_cnt_instr);
}

void *get_nop_adrs( void )
{
    return asm_microbenchmark;
}

void *get_nop_end_adrs( void )
{
    return asm_microbenchmark_end;
}
