/*
 * lfsr.h - lfsr library
 *
 * Copyright (C) 2009 Robert C. Curtis
 *
 * lfsr.h is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * lfsr.h is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with lfsr.h. If not, see <http://www.gnu.org/licenses/>.
 */

/****************************************************************************/

#include <stdint.h>

#ifndef I__LFSR_H__
	#define I__LFSR_H__

extern uint32_t lfsr_state;

__attribute__((always_inline)) static uint8_t lfsr_inc_8();
__attribute__((always_inline)) static uint16_t lfsr_inc_16();
__attribute__((always_inline)) static uint32_t lfsr_inc_32();

static const uint32_t lfsr_taps32[] =
	{0xFFFFFFFF, (1 << 31), (1 << 21), (1 << 1), (1 << 0), 0};

static uint32_t lfsr_inc_32()
{
	uint32_t tap = 0;
	int i = 1;

	while(lfsr_taps32[i])
		tap ^= !!(lfsr_taps32[i++] & lfsr_state);
	lfsr_state <<= 1;
	lfsr_state |= tap;
	lfsr_state &= lfsr_taps32[0];

	return lfsr_state;
}

#endif /* I__LFSR_H__ */
