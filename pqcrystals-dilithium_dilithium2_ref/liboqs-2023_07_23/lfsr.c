/*
 * lfsr.c - lfsr library
 *
 * Copyright (C) 2009 Robert C. Curtis
 *
 * lfsr.c is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * lfsr.c is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with lfsr.c. If not, see <http://www.gnu.org/licenses/>.
 */

/****************************************************************************/

#include "lfsr.h"

uint32_t lfsr_state = 1;

