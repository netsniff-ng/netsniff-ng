/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2008-2010 Herbert Haas
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the 
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more 
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with 
 * this program; if not, see http://www.gnu.org/licenses/gpl-2.0.html
 * 
*/





#include "mz.h"


// Returns a nice string with default and current value of a given variable
//
// EXAMPLE:
//  
//    char mystring[256];
//    mz_def16 ("20 seconds", pd->max_age, mystring)
//    
int mz_def16 (char *def, u_int16_t val, char *str256)
{
   str256[0]=0x00;
   sprintf(str256, "The default value is %s. The current value is %u (0x%04x).", def, val, val);
   return 0;
}


