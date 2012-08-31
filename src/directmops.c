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
#include "cli.h"
#include "mops.h"


int mops_direct(char* dev, int mops_type, char* argstring)
{
	printf("Got device {%s} type {%i} and argstring {%s}\n", dev, mops_type, argstring);
	
	return 0;
}
