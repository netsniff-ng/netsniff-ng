/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 */

#ifndef _NET_VERSION_H_
#define _NET_VERSION_H_

/* Versioning information */
#define PROGNAME_STRING  "netsniff-ng"
#define VERSION_STRING   "0.5.5.0"

/*
 * Some versioning definition:
 * w.x.y.z 
 * `-+-+-+-- "Huge"  changes ---> These only change on overflow of "Minor"
 *   `-+-+-- "Major" changes _/            - x elem of {0, 1, ..., 9}
 *     `-+-- "Minor" changes, new features - y elem of {0, 1, ..., 9}
 *       `-- "Tiny"  changes, bug fixes    - z elem of {0, 1, ...}
 */

#endif				/* _NET_VERSION_H_ */
