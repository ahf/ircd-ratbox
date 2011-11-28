/*
 *  ircd-ratbox: A slightly useful ircd.
 *  common.h: An ircd header common to most code.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 *
 *  $Id: common.h 24067 2007-07-24 18:15:02Z androsyn $
 */

#ifndef INCLUDED_common_h
#define INCLUDED_common_h


#ifndef NULL
#define NULL 0
#endif

#ifdef TRUE
#undef TRUE
#endif

#ifdef FALSE
#undef FALSE
#endif

#define FALSE  0
#define TRUE   1
#define HIDEME 2

/* Blah. I use these a lot. -Dianora */
#ifdef YES
#undef YES
#endif

#define YES 1

#ifdef NO
#undef NO
#endif

#define NO  0

/* Just blindly define our own MIN/MAX macro */

#define IRCD_MAX(a, b)  ((a) > (b) ? (a) : (b))
#define IRCD_MIN(a, b)  ((a) < (b) ? (a) : (b))

/* Right out of the RFC */
#define IRCD_BUFSIZE 512

/* readbuf size */
#define READBUF_SIZE 16384

#endif /* INCLUDED_common_h */
