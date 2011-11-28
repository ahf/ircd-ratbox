/*
 *  ircd-ratbox: A slightly useful ircd.
 *  ircd_defs.h: A header for ircd global definitions.
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
 *  $Id: ircd_defs.h 26700 2009-10-18 19:53:24Z jilles $
 */

/*
 * NOTE: NICKLEN and TOPICLEN do not live here anymore. Set it with configure
 * Otherwise there are no user servicable part here. 
 *
 */
 /* ircd_defs.h - Global size definitions for record entries used
  * througout ircd. Please think 3 times before adding anything to this
  * file.
  */
#ifndef INCLUDED_ircd_defs_h
#define INCLUDED_ircd_defs_h

/* For those unfamiliar with GNU format attributes, a is the 1 based
 * argument number of the format string, and b is the 1 based argument
 * number of the variadic ... */
#ifdef __GNUC__
#define AFP(a,b) __attribute__((format (printf, a, b)))
#else
#define AFP(a,b)
#endif


#ifdef __GNUC__
#define ss_assert(expr)	do								\
			if(!(expr)) {							\
				ilog(L_MAIN, 						\
				"file: %s line: %d (%s): Assertion failed: (%s)",	\
				__FILE__, __LINE__, __PRETTY_FUNCTION__, #expr); 	\
				sendto_realops_flags(UMODE_ALL, L_ALL, 			\
				"file: %s line: %d (%s): Assertion failed: (%s)",	\
				__FILE__, __LINE__, __PRETTY_FUNCTION__, #expr);	\
			}								\
			while(0)
#else
#define ss_assert(expr)	do								\
			if(!(expr)) {							\
				ilog(L_MAIN, 						\
				"file: %s line: %d: Assertion failed: (%s)",		\
				__FILE__, __LINE__, #expr); 				\
				sendto_realops_flags(UMODE_ALL, L_ALL,			\
				"file: %s line: %d: Assertion failed: (%s)"		\
				__FILE__, __LINE__, #expr);				\
			}								\
			while(0)
#endif

#ifdef SOFT_ASSERT
#define s_assert(expr) ss_assert(expr)
#else
#define s_assert(expr)	do { ss_assert(expr); assert(expr); } while(0)
#endif

#if !defined(CONFIG_RATBOX_LEVEL_3)
#  error Incorrect config.h for this revision of ircd.
#endif

#define HOSTLEN         63	/* Length of hostname.  Updated to         */
				/* comply with RFC1123                     */
#define IRCD_RES_HOSTLEN 255	/* Must match with resolver/res.h          */

#define USERLEN         10
#define REALLEN         50
#define KILLLEN         90
#define CHANNELLEN      200
#define LOC_CHANNELLEN	50
#define IDLEN		10

/* always v6 sized, as we can have a v6 sockhost for a remote client */
#define HOSTIPLEN	53	/* sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255.ipv6") */

/* reason length of klines, parts, quits etc */
#define REASONLEN	120

#define AWAYLEN		90

/* 23+1 for \0 */
#define KEYLEN          24
#define BUFSIZE         512	/* WARNING: *DONT* CHANGE THIS!!!! */
#define MAXRECIPIENTS   20
#define MAXBANLENGTH    1024
#define OPERNICKLEN     NICKLEN*2	/* Length of OPERNICKs. */

#define USERHOST_REPLYLEN       (NICKLEN+HOSTLEN+USERLEN+5)
#define MAX_DATE_STRING 32	/* maximum string length for a date string */

#define HELPLEN         400
#define DEFAULT_TOPICLEN	160	/* Default topiclen */
#define MAX_TOPICLEN		390	/* Max topiclen */
/* 
 * message return values 
 */
#define CLIENT_EXITED    -2
#define CLIENT_PARSE_ERROR -1
#define CLIENT_OK	1

#ifdef RB_IPV6
#define PATRICIA_BITS	128
#else
#define PATRICIA_BITS	32
#endif



#endif /* INCLUDED_ircd_defs_h */
