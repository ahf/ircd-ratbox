/*
 *  ircd-ratbox: A slightly useful ircd.
 *  s_auth.h: A header for the ident functions.
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
 *  $Id: s_auth.h 25845 2008-08-05 02:02:08Z androsyn $
 */

#ifndef INCLUDED_s_auth_h
#define INCLUDED_s_auth_h

/* 
 * How many auth allocations to allocate in a block. I'm guessing that
 * a good number here is 64, because these are temporary and don't live
 * as long as clients do.
 *     -- adrian
 */
#define	AUTH_BLOCK_SIZE		64

struct Client;

/* defined in s_auth.c now */
struct AuthRequest;


/*
 * flag values for AuthRequest
 * NAMESPACE: AM_xxx - Authentication Module
 */
#define AM_AUTH_PENDING      0x1
#define AM_DNS_PENDING       0x2

#define SetDNS(x)     ((x)->flags |= AM_DNS_PENDING)
#define ClearDNS(x)   ((x)->flags &= ~AM_DNS_PENDING)
#define IsDNS(x)      ((x)->flags &  AM_DNS_PENDING)

#define SetAuth(x)    ((x)->flags |= AM_AUTH_PENDING)
#define ClearAuth(x)  ((x)->flags &= ~AM_AUTH_PENDING)
#define IsAuth(x)     ((x)->flags & AM_AUTH_PENDING)


void start_auth(struct Client *);
void send_auth_query(struct AuthRequest *req);
void remove_auth_request(struct AuthRequest *req);
void init_auth(void);
void delete_auth_queries(struct Client *);
#endif /* INCLUDED_s_auth_h */
