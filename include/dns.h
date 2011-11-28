/*
 *  ircd-ratbox: A slightly useful ircd.
 *  dns.h: A header with the DNS functions.
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
 *  $Id: dns.h 26094 2008-09-19 15:33:46Z androsyn $
 */

#ifndef _DNS_H_INCLUDED
#define _DNS_H_INCLUDED 1

struct Client;

typedef void DNSCB(const char *res, int status, int aftype, void *data);


void init_resolver(void);
void restart_resolver(void);
void rehash_resolver(void);
uint16_t lookup_hostname(const char *hostname, int aftype, DNSCB * callback, void *data);
uint16_t lookup_ip(const char *hostname, int aftype, DNSCB * callback, void *data);
void cancel_lookup(uint16_t xid);
void report_dns_servers(struct Client *);
void rehash_dns_vhost(void);


#endif
