/*
 *  ircd-ratbox: A slightly useful ircd.
 *  listener.h: A header for the listener code.
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
 *  $Id: listener.h 24553 2007-11-19 17:38:36Z androsyn $
 */

#ifndef INCLUDED_listener_h
#define INCLUDED_listener_h

struct Client;

struct Listener
{
	rb_dlink_node node;
	const char *name;	/* listener name */
	rb_fde_t *F;		/* file descriptor */
	int ref_count;		/* number of connection references */
	int active;		/* current state of listener */
	int ssl;		/* ssl listener */
	struct rb_sockaddr_storage addr;
	char vhost[HOSTLEN + 1];	/* virtual name of listener */
};

void add_listener(int port, const char *vaddr_ip, int family, int ssl);
void close_listener(struct Listener *listener);
void close_listeners(void);
const char *get_listener_name(struct Listener *listener);
void show_ports(struct Client *client);
void free_listener(struct Listener *);


#endif /* INCLUDED_listener_h */
