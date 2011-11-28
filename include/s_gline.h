/*
 *  ircd-ratbox: A slightly useful ircd.
 *  s_gline.h: A header for the gline functions.
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
 *  $Id: s_gline.h 24250 2007-08-22 19:15:08Z androsyn $
 */

#ifndef INCLUDED_s_gline_h
#define INCLUDED_s_gline_h

struct Client;
struct ConfItem;

void cleanup_glines(void *unused);

typedef struct gline_pending
{
	char oper_nick1[NICKLEN + 1];
	char oper_user1[USERLEN + 1];
	char oper_host1[HOSTLEN + 1];
	const char *oper_server1;	/* point to scache */
	char *reason1;
	time_t time_request1;

	char oper_nick2[NICKLEN + 1];
	char oper_user2[USERLEN + 1];
	char oper_host2[HOSTLEN + 1];
	const char *oper_server2;	/* point to scache */
	char *reason2;
	time_t time_request2;

	time_t last_gline_time;	/* for expiring entry */
	char user[USERLEN + 1];
	char host[HOSTLEN + 1];
}
gline_pending_t;

/* how long a pending G line can be around
 * 10 minutes should be plenty
 */

#define GLINE_PENDING_EXPIRE 600
#define CLEANUP_GLINES_TIME  300

extern rb_dlink_list pending_glines;
extern rb_dlink_list glines;

#endif
