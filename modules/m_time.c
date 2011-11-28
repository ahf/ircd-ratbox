/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_time.c: Sends the current time on the server.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2006 ircd-ratbox development team
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
 *  $Id: m_time.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "ircd.h"
#include "numeric.h"
#include "s_serv.h"
#include "send.h"
#include "parse.h"
#include "modules.h"

static int m_time(struct Client *, struct Client *, int, const char **);

struct Message time_msgtab = {
	"TIME", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_time, 0}, {m_time, 2}, mg_ignore, mg_ignore, {m_time, 0}}
};

mapi_clist_av2 time_clist[] = { &time_msgtab, NULL };

DECLARE_MODULE_AV2(time, NULL, NULL, time_clist, NULL, NULL, "$Revision: 27173 $");

/*
 * m_time
 *      parv[1] = servername
 */
static int
m_time(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* this is not rate limited, so end the grace period */
	char buf[80];
	if(MyClient(source_p) && !IsFloodDone(source_p))
		flood_endgrace(source_p);


	if(hunt_server(client_p, source_p, ":%s TIME :%s", 1, parc, parv) == HUNTED_ISME)
	{
		sendto_one_numeric(source_p, RPL_TIME, form_str(RPL_TIME),
				   me.name, rb_date(rb_time(), buf, sizeof(buf)));
	}
	return 0;
}
