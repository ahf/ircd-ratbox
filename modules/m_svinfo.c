/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_svinfo.c: Sends TS information for clock & compatibility checks.
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
 *  $Id: m_svinfo.c 27173 2011-03-28 18:24:39Z moggie $
 */
#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_log.h"
#include "parse.h"
#include "modules.h"

static int ms_svinfo(struct Client *, struct Client *, int, const char **);

struct Message svinfo_msgtab = {
	"SVINFO", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_ignore, mg_ignore, {ms_svinfo, 5}, mg_ignore, mg_ignore}
};

mapi_clist_av2 svinfo_clist[] = { &svinfo_msgtab, NULL };

DECLARE_MODULE_AV2(svinfo, NULL, NULL, svinfo_clist, NULL, NULL, "$Revision: 27173 $");

/*
 * ms_svinfo - SVINFO message handler
 *      parv[1] = TS_CURRENT for the server
 *      parv[2] = TS_MIN for the server
 *      parv[3] = unused, send 0
 *      parv[4] = server's idea of UTC time
 */
static int
ms_svinfo(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	signed int deltat;
	time_t theirtime;

	/* SVINFO isnt remote. */
	if(source_p != client_p)
		return 0;

	if(TS_CURRENT < atoi(parv[2]) || atoi(parv[1]) < TS_MIN)
	{
		/* TS version is too low on one of the sides, drop the link */
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Link %s dropped, wrong TS protocol version (%s,%s)",
				     source_p->name, parv[1], parv[2]);
		exit_client(source_p, source_p, source_p, "Incompatible TS version");
		return 0;
	}

	/*
	 * since we're here, might as well call rb_set_time() while we're at it
	 */
	rb_set_time();
	theirtime = atol(parv[4]);
	deltat = abs(theirtime - rb_time());

	if(deltat > ConfigFileEntry.ts_max_delta)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Link %s dropped, excessive TS delta"
				     " (my TS=%ld, their TS=%ld, delta=%d)",
				     source_p->name,
				     (long)rb_time(), (long)theirtime, deltat);
		ilog(L_SERVER,
		     "Link %s dropped, excessive TS delta"
		     " (my TS=%ld, their TS=%ld, delta=%d)",
		     log_client_name(source_p, SHOW_IP), (long)rb_time(), (long)theirtime,
		     deltat);
		disable_server_conf_autoconn(source_p->name);
		exit_client(source_p, source_p, source_p, "Excessive TS delta");
		return 0;
	}

	if(deltat > ConfigFileEntry.ts_warn_delta)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Link %s notable TS delta"
				     " (my TS=%ld, their TS=%ld, delta=%d)",
				     source_p->name, (long)rb_time(), (long)theirtime,
				     deltat);
	}

	return 0;
}
