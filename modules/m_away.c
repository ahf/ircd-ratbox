/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_away.c: Sets/removes away status on a user.
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
 *  $Id: m_away.c 26576 2009-05-28 15:26:34Z androsyn $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "s_conf.h"
#include "s_serv.h"

static int m_away(struct Client *, struct Client *, int, const char **);

struct Message away_msgtab = {
	"AWAY", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_away, 0}, {m_away, 0}, mg_ignore, mg_ignore, {m_away, 0}}
};

mapi_clist_av2 away_clist[] = { &away_msgtab, NULL };

DECLARE_MODULE_AV2(away, NULL, NULL, away_clist, NULL, NULL, "$Revision: 26576 $");

/***********************************************************************
 * m_away() - Added 14 Dec 1988 by jto. 
 *            Not currently really working, I don't like this
 *            call at all...
 *
 *            ...trying to make it work. I don't like it either,
 *            but perhaps it's worth the load it causes to net.
 *            This requires flooding of the whole net like NICK,
 *            USER, MODE, etc messages...  --msa
 *		
 *            The above comments have long since irrelvant, but
 *            are kept for historical purposes now ;)
 ***********************************************************************/

/*
** m_away
**      parv[1] = away message
*/
static int
m_away(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(MyClient(source_p) && !IsFloodDone(source_p))
		flood_endgrace(source_p);

	if(!IsClient(source_p))
		return 0;

	if(parc < 2 || EmptyString(parv[1]))
	{
		/* Marking as not away */
		if(source_p->user->away != NULL)
		{
			/* we now send this only if they were away before --is */
			sendto_server(client_p, NULL, CAP_TS6, NOCAPS,
				      ":%s AWAY", source_p->id);
			free_away(source_p);
		}
		if(MyConnect(source_p))
			sendto_one(source_p, form_str(RPL_UNAWAY), me.name, source_p->name);
		return 0;
	}


	if(source_p->user->away == NULL)
	{
		allocate_away(source_p);
		rb_strlcpy(source_p->user->away, parv[1], AWAYLEN);
		sendto_server(client_p, NULL, CAP_TS6, NOCAPS,
			      ":%s AWAY :%s", source_p->id, source_p->user->away);

	}
	else
	{
		rb_strlcpy(source_p->user->away, parv[1], AWAYLEN);
	}

	if(MyConnect(source_p))
		sendto_one(source_p, form_str(RPL_NOWAWAY), me.name, source_p->name);

	return 0;
}
