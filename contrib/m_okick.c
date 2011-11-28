/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_okick.c: Kicks a user from a channel with much prejudice.
 *
 *  Copyright (C) 2002 by the past and present ircd coders, and others.
 *  Copyright (C) 2004 ircd-ratbox Development Team
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
 *  $Id: m_okick.c 26421 2009-01-18 17:38:16Z jilles $
 */

#include "stdinc.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "channel.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "modules.h"
#include "parse.h"
#include "hash.h"
#include "packet.h"
#include "s_serv.h"

static int mo_okick(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);


struct Message okick_msgtab = {
	"OKICK", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_okick, 4}}
};

mapi_clist_av2 okick_clist[] = { &okick_msgtab, NULL };

DECLARE_MODULE_AV2(okick, NULL, NULL, okick_clist, NULL, NULL, "$Revision: 26421 $");

/*
** m_okick
**      parv[1] = channel
**      parv[2] = client to kick
**      parv[3] = kick comment
*/
static int
mo_okick(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *who;
	struct Client *target_p;
	struct Channel *chptr;
	struct membership *msptr;
	int chasing = 0;
	char *comment;
	char *name;
	char *p = NULL;
	char *user;
	static char buf[BUFSIZE];

	if(*parv[2] == '\0')
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS), me.name, source_p->name, "KICK");
		return 0;
	}

	if(MyClient(source_p) && !IsFloodDone(source_p))
		flood_endgrace(source_p);

	comment = (EmptyString(LOCAL_COPY(parv[3]))) ? LOCAL_COPY(parv[2]) : LOCAL_COPY(parv[3]);
	if(strlen(comment) > (size_t)REASONLEN)
		comment[REASONLEN] = '\0';

	*buf = '\0';
	if((p = strchr(parv[1], ',')))
		*p = '\0';

	name = LOCAL_COPY(parv[1]);

	chptr = find_channel(name);
	if(!chptr)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL, form_str(ERR_NOSUCHCHANNEL), name);
		return 0;
	}


	if((p = strchr(parv[2], ',')))
		*p = '\0';
	user = LOCAL_COPY(parv[2]);	// strtoken(&p2, parv[2], ","); 
	if(!(who = find_chasing(source_p, user, &chasing)))
	{
		return 0;
	}

	if((target_p = find_client(user)) == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOSUCHNICK), me.name, source_p->name, user);
		return 0;
	}

	if((msptr = find_channel_membership(chptr, target_p)) == NULL)
	{
		sendto_one(source_p, form_str(ERR_USERNOTINCHANNEL),
			   me.name, source_p->name, parv[1], parv[2]);
		return 0;
	}

	sendto_channel_local(ALL_MEMBERS, chptr, ":%s KICK %s %s :%s",
			     me.name, chptr->chname, who->name, comment);
	sendto_server(&me, chptr, NOCAPS, NOCAPS,
		      ":%s KICK %s %s :%s", me.name, chptr->chname, who->name, comment);
	remove_user_from_channel(msptr);
	return 0;
}
