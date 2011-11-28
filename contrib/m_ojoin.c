/*   contrib/m_ojoin.c
 *   Copyright (C) 2002 Hybrid Development Team
 *   Copyright (C) 2004 ircd-ratbox Development Team
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *   $Id: m_ojoin.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "channel.h"
#include "client.h"
#include "ircd.h"
#include "numeric.h"
#include "s_log.h"
#include "s_serv.h"
#include "s_newconf.h"
#include "send.h"
#include "whowas.h"
#include "match.h"
#include "hash.h"
#include "parse.h"
#include "modules.h"


static int mo_ojoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);


struct Message ojoin_msgtab = {
	"OJOIN", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_ojoin, 2}}
};

mapi_clist_av2 ojoin_clist[] = { &ojoin_msgtab, NULL };

DECLARE_MODULE_AV2(ojoin, NULL, NULL, ojoin_clist, NULL, NULL, "$Revision: 27173 $");

/*
** mo_ojoin
**      parv[1] = channel
*/
static int
mo_ojoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;
	int move_me = 0;

	/* admins only */
	if(!IsOperAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "ojoin");
		return 0;
	}

	/* XXX - we might not have CBURSTed this channel if we are a lazylink
	 * yet. */

	if(*parv[1] == '@' || *parv[1] == '%' || *parv[1] == '+')
	{
		parv[1]++;
		move_me = 1;
	}

	if((chptr = find_channel(parv[1])) == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				   form_str(ERR_NOSUCHCHANNEL), parv[1]);
		return 0;
	}

	if(IsMember(source_p, chptr))
	{
		sendto_one(source_p, ":%s NOTICE %s :Please part %s before using OJOIN",
			   me.name, source_p->name, parv[1]);
		return 0;
	}

	if(move_me == 1)
		parv[1]--;

	if(*parv[1] == '@')
	{
		add_user_to_channel(chptr, source_p, CHFL_CHANOP);
		sendto_server(client_p, chptr, NOCAPS, NOCAPS,
			      ":%s SJOIN %ld %s + :@%s",
			      me.name, (long)chptr->channelts, chptr->chname, source_p->name);
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN %s",
				     source_p->name,
				     source_p->username, source_p->host, chptr->chname);
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s +o %s",
				     me.name, chptr->chname, source_p->name);

	}
	else if(*parv[1] == '+')
	{
		add_user_to_channel(chptr, source_p, CHFL_VOICE);
		sendto_server(client_p, chptr, NOCAPS, NOCAPS,
			      ":%s SJOIN %ld %s + :+%s",
			      me.name, (long)chptr->channelts, chptr->chname, source_p->name);
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN %s",
				     source_p->name,
				     source_p->username, source_p->host, chptr->chname);
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s +v %s",
				     me.name, chptr->chname, source_p->name);
	}
	else
	{
		add_user_to_channel(chptr, source_p, CHFL_PEON);
		sendto_server(client_p, chptr, NOCAPS, NOCAPS,
			      ":%s SJOIN %ld %s + :%s",
			      me.name, (long)chptr->channelts, chptr->chname, source_p->name);
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN %s",
				     source_p->name,
				     source_p->username, source_p->host, chptr->chname);
	}

	/* send the topic... */
	if(chptr->topic != NULL)
	{
		sendto_one(source_p, form_str(RPL_TOPIC), me.name,
			   source_p->name, chptr->chname, chptr->topic->topic);
		sendto_one(source_p, form_str(RPL_TOPICWHOTIME), me.name,
			   source_p->name, chptr->chname, chptr->topic->topic_info,
			   chptr->topic->topic_time);
	}

	source_p->localClient->last_join_time = rb_time();
	channel_member_names(chptr, source_p, 1);

	return 0;
}
