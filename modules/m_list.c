/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_list.c: Shows what servers are currently connected.
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
 *  $Id: m_list.c 27173 2011-03-28 18:24:39Z moggie $
 */

#include "stdinc.h"
#include "struct.h"
#include "channel.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "class.h"
#include "client.h"

static int m_list(struct Client *, struct Client *, int, const char **);
static int mo_list(struct Client *, struct Client *, int, const char **);

struct Message list_msgtab = {
	"LIST", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_list, 0}, mg_ignore, mg_ignore, mg_ignore, {mo_list, 0}}
};

mapi_clist_av2 list_clist[] = { &list_msgtab, NULL };

DECLARE_MODULE_AV2(list, NULL, NULL, list_clist, NULL, NULL, "$Revision: 27173 $");

static void list_all_channels(struct Client *source_p);
static void list_limit_channels(struct Client *source_p, const char *param);
static void list_named_channel(struct Client *source_p, const char *name);

/* m_list()
 *      parv[1] = channel
 */
static int
m_list(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static time_t last_used = 0L;

	if(parc < 2 || !IsChannelName(parv[1]))
	{
		/* pace this due to the sheer traffic involved */
		if(((last_used + ConfigFileEntry.pace_wait) > rb_time()))
		{
			sendto_one(source_p, form_str(RPL_LOAD2HI),
				   me.name, source_p->name, "LIST");
			sendto_one(source_p, form_str(RPL_LISTEND), me.name, source_p->name);
			return 0;
		}
		else
			last_used = rb_time();
	}

	/* If no arg, do all channels *whee*, else just one channel */
	if(parc < 2 || EmptyString(parv[1]))
		list_all_channels(source_p);
	else if(IsChannelName(parv[1]))
		list_named_channel(source_p, parv[1]);
	else
		list_limit_channels(source_p, parv[1]);

	return 0;
}

/* mo_list()
 *      parv[1] = channel
 */
static int
mo_list(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* If no arg, do all channels *whee*, else just one channel */
	if(parc < 2 || EmptyString(parv[1]))
		list_all_channels(source_p);
	else if(IsChannelName(parv[1]))
		list_named_channel(source_p, parv[1]);
	else
		list_limit_channels(source_p, parv[1]);

	return 0;
}

/* list_all_channels()
 *
 * inputs	- pointer to client requesting list
 * output	-
 * side effects	- list all channels to source_p
 */
static void
list_all_channels(struct Client *source_p)
{
	struct Channel *chptr;
	rb_dlink_node *ptr;
	int sendq_limit;
	int count = 0;
	/* give them an output limit of 90% of their sendq. --fl */
	sendq_limit = (int)get_sendq(source_p);
	sendq_limit /= 10;
	sendq_limit *= 9;

	sendto_one(source_p, form_str(RPL_LISTSTART), me.name, source_p->name);
	SetCork(source_p);

	RB_DLINK_FOREACH(ptr, global_channel_list.head)
	{
		chptr = ptr->data;

		/* if theyre overflowing their sendq, stop. --fl */
		if(rb_linebuf_len(&source_p->localClient->buf_sendq) > sendq_limit)
		{
			sendto_one(source_p, form_str(ERR_TOOMANYMATCHES),
				   me.name, source_p->name, "LIST");
			break;
		}

		if(SecretChannel(chptr) && !IsMember(source_p, chptr))
			continue;
		sendto_one(source_p, form_str(RPL_LIST),
			   me.name, source_p->name, chptr->chname,
			   rb_dlink_list_length(&chptr->members),
			   chptr->topic == NULL ? "" : chptr->topic->topic);

		if(count++ >= 10)
		{
			ClearCork(source_p);
			send_pop_queue(source_p);
			SetCork(source_p);
			count = 0;
		}
	}
	ClearCork(source_p);
	sendto_one(source_p, form_str(RPL_LISTEND), me.name, source_p->name);
	return;
}

static void
list_limit_channels(struct Client *source_p, const char *param)
{
	struct Channel *chptr;
	char *args;
	char *p;
	rb_dlink_node *ptr;
	int sendq_limit;
	int max = INT_MAX;
	int min = 0;
	int i;
	int count = 0;

	args = LOCAL_COPY(param);

	for(i = 0; i < 2; i++)
	{
		if((p = strchr(args, ',')) != NULL)
			*p++ = '\0';

		if(*args == '<')
		{
			args++;
			if((max = atoi(args)) <= 0)
				max = INT_MAX;
		}
		else if(*args == '>')
		{
			args++;
			if((min = atoi(args)) < 0)
				min = 0;
		}

		if(EmptyString(p))
			break;
		else
			args = p;
	}

	/* give them an output limit of 90% of their sendq. --fl */
	sendq_limit = (unsigned int)get_sendq(source_p);
	sendq_limit /= 10;
	sendq_limit *= 9;

	sendto_one(source_p, form_str(RPL_LISTSTART), me.name, source_p->name);
	SetCork(source_p);

	RB_DLINK_FOREACH(ptr, global_channel_list.head)
	{
		chptr = ptr->data;

		/* if theyre overflowing their sendq, stop. --fl */
		if(rb_linebuf_len(&source_p->localClient->buf_sendq) > sendq_limit)
		{
			sendto_one(source_p, form_str(ERR_TOOMANYMATCHES),
				   me.name, source_p->name, "LIST");
			break;
		}

		if((int)rb_dlink_list_length(&chptr->members) >= max ||
		   (int)rb_dlink_list_length(&chptr->members) <= min)
			continue;

		if(SecretChannel(chptr) && !IsMember(source_p, chptr))
			continue;

		sendto_one(source_p, form_str(RPL_LIST),
			   me.name, source_p->name, chptr->chname,
			   rb_dlink_list_length(&chptr->members),
			   chptr->topic == NULL ? "" : chptr->topic->topic);

		if(count++ >= 10)
		{
			ClearCork(source_p);
			send_pop_queue(source_p);
			SetCork(source_p);
			count = 0;
		}
	}
	ClearCork(source_p);
	sendto_one(source_p, form_str(RPL_LISTEND), me.name, source_p->name);
	return;
}


/* list_named_channel()
 * 
 * inputs       - pointer to client requesting list
 * output       -
 * side effects	- list single channel to source
 */
static void
list_named_channel(struct Client *source_p, const char *name)
{
	struct Channel *chptr;
	char *p;
	char *n = LOCAL_COPY(name);

	SetCork(source_p);
	sendto_one(source_p, form_str(RPL_LISTSTART), me.name, source_p->name);

	if((p = strchr(n, ',')))
		*p = '\0';

	if(*n == '\0')
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), name);
		ClearCork(source_p);
		sendto_one(source_p, form_str(RPL_LISTEND), me.name, source_p->name);
		return;
	}

	chptr = find_channel(n);

	if(chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), n);
		ClearCork(source_p);
		sendto_one(source_p, form_str(RPL_LISTEND), me.name, source_p->name);
		return;
	}

	if(ShowChannel(source_p, chptr))
		sendto_one(source_p, form_str(RPL_LIST),
			   me.name, source_p->name, chptr->chname,
			   rb_dlink_list_length(&chptr->members),
			   chptr->topic == NULL ? "" : chptr->topic->topic);

	ClearCork(source_p);
	sendto_one(source_p, form_str(RPL_LISTEND), me.name, source_p->name);
	return;
}
