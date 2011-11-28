/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_map.c: Sends an Undernet compatible map to a user.
 *
 *  Copyright (C) 2002 by the past and present ircd coders, and others.
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
 *  $Id: m_map.c 26574 2009-05-28 14:30:34Z androsyn $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "parse.h"
#include "modules.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "ircd.h"
#include "match.h"

#define USER_COL       50	/* display | Users: %d at col 50 */

static int m_map(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int mo_map(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message map_msgtab = {
	"MAP", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_map, 0}, mg_ignore, mg_ignore, mg_ignore, {mo_map, 0}}
};

mapi_clist_av2 map_clist[] = { &map_msgtab, NULL };

DECLARE_MODULE_AV2(map, NULL, NULL, map_clist, NULL, NULL, "$Revision: 26574 $");

static void dump_map(struct Client *client_p, struct Client *root, char *pbuf);

static char buf[BUFSIZE];

/* m_map
*/
static int
m_map(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if((!IsExemptShide(source_p) && ConfigServerHide.flatten_links) ||
	   ConfigFileEntry.map_oper_only)
	{
		m_not_oper(client_p, source_p, parc, parv);
		return 0;
	}
	SetCork(source_p);
	dump_map(source_p, &me, buf);
	ClearCork(source_p);
	sendto_one(source_p, form_str(RPL_MAPEND), me.name, source_p->name);
	return 0;
}

/*
** mo_map
*/
static int
mo_map(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	SetCork(source_p);
	dump_map(source_p, &me, buf);
	ClearCork(source_p);
	sendto_one(source_p, form_str(RPL_MAPEND), me.name, source_p->name);

	return 0;
}

/*
** dump_map
**   dumps server map, called recursively.
*    you must pop the sendq after this is done..with the MAPEND numeric
*/
static void
dump_map(struct Client *client_p, struct Client *root_p, char *pbuf)
{
	int cnt = 0, i = 0, len;
	struct Client *server_p;
	char scratch[128];
	rb_dlink_node *ptr;
	*pbuf = '\0';

	rb_strlcat(pbuf, root_p->name, BUFSIZE);

	rb_strlcat(pbuf, "[", BUFSIZE);
	rb_strlcat(pbuf, root_p->id, BUFSIZE);
	rb_strlcat(pbuf, "]", BUFSIZE);

	len = strlen(buf);
	buf[len] = ' ';

	if(len < USER_COL)
	{
		for(i = len + 1; i < USER_COL; i++)
		{
			buf[i] = '-';
		}
	}
	sprintf(scratch, "%4.1f%%",
		(float)100 * (float)rb_dlink_list_length(&root_p->serv->users) /
		(float)Count.total);

	rb_snprintf(buf + USER_COL, BUFSIZE - USER_COL,
		    " | Users: %5lu (%s)", rb_dlink_list_length(&root_p->serv->users), scratch);

	sendto_one(client_p, form_str(RPL_MAP), me.name, client_p->name, buf);

	if(root_p->serv->servers.head != NULL)
	{
		cnt += rb_dlink_list_length(&root_p->serv->servers);

		if(cnt)
		{
			if(pbuf > buf + 3)
			{
				pbuf[-2] = ' ';
				if(pbuf[-3] == '`')
					pbuf[-3] = ' ';
			}
		}
	}
	i = 1;
	RB_DLINK_FOREACH(ptr, root_p->serv->servers.head)
	{
		server_p = ptr->data;
		*pbuf = ' ';
		if(i < cnt)
			*(pbuf + 1) = '|';
		else
			*(pbuf + 1) = '`';

		*(pbuf + 2) = '-';
		*(pbuf + 3) = ' ';
		dump_map(client_p, server_p, pbuf + 4);

		i++;
	}
}
